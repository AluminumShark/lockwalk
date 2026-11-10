"""Turn tool-like values from any source into ToolDescriptor.

Every agent framework has to describe its tools to the model in the same basic shape:
a name, a description, and a JSON Schema for the arguments. MCP's tools/list returns that
shape too. So instead of one adapter per framework, lockwalk recognizes the shape, and
opens tool containers (toolkits, tool nodes, agents) to reach the tools inside.
"""

import inspect
import sys
from collections.abc import Callable, Hashable, Iterable, Mapping, MutableMapping
from typing import Any, Literal

from lockwalk.models import ToolDescriptor, check_name
from lockwalk.urls import redact_urls

# MCP tool annotations that lockwalk keeps for display. They are hints only and are never
# used to decide a tool's risk.
HINT_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")

# How deeply tool containers (agent -> toolkit -> tools) may nest. Also stops cycles.
MAX_NESTING = 5

# Attributes that link an agent to other agents or to servers. Having one of
# them as a list or tuple is part of what makes an object look like an agent. Only a list
# or tuple counts, so objects that answer every attribute (unittest.mock.MagicMock, an
# xmlrpc ServerProxy) do not look like agents.
AGENT_LINK_ATTRIBUTES = ("handoffs", "members", "agents", "toolsets", "mcp_servers")


class NormalizeError(ValueError):
    """A value could not be recognized as a tool."""


class RuntimeToolsetError(NormalizeError):
    """A toolset whose tools are known only at run time: its get_tools() is async.

    Pydantic AI toolsets that wrap or build other toolsets (PrefixedToolset,
    FilteredToolset, RenamedToolset, a function decorated with @agent.toolset, and so on)
    list their tools only inside a run, given a run context. lockwalk never runs anything.
    """


def describe_error(exc: BaseException) -> str:
    """The exception's type name and message, for a warning or an error.

    The message comes from user code, so every URL in it loses its credentials, query, and
    fragment (other secrets in plain text cannot be recognized). When str() itself raises,
    only the type name is given.
    """
    name = type(exc).__name__
    try:
        text = str(exc)
    except BaseException:
        return name
    text = redact_urls(text)
    return f"{name}: {text}" if text else name


def tool_key(tool: ToolDescriptor) -> Hashable:
    """A hashable key that is equal exactly when two descriptors are equal."""
    return (tool.name, tool.description, tuple(sorted(tool.hints.items())))


def has_static(value: object, name: str) -> bool:
    """True when the attribute exists, checked without running any property or __getattr__."""
    try:
        inspect.getattr_static(value, name)
    except AttributeError:
        return False
    return True


def is_network_proxy(value: object) -> bool:
    """True for objects whose ordinary attribute reads call the network.

    Agno RemoteAgent, RemoteTeam, and RemoteWorkflow (subclasses of agno.remote.base.BaseRemote)
    fetch their configuration over HTTP when .name, .role, .tools, or .description is read
    (verified on agno 3.1.12). This is a safety exception to recognizing shapes instead of
    classes: it looks only at type(value).__mro__, so no attribute of the value is read.
    Every helper below checks it first, before even isinstance() (which can read
    __class__), and then reads nothing else from such an object.
    """
    return any(
        klass.__name__ == "BaseRemote" and klass.__module__.startswith("agno.")
        for klass in type(value).__mro__
    )


def is_mcp_client(value: object) -> bool:
    """An MCP client found among an agent's tools or toolsets.

    - list_tools() and call_tool(): the MCP client verbs (OpenAI Agents SDK MCP servers,
      Pydantic AI MCP toolsets, mcp.ClientSession)
    - server_params and session: Agno MCPTools, a toolkit that is empty until it connects

    Presence is checked with inspect.getattr_static, so no property runs. (mcp's Client and
    CrewAI's MCPClient raise from .session before they connect.)
    """
    if has_static(value, "list_tools") and has_static(value, "call_tool"):
        return True
    return has_static(value, "server_params") and has_static(value, "session")


def is_async_toolset(value: object) -> bool:
    """True when the value's class defines an async get_tools(): a Pydantic AI toolset.

    Such an object holds tools; it is never an agent, even when it holds other toolsets in
    a .toolsets list (a CombinedToolset). Only the class is looked at, so nothing runs.
    """
    if is_network_proxy(value):
        return False
    try:
        get_tools = inspect.getattr_static(type(value), "get_tools")
    except AttributeError:
        return False
    return inspect.iscoroutinefunction(get_tools) or inspect.isasyncgenfunction(get_tools)


def is_plain_tool_container(value: object) -> bool:
    """True for containers that hold tools by name: they are never agents.

    Agno Toolkit (.functions), LangGraph ToolNode (.tools_by_name), and Pydantic AI
    FunctionToolset (.tools mapping).
    """
    if is_network_proxy(value) or isinstance(value, Mapping):
        return False
    return any(
        isinstance(getattr(value, attribute, None), Mapping)
        for attribute in ("functions", "tools_by_name", "tools")
    )


def has_agent_shape(value: object) -> bool:
    """True when a value is shaped like an agent, a team, a crew, or a LangGraph graph.

    This is the second condition for being an agent; agent_name() is the first. Attributes are only
    read; nothing is called. A network proxy (a remote agent) counts as an agent, without
    reading any of its attributes. Tool containers never do, and neither does a Pydantic
    AI toolset (is_async_toolset), even a CombinedToolset with its .toolsets list.
    """
    if value is None:
        return False
    if is_network_proxy(value):
        return True
    if isinstance(value, Mapping | type) or is_plain_tool_container(value):
        return False
    if is_async_toolset(value):
        return False
    if isinstance(getattr(value, "tools", None), list | tuple) or stores_factory(value, "tools"):
        return True
    for attribute in AGENT_LINK_ATTRIBUTES:
        if isinstance(getattr(value, attribute, None), list | tuple):
            return True
        if stores_factory(value, attribute):
            return True
    return is_compiled_graph(value)


def stores_factory(value: object, attribute: str) -> bool:
    """True when the object itself stores a function under this attribute: a factory.

    Agno 3.1.12 agents and teams accept tools=<a function that returns the tools at run
    time>, and teams accept members= the same way. Only a function stored on the instance
    counts; a tools() method defined on a class (as some toolkits and adapters have) does
    not, and neither does an attribute that a proxy makes up on access.
    """
    try:
        stored = vars(value).get(attribute)
    except TypeError:  # no __dict__
        return False
    return callable(stored) and not isinstance(stored, type)


def is_compiled_graph(value: object) -> bool:
    """A LangGraph compiled graph: it has get_graph() and keeps the StateGraph as .builder.

    Both are checked statically first, so a proxy that answers every attribute is not one.
    """
    if is_network_proxy(value) or not (
        has_static(value, "get_graph") and has_static(value, "builder")
    ):
        return False
    return (
        callable(getattr(value, "get_graph", None)) and getattr(value, "builder", None) is not None
    )


def agent_name(value: object) -> str | None:
    """The agent's name: .name, or else .role (CrewAI agents only have a role).

    None for a network proxy, whose .name would call the network.
    """
    if is_network_proxy(value):
        return None
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    role = getattr(value, "role", None)
    return role if isinstance(role, str) else None


AgentToolKind = Literal["agent", "unknown", "plain"]


def agent_tool_check(value: object) -> tuple[AgentToolKind, object | None]:
    """Whether a tool wraps an agent: ("agent", the agent), ("unknown", None), or
    ("plain", None).

    OpenAI Agents SDK: Agent.as_tool() returns a FunctionTool that keeps the agent in the
    private attributes `_is_agent_tool` and `_agent_instance` (verified on openai-agents
    0.24.0, where `_is_agent_tool` is a dataclass field with the class default False). It
    also records where the tool came from: `_tool_origin.type` is
    `agents.ToolOriginType.AGENT_AS_TOOL` (a str enum with the value "agent_as_tool"); a
    plain function tool has `_tool_origin = None`. Either signal marks a wrapper.
    Private attributes can change in any release, so this fails closed:
    - a wrapper by either signal, but no agent is found: "unknown";
    - an SDK FunctionTool whose class has no `_is_agent_tool` at all, and whose origin
      does not say it wraps an agent: "unknown", because lockwalk can then no longer tell
      a wrapper from a plain function tool.
    Only FunctionTool is checked: the SDK's hosted tools (HostedMCPTool, WebSearchTool,
    and so on) never had the attribute and never wrap an agent. An "unknown" tool is still
    a tool; the caller decides what else follows from it. One change cannot be noticed: the
    class keeps the `_is_agent_tool` field but as_tool() no longer sets it, and the origin no
    longer says AGENT_AS_TOOL. Its wrappers are "plain".
    """
    if is_network_proxy(value):
        return "plain", None
    if getattr(value, "_is_agent_tool", False) is True or _made_by_as_tool(value):
        agent = getattr(value, "_agent_instance", None)
        return ("agent", agent) if has_agent_shape(agent) else ("unknown", None)
    if _is_sdk_function_tool(value) and not has_static(type(value), "_is_agent_tool"):
        return "unknown", None
    return "plain", None


def _made_by_as_tool(value: object) -> bool:
    """True when the tool's recorded origin says Agent.as_tool() made it.

    `_tool_origin` and its `type` are read with inspect.getattr_static only, so no property
    runs. The type is compared with the SDK's own ToolOriginType.AGENT_AS_TOOL when the
    SDK is already imported (it is, whenever such a tool exists); otherwise with its value
    "agent_as_tool", which is what the str enum compares equal to.
    """
    try:
        origin = inspect.getattr_static(value, "_tool_origin")
        kind = inspect.getattr_static(origin, "type")
    except AttributeError:
        return False
    if not isinstance(kind, str):
        return False
    origin_types = getattr(sys.modules.get("agents"), "ToolOriginType", None)
    marker = getattr(origin_types, "AGENT_AS_TOOL", None)
    if isinstance(marker, str):
        return kind == marker
    return kind == "agent_as_tool"


def _is_sdk_function_tool(value: object) -> bool:
    """An OpenAI Agents SDK FunctionTool (or a subclass), told by its class alone."""
    return any(
        klass.__name__ == "FunctionTool" and klass.__module__.partition(".")[0] == "agents"
        for klass in type(value).__mro__
    )


def wrapped_agent(value: object) -> object | None:
    """The agent inside an agent-as-tool wrapper, or None (see agent_tool_check).

    An "unknown" wrapper gives None, so it is read as a plain tool, as before;
    tests/test_agent_shapes.py fails loudly if the private attributes disappear.
    """
    kind, agent = agent_tool_check(value)
    return agent if kind == "agent" else None


def descriptor_from_dict(data: Mapping[str, Any]) -> ToolDescriptor:
    """Read a tool description dict in MCP, Anthropic, OpenAI chat, or OpenAI flat format."""
    inner = data.get("function")
    if isinstance(inner, Mapping):
        data = inner
    name = data.get("name")
    if not isinstance(name, str):
        raise NormalizeError("tool description has no string 'name'")
    description = data.get("description")
    return ToolDescriptor(
        name=_valid_name(name),
        description=description if isinstance(description, str) else None,
        hints=_hints(data.get("annotations")),
    )


def descriptor_from_object(value: object) -> ToolDescriptor:
    """Recognize one tool: a description dict, an object with a .name, or a plain function."""
    if is_network_proxy(value):
        raise NormalizeError(
            f"{_type_name(value)} calls the network when it is read; lockwalk does not read it"
        )
    if isinstance(value, Mapping):
        return descriptor_from_dict(value)
    if isinstance(value, type):
        raise NormalizeError(
            f"{value.__qualname__} is a class, not a tool; point at an instance or a list of tools"
        )
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        description = getattr(value, "description", None)
        return ToolDescriptor(
            name=_valid_name(name),
            description=description if isinstance(description, str) else None,
        )
    if callable(value):
        function_name = getattr(value, "__name__", None)
        if isinstance(function_name, str) and function_name != "<lambda>":
            return ToolDescriptor(
                name=_valid_name(function_name), description=_first_doc_line(value)
            )
    raise NormalizeError(f"cannot recognize a tool in a value of type {_type_name(value)}")


def tool_container_contents(value: object) -> list[object] | None:
    """Return the tools inside a tool container, or None if the value is not a container.

    This is checked before the .name rule, because containers often have a name of their
    own (an Agno Toolkit is named "finance_tools", a LangGraph ToolNode is named "tools").
    Checked in this order:
    - an agent-as-tool wrapper: OpenAI Agents SDK Agent.as_tool(); returns [the agent], so
      the wrapped agent's tools are collected and the wrapper is not reported as a tool
    - .functions mapping:      Agno Toolkit
    - .tools_by_name mapping:  LangGraph ToolNode
    - .tools mapping:          Pydantic AI FunctionToolset
    - .tools list or tuple:    Agno, CrewAI, and OpenAI Agents SDK agents
    - .toolsets list or tuple: Pydantic AI Agent
    - .get_tools() that takes no arguments: LangChain BaseToolkit
      (Agno agents have a get_tools that needs a run context, so it is skipped for them).
      get_tools must really exist (checked statically), so a proxy that answers every
      attribute is never called.
    An async get_tools() (a Pydantic AI toolset that is resolved at run time) raises
    RuntimeToolsetError, because its tools cannot be listed without running it.
    """
    if is_network_proxy(value) or isinstance(value, Mapping):
        return None
    agent = wrapped_agent(value)
    if agent is not None:
        return [agent]
    functions = getattr(value, "functions", None)
    if isinstance(functions, Mapping):
        return list(functions.values())
    by_name = getattr(value, "tools_by_name", None)
    if isinstance(by_name, Mapping):
        return list(by_name.values())
    tools = getattr(value, "tools", None)
    if isinstance(tools, Mapping):
        return list(tools.values())
    if isinstance(tools, list | tuple):
        return list(tools)
    toolsets = getattr(value, "toolsets", None)
    if isinstance(toolsets, list | tuple):
        return list(toolsets)
    if not has_static(value, "get_tools"):
        return None
    get_tools = getattr(value, "get_tools", None)
    if callable(get_tools):
        if inspect.iscoroutinefunction(get_tools) or inspect.isasyncgenfunction(get_tools):
            raise RuntimeToolsetError(
                "async get_tools() is not supported; point lockwalk at the tool list instead"
            )
        if _takes_no_arguments(get_tools):
            result = get_tools()
            if isinstance(result, list | tuple):
                return list(result)
            if isinstance(result, Mapping):
                return list(result.values())
            raise NormalizeError(
                f"get_tools() returned {_type_name(result)}, expected a list of tools"
            )
    return None


def _takes_no_arguments(function: Callable[..., object]) -> bool:
    try:
        parameters = inspect.signature(function).parameters.values()
    except (TypeError, ValueError):
        return False
    variadic = (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    return all(p.default is not inspect.Parameter.empty or p.kind in variadic for p in parameters)


def normalize_items(
    items: Iterable[object],
    *,
    opened: MutableMapping[int, object] | None = None,
    objects: MutableMapping[str, object] | None = None,
) -> tuple[list[ToolDescriptor], list[str]]:
    """Normalize many values. Return the recognized tools and one error per bad item.

    Tool containers are opened (up to MAX_NESTING levels deep) and their tools are
    normalized one by one. Error locations look like "item 2.1" for nested items.
    When `opened` is given, every container whose tools were looked at (and whose tool
    problems are therefore reported here) is added to it, keyed by id(). The objects are
    kept as the values, so no id() is reused while the mapping lives.

    An agent-as-tool wrapper is replaced by its agent without adding a nesting level. A
    named agent inside a tool list (a wrapped one included) is a boundary: it is not
    opened here, and the agent graph walk collects its tools and reports their problems.
    So a chain of agents used as tools never hits MAX_NESTING. An object shaped like an
    agent without a tool list of its own (a team, a crew, a LangGraph graph) is not a
    tool; the tools of its members are collected by the agent graph walk.

    Inside an agent, two more things are boundaries, without an error: an MCP client (the
    walk links the agent to an mcp_server node) and a toolset that is resolved at run time
    (the walk marks the agent opaque and warns). Anywhere else they are what they were: a
    run-time toolset is an error, because then no agent stands for its hidden tools.

    When `objects` is given, the first object seen for each recognized tool name is added
    to it (the door-test harness uses this to find the tool behind a name).
    """
    tools: list[ToolDescriptor] = []
    errors: list[str] = []
    seen: MutableMapping[int, object] = opened if opened is not None else {}
    for index, item in enumerate(items):
        _collect(
            item,
            f"item {index}",
            0,
            tools,
            errors,
            (),
            set(),
            seen,
            in_agent=False,
            objects=objects,
        )
    return tools, errors


def _collect(
    value: object,
    where: str,
    depth: int,
    tools: list[ToolDescriptor],
    errors: list[str],
    path: tuple[int, ...],
    cycles: set[int],
    opened: MutableMapping[int, object],
    *,
    in_agent: bool,
    objects: MutableMapping[str, object] | None = None,
) -> None:
    """Collect one value. in_agent: some agent holds it, directly or inside containers."""
    try:
        # An "unknown" wrapper (agent_tool_check) gives None here, so it is collected as a
        # plain tool and the inventory stays what it was; the graph walk marks its owner.
        agent = wrapped_agent(value)
        if agent is not None:
            value = agent
        if depth > 0 and (agent is not None or _is_named_agent(value)):
            return  # a boundary: the agent graph walk collects this agent's tools
        if in_agent and is_mcp_client(value):
            return  # a boundary: the agent graph walk links the agent to an mcp_server node
        contents = tool_container_contents(value)
        holds = in_agent or (contents is not None and has_agent_shape(value))
    except RuntimeToolsetError as exc:
        if not in_agent:
            errors.append(f"{where}: {redact_urls(str(exc))}")
        # Otherwise the agent graph walk marks the agent opaque and names the toolset.
        return
    except NormalizeError as exc:
        errors.append(f"{where}: {redact_urls(str(exc))}")
        return
    except Exception as exc:  # get_tools() and properties are user code and may fail
        errors.append(f"{where}: reading its tools raised {describe_error(exc)}")
        return
    if contents is not None:
        opened[id(value)] = value
        if id(value) in path:
            if id(value) not in cycles:  # report each cyclic container only once
                cycles.add(id(value))
                errors.append(f"{where}: tool container contains itself")
            return
        if depth >= MAX_NESTING:
            errors.append(
                f"{where}: tool containers are nested more than {MAX_NESTING} levels deep"
            )
            return
        for index, child in enumerate(contents):
            _collect(
                child,
                f"{where}.{index}",
                depth + 1,
                tools,
                errors,
                (*path, id(value)),
                cycles,
                opened,
                in_agent=holds,
                objects=objects,
            )
        return
    try:
        if has_agent_shape(value):
            opened[id(value)] = value
            return
        descriptor = descriptor_from_object(value)
        tools.append(descriptor)
        if objects is not None:
            objects.setdefault(descriptor.name, value)
    except NormalizeError as exc:
        errors.append(f"{where}: {redact_urls(str(exc))}")
    except Exception as exc:  # .name, .description, __doc__ are user code and may fail
        errors.append(f"{where}: reading the tool raised {describe_error(exc)}")


def _is_named_agent(value: object) -> bool:
    return has_agent_shape(value) and agent_name(value) is not None


def _valid_name(name: str) -> str:
    try:
        return check_name(name)
    except ValueError as exc:
        raise NormalizeError(f"invalid tool name {name!r}: {exc}") from exc


def _hints(annotations: object) -> dict[str, bool]:
    if not isinstance(annotations, Mapping):
        return {}
    return {key: annotations[key] for key in HINT_KEYS if isinstance(annotations.get(key), bool)}


def _first_doc_line(value: object) -> str | None:
    doc = getattr(value, "__doc__", None)
    if not isinstance(doc, str):
        return None
    for line in doc.strip().splitlines():
        if line.strip():
            return line.strip()
    return None


def _type_name(value: object) -> str:
    kind = type(value)
    return f"{kind.__module__}.{kind.__qualname__}"
