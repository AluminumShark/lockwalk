"""Find the agent and tool objects behind the inventory ids and tool names.

The ids come from lockwalk's static discovery, run again inside the
harness subprocess on the objects the user's targets resolved to. Framework classes are
only looked at when their module is already imported: this module never imports one.
"""

import sys
from collections.abc import Sequence
from dataclasses import dataclass, field

from lockwalk.harness.protocol import Framework
from lockwalk.inventory import normalize
from lockwalk.inventory.agent_shapes import Collected, discover


@dataclass(frozen=True)
class Found:
    agents: dict[str, object] = field(default_factory=dict)  # inventory node id -> agent object
    frameworks: dict[str, Framework] = field(default_factory=dict)  # inventory node id -> framework
    tools: dict[str, object] = field(default_factory=dict)  # tool name -> first object seen
    # agent id -> {wrapped agent id: (wrapper tool name, wrapper object)}
    agent_tools: dict[str, dict[str, tuple[str, object]]] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


def find(values: Sequence[object]) -> Found:
    """Collect the agents and tools in values. Never raises because of user properties."""
    warnings: list[str] = []
    values = list(values)
    top_tools: dict[str, object] = {}
    collected = Collected()
    try:
        opened: dict[int, object] = {}
        normalize.normalize_items(values, opened=opened, objects=top_tools)
        discover(values, covered=opened, objects=collected)
    except Exception as exc:
        warnings.append(f"finding agents and tools raised {normalize.describe_error(exc)}")
    tools = dict(collected.tools)
    for name, obj in top_tools.items():
        tools.setdefault(name, obj)
    frameworks: dict[str, Framework] = {}
    agent_tools: dict[str, dict[str, tuple[str, object]]] = {}
    for agent_id, agent in collected.agents.items():
        try:
            frameworks[agent_id] = _framework_of(agent)
            wrapped = _wrapper_tools(agent, collected.agents)
            if wrapped:
                agent_tools[agent_id] = wrapped
        except Exception as exc:
            warnings.append(f"reading agent {agent_id!r} raised {normalize.describe_error(exc)}")
            frameworks.setdefault(agent_id, "other")
    return Found(
        agents=dict(collected.agents),
        frameworks=frameworks,
        tools=tools,
        agent_tools=agent_tools,
        warnings=tuple(warnings),
    )


def _framework_of(agent: object) -> Framework:
    """The framework of an agent, from classes of modules that are already imported."""
    if _is_instance(agent, "agents", "Agent", ("function_tool", "Runner")):
        return "openai_agents"
    if _is_instance(agent, "pydantic_ai", "Agent", ("models",)):
        return "pydantic_ai"
    if _is_instance(agent, "langgraph.pregel", "Pregel", (), top="langgraph"):
        return "langgraph"
    return "other"


def _is_instance(
    obj: object, module: str, name: str, required: tuple[str, ...], *, top: str | None = None
) -> bool:
    """True when obj is an instance of the framework's own class.

    A user package that happens to be called `agents` must not count: the class has to
    live in the framework's top package, and the module needs attributes only the real
    framework has.
    """
    top = top or module
    loaded = sys.modules.get(module)
    klass = getattr(loaded, name, None)
    if not isinstance(klass, type) or not isinstance(obj, klass):
        return False
    if not (klass.__module__ == top or klass.__module__.startswith(top + ".")):
        return False
    return all(hasattr(sys.modules.get(top), attr) for attr in required)


def _wrapper_tools(agent: object, known: dict[str, object]) -> dict[str, tuple[str, object]]:
    """The agent-as-tool wrappers among the agent's own tools (one level).

    A wrapper counts only when its agent is the object recorded under that name, so two
    agents that share a name never get each other's wrapper.
    """
    result: dict[str, tuple[str, object]] = {}
    for item in normalize.tool_container_contents(agent) or []:
        wrapped = normalize.wrapped_agent(item)
        if wrapped is None:
            continue
        wrapped_name = normalize.agent_name(wrapped)
        tool_name = getattr(item, "name", None)
        if known.get(wrapped_name or "") is not wrapped:
            continue
        if isinstance(wrapped_name, str) and isinstance(tool_name, str):
            result.setdefault(wrapped_name, (tool_name, item))
    return result
