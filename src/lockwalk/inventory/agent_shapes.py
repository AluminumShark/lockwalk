"""Find agents, and the edges between them, in the objects a Python target resolves to.

Like normalize.py, this recognizes shapes instead of framework classes. An
object has an agent shape (normalize.has_agent_shape) when it has at least one of: a tools
list or tuple, a handoffs, members, agents, toolsets, or mcp_servers list or tuple, a
tools or link factory stored on the instance, or a LangGraph get_graph() with a builder.
No name is needed for the shape: an agent with a string name (or, for CrewAI, a role)
becomes a node, and one without is still walked for its tools, with a warning.

What is read and called: attributes are read, which runs property code, except on network
proxies (see normalize.is_network_proxy), which are only inspected with
inspect.getattr_static. Beyond reading attributes, the only calls are:
- get_tools() when it really exists and takes no arguments (as tool collection already
  does), and inspect.signature() to find that out;
- the weakref.ref inside an OpenAI Agents SDK Handoff, which runs no user code;
- vars() of an object, to tell a stored tools factory from a method;
- str() of MCP server command arguments that are not strings (guarded);
- iteration and .get(), .keys(), .values(), .items() on the lists and mappings it reads;
- str() of exceptions, through normalize.describe_error (guarded, URLs redacted).
A factory (tools=<function>) is never called. Every agent is read inside its own guard:
an attribute that raises costs only that agent, which is marked opaque.

MCP server ids are "mcp:<name>"; mcp_naming.py chooses the name so that command
arguments, which can hold tokens, never reach it.

Edges:
- a tool that is an agent, or an agent-as-tool wrapper:  agent_as_tool
- any other tool:                                         uses_tool (to the tool name)
- .handoffs:                                              handoff
- .members, .agents, and a .manager_agent:                team
- .allow_delegation is True inside .members or .agents:   calls (inferred) to each coworker
- .mcp_servers, .mcps, and MCP clients among the tools:   remote, to an mcp_server node
- .tasks[*].tools (CrewAI Task(tools=...)):              uses_tool from the task's .agent;
  for a task without an agent, inferred edges from every agent of the crew

LangGraph node ids are "<graph id>:<node name>". LangGraph itself reserves ":" in node
names, so these ids never collide with each other. A node whose runnable is a compiled
subgraph is that subgraph, so its own nodes are "<graph id>:<node name>:<inner node>".

Nodes are opaque (what they reach is unknown) when they are known only by a name, when
they are remote (an Agno RemoteAgent, a LangGraph RemoteGraph), or when they lie more than
MAX_AGENT_DEPTH agents deep. A walked agent is opaque too when the walk dropped part of
what it reaches: an attribute that is not a list or that raised when read, a tools
factory, a child with no name or an invalid name, a child whose name another agent or MCP
server already has (its edge then points at that other one), a handoff, member, or
manager_agent that is not an agent, a task with tools but no agent, an unnamed MCP server,
a tool that cannot be read, or a LangGraph route entry that cannot be read. opaque=False
means the walk saw all of the agent's edges.

When what was dropped are tools (the tools attribute or one of its items, an MCP server, a
task's tools, a LangGraph ToolNode, a LangGraph route that cannot be read in a graph that
has a ToolNode, or anything else the walk read while it collected the tools), the node also
gets tools_hidden=True. Declaring `calls` in the registry clears the
opacity of an agent whose calls to other agents were missed, but not of one whose tools
were: `calls` lists agents, not tools (see graph/build.py).

Network safety: the attributes of an Agno RemoteAgent, RemoteTeam, or RemoteWorkflow call
the network, so they are never read. Its node id and URL come from what its constructor
stored, read with inspect.getattr_static.
"""

import contextlib
import importlib.metadata
import inspect
import weakref
from collections import deque
from collections.abc import Callable, Generator, Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple

from lockwalk.inventory.mcp_naming import (
    node_id_text,
    read_server,
    server_name,
    server_url,
)
from lockwalk.inventory.normalize import (
    MAX_NESTING,
    NormalizeError,
    RuntimeToolsetError,
    agent_name,
    agent_tool_check,
    describe_error,
    descriptor_from_object,
    has_agent_shape,
    has_static,
    is_compiled_graph,
    is_mcp_client,
    is_network_proxy,
    normalize_items,
    tool_container_contents,
    tool_key,
)
from lockwalk.models import (
    EdgeKind,
    GraphEdge,
    GraphFragment,
    GraphNode,
    NodeKind,
    Provenance,
    ToolDescriptor,
    check_name,
)
from lockwalk.urls import redact_url, redact_urls

# LangGraph's reserved names for the start and the end of a graph. They are not nodes.
START = "__start__"
END = "__end__"

# How many agents deep (agent -> member -> handoff -> ...) the walk looks. Agents beyond
# this are shown as opaque nodes. Tool containers have their own limit, MAX_NESTING.
MAX_AGENT_DEPTH = 32

# Agno remote objects keep their remote id in one of these fields (agno 3.1.12).
_REMOTE_ID_FIELDS = ("agent_id", "team_id", "workflow_id")

_DISCOVERED = Provenance.DISCOVERED
_INFERRED = Provenance.INFERRED


class _Reach(NamedTuple):
    """What a tool item lets an agent reach: an edge kind and a target id.

    wrapper is the tool name when the item is an agent-as-tool wrapper whose name was read.
    """

    kind: EdgeKind
    target: str
    wrapper: str | None = None


@dataclass(frozen=True)
class Discovery:
    """What the graph walk found.

    tools holds every tool that some agent in the graph uses, in first-seen order. It
    includes the tools of agents that normalize_items never opens, such as handoff
    targets, team members, agents used as tools, task tools, and LangGraph ToolNodes.
    """

    fragment: GraphFragment
    warnings: tuple[str, ...]
    tools: tuple[ToolDescriptor, ...]


@dataclass
class Collected:
    """The objects behind what discover() found, for the door-test harness.

    Filled only when discover() is given one; the default None changes nothing.
    """

    agents: dict[str, object] = field(default_factory=dict)  # node id -> agent object
    tools: dict[str, object] = field(default_factory=dict)  # tool name -> first object seen


def discover_graph(values: Sequence[object]) -> tuple[GraphFragment, list[str]]:
    """Discover agents and tools from values and return only the graph fragment and warnings."""
    found = discover(values)
    return found.fragment, list(found.warnings)


def discover(
    values: Sequence[object],
    *,
    covered: Mapping[int, object] | None = None,
    objects: Collected | None = None,
) -> Discovery:
    """Walk agent-like objects and return the graph they describe, warnings, and tools.

    `values` are the top-level objects the target resolved to; agent-like ones become
    entry nodes (entry=True). The module docstring lists what is read and called.

    `covered` maps id() to the containers that normalize_items already opened (its
    `opened` argument). Problems with their tools were reported there as errors, so they
    are not repeated here. When it is None, normalize_items is run to find out.

    `objects`, when given, receives the agent object behind each node id and the first
    object seen for each tool name.
    """
    values = list(values)
    if covered is None:
        opened: dict[int, object] = {}
        normalize_items(values, opened=opened)
        covered = opened
    walker = _Walker(values, covered, objects)
    walker.run()
    return walker.result()


class _Walker:
    """Breadth-first walk, so every agent is first reached by its shortest path."""

    def __init__(
        self,
        values: list[object],
        covered: Mapping[int, object],
        objects: Collected | None = None,
    ) -> None:
        self._values = values
        self._covered = covered
        self._objects = objects
        self._entries: set[int] = set()
        self._nodes: dict[str, GraphNode] = {}
        self._owners: dict[str, Hashable] = {}
        self._edges: dict[tuple[str, str, EdgeKind, Provenance], dict[str, None]] = {}
        self._warnings: dict[str, None] = {}
        self._tools: dict[Hashable, ToolDescriptor] = {}
        # (agent, node id, depth, tools only)
        self._queue: deque[tuple[object, str | None, int, bool]] = deque()
        self._tools_only: set[int] = set()
        self._seen: set[tuple[int, str | None]] = set()
        self._name_only: dict[str, None] = {}
        # Objects stay referenced for the whole walk, so no id() is reused by another object.
        self._keep: list[object] = []

    def run(self) -> None:
        tops: list[object] = []
        for value in self._values:
            try:
                kind, agent = agent_tool_check(value)
                if kind == "unknown":
                    self._warn_as_tool_changed()  # a top-level tool has no owner to mark
                if agent is not None:
                    tops.append(agent)
                elif has_agent_shape(value):
                    self._entries.add(id(value))
                    tops.append(value)
            except Exception as exc:  # properties are user code
                self._warn(
                    f"reading a top-level value of type {_type_name(value)} raised "
                    f"{describe_error(exc)}; it is skipped"
                )
        for value in tops:
            try:
                self._ref(value, 0, parent=None)
            except Exception as exc:
                self._warn(
                    f"reading a top-level value of type {_type_name(value)} raised "
                    f"{describe_error(exc)}; it is skipped"
                )
        while self._queue:
            value, node_id, depth, tools_only = self._queue.popleft()
            label = _label(value, node_id)
            # Anything that escapes the inner guards may have cost tools, too.
            with self._guard(node_id, label, tools=True):
                if tools_only:
                    self._expand_tools(value, None, depth, label)
                else:
                    self._expand(value, node_id, depth, label)
        for name in self._name_only:
            if name not in self._nodes:
                self._nodes[name] = GraphNode(id=name, opaque=True)
                self._warn(
                    f"agent {name!r} is known only by its name; lockwalk cannot see "
                    "what it can reach, so declare it in the registry"
                )

    def result(self) -> Discovery:
        nodes = tuple(self._nodes.values())
        # A discovered edge makes the inferred edge between the same two ends redundant.
        found = {
            (start, end, kind) for start, end, kind, prov in self._edges if prov is _DISCOVERED
        }
        edges = tuple(
            GraphEdge(
                from_id=start, to_id=end, kind=kind, provenance=prov, wrapped_by=tuple(wrappers)
            )
            for (start, end, kind, prov), wrappers in self._edges.items()
            if prov is _DISCOVERED or (start, end, kind) not in found
        )
        return Discovery(
            fragment=GraphFragment(nodes=nodes, edges=edges),
            warnings=tuple(self._warnings),
            tools=tuple(self._tools.values()),
        )

    @contextlib.contextmanager
    def _guard(
        self, node_id: str | None, label: str, *, tools: bool = False
    ) -> Generator[None, None, None]:
        """Run one step of reading an agent; if user code raises, the agent goes opaque.

        tools=True for a step that reads tools: an error there also hides tools.
        Nodes are registered before their edges, so whatever was added before the error
        still refers only to known nodes.
        """
        try:
            yield
        except Exception as exc:  # properties and __getattr__ are user code
            self._mark_opaque(node_id, tools=tools)
            self._warn(
                f"{label}: reading it raised {describe_error(exc)}; "
                "lockwalk could not see all of its edges"
            )

    # ---- nodes and edges ----

    def _mark_opaque(self, node_id: str | None, *, tools: bool = False) -> None:
        """The walk dropped part of what this agent reaches, so its edges are incomplete.

        tools=True when what was dropped are tools: the node is then tools_hidden as well.
        """
        node = self._nodes.get(node_id) if node_id is not None else None
        if node is None:
            return
        update = {"opaque": True, "tools_hidden": node.tools_hidden or tools}
        if (node.opaque, node.tools_hidden) != (update["opaque"], update["tools_hidden"]):
            self._nodes[node.id] = node.model_copy(update=update)

    def _claim(self, node_id: str, owner: Hashable, node: GraphNode) -> bool:
        """Give node_id to owner and register its node.

        Return False, with a warning, when another owner already has the id; the caller
        decides whether an edge may still point at the node that is already there.
        """
        known = self._owners.get(node_id)
        if known is None:
            self._owners[node_id] = owner
            self._nodes[node_id] = node
            return True
        if known == owner:
            return True
        kinds = {node.kind, self._nodes[node_id].kind}
        if kinds == {NodeKind.MCP_SERVER}:
            self._warn(
                f"two different MCP servers are both shown as {node_id!r}; give them distinct names"
            )
        elif NodeKind.MCP_SERVER in kinds:
            self._warn(
                f"an agent and an MCP server are both named {node_id!r}; "
                "only the first one is shown"
            )
        else:
            self._warn(f"two different agents are named {node_id!r}; only the first one is shown")
        return False

    def _ref(
        self, value: object, depth: int, as_id: str | None = None, *, parent: str | None
    ) -> str | None:
        """Register an agent reached from `parent` and queue it for expansion.

        Return the id edges should use. When the agent cannot be shown, or its edge would
        resolve to a different agent of the same name, the parent is marked opaque.
        """
        target, exact = self._resolve(value, depth, as_id)
        if target is None or not exact:
            self._mark_opaque(parent)
        return target

    def _resolve(self, value: object, depth: int, as_id: str | None) -> tuple[str | None, bool]:
        """(the node id, whether that node really is this object)."""
        self._keep.append(value)
        if is_network_proxy(value):
            return self._remote_proxy(value)
        if depth > MAX_AGENT_DEPTH:
            # Below the opaque node at the depth limit: no node, but the tools still count.
            self._queue_tools_only(value, depth)
            return None, False
        node_id = self._agent_id(value) if as_id is None else self._valid_id(as_id, "agent id")
        key = (id(value), node_id)
        if key in self._seen:
            return node_id, node_id is not None
        too_deep = depth >= MAX_AGENT_DEPTH
        if node_id is not None:
            node = GraphNode(id=node_id, entry=id(value) in self._entries, opaque=too_deep)
            if not self._claim(node_id, ("agent", id(value)), node):
                # Its id belongs to another agent or server, so it gets no node and no edges
                # of its own; its tools are still collected, as they are for any agent.
                self._queue_tools_only(value, depth)
                return node_id, False
            if self._objects is not None:
                self._objects.agents.setdefault(node_id, value)
        self._seen.add(key)
        if too_deep:
            what = repr(node_id) if node_id is not None else f"of type {_type_name(value)}"
            self._warn(
                f"agent {what} is nested more than {MAX_AGENT_DEPTH} agents deep; lockwalk "
                "shows it as opaque and only collects the tools below it"
            )
            self._queue_tools_only(value, depth)
        else:
            # An unnamed agent is still walked, so its tools are collected.
            self._queue.append((value, node_id, depth, False))
        return node_id, node_id is not None

    def _queue_tools_only(self, value: object, depth: int) -> None:
        """Collect this agent's tools (and those of agents used as its tools), once, with
        no node and no edges of its own."""
        if id(value) not in self._tools_only:
            self._tools_only.add(id(value))
            self._queue.append((value, None, depth, True))

    def _remote_proxy(self, value: object) -> tuple[str | None, bool]:
        """An opaque remote_agent node for an object whose attributes call the network."""
        remote_id = _static_text(value, _REMOTE_ID_FIELDS)
        if remote_id is None:
            self._warn(
                f"an Agno {type(value).__name__} was found; lockwalk does not read its "
                "properties because they call the network; declare it in the registry "
                "with remote:"
            )
            return None, False
        node_id = self._valid_id(remote_id, "remote agent id")
        if node_id is None:
            return None, False
        url = _static_text(value, ("base_url",))
        remote_url = redact_url(url) if url is not None else None
        node = GraphNode(
            id=node_id,
            kind=NodeKind.REMOTE_AGENT,
            entry=id(value) in self._entries,
            opaque=True,
            remote_url=remote_url,
        )
        return node_id, self._claim(node_id, ("remote", node_id, remote_url), node)

    def _leaf(
        self, node_id: str, owner: Hashable, parent: str, *, remote: bool = False
    ) -> str | None:
        """Register a node that has nothing inside it to walk: a plain LangGraph node, or
        (remote=True) an opaque remote_agent node for a LangGraph RemoteGraph."""
        valid = self._valid_id(node_id, "LangGraph node id")
        if valid is None:
            self._mark_opaque(parent)
            return None
        if remote:
            node = GraphNode(id=valid, kind=NodeKind.REMOTE_AGENT, opaque=True)
        else:
            node = GraphNode(id=valid)
        if not self._claim(valid, ("leaf", owner), node):
            self._mark_opaque(parent)
        return valid

    def _name_only_ref(self, name: str, parent: str | None) -> str | None:
        """An agent that is known only by its name: emit the edge and a bare node, no walk."""
        valid = self._valid_id(name, "agent name")
        if valid is None:
            self._mark_opaque(parent)
        else:
            self._name_only[valid] = None
        return valid

    def _edge(
        self,
        start: str | None,
        end: str | None,
        kind: EdgeKind,
        provenance: Provenance,
        wrapper: str | None = None,
    ) -> None:
        if start is not None and end is not None:
            wrappers = self._edges.setdefault((start, end, kind, provenance), {})
            if wrapper is not None:
                wrappers[wrapper] = None

    def _emit(
        self,
        owner: str | None,
        reaches: Iterable[_Reach],
        complete: bool,
        provenance: Provenance = _DISCOVERED,
    ) -> None:
        """Edges from `owner` to what its tool items reach.

        When some item was dropped, the owner is opaque and its tools are hidden.
        """
        for kind, target, wrapper in reaches:
            self._edge(owner, target, kind, provenance, wrapper)
        if not complete:
            self._mark_opaque(owner, tools=True)

    def _wrapper_name(self, item: object) -> str | None:
        """The tool name of an agent-as-tool wrapper, or None when it cannot be read.

        A wrapper without a readable name is simply not named: observe then reports a trace
        span of that name as an unknown tool, which is the safe side.
        """
        try:
            return descriptor_from_object(item).name
        except Exception:  # properties are user code
            return None

    def _agent_id(self, value: object) -> str | None:
        name = agent_name(value)
        if name is None:
            self._warn(
                f"agent of type {_type_name(value)} has no name; "
                "set name= so lockwalk can show its edges"
            )
            return None
        return self._valid_id(name, "agent name")

    def _valid_id(self, text: str, what: str) -> str | None:
        try:
            return check_name(text)
        except ValueError as exc:
            self._warn(f"{what} {text!r} is not valid ({exc}); lockwalk cannot show its edges")
            return None

    def _warn(self, message: str) -> None:
        self._warnings[message] = None

    def _warn_as_tool_changed(self) -> None:
        """The as_tool() canary (normalize.agent_tool_check) failed; warn once."""
        try:
            version = importlib.metadata.version("openai-agents")
        except Exception:  # not installed as a distribution, or broken metadata
            version = "(unknown version)"
        self._warn(
            f"openai-agents {version} changed how as_tool() is stored; lockwalk cannot tell "
            "which tools wrap agents, so agents with function tools are treated as opaque"
        )

    def _add_tool(self, tool: ToolDescriptor) -> None:
        self._tools.setdefault(tool_key(tool), tool)

    # ---- expanding one agent ----

    def _expand(self, value: object, node_id: str | None, depth: int, label: str) -> None:
        with self._guard(node_id, label, tools=True):
            self._expand_tools(value, node_id, depth, label)
        for item in self._listed(value, "handoffs", node_id, label):
            with self._guard(node_id, label):
                target = self._handoff_target(item, depth, node_id, label)
                self._edge(node_id, target, EdgeKind.HANDOFF, _DISCOVERED)
        group: list[str] = []
        for attribute in ("members", "agents"):
            group.extend(self._team(value, attribute, node_id, depth, label))
        manager_id: str | None = None
        with self._guard(node_id, label):
            manager = getattr(value, "manager_agent", None)
            if manager is not None and has_agent_shape(manager):
                manager_id = self._ref(manager, depth + 1, parent=node_id)
                self._edge(node_id, manager_id, EdgeKind.TEAM, _DISCOVERED)
                for member_id in group:
                    if member_id != manager_id:
                        self._edge(manager_id, member_id, EdgeKind.TEAM, _DISCOVERED)
            elif manager is not None:
                self._warn(
                    f"{label}: manager_agent is a {_type_name(manager)}, which is not an "
                    "agent; it is ignored"
                )
                self._mark_opaque(node_id)
        crew = [*group, *([manager_id] if manager_id is not None else [])]
        self._tasks(value, node_id, depth, label, crew)
        if node_id is not None:
            for attribute in ("mcp_servers", "mcps"):
                for item in self._listed(value, attribute, node_id, label, tools=True):
                    with self._guard(node_id, label, tools=True):
                        target, exact = self._mcp_node(item)
                        reaches = [] if target is None else [_Reach(EdgeKind.REMOTE, target)]
                        self._emit(node_id, reaches, exact)
        if is_compiled_graph(value) and node_id is not None:
            self._expand_graph(value, node_id, depth, label)

    def _listed(
        self, value: object, attribute: str, node_id: str | None, label: str, *, tools: bool = False
    ) -> list[object]:
        """The list stored under this attribute; anything else is warned about.

        tools=True when the list holds tools or their providers (tasks, MCP servers), so a
        list that cannot be read hides tools.
        """
        items: object = None
        with self._guard(node_id, label, tools=tools):
            items = getattr(value, attribute, None)
        if items is None:
            return []
        if isinstance(items, list | tuple):
            return list(items)
        self._warn(
            f"{label}: {attribute} is a {_type_name(items)}, not a list; "
            "lockwalk cannot see what it holds"
        )
        self._mark_opaque(node_id, tools=tools)
        return []

    def _handoff_target(
        self, item: object, depth: int, node_id: str | None, label: str
    ) -> str | None:
        if has_agent_shape(item):
            return self._ref(item, depth + 1, parent=node_id)
        target = _handoff_agent(item)
        if target is not None:
            return self._ref(target, depth + 1, parent=node_id)
        name = getattr(item, "agent_name", None)
        if isinstance(name, str):
            return self._name_only_ref(name, node_id)
        name = agent_name(item)
        if name is not None:
            return self._name_only_ref(name, node_id)
        self._warn(f"{label}: a handoff of type {_type_name(item)} names no agent; it is ignored")
        self._mark_opaque(node_id)
        return None

    def _team(
        self, value: object, attribute: str, node_id: str | None, depth: int, label: str
    ) -> list[str]:
        members: list[tuple[object, str]] = []
        for item in self._listed(value, attribute, node_id, label):
            with self._guard(node_id, label):
                shaped = has_agent_shape(item)
                name = None if shaped else agent_name(item)
                if shaped:
                    member_id = self._ref(item, depth + 1, parent=node_id)
                elif name is not None:
                    # A name, but no agent shape: nothing to look inside, so a bare opaque node.
                    member_id = self._name_only_ref(name, node_id)
                else:
                    self._warn(
                        f"{label}: {attribute} holds a {_type_name(item)}, which is not an "
                        "agent; it is ignored"
                    )
                    self._mark_opaque(node_id)
                    member_id = None
                if member_id is not None:
                    self._edge(node_id, member_id, EdgeKind.TEAM, _DISCOVERED)
                    members.append((item, member_id))
        # CrewAI allow_delegation=True gives an agent a tool that can ask any coworker.
        # A remote proxy is never read, so it cannot delegate as far as lockwalk knows.
        for item, member_id in members:
            if is_network_proxy(item):
                continue
            with self._guard(member_id, f"agent {member_id!r}"):
                if getattr(item, "allow_delegation", False) is True:
                    for _, other_id in members:
                        if other_id != member_id:
                            self._edge(member_id, other_id, EdgeKind.CALLS, _INFERRED)
        return [member_id for _, member_id in members]

    def _tasks(
        self, value: object, node_id: str | None, depth: int, label: str, crew: list[str]
    ) -> None:
        """Tools given to a task (CrewAI Task(tools=...)) are used by the task's agent.

        A task with tools but no agent is handed to an agent at run time (by the manager
        in a hierarchical crew), so every agent of the crew may reach those tools: they
        get inferred edges, and the crew is marked opaque. The tools are collected either
        way.
        """
        for task in self._listed(value, "tasks", node_id, label, tools=True):
            with self._guard(node_id, label, tools=True):
                tools = getattr(task, "tools", None)
                if tools is None:
                    continue
                if not isinstance(tools, list | tuple):
                    self._warn(
                        f"{label}: a task's tools are a {_type_name(tools)}, not a list; "
                        "lockwalk cannot see what they hold"
                    )
                    self._mark_opaque(node_id, tools=True)
                    continue
                if not tools:
                    continue
                try:
                    agent = getattr(task, "agent", None)
                except Exception as exc:  # treated like a task without an agent
                    self._warn(
                        f"{label}: reading a task's agent raised {describe_error(exc)}; "
                        "lockwalk treats the task as having no agent"
                    )
                    agent = None
                if agent is None or not has_agent_shape(agent):
                    self._warn(
                        f"{label}: a task has tools but no agent, so the crew picks the agent "
                        "at run time; lockwalk cannot tell which agent reaches those tools"
                    )
                    self._mark_opaque(node_id, tools=True)
                    reaches, complete = self._tool_items(
                        tools, depth, label, where="task tool", quiet=False
                    )
                    for member_id in crew:
                        self._emit(member_id, reaches, complete, _INFERRED)
                    continue
                agent_id = self._ref(agent, depth + 1, parent=node_id)
                self._edge(node_id, agent_id, EdgeKind.TEAM, _DISCOVERED)
                agent_label = f"agent {agent_id!r}" if agent_id is not None else label
                reaches, complete = self._tool_items(
                    tools, depth + 1, agent_label, where="task tool", quiet=False
                )
                self._emit(agent_id, reaches, complete)

    # ---- tools ----

    def _expand_tools(self, value: object, node_id: str | None, depth: int, label: str) -> None:
        # Problems in tools that normalize_items also opened were reported there as errors,
        # so they are not repeated as warnings; the agent is still marked opaque.
        quiet = id(value) in self._covered
        items: list[object] | None = None
        try:
            items = tool_container_contents(value)
        except Exception as exc:  # get_tools() and properties are user code
            self._mark_opaque(node_id, tools=True)
            if not quiet:
                self._warn(f"{label}: reading its tools raised {describe_error(exc)}")
        if items is not None:
            reaches, complete = self._tool_items(items, depth, label, quiet=quiet)
            self._emit(node_id, reaches, complete)
        tools = getattr(value, "tools", None)
        if tools is not None and not isinstance(tools, list | tuple | Mapping):
            # For example an Agno tools factory (a function that returns the tools at run
            # time). It is never called.
            self._warn(
                f"{label}: tools is a {_type_name(tools)}, not a list; lockwalk does not "
                "call a tools factory, so it cannot see the tools it returns"
            )
            self._mark_opaque(node_id, tools=True)

    def _tool_items(
        self,
        items: Iterable[object],
        depth: int,
        label: str,
        *,
        where: str = "tool",
        nesting: int = 1,
        quiet: bool,
    ) -> tuple[list[_Reach], bool]:
        """What these tool items let their owner reach, and whether every one was readable.

        Agents and agent-as-tool wrappers are agent_as_tool targets, MCP clients are remote
        targets, containers are opened, and everything else must be a tool. Tools are
        collected. Problems are warned about unless `quiet` (normalize_items reported them).
        A function tool that may or may not wrap an agent (agent_tool_check gives "unknown")
        is collected as a tool, and makes the list incomplete: what it reaches is unknown.
        So does a toolset that is resolved at run time, whose tools cannot be listed; it is
        always warned about, because normalize_items leaves it to this walk.
        """
        reaches: list[_Reach] = []
        complete = True
        for index, item in enumerate(items):
            place = f"{where} {index}" if nesting == 1 else f"{where}.{index}"
            try:
                kind, agent = agent_tool_check(item)
                if kind == "unknown":
                    self._warn_as_tool_changed()
                    complete = False
                if agent is None and has_agent_shape(item):
                    agent = item
                if agent is not None:
                    target, exact = self._resolve(agent, depth + 1, None)
                    if target is not None:
                        name = self._wrapper_name(item) if kind == "agent" else None
                        reaches.append(_Reach(EdgeKind.AGENT_AS_TOOL, target, name))
                    complete = complete and target is not None and exact
                    continue
                if is_mcp_client(item):
                    target, exact = self._mcp_node(item)
                    if target is not None:
                        reaches.append(_Reach(EdgeKind.REMOTE, target))
                    complete = complete and target is not None and exact
                    continue
                contents = tool_container_contents(item)
                if contents is not None:
                    if nesting < MAX_NESTING:
                        inner, ok = self._tool_items(
                            contents, depth, label, where=place, nesting=nesting + 1, quiet=quiet
                        )
                        reaches.extend(inner)
                        complete = complete and ok
                    else:
                        complete = False
                        if not quiet:
                            self._warn(
                                f"{label}: {place}: tool containers are nested more than "
                                f"{MAX_NESTING} levels deep"
                            )
                    continue
                tool = descriptor_from_object(item)
                if self._objects is not None:
                    self._objects.tools.setdefault(tool.name, item)
            except RuntimeToolsetError:
                complete = False
                self._warn(
                    f"{label} uses a toolset that is resolved at run time "
                    f"({type(item).__name__}); lockwalk cannot list its tools"
                )
                continue
            except NormalizeError as exc:
                complete = False
                if not quiet:
                    self._warn(f"{label}: {place}: {redact_urls(str(exc))}")
                continue
            except Exception as exc:  # properties and get_tools() are user code
                complete = False
                if not quiet:
                    self._warn(f"{label}: {place}: reading it raised {describe_error(exc)}")
                continue
            self._add_tool(tool)
            reaches.append(_Reach(EdgeKind.USES_TOOL, tool.name))
        return reaches, complete

    # ---- MCP servers ----

    def _mcp_node(self, item: object) -> tuple[str | None, bool]:
        """The mcp_server node for this server, and whether the node really is this server."""
        config = read_server(item)
        name = server_name(config)
        if name is None:
            self._warn(
                f"MCP server of type {_type_name(item)} has no name; "
                "set name= so lockwalk can show it"
            )
            return None, False
        node_id = self._valid_id(node_id_text(name), "MCP server name")
        if node_id is None:
            return None, False
        node = GraphNode(id=node_id, kind=NodeKind.MCP_SERVER, remote_url=server_url(config))
        if self._claim(node_id, ("mcp", config), node):
            return node_id, True
        # Another MCP server already has the id: the edge still goes to the shared node,
        # which may stand for that other server. An agent with the id gets no MCP edge.
        if self._nodes[node_id].kind is NodeKind.MCP_SERVER:
            return node_id, False
        return None, False

    # ---- LangGraph ----

    def _expand_graph(self, graph: object, graph_id: str, depth: int, label: str) -> None:
        """Turn a compiled LangGraph StateGraph into nodes and edges.

        Read from graph.builder (a StateGraph): .nodes (name -> StateNodeSpec with .runnable,
        .ends, and .error_handler_node), .edges, .waiting_edges, and .branches (source ->
        name -> BranchSpec with .ends). Verified on langgraph 1.2.20.
        """
        builder = getattr(graph, "builder", None)
        specs = getattr(builder, "nodes", None)
        # A node that cannot be read may be a ToolNode, so these problems hide tools.
        if not isinstance(specs, Mapping):
            self._warn(f"{label}: its LangGraph nodes cannot be read")
            self._mark_opaque(graph_id, tools=True)
            return
        names = [name for name in specs if isinstance(name, str)]
        if len(names) != len(specs):
            self._warn(f"{label}: LangGraph nodes has a name that is not a string; it is skipped")
            self._mark_opaque(graph_id, tools=True)
        inner: dict[str, str | None] = {}
        tool_nodes: dict[str, tuple[list[_Reach], bool]] = {}
        for name in names:
            node_id = f"{graph_id}:{name}"
            with self._guard(graph_id, label, tools=True):
                runnable = getattr(specs[name], "runnable", None)
                if _is_remote_graph(runnable):
                    # Checked first, with getattr_static only, before anything reads it.
                    inner[name] = self._leaf(node_id, (id(graph), name), graph_id, remote=True)
                    continue
                if has_agent_shape(runnable):
                    # A compiled subgraph used as a node: the node is that subgraph.
                    inner[name] = self._ref(runnable, depth + 1, node_id, parent=graph_id)
                    continue
                contents = _tool_node_contents(runnable)
                if contents is not None:
                    tool_nodes[name] = self._tool_items(
                        contents, depth, f"LangGraph node {node_id!r}", quiet=False
                    )
                else:
                    inner[name] = self._leaf(node_id, (id(graph), name), graph_id)
        try:
            routes, problems = _graph_routes(builder, specs, names)
        except Exception as exc:  # for example a tuple subclass whose __len__ raises
            routes, problems = {}, [(f"reading its routes raised {describe_error(exc)}", None)]
        # A lost route may be the one into a ToolNode, which is how a node reaches those
        # tools: with a ToolNode in the graph, a route problem hides tools as well.
        hides = bool(tool_nodes)
        for problem, sources in problems:
            self._warn(f"{label}: LangGraph {problem}; lockwalk skipped it")
            self._mark_opaque(graph_id, tools=hides)
            # The routes out of these nodes may be missing. When the source is unknown, or
            # is a ToolNode (whose routes belong to the nodes routing into it), that is
            # every node of the graph.
            unknown = sources is None or any(source in tool_nodes for source in sources)
            for source in names if unknown else sources:
                self._mark_opaque(inner.get(source), tools=hides)
        for source in [START, *names]:
            if source in tool_nodes:
                continue
            start = graph_id if source == START else inner.get(source)
            kind = EdgeKind.TEAM if source == START else EdgeKind.HANDOFF
            self._follow(source, start, kind, routes, inner, tool_nodes)

    def _follow(
        self,
        source: str,
        start: str | None,
        kind: EdgeKind,
        routes: Mapping[str, list[tuple[str, Provenance]]],
        inner: Mapping[str, str | None],
        tool_nodes: Mapping[str, tuple[list[_Reach], bool]],
    ) -> None:
        """Emit the edges out of one LangGraph node, looking through ToolNodes.

        A route into a ToolNode means an edge to everything its tools reach, and the routes
        out of the ToolNode are followed as if they started at `source`. A route into a
        ToolNode with an unreadable tool, or to a node that has no id, marks `start` opaque.
        """
        if start is None:
            return
        stack = [(end, prov, False) for end, prov in reversed(routes.get(source, []))]
        visited: set[tuple[str, Provenance]] = set()
        while stack:
            end, prov, via_tools = stack.pop()
            if end in tool_nodes:
                if (end, prov) in visited:
                    continue
                visited.add((end, prov))
                reaches, complete = tool_nodes[end]
                self._emit(start, reaches, complete, prov)
                for after, after_prov in reversed(routes.get(end, [])):
                    weaker = _INFERRED if _INFERRED in (prov, after_prov) else _DISCOVERED
                    stack.append((after, weaker, True))
                continue
            if end in (START, END) or (via_tools and end == source):
                continue
            target = inner.get(end)
            if target is None:
                self._mark_opaque(start)
            self._edge(start, target, kind, prov)


# A route problem: what went wrong, and the nodes whose outgoing routes may be missing
# (None when that cannot be told, which means every node).
_Problem = tuple[str, tuple[str, ...] | None]


def _graph_routes(
    builder: object, specs: Mapping[object, object], names: list[str]
) -> tuple[dict[str, list[tuple[str, Provenance]]], list[_Problem]]:
    """Every route between LangGraph nodes, as source -> [(destination, provenance)].

    Also returns every entry that could not be read, so the graph and the nodes whose
    routes may be missing can be marked opaque instead of silently losing a route. Each
    entry is read on its own, so one that raises does not hide the others. Nothing in an
    entry is compared or sorted until it is known to be a string.
    """
    routes: dict[str, list[tuple[str, Provenance]]] = {}
    problems: list[_Problem] = []

    def add(source: object, end: object, provenance: Provenance, where: str) -> None:
        if isinstance(source, str) and isinstance(end, str):
            routes.setdefault(source, []).append((end, provenance))
            return
        problems.append(
            (
                f"{where} has a route from a {_type_name(source)} to a {_type_name(end)}",
                (source,) if isinstance(source, str) else None,
            )
        )

    def read(what: str, sources: tuple[str, ...] | None, read_it: Callable[[], object]) -> object:
        try:
            return read_it()
        except Exception as exc:  # builder attributes may be properties
            problems.append((f"reading {what} raised {describe_error(exc)}", sources))
            return _UNREADABLE

    edges = read("edges", None, lambda: getattr(builder, "edges", None))
    if edges is not _UNREADABLE:
        for start, end in _route_pairs(edges, "edges", problems):
            add(start, end, _DISCOVERED, "edges")
    waiting = read("waiting_edges", None, lambda: getattr(builder, "waiting_edges", None))
    if waiting is not _UNREADABLE:
        for starts, end in _route_pairs(waiting, "waiting_edges", problems, joins=True):
            for start in starts:
                add(start, end, _DISCOVERED, "waiting_edges")
    branches = read("branches", None, lambda: getattr(builder, "branches", None))
    if branches is not _UNREADABLE:
        if not isinstance(branches, Mapping):
            problems.append((f"branches is a {_type_name(branches)}", None))
            branches = {}
        entries = read("branches", None, lambda: list(branches.items()))
        for source, by_name in entries if isinstance(entries, list) else []:
            if not isinstance(source, str):
                problems.append((f"branches has a source that is a {_type_name(source)}", None))
                continue
            try:
                _branch_routes(source, by_name, names, add, problems)
            except Exception as exc:  # BranchSpec attributes may be properties
                problems.append(
                    (f"reading the branches of {source!r} raised {describe_error(exc)}", (source,))
                )
    for name in names:
        try:
            spec = specs[name]
            # Command(goto=...) destinations declared with destinations= or a return annotation.
            ends = getattr(spec, "ends", None)
            if isinstance(ends, Mapping | list | tuple):
                for end in list(ends):
                    add(name, end, _DISCOVERED, f"node {name!r}")
            elif ends is not None:
                problems.append((f"node {name!r} has ends that are a {_type_name(ends)}", (name,)))
            handler = getattr(spec, "error_handler_node", None)
            if handler is not None:
                add(name, handler, _DISCOVERED, f"node {name!r}")
        except Exception as exc:  # StateNodeSpec attributes may be properties
            problems.append(
                (f"reading the routes of node {name!r} raised {describe_error(exc)}", (name,))
            )
    return routes, problems


_UNREADABLE = object()


def _branch_routes(
    source: str,
    by_name: object,
    names: list[str],
    add: Callable[[object, object, Provenance, str], None],
    problems: list[_Problem],
) -> None:
    """The routes of the conditional branches that start at one node."""
    if not isinstance(by_name, Mapping):
        problems.append((f"branches has an entry that is a {_type_name(by_name)}", (source,)))
        return
    for branch in list(by_name.values()):
        ends = getattr(branch, "ends", None)
        if isinstance(ends, Mapping):
            for end in list(ends.values()):
                add(source, end, _DISCOVERED, "a branch")
            continue
        if ends is not None:
            problems.append((f"a branch has ends that are a {_type_name(ends)}", (source,)))
        # No declared destinations: the router may go to any other node.
        for end in names:
            if end != source:
                add(source, end, _INFERRED, "a branch")


def _route_pairs(
    value: object, what: str, problems: list[_Problem], *, joins: bool = False
) -> list[tuple]:
    """The (start, end) pairs of a set of LangGraph edges, sorted for a stable order.

    With joins=True the start is a list or tuple of names (waiting_edges). Only pairs
    made of strings are kept and sorted; every other entry is a problem.
    """
    if not isinstance(value, set | frozenset | list | tuple):
        problems.append((f"{what} is a {_type_name(value)}", None))
        return []
    pairs: list[tuple] = []
    try:
        items = list(value)
    except Exception as exc:  # a set subclass may raise while iterating
        problems.append((f"reading {what} raised {describe_error(exc)}", None))
        return []
    for item in items:
        if not (isinstance(item, tuple) and len(item) == 2):
            problems.append((f"{what} holds a {_type_name(item)}", None))
            continue
        start, end = item
        if joins:
            if not isinstance(start, list | tuple):
                problems.append((f"{what} has starts that are a {_type_name(start)}", None))
                continue
            named = tuple(name for name in start if isinstance(name, str))
            if len(named) != len(start) or not isinstance(end, str):
                problems.append((f"{what} has a route that is not made of strings", named or None))
                continue
            pairs.append((named, end))
        elif isinstance(start, str) and isinstance(end, str):
            pairs.append((start, end))
        else:
            problems.append(
                (
                    f"{what} has a route from a {_type_name(start)} to a {_type_name(end)}",
                    (start,) if isinstance(start, str) else None,
                )
            )
    return sorted(pairs, key=lambda pair: (pair[0], pair[1]))


def _tool_node_contents(value: object) -> list[object] | None:
    """The tools of a tool container that is not an agent (a LangGraph ToolNode), read once.

    None when the value is not a tool container. Errors are raised to the caller.
    """
    if value is None or has_agent_shape(value):
        return None
    return tool_container_contents(value)


def _handoff_agent(item: object) -> object | None:
    """The agent behind an OpenAI Agents SDK Handoff made by handoff(agent).

    The SDK keeps it only in the private weak reference `_agent_ref` (verified on
    openai-agents 0.24.0, where agents.extensions.visualization reads it the same way).
    """
    reference = getattr(item, "_agent_ref", None)
    # Only a real weak reference is called: dereferencing one runs no user code.
    if not isinstance(reference, weakref.ref):
        return None
    agent = reference()
    return agent if has_agent_shape(agent) else None


def _is_remote_graph(value: object) -> bool:
    """A LangGraph RemoteGraph: a graph that runs on a server, with no local builder.

    It keeps the server's graph id in .assistant_id (langgraph 1.2.20). Its get_graph()
    calls the server, so it is never called.
    """
    return isinstance(_static_text(value, ("assistant_id",)), str) and has_static(
        value, "get_graph"
    )


def _static_text(value: object, names: Sequence[str]) -> str | None:
    """The first non-empty string stored under one of these names, read without running
    any property or __getattr__."""
    for name in names:
        try:
            found = inspect.getattr_static(value, name)
        except AttributeError:
            continue
        if isinstance(found, str) and found:
            return found
    return None


def _label(value: object, node_id: str | None) -> str:
    return f"agent {node_id!r}" if node_id is not None else f"an agent of type {_type_name(value)}"


def _type_name(value: object) -> str:
    kind = type(value)
    return f"{kind.__module__}.{kind.__qualname__}"
