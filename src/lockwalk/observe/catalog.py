"""What the static map knows, in the shape observe needs."""

from collections.abc import Mapping
from dataclasses import dataclass

from lockwalk.config import ObserveConfig
from lockwalk.errors import StructuralError
from lockwalk.graph.analysis import direct_tools, index_graph
from lockwalk.models import AgentGraph, DelegationMode, EdgeKind, Inventory, NodeKind, Risk
from lockwalk.registry import Registry
from lockwalk.spec_loader import SpecFile

AGENT_KINDS = (NodeKind.AGENT, NodeKind.REMOTE_AGENT)


@dataclass(frozen=True)
class Catalog:
    agents: frozenset[str]  # graph nodes that are agents (local or remote)
    tools: frozenset[str]  # inventory tool ids
    # "tools" that are agents: registry delegation_tools ids, and the tool names discovery
    # reported on an agent_as_tool edge (GraphEdge.wrapped_by). Matched by exact name.
    wrappers: frozenset[str]
    entry_agents: frozenset[str]
    agent_alias: Mapping[str, str]  # [observe.agents]: name in traces -> agent id
    tool_alias: Mapping[str, str]  # [observe.tools]
    agent_edges: frozenset[tuple[str, str]]  # (caller, callee) node-to-node edges between agents
    tool_edges: frozenset[tuple[str, str]]  # (agent, tool): the agent uses the tool directly
    risks: Mapping[str, Risk]  # tool id -> risk
    modes: Mapping[str, DelegationMode | None]  # agent id -> delegation_mode (None: undeclared)
    # case_routes and case_agents come from authored spec cases only (only
    # human-written cases count as tests). A case with an empty route has no last agent, so
    # it adds nothing to case_agents.
    case_routes: frozenset[tuple[tuple[str, ...], str]]  # (route, tool) of every spec case
    case_agents: frozenset[tuple[str, str]]  # (last agent of the route, tool) of every spec case

    def agent_id(self, name: str) -> str | None:
        """The agent id a name in a trace stands for, or None."""
        return name if name in self.agents else self.agent_alias.get(name)

    def tool_id(self, name: str) -> str | None:
        return name if name in self.tools else self.tool_alias.get(name)

    @property
    def agent_names(self) -> frozenset[str]:
        """Names a span may carry to be recognized as an agent by name."""
        return self.agents | frozenset(self.agent_alias)


def build_catalog(
    inventory: Inventory,
    graph: AgentGraph,
    registry: Registry,
    config: ObserveConfig,
    spec: SpecFile,
) -> Catalog:
    """Raise StructuralError when an alias names an id the map does not have."""
    agents = frozenset(node.id for node in graph.nodes if node.kind in AGENT_KINDS)
    tools = frozenset(tool.id for tool in inventory.tools)
    problems = [
        f"[observe.agents] {name!r} = {target!r}: there is no agent {target!r}"
        for name, target in config.agents.items()
        if target not in agents
    ]
    problems.extend(
        f"[observe.tools] {name!r} = {target!r}: there is no tool {target!r}"
        for name, target in config.tools.items()
        if target not in tools
    )
    problems.extend(
        f"[observe.agents] {name!r} = {target!r}: {name!r} is already a real "
        f"{'agent' if name in agents else 'tool'} id"
        for name, target in config.agents.items()
        if (name in agents and name != target) or name in tools
    )
    problems.extend(
        f"[observe.tools] {name!r} = {target!r}: {name!r} is already a real "
        f"{'tool' if name in tools else 'agent'} id"
        for name, target in config.tools.items()
        if (name in tools and name != target) or name in agents
    )
    if "user" in agents:
        problems.append(
            "an agent named 'user' clashes with lockwalk's name for the person who starts a "
            "trace; rename it to check it with observe"
        )
    if problems:
        raise StructuralError("[observe]", problems)
    index = index_graph(graph)
    # agent_edges deliberately ignore agent -> mcp_server -> agent: an MCP server is a tool
    # boundary. Registry delegation tools are wrappers (agents seen as tools), not tool edges.
    agent_edges = frozenset(
        (edge.from_id, edge.to_id)
        for edge in graph.edges
        if edge.kind is not EdgeKind.USES_TOOL and edge.from_id in agents and edge.to_id in agents
    )
    tool_edges = frozenset((agent, tool) for agent in agents for tool in direct_tools(index, agent))
    wrappers = frozenset(tool.id for tool in registry.delegation_tools).union(
        name
        for edge in graph.edges
        if edge.kind is EdgeKind.AGENT_AS_TOOL
        for name in edge.wrapped_by
    )
    return Catalog(
        agents=agents,
        tools=tools,
        wrappers=wrappers,
        entry_agents=frozenset(graph.entry_agents),
        agent_alias=dict(config.agents),
        tool_alias=dict(config.tools),
        agent_edges=agent_edges,
        tool_edges=tool_edges,
        risks={tool.id: tool.risk for tool in inventory.tools},
        modes={node.id: node.delegation_mode for node in graph.nodes if node.kind in AGENT_KINDS},
        case_routes=frozenset((case.route, case.tool) for case in spec.cases),
        case_agents=frozenset((case.route[-1], case.tool) for case in spec.cases if case.route),
    )
