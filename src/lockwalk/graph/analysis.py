"""Pure analysis of the agent call graph.

Nothing here runs an agent or a tool. Every function only reads the graph, the
inventory, and the planned cases, and every output is deterministic: the same
input always gives the same rows, witnesses, and warnings, in the same order.
"""

import heapq
from collections import deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import count, pairwise
from typing import NamedTuple

from lockwalk.models import (
    AgentGraph,
    CaseStatus,
    DelegationMode,
    EdgeKind,
    GraphEdge,
    GraphNode,
    GraphSection,
    Inventory,
    NeverReachesRule,
    NodeKind,
    PlannedCase,
    Provenance,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
)

# Risks for which an identity warning is worth giving.
IDENTITY_RISKS = frozenset({Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN})
# Node kinds that call tools with a declared delegation_mode of their own. Remote
# agents count; mcp_server nodes are only boundaries the call passes through.
CALLER_KINDS = frozenset({NodeKind.AGENT, NodeKind.REMOTE_AGENT})
# A summary warning names at most this many tools; the JSON reachability rows list them all.
SUMMARY_LIMIT = 5


@dataclass(frozen=True)
class Reach:
    """What a set of start nodes can reach."""

    nodes: frozenset[str]  # nodes reached, starts included
    tools: frozenset[str]  # tools reached through uses_tool edges
    opaque: tuple[str, ...]  # opaque nodes reached, sorted


@dataclass(frozen=True)
class GraphIndex:
    """Lookups built once from one graph, so repeated analysis calls stay cheap.

    Build it with index_graph and only pass it along with the same graph object;
    path_warnings checks this by identity.
    """

    graph: AgentGraph = field(repr=False, compare=False)  # the graph this index was built from
    nodes: Mapping[str, GraphNode]  # the first node with each id, like AgentGraph.node
    outgoing: Mapping[str, tuple[GraphEdge, ...]]  # edges by from_id, in graph order
    opaque: frozenset[str]  # ids of the opaque nodes
    held_tools: frozenset[str]  # tools that some node has a uses_tool edge to


def _node_map(graph: AgentGraph) -> dict[str, GraphNode]:
    nodes: dict[str, GraphNode] = {}
    for node in graph.nodes:
        nodes.setdefault(node.id, node)
    return nodes


def index_graph(graph: AgentGraph) -> GraphIndex:
    """Index the graph's nodes by id and its edges by from_id."""
    outgoing: dict[str, list[GraphEdge]] = {}
    for edge in graph.edges:
        outgoing.setdefault(edge.from_id, []).append(edge)
    return GraphIndex(
        graph=graph,
        nodes=_node_map(graph),
        outgoing={node_id: tuple(edges) for node_id, edges in outgoing.items()},
        opaque=frozenset(node.id for node in graph.nodes if node.opaque),
        held_tools=frozenset(e.to_id for e in graph.edges if e.kind is EdgeKind.USES_TOOL),
    )


class _Entry(NamedTuple):
    """One path in the witness search heap. Fields compare in this order."""

    inferred: int
    hops: int
    pairs: tuple[tuple[str, str], ...]  # (to_id, kind) along the path
    start: str
    edge_details: tuple[tuple[str, tuple[str, ...]], ...]  # (provenance, sources) per edge
    tie: int  # push order; it only decides between exactly duplicated edges
    node: str | None  # None once the path ends at a tool, because tools have no edges
    path: tuple[GraphEdge, ...]


def _first_entries(index: GraphIndex, starts: Iterable[str], tie: Iterator[int]) -> list[_Entry]:
    return [_Entry(0, 0, (), start, (), next(tie), start, ()) for start in _starts(index, starts)]


def _extend(entry: _Entry, edge: GraphEdge, node: str | None, tie: Iterator[int]) -> _Entry:
    return _Entry(
        inferred=entry.inferred + (1 if edge.provenance is Provenance.INFERRED else 0),
        hops=entry.hops + 1,
        pairs=(*entry.pairs, (edge.to_id, edge.kind.value)),
        start=entry.start,
        edge_details=(*entry.edge_details, (edge.provenance.value, edge.sources)),
        tie=next(tie),
        node=node,
        path=(*entry.path, edge),
    )


def _starts(index: GraphIndex, starts: Iterable[str]) -> list[str]:
    """The starts that are graph nodes, without duplicates, sorted."""
    return sorted({start for start in starts if start in index.nodes})


def _role_starts(graph: AgentGraph, nodes: Mapping[str, GraphNode], role: str) -> tuple[str, ...]:
    starts: list[str] = []
    for agent_id in graph.entry_agents:
        node = nodes.get(agent_id)
        if node is not None and (node.roles is None or role in node.roles):
            starts.append(agent_id)
    return tuple(starts)


def start_agents_for_role(graph: AgentGraph, role: str) -> tuple[str, ...]:
    """Entry agents a role may start at: those whose roles are unset or contain the role."""
    return _role_starts(graph, _node_map(graph), role)


def _reach(index: GraphIndex, starts: Iterable[str]) -> Reach:
    ordered = _starts(index, starts)
    visited = set(ordered)
    tools: set[str] = set()
    queue = deque(ordered)
    while queue:
        current = queue.popleft()
        for edge in index.outgoing.get(current, ()):
            if edge.kind is EdgeKind.USES_TOOL:
                tools.add(edge.to_id)
            elif edge.to_id not in visited:
                visited.add(edge.to_id)
                queue.append(edge.to_id)
    opaque = tuple(sorted(visited & index.opaque))
    return Reach(nodes=frozenset(visited), tools=frozenset(tools), opaque=opaque)


def reach(graph: AgentGraph, starts: Iterable[str]) -> Reach:
    """Walk every edge from the starts. A visited set keeps cycles from looping."""
    return _reach(index_graph(graph), starts)


def _tool_witnesses(
    index: GraphIndex, starts: Iterable[str], only: str | None = None
) -> dict[str, tuple[GraphEdge, ...]]:
    """The best witness to every reachable tool, found in one search.

    With only set, the search looks for that one tool and stops when it is found.
    Paths that end at a tool are never extended, so the order in which nodes are
    settled, and therefore each tool's witness, is the same either way.
    """
    tie = count()
    heap = _first_entries(index, starts, tie)
    settled: set[str] = set()
    found: dict[str, tuple[GraphEdge, ...]] = {}
    while heap:
        entry = heapq.heappop(heap)
        if entry.node is None:
            found.setdefault(entry.path[-1].to_id, entry.path)
            if only is not None:
                return found
            continue
        if entry.node in settled:
            continue
        settled.add(entry.node)
        for edge in index.outgoing.get(entry.node, ()):
            if edge.kind is EdgeKind.USES_TOOL:
                if edge.to_id in found or (only is not None and edge.to_id != only):
                    continue
                heapq.heappush(heap, _extend(entry, edge, None, tie))
            elif edge.to_id not in settled:
                heapq.heappush(heap, _extend(entry, edge, edge.to_id, tie))
    return found


def _agent_witness(
    index: GraphIndex, starts: Iterable[str], agent: str
) -> tuple[GraphEdge, ...] | None:
    """The best witness to an agent. A start reaches itself only through an edge."""
    tie = count()
    heap = _first_entries(index, starts, tie)
    settled: set[str] = set()
    while heap:
        entry = heapq.heappop(heap)
        if entry.path and entry.node == agent:
            return entry.path
        if entry.node is None or entry.node in settled:
            continue
        settled.add(entry.node)
        for edge in index.outgoing.get(entry.node, ()):
            if edge.kind is EdgeKind.USES_TOOL:
                continue
            if edge.to_id not in settled or edge.to_id == agent:
                heapq.heappush(heap, _extend(entry, edge, edge.to_id, tie))
    return None


def _agent_witnesses(index: GraphIndex, starts: Iterable[str]) -> dict[str, tuple[GraphEdge, ...]]:
    """The best witness to every reached non-start agent, found in one search.

    This is the search of _agent_witness without the early exit. A non-start node is
    first popped with exactly the path _agent_witness would return for it, so that path is
    recorded when the node is settled. Start nodes are left out: callers use route (start,).
    """
    tie = count()
    heap = _first_entries(index, starts, tie)
    begin = {entry.start for entry in heap}
    settled: set[str] = set()
    found: dict[str, tuple[GraphEdge, ...]] = {}
    while heap:
        entry = heapq.heappop(heap)
        if entry.node is None or entry.node in settled:
            continue
        settled.add(entry.node)
        if entry.path and entry.node not in begin:
            found[entry.node] = entry.path
        for edge in index.outgoing.get(entry.node, ()):
            if edge.kind is EdgeKind.USES_TOOL:
                continue
            if edge.to_id not in settled:
                heapq.heappush(heap, _extend(entry, edge, edge.to_id, tie))
    return found


def _witness(
    index: GraphIndex, starts: Iterable[str], tool: str | None, agent: str | None
) -> tuple[GraphEdge, ...] | None:
    if tool is not None and agent is None:
        return _tool_witnesses(index, starts, only=tool).get(tool)
    if agent is not None and tool is None:
        return _agent_witness(index, starts, agent)
    raise ValueError("give exactly one of 'tool' or 'agent'")


def find_witness(
    graph: AgentGraph,
    starts: Iterable[str],
    *,
    tool: str | None = None,
    agent: str | None = None,
) -> tuple[GraphEdge, ...] | None:
    """Return the best path from the starts to a tool or an agent, or None.

    Paths are compared by (number of inferred edges, number of edges, the
    (to_id, kind) pairs along the path). Remaining ties are broken by the start
    id (starts are tried in sorted order), then by each edge's provenance and
    sources, so the result never depends on the order of the input edges.
    A start agent reaches itself only through at least one edge.
    """
    return _witness(index_graph(graph), starts, tool, agent)


def _node_neighbors(graph: AgentGraph) -> dict[str, list[str]]:
    """Sorted, unique node-to-node neighbors of every node; tool edges are left out."""
    neighbors: dict[str, set[str]] = {node.id: set() for node in graph.nodes}
    for edge in graph.edges:
        if edge.kind is not EdgeKind.USES_TOOL:
            neighbors.setdefault(edge.from_id, set()).add(edge.to_id)
            neighbors.setdefault(edge.to_id, set())
    return {node_id: sorted(targets) for node_id, targets in neighbors.items()}


def _strongly_connected(neighbors: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan's algorithm, written without recursion so long chains are safe."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []
    counter = count()
    for root in sorted(neighbors):
        if root in index:
            continue
        index[root] = low[root] = next(counter)
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(neighbors[root]))]
        while work:
            current, pending = work[-1]
            descended = False
            for following in pending:
                if following not in index:
                    index[following] = low[following] = next(counter)
                    stack.append(following)
                    on_stack.add(following)
                    work.append((following, iter(neighbors[following])))
                    descended = True
                    break
                if following in on_stack:
                    low[current] = min(low[current], index[following])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[current])
            if low[current] == index[current]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == current:
                        break
                components.append(component)
    return components


def _shortest_loop(
    start: str, members: set[str], neighbors: dict[str, list[str]]
) -> tuple[str, ...]:
    """The shortest path from start back to start that stays inside members."""
    parent: dict[str, str] = {}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for following in neighbors[current]:
            if following == start:
                loop = [start, current]
                while loop[-1] != start:
                    loop.append(parent[loop[-1]])
                return tuple(reversed(loop))
            if following in members and following not in parent:
                parent[following] = current
                queue.append(following)
    raise AssertionError(f"no loop back to {start!r} inside its component")


def find_cycles(graph: AgentGraph) -> tuple[tuple[str, ...], ...]:
    """One loop per strongly connected component that contains a cycle, sorted.

    Each loop starts and ends at the component's smallest node id and is the
    shortest way back to it. Only node-to-node edges count.
    """
    neighbors = _node_neighbors(graph)
    cycles: list[tuple[str, ...]] = []
    for component in _strongly_connected(neighbors):
        start = min(component)
        if len(component) > 1 or start in neighbors[start]:
            cycles.append(_shortest_loop(start, set(component), neighbors))
    return tuple(sorted(cycles))


def unreachable_agents(graph: AgentGraph) -> tuple[str, ...]:
    """Sorted ids of the agents and remote agents that no entry agent reaches.

    No role starts at them, so no rule or role x tool row looks at what they reach.
    """
    reached = reach(graph, graph.entry_agents).nodes
    return tuple(
        sorted(
            {
                node.id
                for node in graph.nodes
                if node.kind in CALLER_KINDS and node.id not in reached
            }
        )
    )


def graph_section(graph: AgentGraph) -> GraphSection:
    """The agent_graph section of the report."""
    return GraphSection(
        entry_agents=graph.entry_agents,
        entry_inferred=graph.entry_inferred,
        nodes=graph.nodes,
        edges=graph.edges,
        cycles=find_cycles(graph),
        opaque=tuple(sorted({node.id for node in graph.nodes if node.opaque})),
        unreachable=unreachable_agents(graph),
        drift=graph.drift,
    )


def _rule_problems(
    graph: AgentGraph, index: GraphIndex, rule: NeverReachesRule, inventory: Inventory
) -> list[str]:
    problems: list[str] = []
    for agent_id in dict.fromkeys((rule.agent, rule.target_agent)):
        if agent_id is not None and agent_id not in index.nodes:
            problems.append(f"agent {agent_id!r} is not in the agent graph")
    if rule.role is not None:
        if graph.roles is None:
            problems.append(
                f"rule uses role {rule.role!r} but the registry has no top-level roles list"
            )
        elif rule.role not in graph.roles:
            problems.append(f"role {rule.role!r} is not in the registry roles list")
    if rule.tool is not None and inventory.tool(rule.tool) is None:
        delegate = inventory.delegation_agents.get(rule.tool)
        if delegate is not None:
            problems.append(
                f"tool {rule.tool!r} is a delegation to agent {delegate!r}; "
                "target the tools behind that agent instead"
            )
        else:
            problems.append(f"tool {rule.tool!r} is not in the inventory")
    return problems


def _rule_row(
    rule: NeverReachesRule,
    result: RuleResult,
    *,
    witness: tuple[GraphEdge, ...] = (),
    opaque_reached: tuple[str, ...] = (),
    problems: tuple[str, ...] = (),
) -> RuleRow:
    return RuleRow(
        id=rule.id,
        agent=rule.agent,
        role=rule.role,
        tool=rule.tool,
        target_agent=rule.target_agent,
        result=result,
        witness=witness,
        opaque_reached=opaque_reached,
        problems=problems,
        reason=rule.reason,
    )


def _evaluate_rule(
    graph: AgentGraph, index: GraphIndex, rule: NeverReachesRule, inventory: Inventory
) -> RuleRow:
    problems = _rule_problems(graph, index, rule, inventory)
    if problems:
        return _rule_row(rule, RuleResult.ERROR, problems=tuple(problems))
    if rule.role is not None:
        starts = _role_starts(graph, index.nodes, rule.role)
        if rule.target_agent is not None and rule.target_agent in starts:
            # The role talks to the target directly, so no edge is needed.
            return _rule_row(rule, RuleResult.FAIL)
    else:
        starts = (rule.agent,) if rule.agent is not None else ()
    # A witness exists exactly when the target is reached. For an agent target it
    # also needs at least one edge, so "agent X never reaches X" means "X is on no cycle".
    witness = _witness(index, starts, rule.tool, rule.target_agent)
    if witness is not None:
        return _rule_row(rule, RuleResult.FAIL, witness=witness)
    reached = _reach(index, starts)
    # Two gaps are no proof of PASS, though nothing opaque is reached. The reasons go to
    # `problems`, so such an INCONCLUSIVE row may have no opaque_reached:
    # - a valid role that no entry agent lists starts nowhere, so the rule checked nothing;
    # - a tool that no node uses cannot be reached in the graph, but some agent must hold
    #   it at run time; lockwalk only does not know which one.
    unknown: list[str] = []
    if rule.role is not None and not starts:
        unknown.append(startless_problem(rule.role))
    if rule.tool is not None and rule.tool not in index.held_tools:
        unknown.append(holderless_problem(rule.tool))
    if reached.opaque or unknown:
        return _rule_row(
            rule, RuleResult.INCONCLUSIVE, opaque_reached=reached.opaque, problems=tuple(unknown)
        )
    return _rule_row(rule, RuleResult.PASS)


def startless_problem(role: str) -> str:
    """Why a rule from a role that no entry agent lists is INCONCLUSIVE."""
    return (
        f"no entry agent lists role {role!r}, so lockwalk cannot tell where it starts; "
        "mark its entry agent with entry: true and add the role to its roles"
    )


def startless_roles(graph: AgentGraph, *, index: GraphIndex | None = None) -> tuple[str, ...]:
    """Registry roles, in registry order, that no entry agent lets start. () without roles.

    Pass index (from index_graph of this same graph object) to reuse one; any other index
    raises ValueError.
    """
    _check_index(graph, index)
    if graph.roles is None:
        return ()
    if index is None:
        index = index_graph(graph)
    return tuple(role for role in graph.roles if not _role_starts(graph, index.nodes, role))


def startless_warnings(graph: AgentGraph, *, index: GraphIndex | None = None) -> tuple[str, ...]:
    """At most one warning naming the roles that no entry agent lists.

    Given whenever the registry has roles, rules or not: the role x tool table shows
    nothing for such a role either. It names at most SUMMARY_LIMIT roles.
    """
    names = startless_roles(graph, index=index)
    if not names:
        return ()
    one = len(names) == 1
    return (
        f"no entry agent lists {len(names)} {plural('role', len(names))}, so lockwalk cannot "
        f"tell where {'it starts' if one else 'they start'}: {name_list(names)}; mark "
        f"{'its entry agent' if one else 'their entry agents'} with entry: true and add "
        f"{'the role to its' if one else 'the roles to their'} roles",
    )


def holderless_problem(tool: str) -> str:
    """Why a rule to a tool that no agent is known to use is INCONCLUSIVE."""
    return (
        f"no agent is known to use tool {tool!r}; set 'agents' on its source or "
        "'supported_agents' in the registry"
    )


def holderless_tools(
    graph: AgentGraph, inventory: Inventory, *, index: GraphIndex | None = None
) -> tuple[str, ...]:
    """Inventory tools, in inventory order, that no node has a uses_tool edge to.

    Delegation tools are not inventory tools, so they are never listed. Pass index (from
    index_graph of this same graph object) to reuse one; any other index raises ValueError.
    """
    _check_index(graph, index)
    if index is None:
        index = index_graph(graph)
    return tuple(tool.id for tool in inventory.tools if tool.id not in index.held_tools)


def holderless_warnings(
    graph: AgentGraph,
    inventory: Inventory,
    *,
    has_rules: bool,
    index: GraphIndex | None = None,
) -> tuple[str, ...]:
    """At most one warning naming the tools that no agent is known to use.

    Only given when there are rules or registry roles, the two features that need to know
    who holds each tool. It names at most SUMMARY_LIMIT tools.
    """
    if not has_rules and graph.roles is None:
        return ()
    names = holderless_tools(graph, inventory, index=index)
    if not names:
        return ()
    one = len(names) == 1
    return (
        f"no agent is known to use {len(names)} {plural('tool', len(names))}, so lockwalk "
        f"cannot tell who reaches {'it' if one else 'them'}: {name_list(names)}; set 'agents' "
        f"on {'its' if one else 'their'} source or 'supported_agents' in the registry",
    )


def evaluate_rules(
    graph: AgentGraph, rules: Sequence[NeverReachesRule], inventory: Inventory
) -> tuple[RuleRow, ...]:
    """One RuleRow per never_reaches rule, in rule order."""
    index = index_graph(graph)
    return tuple(_evaluate_rule(graph, index, rule, inventory) for rule in rules)


def _last_caller_mode(index: GraphIndex, witness: Sequence[GraphEdge]) -> DelegationMode | None:
    """delegation_mode of the last agent or remote agent on the witness.

    mcp_server nodes do not count: the agent behind them is the one that calls.
    """
    for edge in reversed(witness):
        node = index.nodes.get(edge.from_id)
        if node is not None and node.kind in CALLER_KINDS:
            return node.delegation_mode
    return None


def _coverage(
    plan: Sequence[PlannedCase], rules: Sequence[RuleRow]
) -> dict[tuple[str, str], tuple[str, ...]]:
    """(role, tool) -> ids of the non-ERROR cases, then the non-ERROR rules, that cover it."""
    covered: dict[tuple[str, str], dict[str, None]] = {}
    for planned in plan:
        if planned.status is not CaseStatus.ERROR:
            key = (planned.scenario.role, planned.scenario.tool)
            covered.setdefault(key, {})[planned.scenario.id] = None
    for row in rules:
        if row.result is not RuleResult.ERROR and row.role is not None and row.tool is not None:
            covered.setdefault((row.role, row.tool), {})[row.id] = None
    return {key: tuple(ids) for key, ids in covered.items()}


def role_reachability(
    graph: AgentGraph,
    inventory: Inventory,
    plan: Sequence[PlannedCase],
    rules: Sequence[RuleRow],
) -> tuple[ReachRow, ...] | None:
    """The role x tool table: reachable and inconclusive pairs only. None without roles."""
    if graph.roles is None:
        return None
    index = index_graph(graph)
    coverage = _coverage(plan, rules)
    rows: list[ReachRow] = []
    for role in graph.roles:
        starts = _role_starts(graph, index.nodes, role)
        opaque = _reach(index, starts).opaque
        witnesses = _tool_witnesses(index, starts)
        for tool in inventory.tools:
            covered_by = coverage.get((role, tool.id), ())
            witness = witnesses.get(tool.id)
            if witness is not None:
                rows.append(
                    ReachRow(
                        role=role,
                        tool=tool.id,
                        risk=tool.risk,
                        status=ReachStatus.REACHABLE,
                        witness=witness,
                        delegation_mode=_last_caller_mode(index, witness),
                        covered_by=covered_by,
                    )
                )
            elif opaque:
                rows.append(
                    ReachRow(
                        role=role,
                        tool=tool.id,
                        risk=tool.risk,
                        status=ReachStatus.INCONCLUSIVE,
                        opaque_reached=opaque,
                        covered_by=covered_by,
                    )
                )
    return tuple(rows)


def _direct_tools(index: GraphIndex, node_id: str) -> set[str]:
    """The tools a node uses directly, whatever its kind.

    That is: the targets of its uses_tool edges, plus the uses_tool targets of
    every mcp_server node it has a node-to-node edge to.
    """
    tools: set[str] = set()
    for edge in index.outgoing.get(node_id, ()):
        if edge.kind is EdgeKind.USES_TOOL:
            tools.add(edge.to_id)
            continue
        server = index.nodes.get(edge.to_id)
        if server is not None and server.kind is NodeKind.MCP_SERVER:
            tools.update(
                server_edge.to_id
                for server_edge in index.outgoing.get(server.id, ())
                if server_edge.kind is EdgeKind.USES_TOOL
            )
    return tools


def direct_tools(index: GraphIndex, node_id: str) -> frozenset[str]:
    """The tools a node uses directly, MCP servers it reaches included."""
    return frozenset(_direct_tools(index, node_id))


def _identity_callers(index: GraphIndex, reached: Iterable[str]) -> dict[str, list[str]]:
    """tool -> sorted ids of reached callers whose delegation_mode is 'agent' or undeclared."""
    callers: dict[str, list[str]] = {}
    for node_id in sorted(reached):
        node = index.nodes.get(node_id)
        if node is None or node.kind not in CALLER_KINDS:
            continue
        if node.delegation_mode not in ("agent", None):
            continue
        for tool_id in _direct_tools(index, node_id):
            callers.setdefault(tool_id, []).append(node_id)
    return callers


def identity_warnings(
    graph: AgentGraph, inventory: Inventory, rows: Sequence[ReachRow]
) -> tuple[str, ...]:
    """Warn when a risky reachable tool is called by an agent that uses its own identity.

    Callers are reached agent or remote agent nodes that use the tool directly;
    mcp_server nodes are never callers. Only declarations are used here; the
    identity actually sent is not checked here; ``lockwalk observe`` checks it. The rows
    already carry each tool's risk, so the inventory parameter is kept only for interface
    stability and is not read.
    """
    index = index_graph(graph)
    warnings: dict[str, None] = {}
    for row, node_id in _identity_pairs(graph, index, rows):
        prefix = (
            f"role {row.role!r} can reach tool {row.tool!r} (risk={row.risk.value}) through agent"
        )
        if index.nodes[node_id].delegation_mode == "agent":
            warnings[
                f"{prefix} {node_id!r}, which calls tools with its own identity; "
                "the IAM will not see the user"
            ] = None
        else:
            warnings[
                f"{prefix} {node_id!r}, whose delegation_mode is not declared; "
                "the IAM may not see the user"
            ] = None
    return tuple(warnings)


def _identity_pairs(
    graph: AgentGraph, index: GraphIndex, rows: Sequence[ReachRow]
) -> Iterator[tuple[ReachRow, str]]:
    """(row, caller id) for every identity finding, in row order.

    A finding is a reachable row whose risk is in IDENTITY_RISKS, paired with each
    reached caller that uses the row's tool directly; callers come sorted by id.
    identity_warnings and identity_summaries both read this, so the rule lives here once.
    """
    by_role: dict[str, dict[str, list[str]]] = {}
    for row in rows:
        if row.status is not ReachStatus.REACHABLE or row.risk not in IDENTITY_RISKS:
            continue
        callers = by_role.get(row.role)
        if callers is None:
            reached = _reach(index, _role_starts(graph, index.nodes, row.role)).nodes
            callers = by_role[row.role] = _identity_callers(index, reached)
        for node_id in callers.get(row.tool, ()):
            yield row, node_id


def name_list(names: Sequence[str], limit: int = SUMMARY_LIMIT) -> str:
    """Join names with ", ": at most `limit` of them, then "..." when some were left out."""
    shown = ", ".join(names[:limit])
    return shown if len(names) <= limit else f"{shown}, ..."


def plural(word: str, number: int) -> str:
    """The word as it is for exactly one thing, otherwise with an "s" added."""
    return word if number == 1 else f"{word}s"


def _check_index(graph: AgentGraph, index: GraphIndex | None) -> None:
    # Identity, not equality: comparing two graphs would cost as much as rebuilding.
    if index is not None and index.graph is not graph:
        raise ValueError("index was built from a different graph")


def identity_summaries(
    graph: AgentGraph, rows: Sequence[ReachRow], *, index: GraphIndex | None = None
) -> tuple[str, ...]:
    """identity_warnings summed up: one warning per caller agent.

    One line per (role, tool, agent) can run to tens of thousands in a large system, so
    each caller gets one line naming its roles, how many risky tools they reach through
    it, and at most SUMMARY_LIMIT of those tools. Findings are exactly the ones
    identity_warnings reports, and callers come in the order it first names them; the
    reachability rows keep every pair. Pass index (from index_graph of this same graph
    object) to reuse one; an index built from any other graph raises ValueError.
    """
    _check_index(graph, index)
    if index is None:
        index = index_graph(graph)
    exposed: dict[str, tuple[dict[str, None], dict[str, None]]] = {}  # id -> (roles, tools)
    for row, node_id in _identity_pairs(graph, index, rows):
        roles, tools = exposed.setdefault(node_id, ({}, {}))
        roles[row.role] = None
        tools[row.tool] = None
    lines: list[str] = []
    for node_id, (roles, tools) in exposed.items():
        if index.nodes[node_id].delegation_mode == "agent":
            how = "calls tools with its own identity; the IAM will not see the user"
        else:
            how = "has no declared delegation_mode; the IAM may not see the user"
        lines.append(
            f"agent {node_id!r} {how}. Through it, {plural('role', len(roles))} "
            f"{', '.join(roles)} can reach {len(tools)} high-risk "
            f"{plural('tool', len(tools))}: {name_list(list(tools))}"
        )
    return tuple(lines)


def path_warnings(
    graph: AgentGraph, planned: PlannedCase, *, index: GraphIndex | None = None
) -> tuple[str, ...]:
    """Warnings for an allow case whose path does not match the graph.

    Only path cases are checked, so agent cases are not checked against paths.
    Deny cases are not checked: a path that does not exist is the expected defense.
    Whether the last agent can use the tool is decided from its edges only, not
    from its node kind, so a remote agent or mcp_server at the end also counts.
    Pass index (from index_graph of this same graph object) when checking many
    cases; an index built from any other graph raises ValueError.
    """
    _check_index(graph, index)
    scenario = planned.scenario
    path = scenario.path
    if path is None or scenario.expect != "allow" or planned.status is CaseStatus.ERROR:
        return ()
    if index is None:
        index = index_graph(graph)
    warnings: dict[str, None] = {}
    for step_from, step_to in pairwise(path):
        if not any(
            edge.kind is not EdgeKind.USES_TOOL and edge.to_id == step_to
            for edge in index.outgoing.get(step_from, ())
        ):
            warnings[
                f"path step {step_from!r} -> {step_to!r} is not an edge in the agent graph"
            ] = None
    last = path[-1]
    if scenario.tool not in _direct_tools(index, last):
        warnings[f"agent {last!r} has no known way to use tool {scenario.tool!r}"] = None
    if graph.roles is not None and path[0] not in _role_starts(graph, index.nodes, scenario.role):
        warnings[
            f"role {scenario.role!r} cannot start at {path[0]!r} "
            "(it is not an entry agent available to that role)"
        ] = None
    return tuple(f"{scenario.id}: {warning}" for warning in warnings)


def role_callers(
    graph: AgentGraph, role: str, *, index: GraphIndex | None = None
) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """(caller, tool, route) for every agent a role reaches that calls tools as itself.

    Callers are reached agent and remote agent nodes whose delegation_mode is not "user".
    The tools are the ones the caller uses directly, including those behind an attached
    mcp_server. The route lists the agent ids along the best witness to the caller (no
    mcp_server ids); a caller that is a start agent has route (caller,). Sorted by caller,
    then tool. Pass index (from index_graph of this same graph object) to reuse one.
    """
    _check_index(graph, index)
    if index is None:
        index = index_graph(graph)
    starts = _role_starts(graph, index.nodes, role)
    found: list[tuple[str, str, tuple[str, ...]]] = []
    witnesses = _agent_witnesses(index, starts)
    for node_id in sorted(_reach(index, starts).nodes):
        node = index.nodes.get(node_id)
        if node is None:  # an edge to an undeclared agent; the graph build reports it
            continue
        if node.kind not in CALLER_KINDS or node.delegation_mode == "user":
            continue
        tools = sorted(_direct_tools(index, node_id))
        if not tools:
            continue
        route: tuple[str, ...] = (node_id,)
        if node_id not in starts:
            witness = witnesses.get(node_id)
            if witness is None:
                continue
            ids = [witness[0].from_id, *(edge.to_id for edge in witness)]
            route = tuple(
                step for step in ids if (n := index.nodes.get(step)) and n.kind in CALLER_KINDS
            )
        found.extend((node_id, tool_id, route) for tool_id in tools)
    return tuple(found)
