"""Tests for the pure agent graph analysis functions."""

import random
from collections.abc import Sequence
from itertools import pairwise

import pytest

from lockwalk.graph.analysis import (
    Reach,
    evaluate_rules,
    find_cycles,
    find_witness,
    graph_section,
    holderless_tools,
    holderless_warnings,
    identity_warnings,
    index_graph,
    path_warnings,
    reach,
    role_reachability,
    start_agents_for_role,
    startless_roles,
    startless_warnings,
)
from lockwalk.models import (
    AgentGraph,
    CaseStatus,
    DelegationMode,
    EdgeKind,
    GraphDrift,
    GraphEdge,
    GraphNode,
    Inventory,
    InventoryTool,
    NeverReachesRule,
    NodeKind,
    PlannedCase,
    Provenance,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    TestScenario,
)

# ---- helpers ----


def edge(a: str, b: str, kind: str = "handoff", prov: str = "discovered") -> GraphEdge:
    return GraphEdge(from_id=a, to_id=b, kind=EdgeKind(kind), provenance=Provenance(prov))


def uses(a: str, tool: str, prov: str = "discovered") -> GraphEdge:
    return edge(a, tool, kind="uses_tool", prov=prov)


def node(
    node_id: str,
    *,
    kind: NodeKind = NodeKind.AGENT,
    entry: bool = False,
    roles: tuple[str, ...] | None = None,
    mode: DelegationMode | None = None,
    opaque: bool = False,
) -> GraphNode:
    return GraphNode(
        id=node_id, kind=kind, entry=entry, roles=roles, delegation_mode=mode, opaque=opaque
    )


def make_graph(
    nodes: Sequence[GraphNode | str],
    edges: Sequence[GraphEdge] = (),
    *,
    entries: Sequence[str] | None = None,
    roles: Sequence[str] | None = None,
    drift: GraphDrift | None = None,
) -> AgentGraph:
    built = tuple(node(item) if isinstance(item, str) else item for item in nodes)
    if entries is None:
        entries = [item.id for item in built if item.entry]
    return AgentGraph(
        nodes=built,
        edges=tuple(edges),
        entry_agents=tuple(entries),
        entry_inferred=False,
        roles=None if roles is None else tuple(roles),
        drift=drift,
    )


def tool(tool_id: str, risk: str = "high") -> InventoryTool:
    return InventoryTool(
        id=tool_id,
        action=None,
        risk=Risk(risk),
        resource_type=None,
        supported_agents=(),
        sources=(),
        description=None,
        hints={},
    )


def make_inventory(*tools: InventoryTool, delegation: dict[str, str] | None = None) -> Inventory:
    return Inventory(
        agents=(),
        tools=tools,
        sources=(),
        drift=None,
        errors=(),
        warnings=(),
        delegation_agents=delegation or {},
    )


def case(
    case_id: str,
    *,
    tool_id: str = "t",
    role: str = "analyst",
    agent: str | None = None,
    path: tuple[str, ...] | None = None,
    expect: str = "allow",
    status: CaseStatus = CaseStatus.UNTESTED,
) -> PlannedCase:
    scenario = TestScenario.model_validate(
        {
            "id": case_id,
            "actor": "alice",
            "role": role,
            "agent": agent,
            "path": path,
            "tool": tool_id,
            "action": "x:y",
            "resource_fixture": "fx",
            "expect": expect,
        }
    )
    problems = ("broken",) if status is CaseStatus.ERROR else ()
    return PlannedCase(scenario=scenario, status=status, problems=problems)


def rule(rule_id: str = "RULE-001", **fields: str) -> NeverReachesRule:
    return NeverReachesRule.model_validate({"id": rule_id, **fields})


def rule_row(
    rule_id: str, *, role: str | None, tool_id: str, result: RuleResult = RuleResult.PASS
) -> RuleRow:
    problems = ("broken",) if result is RuleResult.ERROR else ()
    return RuleRow(
        id=rule_id,
        agent=None if role else "someone",
        role=role,
        tool=tool_id,
        target_agent=None,
        result=result,
        problems=problems,
    )


def table(graph: AgentGraph, inventory: Inventory) -> tuple[ReachRow, ...]:
    """The role x tool table for a graph that has roles, with no cases and no rules."""
    rows = role_reachability(graph, inventory, [], [])
    assert rows is not None
    return rows


# ---- start_agents_for_role ----


def test_role_start_uses_only_entries_that_allow_the_role():
    graph = make_graph(
        [
            node("a", entry=True, roles=("analyst",)),
            node("b", entry=True, roles=("admin",)),
            node("c", entry=True),
            node("d", roles=("analyst",)),
        ],
        entries=["c", "a", "b"],
        roles=["analyst", "admin"],
    )
    assert start_agents_for_role(graph, "analyst") == ("c", "a")
    assert start_agents_for_role(graph, "admin") == ("c", "b")
    assert start_agents_for_role(graph, "auditor") == ("c",)


def test_entry_without_roles_allows_every_role():
    graph = make_graph([node("a", entry=True), node("b", entry=True)], roles=["x"])
    assert start_agents_for_role(graph, "x") == ("a", "b")
    assert start_agents_for_role(graph, "anything") == ("a", "b")


# ---- reach ----


def test_reach_follows_every_edge_and_collects_tools():
    graph = make_graph(
        ["s", "a", "b", "unrelated"],
        [
            edge("s", "a", prov="inferred"),
            edge("a", "b", kind="team", prov="declared"),
            uses("b", "t1"),
            uses("s", "t2"),
            uses("unrelated", "t3"),
        ],
    )
    result = reach(graph, ["s"])
    assert result == Reach(
        nodes=frozenset({"s", "a", "b"}), tools=frozenset({"t1", "t2"}), opaque=()
    )


def test_reach_terminates_on_a_cycle():
    graph = make_graph(["a", "b"], [edge("a", "b"), edge("b", "a"), uses("b", "t")])
    result = reach(graph, ["a"])
    assert result.nodes == frozenset({"a", "b"})
    assert result.tools == frozenset({"t"})


def test_reach_ignores_unknown_starts_and_counts_opaque_starts():
    graph = make_graph(
        [
            node("s", opaque=True),
            node("z", kind=NodeKind.REMOTE_AGENT, opaque=True),
            node("m", kind=NodeKind.MCP_SERVER, opaque=True),
        ],
        [edge("s", "z", kind="remote"), edge("s", "m", kind="calls")],
    )
    result = reach(graph, ["ghost", "s"])
    assert result.nodes == frozenset({"s", "z", "m"})
    assert result.opaque == ("m", "s", "z")
    assert reach(graph, ["ghost"]) == Reach(nodes=frozenset(), tools=frozenset(), opaque=())


def test_reach_treats_a_uses_tool_target_as_a_tool_even_if_a_node_has_that_id():
    graph = make_graph(
        ["s", node("x", opaque=True), "y"],
        [uses("s", "x"), edge("x", "y"), uses("x", "t")],
    )
    assert reach(graph, ["s"]) == Reach(nodes=frozenset({"s"}), tools=frozenset({"x"}), opaque=())


# ---- find_witness ----


def test_witness_prefers_a_discovered_path_over_a_shorter_inferred_one():
    graph = make_graph(
        ["s", "x", "a", "b"],
        [
            edge("s", "x", prov="inferred"),
            uses("x", "t"),
            edge("s", "a"),
            edge("a", "b"),
            uses("b", "t"),
        ],
    )
    assert find_witness(graph, ["s"], tool="t") == (edge("s", "a"), edge("a", "b"), uses("b", "t"))


def test_witness_prefers_fewer_hops_when_inferred_counts_tie():
    graph = make_graph(
        ["s", "a"],
        [edge("s", "a"), uses("a", "t"), uses("s", "t", prov="declared")],
    )
    assert find_witness(graph, ["s"], tool="t") == (uses("s", "t", prov="declared"),)


def test_witness_breaks_ties_by_target_id_then_kind():
    graph = make_graph(
        ["s", "a", "b"],
        [
            edge("s", "b"),
            edge("s", "a", kind="team"),
            edge("s", "a", kind="handoff"),
            uses("a", "t"),
            uses("b", "t"),
        ],
    )
    assert find_witness(graph, ["s"], tool="t") == (edge("s", "a", kind="handoff"), uses("a", "t"))


def test_witness_tries_starts_in_sorted_order():
    graph = make_graph(["z", "a"], [uses("z", "t"), uses("a", "t")])
    assert find_witness(graph, ["z", "a"], tool="t") == (uses("a", "t"),)


def test_witness_cost_is_compared_across_all_starts():
    graph = make_graph(["a", "z"], [uses("a", "t", prov="inferred"), uses("z", "t")])
    assert find_witness(graph, ["a", "z"], tool="t") == (uses("z", "t"),)


def test_witness_is_identical_across_runs_and_edge_orders():
    edges = [
        edge("s", "c"),
        edge("s", "b"),
        edge("s", "a", prov="inferred"),
        edge("a", "t-agent"),
        edge("b", "t-agent", kind="team"),
        edge("b", "t-agent", kind="calls"),
        edge("b", "t-agent", kind="calls", prov="declared"),
        edge("c", "t-agent", kind="calls"),
        uses("t-agent", "t"),
    ]
    nodes = ["s", "a", "b", "c", "t-agent"]
    expected = (edge("s", "b"), edge("b", "t-agent", kind="calls", prov="declared"))
    graph = make_graph(nodes, edges)
    results = [find_witness(graph, ["s"], agent="t-agent") for _ in range(3)]
    assert results == [expected] * 3
    for shifted in (edges[::-1], edges[3:] + edges[:3], edges[5:] + edges[:5]):
        assert find_witness(make_graph(nodes[::-1], shifted), ["s"], agent="t-agent") == expected


def test_witness_is_none_when_target_is_unreachable():
    graph = make_graph(["s", "a"], [uses("a", "t")])
    assert find_witness(graph, ["s"], tool="t") is None
    assert find_witness(graph, ["s"], agent="a") is None
    assert find_witness(graph, ["ghost"], tool="t") is None


def test_start_agent_reaches_itself_only_through_an_edge():
    acyclic = make_graph(["a", "b"], [edge("a", "b")])
    assert find_witness(acyclic, ["a"], agent="a") is None
    cyclic = make_graph(["a", "b"], [edge("a", "b"), edge("b", "a")])
    assert find_witness(cyclic, ["a"], agent="a") == (edge("a", "b"), edge("b", "a"))


def test_witness_does_not_treat_a_tool_edge_as_an_agent_hop():
    graph = make_graph(["s", "x"], [uses("s", "x")])
    assert find_witness(graph, ["s"], agent="x") is None


@pytest.mark.parametrize("targets", [{}, {"tool": "t", "agent": "a"}])
def test_witness_needs_exactly_one_target(targets: dict[str, str]):
    graph = make_graph(["a"])
    with pytest.raises(ValueError, match="exactly one"):
        find_witness(graph, ["a"], **targets)


# ---- find_cycles ----


def test_two_node_cycle():
    graph = make_graph(["a", "b"], [edge("a", "b"), edge("b", "a")])
    assert find_cycles(graph) == (("a", "b", "a"),)


def test_self_loop():
    graph = make_graph(["x", "y"], [edge("x", "x"), edge("x", "y")])
    assert find_cycles(graph) == (("x", "x"),)


def test_cycles_ignore_tool_edges_and_acyclic_parts():
    graph = make_graph(["a", "b"], [edge("a", "b"), uses("b", "a")])
    assert find_cycles(graph) == ()


def test_cycle_starts_at_smallest_id_and_takes_the_shortest_way_back():
    graph = make_graph(
        ["b", "c", "d", "a", "p", "q"],
        [
            edge("a", "b"),
            edge("b", "c"),
            edge("c", "d"),
            edge("d", "a"),
            edge("b", "a", kind="team"),
            edge("q", "p"),
            edge("p", "q"),
        ],
    )
    assert find_cycles(graph) == (("a", "b", "a"), ("p", "q", "p"))


def test_cycle_in_a_long_chain_does_not_hit_the_recursion_limit():
    ids = [f"n{index:05d}" for index in range(3000)]
    edges = [edge(a, b) for a, b in pairwise(ids)] + [edge(ids[-1], ids[0])]
    [cycle] = find_cycles(make_graph(ids, edges))
    assert cycle[0] == cycle[-1] == "n00000"
    assert len(cycle) == 3001


# ---- graph_section ----


def test_graph_section_copies_structure_and_adds_cycles_and_opaque():
    drift = GraphDrift(
        discovered_only_agents=("b",), declared_only_agents=(), undeclared_edges=(), complete=True
    )
    nodes = (
        node("b", opaque=True),
        node("a", entry=True),
        node("m", kind=NodeKind.MCP_SERVER, opaque=True),
    )
    edges = (edge("a", "b"), edge("b", "a"), uses("a", "t"))
    graph = AgentGraph(
        nodes=nodes,
        edges=edges,
        entry_agents=("a",),
        entry_inferred=True,
        roles=("analyst",),
        drift=drift,
        warnings=("w",),
    )
    section = graph_section(graph)
    assert section.entry_agents == ("a",)
    assert section.entry_inferred is True
    assert section.nodes == nodes
    assert section.edges == edges
    assert section.cycles == (("a", "b", "a"),)
    assert section.opaque == ("b", "m")
    assert section.unreachable == ()
    assert section.drift == drift


def test_graph_section_lists_the_agents_no_entry_reaches():
    nodes = (
        node("front", entry=True),
        "helper",
        "zeta",
        "alone",
        node("far", kind=NodeKind.REMOTE_AGENT),
        node("mcp:x", kind=NodeKind.MCP_SERVER),
    )
    edges = (edge("front", "helper"), edge("zeta", "far"), edge("zeta", "mcp:x", kind="remote"))
    section = graph_section(make_graph(nodes, edges, entries=["front"]))
    # mcp_server nodes are boundaries, not agents, so they are never listed.
    assert section.unreachable == ("alone", "far", "zeta")
    assert graph_section(make_graph(nodes, edges, entries=[])).unreachable == (
        "alone",
        "far",
        "front",
        "helper",
        "zeta",
    )


# ---- evaluate_rules ----


def test_rule_fails_with_a_witness_when_the_tool_is_reached():
    graph = make_graph(["s", "a"], [edge("s", "a"), uses("a", "t")])
    [row] = evaluate_rules(
        graph, [rule(agent="s", tool="t", reason="never trade")], make_inventory(tool("t"))
    )
    assert row == RuleRow(
        id="RULE-001",
        agent="s",
        role=None,
        tool="t",
        target_agent=None,
        result=RuleResult.FAIL,
        witness=(edge("s", "a"), uses("a", "t")),
        reason="never trade",
    )


def test_rule_fails_when_the_target_agent_is_reached():
    graph = make_graph(["s", "a", "b"], [edge("s", "a"), edge("a", "b", kind="team")])
    [row] = evaluate_rules(graph, [rule(agent="s", target_agent="b")], make_inventory())
    assert row.result is RuleResult.FAIL
    assert row.witness == (edge("s", "a"), edge("a", "b", kind="team"))


def test_opaque_node_on_the_way_makes_the_rule_inconclusive():
    remote = node("remote", kind=NodeKind.REMOTE_AGENT, opaque=True)
    edges = [edge("s", "remote", kind="remote")]
    inventory = make_inventory(tool("t"))
    [row] = evaluate_rules(make_graph(["s", remote], edges), [rule(agent="s", tool="t")], inventory)
    assert row.result is RuleResult.INCONCLUSIVE
    assert row.opaque_reached == ("remote",)
    assert row.witness == ()

    # Some agent holds t, so lockwalk knows who reaches it ("x", which s never reaches).
    visible = node("remote", kind=NodeKind.REMOTE_AGENT)
    [row] = evaluate_rules(
        make_graph(["s", visible, "x"], [*edges, uses("x", "t")]),
        [rule(agent="s", tool="t")],
        inventory,
    )
    assert row.result is RuleResult.PASS
    assert row.opaque_reached == ()


HOLDERLESS = (
    "no agent is known to use tool 't'; set 'agents' on its source or "
    "'supported_agents' in the registry"
)


def test_a_rule_to_a_tool_that_no_agent_uses_is_inconclusive():
    """Without a uses_tool edge to the tool, nothing proves that the start cannot reach it."""
    inventory = make_inventory(tool("t"))
    graph = make_graph(["s", "a"], [edge("s", "a")])
    [row] = evaluate_rules(graph, [rule(agent="s", tool="t")], inventory)
    assert row.result is RuleResult.INCONCLUSIVE
    assert row.opaque_reached == ()
    assert row.problems == (HOLDERLESS,)
    assert row.witness == ()

    roles = make_graph([node("s", entry=True)], roles=["analyst"])
    [row] = evaluate_rules(roles, [rule(role="analyst", tool="t")], inventory)
    assert (row.result, row.problems) == (RuleResult.INCONCLUSIVE, (HOLDERLESS,))


def test_a_holderless_tool_and_an_opaque_node_are_both_reported():
    remote = node("remote", kind=NodeKind.REMOTE_AGENT, opaque=True)
    graph = make_graph(["s", remote], [edge("s", "remote", kind="remote")])
    [row] = evaluate_rules(graph, [rule(agent="s", tool="t")], make_inventory(tool("t")))
    assert row.result is RuleResult.INCONCLUSIVE
    assert row.opaque_reached == ("remote",)
    assert row.problems == (HOLDERLESS,)


STARTLESS = (
    "no entry agent lists role 'ops', so lockwalk cannot tell where it starts; "
    "mark its entry agent with entry: true and add the role to its roles"
)


def startless_graph() -> AgentGraph:
    """Only analysts may use the one entry agent; ops is a role that starts nowhere."""
    return make_graph(
        [node("front", entry=True, roles=("analyst",)), "back"],
        [edge("front", "back"), uses("back", "t")],
        roles=["analyst", "ops"],
    )


def test_a_rule_from_a_role_that_no_entry_agent_lists_is_inconclusive():
    """Starting nowhere, the rule would check nothing and PASS; that is no proof."""
    graph = startless_graph()
    inventory = make_inventory(tool("t"))
    [to_tool, to_agent] = evaluate_rules(
        graph,
        [rule("R1", role="ops", tool="t"), rule("R2", role="ops", target_agent="back")],
        inventory,
    )
    for row in (to_tool, to_agent):
        assert row.result is RuleResult.INCONCLUSIVE
        assert row.problems == (STARTLESS,)
        assert (row.opaque_reached, row.witness) == ((), ())


def test_a_startless_role_and_a_holderless_tool_are_both_reported():
    graph = startless_graph()
    [row] = evaluate_rules(graph, [rule(role="ops", tool="u")], make_inventory(tool("u")))
    assert row.result is RuleResult.INCONCLUSIVE
    assert row.problems == (STARTLESS, HOLDERLESS.replace("'t'", "'u'"))


def test_a_role_whose_starts_reach_nothing_relevant_still_passes():
    graph = make_graph(
        [node("front", entry=True, roles=("analyst",)), "back", "other"],
        [edge("front", "back"), uses("other", "t")],
        roles=["analyst"],
    )
    [row] = evaluate_rules(graph, [rule(role="analyst", tool="t")], make_inventory(tool("t")))
    assert (row.result, row.problems) == (RuleResult.PASS, ())


def test_a_role_not_in_the_roles_list_is_still_an_error():
    [row] = evaluate_rules(
        startless_graph(), [rule(role="auditor", tool="t")], make_inventory(tool("t"))
    )
    assert_error(row, "role 'auditor' is not in the registry roles list")


def test_startless_roles_keep_the_registry_order():
    graph = make_graph(
        [node("front", entry=True, roles=("b",))], roles=["c", "b", "a"], entries=["front"]
    )
    assert startless_roles(graph) == ("c", "a")
    index = index_graph(graph)
    assert startless_roles(graph, index=index) == ("c", "a")
    with pytest.raises(ValueError, match="different graph"):
        startless_roles(startless_graph(), index=index)
    # An entry agent without roles lets every role start; without roles, nothing is listed.
    assert startless_roles(make_graph([node("front", entry=True)], roles=["a"])) == ()
    assert startless_roles(make_graph([node("front", entry=True)])) == ()


def test_the_startless_warning_names_at_most_five_roles():
    assert startless_warnings(startless_graph()) == (
        "no entry agent lists 1 role, so lockwalk cannot tell where it starts: ops; mark "
        "its entry agent with entry: true and add the role to its roles",
    )
    roles = [f"r{n}" for n in range(7)]
    many = make_graph([node("front", entry=True, roles=("x",))], roles=["x", *roles])
    assert startless_warnings(many) == (
        "no entry agent lists 7 roles, so lockwalk cannot tell where they start: "
        "r0, r1, r2, r3, r4, ...; mark their entry agents with entry: true and add the "
        "roles to their roles",
    )
    assert startless_warnings(make_graph([node("front", entry=True)], roles=["a"])) == ()


def test_an_mcp_server_node_counts_as_a_holder():
    server = node("mcp:s", kind=NodeKind.MCP_SERVER)
    graph = make_graph(["a", "b", server], [edge("b", "mcp:s", kind="remote"), uses("mcp:s", "t")])
    [row] = evaluate_rules(graph, [rule(agent="a", tool="t")], make_inventory(tool("t")))
    assert row.result is RuleResult.PASS


def test_agent_targets_need_no_holder():
    graph = make_graph(["a", "b"])
    [row] = evaluate_rules(graph, [rule(agent="a", target_agent="b")], make_inventory())
    assert row.result is RuleResult.PASS


def test_holderless_tools_keep_the_inventory_order():
    graph = make_graph(["a"], [uses("a", "held")])
    inventory = make_inventory(tool("z"), tool("held"), tool("b"))
    assert holderless_tools(graph, inventory) == ("z", "b")
    index = index_graph(graph)
    assert holderless_tools(graph, inventory, index=index) == ("z", "b")
    with pytest.raises(ValueError, match="different graph"):
        holderless_tools(make_graph(["a"]), inventory, index=index)


def test_the_holderless_warning_needs_rules_or_roles():
    inventory = make_inventory(tool("t"))
    plain = make_graph(["a"])
    assert holderless_warnings(plain, inventory, has_rules=False) == ()
    assert holderless_warnings(plain, inventory, has_rules=True) == (
        "no agent is known to use 1 tool, so lockwalk cannot tell who reaches it: t; "
        "set 'agents' on its source or 'supported_agents' in the registry",
    )
    with_roles = make_graph(["a"], roles=["analyst"])
    assert len(holderless_warnings(with_roles, inventory, has_rules=False)) == 1
    held = make_graph(["a"], [uses("a", "t")], roles=["analyst"])
    assert holderless_warnings(held, inventory, has_rules=True) == ()


def test_the_holderless_warning_names_at_most_five_tools():
    inventory = make_inventory(*(tool(f"t{n}") for n in range(7)))
    assert holderless_warnings(make_graph(["a"]), inventory, has_rules=True) == (
        "no agent is known to use 7 tools, so lockwalk cannot tell who reaches them: "
        "t0, t1, t2, t3, t4, ...; set 'agents' on their source or 'supported_agents' "
        "in the registry",
    )


def test_reached_target_wins_over_opaque_nodes():
    remote = node("remote", kind=NodeKind.REMOTE_AGENT, opaque=True)
    graph = make_graph(["s", remote], [edge("s", "remote", kind="remote"), uses("s", "t")])
    [row] = evaluate_rules(graph, [rule(agent="s", tool="t")], make_inventory(tool("t")))
    assert row.result is RuleResult.FAIL
    assert row.opaque_reached == ()


def test_role_rule_starts_from_the_entries_of_that_role():
    graph = make_graph(
        [
            node("a", entry=True, roles=("analyst",)),
            node("b", entry=True, roles=("admin",)),
        ],
        [uses("b", "t")],
        roles=["analyst", "admin"],
    )
    inventory = make_inventory(tool("t"))
    analyst, admin = evaluate_rules(
        graph,
        [rule("R1", role="analyst", tool="t"), rule("R2", role="admin", tool="t")],
        inventory,
    )
    assert analyst.result is RuleResult.PASS
    assert admin.result is RuleResult.FAIL
    assert admin.witness == (uses("b", "t"),)


def test_role_rule_targeting_an_entry_of_that_role_fails_with_an_empty_witness():
    graph = make_graph(
        [node("front", entry=True, roles=("analyst",)), "back"],
        [edge("back", "front")],
        roles=["analyst"],
    )
    [row] = evaluate_rules(graph, [rule(role="analyst", target_agent="front")], make_inventory())
    assert row.result is RuleResult.FAIL
    assert row.witness == ()


def test_agent_rule_targeting_itself_needs_a_cycle():
    graph = make_graph(["a", "b"], [edge("a", "b")])
    [row] = evaluate_rules(graph, [rule(agent="a", target_agent="a")], make_inventory())
    assert row.result is RuleResult.PASS

    cyclic = make_graph(["a", "b"], [edge("a", "b"), edge("b", "a")])
    [row] = evaluate_rules(cyclic, [rule(agent="a", target_agent="a")], make_inventory())
    assert row.result is RuleResult.FAIL
    assert row.witness == (edge("a", "b"), edge("b", "a"))


def test_rules_keep_their_order():
    graph = make_graph(["s", "h"], [uses("s", "t"), uses("h", "u")])
    rows = evaluate_rules(
        graph,
        [rule("Z", agent="s", tool="t"), rule("A", agent="s", tool="u")],
        make_inventory(tool("t"), tool("u")),
    )
    assert [(row.id, row.result) for row in rows] == [
        ("Z", RuleResult.FAIL),
        ("A", RuleResult.PASS),
    ]


def assert_error(row: RuleRow, *problems: str) -> None:
    assert row.result is RuleResult.ERROR
    assert row.problems == problems
    assert row.witness == ()


ERROR_GRAPH = make_graph(["s", "a"], [edge("s", "a")], entries=["s"], roles=["analyst"])
ERROR_INVENTORY = make_inventory(tool("t"), delegation={"ask_oracle": "oracle"})


def test_error_unknown_start_agent():
    [row] = evaluate_rules(ERROR_GRAPH, [rule(agent="ghost", tool="t")], ERROR_INVENTORY)
    assert_error(row, "agent 'ghost' is not in the agent graph")


def test_error_unknown_target_agent():
    [row] = evaluate_rules(ERROR_GRAPH, [rule(agent="s", target_agent="ghost")], ERROR_INVENTORY)
    assert_error(row, "agent 'ghost' is not in the agent graph")


def test_error_role_without_registry_roles():
    graph = make_graph(["s"], entries=["s"])
    [row] = evaluate_rules(graph, [rule(role="analyst", tool="t")], ERROR_INVENTORY)
    assert_error(row, "rule uses role 'analyst' but the registry has no top-level roles list")


def test_error_role_not_in_registry_roles():
    [row] = evaluate_rules(ERROR_GRAPH, [rule(role="auditor", tool="t")], ERROR_INVENTORY)
    assert_error(row, "role 'auditor' is not in the registry roles list")


def test_error_delegation_tool():
    [row] = evaluate_rules(ERROR_GRAPH, [rule(agent="s", tool="ask_oracle")], ERROR_INVENTORY)
    assert_error(
        row,
        "tool 'ask_oracle' is a delegation to agent 'oracle'; "
        "target the tools behind that agent instead",
    )


def test_error_tool_not_in_inventory():
    [row] = evaluate_rules(ERROR_GRAPH, [rule(agent="s", tool="nope")], ERROR_INVENTORY)
    assert_error(row, "tool 'nope' is not in the inventory")


def test_error_lists_every_problem_and_copies_the_reason():
    [row] = evaluate_rules(
        ERROR_GRAPH, [rule(role="auditor", tool="nope", reason="why")], ERROR_INVENTORY
    )
    assert_error(
        row,
        "role 'auditor' is not in the registry roles list",
        "tool 'nope' is not in the inventory",
    )
    assert row.reason == "why"
    assert (row.role, row.tool, row.agent, row.target_agent) == ("auditor", "nope", None, None)


# ---- role_reachability ----


def reach_graph() -> AgentGraph:
    return make_graph(
        [
            node("e1", entry=True, roles=("analyst",), mode="user"),
            node("e2", entry=True, roles=("admin",)),
            node("r", kind=NodeKind.REMOTE_AGENT, opaque=True),
        ],
        [uses("e1", "t1"), edge("e1", "r", kind="remote"), uses("e2", "t2")],
        roles=["analyst", "admin"],
    )


def test_role_reachability_is_none_without_roles():
    graph = make_graph([node("a", entry=True)], [uses("a", "t")])
    assert role_reachability(graph, make_inventory(tool("t")), [], []) is None


def test_role_reachability_rows():
    inventory = make_inventory(tool("t1", "critical"), tool("t2", "low"), tool("t3", "unknown"))
    plan = [
        case("C1", tool_id="t1", role="analyst", agent="e1"),
        case("C2", tool_id="t1", role="analyst", agent="e1", status=CaseStatus.ERROR),
        case("C3", tool_id="t1", role="admin", agent="e1"),
        case("C4", tool_id="t2", role="analyst", agent="e1", expect="deny"),
    ]
    rules = [
        rule_row("R1", role="analyst", tool_id="t1", result=RuleResult.FAIL),
        rule_row("R2", role="analyst", tool_id="t1", result=RuleResult.ERROR),
        rule_row("R3", role=None, tool_id="t1"),
        rule_row("R4", role="analyst", tool_id="t2", result=RuleResult.INCONCLUSIVE),
    ]
    rows = role_reachability(reach_graph(), inventory, plan, rules)
    assert rows == (
        ReachRow(
            role="analyst",
            tool="t1",
            risk=Risk.CRITICAL,
            status=ReachStatus.REACHABLE,
            witness=(uses("e1", "t1"),),
            delegation_mode="user",
            covered_by=("C1", "R1"),
        ),
        ReachRow(
            role="analyst",
            tool="t2",
            risk=Risk.LOW,
            status=ReachStatus.INCONCLUSIVE,
            opaque_reached=("r",),
            covered_by=("C4", "R4"),
        ),
        ReachRow(
            role="analyst",
            tool="t3",
            risk=Risk.UNKNOWN,
            status=ReachStatus.INCONCLUSIVE,
            opaque_reached=("r",),
        ),
        ReachRow(
            role="admin",
            tool="t2",
            risk=Risk.LOW,
            status=ReachStatus.REACHABLE,
            witness=(uses("e2", "t2"),),
        ),
    )


def test_role_reachability_lists_reachable_tools_even_with_opaque_nodes():
    inventory = make_inventory(tool("t1"))
    [row] = table(reach_graph(), inventory)
    assert row.status is ReachStatus.REACHABLE
    assert row.opaque_reached == ()


def test_delegation_mode_comes_from_the_last_agent_not_the_mcp_server():
    graph = make_graph(
        [
            node("e", entry=True, mode="user"),
            node("w", mode="agent"),
            node("m", kind=NodeKind.MCP_SERVER, mode="on_behalf_of"),
        ],
        [edge("e", "w", kind="agent_as_tool"), edge("w", "m", kind="calls"), uses("m", "t")],
        roles=["analyst"],
    )
    [row] = table(graph, make_inventory(tool("t")))
    assert row.witness == (
        edge("e", "w", kind="agent_as_tool"),
        edge("w", "m", kind="calls"),
        uses("m", "t"),
    )
    assert row.delegation_mode == "agent"


def test_delegation_mode_is_none_when_the_last_agent_declares_none():
    graph = make_graph(
        [node("e", entry=True, mode="user"), node("w")],
        [edge("e", "w"), uses("w", "t")],
        roles=["analyst"],
    )
    [row] = table(graph, make_inventory(tool("t")))
    assert row.delegation_mode is None


# ---- identity_warnings ----


def identity_setup() -> tuple[AgentGraph, Inventory, tuple[ReachRow, ...]]:
    graph = make_graph(
        [
            node("e", entry=True, roles=("analyst",), mode="user"),
            node("a1", mode="agent"),
            node("a2"),
            node("a3", mode="user"),
            node("a4"),
            node("a5", mode="on_behalf_of"),
            node("m", kind=NodeKind.MCP_SERVER),
            node("lonely", mode="agent"),
        ],
        [
            edge("e", "a1"),
            edge("e", "a2"),
            edge("e", "a3"),
            edge("e", "a4"),
            edge("e", "a5"),
            uses("a1", "crit"),
            edge("a2", "m", kind="calls"),
            uses("m", "crit"),
            uses("m", "unk"),
            uses("a3", "crit"),
            uses("a4", "low"),
            uses("a5", "crit"),
            uses("lonely", "crit"),
        ],
        roles=["analyst"],
    )
    inventory = make_inventory(tool("crit", "critical"), tool("low", "low"), tool("unk", "unknown"))
    rows = table(graph, inventory)
    return graph, inventory, rows


def test_identity_warnings_texts_and_order():
    graph, inventory, rows = identity_setup()
    assert identity_warnings(graph, inventory, rows) == (
        "role 'analyst' can reach tool 'crit' (risk=critical) through agent 'a1', which calls"
        " tools with its own identity; the IAM will not see the user",
        "role 'analyst' can reach tool 'crit' (risk=critical) through agent 'a2', whose"
        " delegation_mode is not declared; the IAM may not see the user",
        "role 'analyst' can reach tool 'unk' (risk=unknown) through agent 'a2', whose"
        " delegation_mode is not declared; the IAM may not see the user",
    )


def test_identity_warnings_have_no_duplicates():
    graph, inventory, rows = identity_setup()
    assert identity_warnings(graph, inventory, rows + rows) == identity_warnings(
        graph, inventory, rows
    )


def test_remote_agent_counts_as_the_tool_caller():
    graph = make_graph(
        [
            node("e", entry=True, mode="user"),
            node("remote-r", kind=NodeKind.REMOTE_AGENT, mode="agent"),
        ],
        [edge("e", "remote-r", kind="remote"), uses("remote-r", "t")],
        roles=["analyst"],
    )
    inventory = make_inventory(tool("t", "critical"))
    [row] = table(graph, inventory)
    assert row.witness == (edge("e", "remote-r", kind="remote"), uses("remote-r", "t"))
    assert row.delegation_mode == "agent"
    assert identity_warnings(graph, inventory, (row,)) == (
        "role 'analyst' can reach tool 't' (risk=critical) through agent 'remote-r', which"
        " calls tools with its own identity; the IAM will not see the user",
    )


def test_mcp_server_behind_a_remote_agent_is_still_skipped():
    graph = make_graph(
        [
            node("e", entry=True, mode="user"),
            node("remote-r", kind=NodeKind.REMOTE_AGENT, mode="agent"),
            node("m", kind=NodeKind.MCP_SERVER),
        ],
        [edge("e", "remote-r", kind="remote"), edge("remote-r", "m", kind="calls"), uses("m", "t")],
        roles=["analyst"],
    )
    inventory = make_inventory(tool("t", "critical"))
    [row] = table(graph, inventory)
    assert row.witness == (
        edge("e", "remote-r", kind="remote"),
        edge("remote-r", "m", kind="calls"),
        uses("m", "t"),
    )
    # The mcp_server declares no delegation_mode; the remote agent's mode is reported.
    assert row.delegation_mode == "agent"
    # The remote agent uses the tool through the server; the server itself is not a caller.
    assert identity_warnings(graph, inventory, (row,)) == (
        "role 'analyst' can reach tool 't' (risk=critical) through agent 'remote-r', which"
        " calls tools with its own identity; the IAM will not see the user",
    )


def test_user_delegation_mode_gives_no_identity_warning():
    graph = make_graph([node("e", entry=True, mode="user")], [uses("e", "t")], roles=["analyst"])
    inventory = make_inventory(tool("t", "critical"))
    rows = table(graph, inventory)
    assert identity_warnings(graph, inventory, rows) == ()


def test_inconclusive_rows_give_no_identity_warning():
    graph = make_graph(
        [node("e", entry=True), node("r", kind=NodeKind.REMOTE_AGENT, opaque=True)],
        [edge("e", "r", kind="remote")],
        roles=["analyst"],
    )
    inventory = make_inventory(tool("t", "critical"))
    rows = table(graph, inventory)
    assert [row.status for row in rows] == [ReachStatus.INCONCLUSIVE]
    assert identity_warnings(graph, inventory, rows) == ()


# ---- path_warnings ----


PATH_GRAPH = make_graph(
    [
        node("e", entry=True, roles=("analyst",)),
        node("f"),
        node("g"),
        node("m", kind=NodeKind.MCP_SERVER),
        node("b"),
    ],
    [
        edge("e", "f"),
        uses("f", "t"),
        edge("e", "g", kind="team"),
        edge("g", "m", kind="calls"),
        uses("m", "t"),
        uses("e", "b"),
    ],
    roles=["analyst"],
)


def test_path_that_matches_the_graph_gives_no_warnings():
    assert path_warnings(PATH_GRAPH, case("C1", path=("e", "f"))) == ()
    assert path_warnings(PATH_GRAPH, case("C2", path=("e", "g"))) == ()


def test_path_step_that_is_not_an_edge():
    assert path_warnings(PATH_GRAPH, case("C1", path=("e", "b", "f"))) == (
        "C1: path step 'e' -> 'b' is not an edge in the agent graph",
        "C1: path step 'b' -> 'f' is not an edge in the agent graph",
    )


def test_repeated_path_steps_warn_once():
    assert path_warnings(PATH_GRAPH, case("C1", path=("e", "b", "e", "b"))) == (
        "C1: path step 'e' -> 'b' is not an edge in the agent graph",
        "C1: path step 'b' -> 'e' is not an edge in the agent graph",
        "C1: agent 'b' has no known way to use tool 't'",
    )


def test_prebuilt_index_gives_the_same_path_warnings():
    index = index_graph(PATH_GRAPH)
    for path in (("e", "f"), ("e", "b", "f"), ("f", "e"), ("e",)):
        planned = case("C1", path=path)
        assert path_warnings(PATH_GRAPH, planned, index=index) == path_warnings(PATH_GRAPH, planned)
    assert index.graph is PATH_GRAPH


@pytest.mark.parametrize(
    "planned",
    [case("C1", path=("e", "f")), case("C1", agent="e")],
    ids=["checked-case", "unchecked-case"],
)
def test_index_from_another_graph_is_rejected(planned: PlannedCase):
    # The check is by identity, so even an equal copy of the graph is rejected.
    for other in (reach_graph(), PATH_GRAPH.model_copy()):
        with pytest.raises(ValueError, match="index was built from a different graph"):
            path_warnings(PATH_GRAPH, planned, index=index_graph(other))


def test_last_agent_without_a_way_to_use_the_tool():
    assert path_warnings(PATH_GRAPH, case("C1", path=("e",))) == (
        "C1: agent 'e' has no known way to use tool 't'",
    )


def test_role_that_cannot_start_at_the_first_agent():
    assert path_warnings(PATH_GRAPH, case("C1", path=("f",))) == (
        "C1: role 'analyst' cannot start at 'f' (it is not an entry agent available to that role)",
    )
    no_roles = PATH_GRAPH.model_copy(update={"roles": None})
    assert path_warnings(no_roles, case("C1", path=("f",))) == ()


def test_path_warnings_come_in_a_fixed_order():
    assert path_warnings(PATH_GRAPH, case("C9", path=("f", "e"), role="admin")) == (
        "C9: path step 'f' -> 'e' is not an edge in the agent graph",
        "C9: agent 'e' has no known way to use tool 't'",
        "C9: role 'admin' cannot start at 'f' (it is not an entry agent available to that role)",
    )


@pytest.mark.parametrize(
    "planned",
    [
        case("C1", path=("f", "e"), expect="deny"),
        case("C1", agent="f"),
        case("C1", path=("f", "e"), status=CaseStatus.ERROR),
    ],
    ids=["deny", "agent-case", "error"],
)
def test_no_path_warnings_for_deny_agent_or_error_cases(planned: PlannedCase):
    assert path_warnings(PATH_GRAPH, planned) == ()


# ---- generated graphs ----


KINDS = ("handoff", "team", "agent_as_tool", "calls")
PROVENANCES = ("discovered", "discovered", "inferred", "declared")
MODES: tuple[DelegationMode | None, ...] = (None, "user", "agent", "on_behalf_of")


def random_graph(
    seed: int, *, agents: int, tools: int, roles: int, entries: int, mcp: int, opaque: int
) -> tuple[AgentGraph, Inventory]:
    """A reproducible graph with every node kind, provenance, and delegation mode."""
    rng = random.Random(seed)
    role_ids = [f"role{index}" for index in range(roles)]
    agent_ids = [f"agent{index:04d}" for index in range(agents)]
    tool_ids = [f"tool{index:05d}" for index in range(tools)]
    mcp_ids = [f"mcp{index}" for index in range(mcp)]
    nodes = [
        node(
            agent_id,
            kind=NodeKind.REMOTE_AGENT if index % 7 == 6 else NodeKind.AGENT,
            entry=index < entries,
            roles=tuple(rng.sample(role_ids, 2)) if rng.random() < 0.7 else None,
            mode=rng.choice(MODES),
            opaque=index >= agents - opaque,
        )
        for index, agent_id in enumerate(agent_ids)
    ]
    nodes += [node(mcp_id, kind=NodeKind.MCP_SERVER) for mcp_id in mcp_ids]
    edges: list[GraphEdge] = []
    for agent_id in agent_ids:
        for target in rng.sample(agent_ids, 3):
            edges.append(edge(agent_id, target, rng.choice(KINDS), rng.choice(PROVENANCES)))
        for tool_id in rng.sample(tool_ids, 4):
            edges.append(uses(agent_id, tool_id, rng.choice(PROVENANCES)))
        if rng.random() < 0.3:
            edges.append(edge(agent_id, rng.choice(mcp_ids), "calls"))
    for mcp_id in mcp_ids:
        edges.extend(uses(mcp_id, tool_id) for tool_id in rng.sample(tool_ids, 10))
    rng.shuffle(edges)
    graph = make_graph(nodes, edges, entries=agent_ids[:entries], roles=role_ids)
    risks = [risk.value for risk in Risk]
    inventory = make_inventory(*(tool(tool_id, rng.choice(risks)) for tool_id in tool_ids))
    return graph, inventory


def per_pair_rows(
    graph: AgentGraph,
    inventory: Inventory,
    plan: Sequence[PlannedCase],
    rules: Sequence[RuleRow],
) -> tuple[ReachRow, ...]:
    """The role x tool table built the slow way: one find_witness per role and tool."""
    expected: list[ReachRow] = []
    for role in graph.roles or ():
        starts = start_agents_for_role(graph, role)
        reached = reach(graph, starts)
        for item in inventory.tools:
            covered_by = tuple(
                [
                    planned.scenario.id
                    for planned in plan
                    if planned.status is not CaseStatus.ERROR
                    and (planned.scenario.role, planned.scenario.tool) == (role, item.id)
                ]
                + [
                    row.id
                    for row in rules
                    if row.result is not RuleResult.ERROR
                    and (row.role, row.tool) == (role, item.id)
                ]
            )
            witness = find_witness(graph, starts, tool=item.id)
            if witness is not None:
                assert item.id in reached.tools
                callers = [graph.node(step.from_id) for step in reversed(witness)]
                mode = next(
                    (
                        caller.delegation_mode
                        for caller in callers
                        if caller is not None and caller.kind is not NodeKind.MCP_SERVER
                    ),
                    None,
                )
                expected.append(
                    ReachRow(
                        role=role,
                        tool=item.id,
                        risk=item.risk,
                        status=ReachStatus.REACHABLE,
                        witness=witness,
                        delegation_mode=mode,
                        covered_by=covered_by,
                    )
                )
            elif reached.opaque:
                assert item.id not in reached.tools
                expected.append(
                    ReachRow(
                        role=role,
                        tool=item.id,
                        risk=item.risk,
                        status=ReachStatus.INCONCLUSIVE,
                        opaque_reached=reached.opaque,
                        covered_by=covered_by,
                    )
                )
    return tuple(expected)


@pytest.mark.parametrize("seed", range(6))
def test_role_table_agrees_with_one_witness_search_per_pair(seed: int):
    graph, inventory = random_graph(
        seed, agents=15, tools=40, roles=3, entries=3, mcp=2, opaque=seed % 2
    )
    rng = random.Random(seed)
    roles = list(graph.roles or ())
    tool_ids = [item.id for item in inventory.tools]
    plan = [
        case(
            f"C{index}",
            tool_id=rng.choice(tool_ids),
            role=rng.choice(roles),
            agent="agent0000",
            status=rng.choice([CaseStatus.UNTESTED, CaseStatus.ERROR]),
        )
        for index in range(30)
    ]
    rules = [
        rule_row(
            f"R{index}",
            role=rng.choice([*roles, None]),
            tool_id=rng.choice(tool_ids),
            result=rng.choice(list(RuleResult)),
        )
        for index in range(30)
    ]
    rows = role_reachability(graph, inventory, plan, rules)
    assert rows == per_pair_rows(graph, inventory, plan, rules)
    assert rows is not None
    assert any(row.status is ReachStatus.REACHABLE for row in rows)


def test_large_graph_smoke():
    graph, inventory = random_graph(7, agents=200, tools=1000, roles=5, entries=10, mcp=5, opaque=3)
    rows = table(graph, inventory)
    pairs = [(row.role, row.tool) for row in rows]
    assert len(pairs) == len(set(pairs)) <= 5 * 1000
    assert {role for role, _ in pairs} <= set(graph.roles or ())
    assert {tool_id for _, tool_id in pairs} <= {item.id for item in inventory.tools}
    reachable = [row for row in rows if row.status is ReachStatus.REACHABLE]
    assert reachable
    for row in reachable:
        assert row.witness[0].from_id in start_agents_for_role(graph, row.role)
        last = row.witness[-1]
        assert (last.kind, last.to_id) == (EdgeKind.USES_TOOL, row.tool)
        for before, after in pairwise(row.witness):
            assert before.kind is not EdgeKind.USES_TOOL
            assert before.to_id == after.from_id
    for row in rows:
        if row.status is ReachStatus.INCONCLUSIVE:
            assert row.witness == ()
            assert row.opaque_reached
    warnings = identity_warnings(graph, inventory, rows)
    assert len(warnings) == len(set(warnings))
    index = index_graph(graph)
    agent_ids = [item.id for item in graph.nodes if item.kind is NodeKind.AGENT]
    for position in range(0, len(agent_ids) - 2, 20):
        planned = case(f"C{position}", tool_id="tool00000", path=tuple(agent_ids[position:][:3]))
        assert path_warnings(graph, planned, index=index) == path_warnings(graph, planned)
