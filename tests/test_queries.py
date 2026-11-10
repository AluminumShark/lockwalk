"""Tests for building the questions for the IAM."""

import time
from collections.abc import Sequence
from itertools import pairwise
from typing import Any

import pytest

from lockwalk.config import PolicyConfig
from lockwalk.fixtures import FixturesFile
from lockwalk.graph.analysis import _agent_witness, _agent_witnesses, index_graph, role_callers
from lockwalk.models import (
    AgentGraph,
    CaseStatus,
    DelegationMode,
    EdgeKind,
    GraphEdge,
    GraphNode,
    Inventory,
    InventoryTool,
    NodeKind,
    PlannedCase,
    Provenance,
    Risk,
    TestScenario,
)
from lockwalk.queries import build_queries

# ---- helpers ----


def edge(a: str, b: str, kind: str = "handoff") -> GraphEdge:
    return GraphEdge(from_id=a, to_id=b, kind=EdgeKind(kind), provenance=Provenance.DISCOVERED)


def uses(a: str, tool: str) -> GraphEdge:
    return edge(a, tool, "uses_tool")


def node(
    node_id: str,
    *,
    kind: NodeKind = NodeKind.AGENT,
    entry: bool = False,
    mode: DelegationMode | None = None,
) -> GraphNode:
    return GraphNode(id=node_id, kind=kind, entry=entry, delegation_mode=mode)


def make_graph(
    nodes: Sequence[GraphNode],
    edges: Sequence[GraphEdge] = (),
    *,
    entries: Sequence[str] = (),
    roles: Sequence[str] | None = None,
) -> AgentGraph:
    return AgentGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        entry_agents=tuple(entries),
        entry_inferred=False,
        roles=None if roles is None else tuple(roles),
        drift=None,
    )


def tool(
    tool_id: str,
    *,
    risk: str = "high",
    action: str | None = "pay:send",
    resource_type: str | None = "payment",
) -> InventoryTool:
    return InventoryTool(
        id=tool_id,
        action=action,
        risk=Risk(risk),
        resource_type=resource_type,
        supported_agents=(),
        sources=(),
        description=None,
        hints={},
    )


def make_inventory(*tools: InventoryTool) -> Inventory:
    return Inventory(agents=(), tools=tools, sources=(), drift=None, errors=(), warnings=())


def case(
    case_id: str = "C1",
    *,
    tool_id: str = "pay",
    actor: str = "alice",
    role: str = "analyst",
    agent: str | None = None,
    path: tuple[str, ...] | None = None,
    fixture: str = "pay1",
    mode: str | None = None,
    conditions: dict[str, Any] | None = None,
    status: CaseStatus = CaseStatus.UNTESTED,
) -> PlannedCase:
    if agent is None and path is None:
        agent = "a"
    scenario = TestScenario.model_validate(
        {
            "id": case_id,
            "actor": actor,
            "role": role,
            "agent": agent,
            "path": path,
            "tool": tool_id,
            "action": "pay:send",
            "resource_fixture": fixture,
            "expect": "deny",
            "conditions": conditions or {},
            "delegation_mode": mode,
        }
    )
    problems = ("broken",) if status is CaseStatus.ERROR else ()
    return PlannedCase(scenario=scenario, status=status, problems=problems)


def make_fixtures(**extra: Any) -> FixturesFile:
    data: dict[str, Any] = {
        "schema_version": "1",
        "subjects": {
            "alice": {"roles": ["analyst", "viewer"], "properties": {"dept": "fin"}},
            "bob": {"roles": ["admin"]},
        },
        "agents": {"a": {"properties": {"tier": "gold"}}},
        "resources": {
            "pay1": {"type": "payment", "id": "p-1", "properties": {"amount": 5}},
        },
        "probes": {
            "subjects": {"analyst": "alice"},
            "resources": {"payment": "pay1"},
        },
    }
    data.update(extra)
    return FixturesFile.model_validate(data)


def policy(**fields: Any) -> PolicyConfig:
    return PolicyConfig.model_validate({"adapter": "python", "target": "pkg.mod:decide", **fields})


def simple_graph(mode: DelegationMode | None = None, roles: Sequence[str] | None = None):
    return make_graph(
        [node("a", entry=True, mode=mode)],
        [uses("a", "pay")],
        entries=["a"],
        roles=roles,
    )


def build(
    plan: Sequence[PlannedCase],
    graph: AgentGraph | None = None,
    *,
    inventory: Inventory | None = None,
    fixtures: FixturesFile | None = None,
    pol: PolicyConfig | None = None,
):
    return build_queries(
        plan,
        graph or simple_graph("user"),
        inventory or make_inventory(tool("pay")),
        fixtures if fixtures is not None else make_fixtures(),
        pol or policy(),
    )


# ---- cases ----


def test_user_mode_one_query() -> None:
    result = build([case(conditions={"region": "eu"})])
    (ask,) = result.cases
    assert ask.problems == ()
    assert ask.plain_user is None
    (hop,) = ask.hops
    assert hop.kind == "tool" and hop.mode == "user" and hop.caller == "a" and hop.target == "pay"
    assert hop.control == ("pay:send", "payment")
    (query,) = hop.queries
    assert query.subject.type == "user" and query.subject.id == "alice"
    assert query.subject.properties == {"roles": ["analyst", "viewer"], "dept": "fin"}
    assert query.action.name == "pay:send"
    assert query.resource.type == "payment" and query.resource.id == "p-1"
    assert query.resource.properties == {"amount": 5}
    assert query.context == {
        "lockwalk": {"case": "C1", "path": ["a"], "tool": "pay"},
        "region": "eu",
    }
    assert ask.risk is Risk.HIGH and ask.route == ("a",)
    assert result.warnings == ()


def test_case_mode_overrides_node_mode() -> None:
    result = build([case(mode="agent")], simple_graph("user"))
    assert result.cases[0].tool_hop.mode == "agent"
    result = build([case()], simple_graph("agent"))
    assert result.cases[0].tool_hop.mode == "agent"


def test_agent_mode() -> None:
    (ask,) = build([case()], simple_graph("agent")).cases
    (query,) = ask.tool_hop.queries
    assert query.subject.type == "agent" and query.subject.id == "a"
    assert query.subject.properties == {"tier": "gold"}
    assert ask.plain_user is not None
    assert ask.plain_user.subject.id == "alice"
    assert ask.plain_user.subject.type == "user"
    assert ask.plain_user.action == query.action
    assert ask.plain_user.resource == query.resource
    assert ask.plain_user.context == query.context


def test_agent_without_fixture_has_no_properties() -> None:
    (ask,) = build([case(agent="b")], make_graph([node("b", entry=True, mode="agent")])).cases
    assert ask.tool_hop.queries[0].subject.properties == {}


def test_on_behalf_of_act_chain() -> None:
    graph = make_graph(
        [
            node("supervisor", entry=True),
            node("finance-agent"),
            node("pricing-agent", mode="on_behalf_of"),
        ]
    )
    plan = [case(path=("supervisor", "finance-agent", "pricing-agent"))]
    (ask,) = build(plan, graph).cases
    (query,) = ask.tool_hop.queries
    assert query.subject.type == "user" and query.subject.id == "alice"
    assert query.subject.properties["act"] == {
        "type": "agent",
        "id": "pricing-agent",
        "act": {
            "type": "agent",
            "id": "finance-agent",
            "act": {"type": "agent", "id": "supervisor"},
        },
    }
    assert query.subject.properties["roles"] == ["analyst", "viewer"]
    assert ask.plain_user is not None
    assert "act" not in ask.plain_user.subject.properties


def test_undeclared_mode_two_queries() -> None:
    (ask,) = build([case()], simple_graph(None)).cases
    hop = ask.tool_hop
    assert hop.mode == "undeclared"
    user, agent = hop.queries
    assert user.subject.type == "user" and agent.subject.type == "agent"
    assert ask.plain_user == user


def test_missing_actor_warns_with_minimal_subject() -> None:
    result = build([case(actor="zed")])
    (query,) = result.cases[0].tool_hop.queries
    assert query.subject.properties == {"roles": ["analyst"]}
    assert result.warnings == (
        "actor 'zed' has no fixture; sending only its id and role (cases: C1)",
    )


def test_no_fixtures_at_all() -> None:
    result = build_queries(
        [case()], simple_graph("user"), make_inventory(tool("pay")), None, policy()
    )
    assert result.warnings == (
        "actor 'alice' has no fixture; sending only its id and role (cases: C1)",
        "resource fixture 'pay1' is not defined; sending its name as the id, "
        "with no properties (cases: C1)",
    )
    (query,) = result.cases[0].tool_hop.queries
    assert query.subject.properties == {"roles": ["analyst"]}
    assert query.resource.type == "payment" and query.resource.id == "pay1"
    assert query.resource.properties == {}


def test_role_not_among_subject_roles() -> None:
    result = build([case(role="admin")])
    (ask,) = result.cases
    assert ask.hops == () and ask.plain_user is None
    assert ask.problems == (
        "role 'admin' is not one of the roles of subject 'alice' in the fixtures (analyst, viewer)",
    )


def test_resource_type_fallback_and_problem() -> None:
    fixtures = make_fixtures(resources={"pay1": {"properties": {"amount": 1}}})
    result = build([case()], fixtures=fixtures)
    assert result.cases[0].problems == ()
    assert result.cases[0].tool_hop.queries[0].resource.type == "payment"
    assert result.cases[0].tool_hop.queries[0].resource.id == "pay1"

    # A fixture that is not defined warns, then falls back to the registry type.
    result = build([case(fixture="nope")])
    assert result.warnings == (
        "resource fixture 'nope' is not defined; sending its name as the id, "
        "with no properties (cases: C1)",
    )
    assert result.cases[0].problems == ()

    inventory = make_inventory(tool("pay", resource_type=None))
    result = build([case(fixture="nope")], inventory=inventory)
    (ask,) = result.cases
    assert ask.hops == ()
    assert ask.problems == (
        "resource fixture 'nope' has no type, and tool 'pay' has no resource_type in the registry",
    )
    assert len(result.warnings) == 1


def test_ask_every_hop() -> None:
    graph = make_graph(
        [
            node("sup", entry=True, mode="on_behalf_of"),
            node("fin", mode="agent"),
            node("pri"),
        ]
    )
    plan = [case(path=("sup", "fin", "pri"))]
    result = build(plan, graph, pol=policy(ask_every_hop=True, invoke_action="agent:call"))
    (ask,) = result.cases
    assert len(ask.hops) == 4
    first, second, third, tool_hop = ask.hops
    assert (first.caller, first.target, first.kind, first.mode) == ("user", "sup", "agent", "user")
    assert first.queries[0].subject.type == "user"
    assert (second.caller, second.mode) == ("sup", "on_behalf_of")
    assert second.queries[0].subject.properties["act"] == {"type": "agent", "id": "sup"}
    assert (third.caller, third.mode) == ("fin", "agent")
    assert third.queries[0].subject.type == "agent" and third.queries[0].subject.id == "fin"
    assert tool_hop.kind == "tool" and tool_hop.caller == "pri" and tool_hop.mode == "undeclared"
    assert len(tool_hop.queries) == 2
    for hop in (first, second, third):
        assert hop.control == ("agent:call", "agent")
        (query,) = hop.queries
        assert query.action.name == "agent:call"
        assert query.resource.type == "agent" and query.resource.id == hop.target
        assert query.context["lockwalk"]["hop"] == {"caller": hop.caller, "target": hop.target}
        assert query.context["lockwalk"]["case"] == "C1"
    assert tool_hop.control == ("pay:send", "payment")
    assert "hop" not in tool_hop.queries[0].context["lockwalk"]


def test_without_ask_every_hop_only_the_tool_hop() -> None:
    graph = make_graph([node("sup", entry=True), node("pri", mode="user")])
    (ask,) = build([case(path=("sup", "pri"))], graph).cases
    assert len(ask.hops) == 1


def test_long_on_behalf_of_route_cannot_be_built() -> None:
    names = [f"ag{i}" for i in range(70)]
    graph = make_graph(
        [node(name, entry=(i == 0), mode="on_behalf_of") for i, name in enumerate(names)]
    )
    # TestScenario now caps a path at 32 agents (MAX_ROUTE_AGENTS), so a 70-agent path is
    # set with model_copy, which skips validation. The builder's MAX_QUERY_DEPTH limit can no
    # longer be reached through a valid spec, because paths are capped at 32. This test keeps
    # it covered as a defense against a future change to the cap.
    short = case(path=tuple(names[:2]))
    long = short.model_copy(
        update={"scenario": short.scenario.model_copy(update={"path": tuple(names)})}
    )
    result = build([long], graph)
    (ask,) = result.cases
    assert ask.hops == () and ask.plain_user is None
    (problem,) = ask.problems
    assert problem.startswith("the questions for this case cannot be built: ")


def test_planned_error_cases_are_skipped() -> None:
    result = build([case("C1", status=CaseStatus.ERROR), case("C2")])
    assert [ask.case_id for ask in result.cases] == ["C2"]


def test_deterministic_and_query_order() -> None:
    plan = [case("C1"), case("C2", mode="agent")]
    graph = simple_graph(None, roles=["analyst"])
    first = build(plan, graph, pol=policy(ask_every_hop=True))
    second = build(plan, graph, pol=policy(ask_every_hop=True))
    assert first == second
    queries = first.queries()
    expected: list[Any] = []
    for ask in first.cases:
        for hop in ask.hops:
            expected.extend(hop.queries)
        if ask.plain_user is not None:
            expected.append(ask.plain_user)
    for row in first.rows:
        expected.extend(q for q in (row.path_query, row.user_query) if q is not None)
    assert queries == expected
    assert len(queries) > 0


# ---- role_callers and rows ----


def test_role_callers_routes() -> None:
    graph = make_graph(
        [
            node("sup", entry=True, mode="agent"),
            node("srv", kind=NodeKind.MCP_SERVER),
            node("worker", mode="on_behalf_of"),
            node("quiet", mode="user"),
            node("far", mode="agent"),
        ],
        [
            edge("sup", "worker"),
            edge("worker", "srv", "calls"),
            uses("srv", "mcp-tool"),
            uses("worker", "own-tool"),
            edge("sup", "quiet"),
            uses("quiet", "q-tool"),
            uses("sup", "s-tool"),
            uses("far", "f-tool"),
        ],
        entries=["sup"],
        roles=["analyst"],
    )
    found = role_callers(graph, "analyst")
    assert found == (
        ("sup", "s-tool", ("sup",)),
        ("worker", "mcp-tool", ("sup", "worker")),
        ("worker", "own-tool", ("sup", "worker")),
    )
    with pytest.raises(ValueError):
        role_callers(graph, "analyst", index=index_graph(make_graph([])))


def test_role_callers_skips_an_edge_to_an_undeclared_agent() -> None:
    graph = make_graph(
        [node("a", entry=True, mode="agent")],
        [edge("a", "ghost", "calls"), uses("a", "a-tool")],
        entries=["a"],
        roles=["r"],
    )
    assert role_callers(graph, "r") == (("a", "a-tool", ("a",)),)


def row_graph(*, mode: DelegationMode | None = "agent") -> AgentGraph:
    return make_graph(
        [
            node("sup", entry=True, mode="user"),
            node("srv", kind=NodeKind.MCP_SERVER),
            node("worker", mode=mode),
        ],
        [edge("sup", "worker"), edge("worker", "srv", "calls"), uses("srv", "pay")],
        entries=["sup"],
        roles=["analyst", "viewer"],
    )


def test_rows() -> None:
    result = build([], row_graph(), pol=policy())
    assert [(r.role, r.tool, r.via) for r in result.rows] == [
        ("analyst", "pay", "worker"),
        ("viewer", "pay", "worker"),
    ]
    analyst, viewer = result.rows
    assert analyst.unchecked is None
    assert analyst.path == ("sup", "worker")
    assert analyst.mode == "agent" and analyst.risk is Risk.HIGH
    assert analyst.control == ("pay:send", "payment")
    assert analyst.path_query is not None and analyst.user_query is not None
    assert analyst.path_query.subject.type == "agent"
    assert analyst.path_query.subject.id == "worker"
    assert analyst.user_query.subject.id == "alice"
    assert analyst.user_query.subject.properties["roles"] == ["analyst", "viewer"]
    assert analyst.user_query.resource.id == "p-1"
    assert analyst.user_query.context == {
        "lockwalk": {
            "case": None,
            "row": {"role": "analyst", "tool": "pay"},
            "path": ["sup", "worker"],
            "tool": "pay",
        }
    }
    assert viewer.unchecked == "no probe subject for role 'viewer' (probes.subjects)"
    assert viewer.path_query is None and viewer.user_query is None and viewer.control is None


def test_rows_modes() -> None:
    (row, _) = build([], row_graph(mode="on_behalf_of")).rows
    assert row.mode == "on_behalf_of"
    assert row.path_query is not None
    assert row.path_query.subject.type == "user"
    assert row.path_query.subject.properties["act"] == {
        "type": "agent",
        "id": "worker",
        "act": {"type": "agent", "id": "sup"},
    }
    (row, _) = build([], row_graph(mode=None)).rows
    assert row.mode == "undeclared"
    assert row.path_query is not None and row.path_query.subject.type == "agent"


def test_rows_none_without_roles_or_user_callers() -> None:
    graph = make_graph([node("a", entry=True, mode="agent")], [uses("a", "pay")], entries=["a"])
    assert build([], graph).rows == ()
    assert build([], simple_graph("user", roles=["analyst"])).rows == ()


def test_row_start_caller_route() -> None:
    (row, _) = build([], simple_graph("agent", roles=["analyst", "viewer"])).rows
    assert row.path == ("a",)


def test_unchecked_reasons_in_order() -> None:
    graph = simple_graph("agent", roles=["analyst"])

    def reason(inventory: Inventory, fixtures: FixturesFile | None) -> str | None:
        result = build_queries([], graph, inventory, fixtures, policy())
        return result.rows[0].unchecked

    full = make_inventory(tool("pay"))
    assert reason(full, None) == "no fixtures file, so there are no probes"
    assert reason(make_inventory(tool("pay", action=None)), make_fixtures()) == (
        "tool 'pay' has no action in the registry"
    )
    assert reason(make_inventory(tool("pay", resource_type=None)), make_fixtures()) == (
        "tool 'pay' has no resource_type in the registry"
    )
    no_subject = make_fixtures(probes={"resources": {"payment": "pay1"}})
    assert reason(full, no_subject) == "no probe subject for role 'analyst' (probes.subjects)"
    no_resource = make_fixtures(probes={"subjects": {"analyst": "alice"}})
    assert reason(full, no_resource) == "no probe resource for type 'payment' (probes.resources)"
    assert reason(full, make_fixtures()) is None
    # The first reason that applies wins.
    both = make_inventory(tool("pay", action=None, resource_type=None))
    assert reason(both, None) == "no fixtures file, so there are no probes"
    assert reason(both, make_fixtures()) == "tool 'pay' has no action in the registry"


def test_long_route_row_is_unchecked() -> None:
    names = [f"ag{i}" for i in range(70)]
    graph = make_graph(
        [node(name, entry=(i == 0), mode="on_behalf_of") for i, name in enumerate(names)],
        [edge(a, b) for a, b in pairwise(names)] + [uses(names[-1], "pay")],
        entries=[names[0]],
        roles=["analyst"],
    )
    (row,) = build([], graph).rows
    assert row.unchecked is not None
    assert row.unchecked.startswith("the questions for this case cannot be built: ")


# ---- max_queries ----


def budget_graph() -> AgentGraph:
    nodes = [node("a", entry=True, mode="agent")]
    edges = []
    for name in ("t-low", "t-crit", "t-med"):
        edges.append(uses("a", name))
    return make_graph(nodes, edges, entries=["a"], roles=["analyst"])


def test_max_queries_drops_low_risk_first() -> None:
    inventory = make_inventory(
        tool("t-low", risk="low"),
        tool("t-crit", risk="critical"),
        tool("t-med", risk="medium"),
    )
    plan = [case("C1", tool_id="t-crit", agent="a")]
    graph = budget_graph()
    # The case asks 2 distinct questions (agent mode); each row adds 2 distinct ones.
    fixtures = make_fixtures()
    result = build_queries(plan, graph, inventory, fixtures, policy(max_queries=6))
    assert len(result.cases) == 1
    assert result.cases[0].problems == ()
    by_tool = {row.tool: row for row in result.rows}
    assert [row.tool for row in result.rows] == ["t-low", "t-crit", "t-med"]
    # The case asks 2 questions and every row adds 2 new ones (their contexts differ):
    # critical (4 total) and medium (6) fit; low would make 8.
    assert by_tool["t-crit"].unchecked is None
    assert by_tool["t-med"].unchecked is None
    assert by_tool["t-low"].unchecked == "not asked: [policy] max_queries = 6 was reached"
    assert by_tool["t-low"].path_query is None and by_tool["t-low"].control is None
    assert result.warnings == (
        "1 escalation row was not asked because [policy] max_queries = 6 was reached; "
        "narrow the probes",
    )


def test_max_queries_plural_and_cases_are_kept() -> None:
    inventory = make_inventory(
        tool("t-low", risk="low"),
        tool("t-crit", risk="critical"),
        tool("t-med", risk="medium"),
    )
    plan = [case("C1", tool_id="t-crit", agent="a")]
    result = build_queries(plan, budget_graph(), inventory, make_fixtures(), policy(max_queries=1))
    assert len(result.cases) == 1
    assert result.cases[0].hops != ()
    assert all(row.unchecked is not None for row in result.rows)
    assert result.warnings == (
        "3 escalation rows were not asked because [policy] max_queries = 1 was reached; "
        "narrow the probes",
    )


def test_max_queries_not_reached_adds_no_warning() -> None:
    inventory = make_inventory(tool("t-low", risk="low"))
    result = build_queries([], budget_graph(), inventory, make_fixtures(), policy(max_queries=100))
    assert result.warnings == ()
    assert all(row.unchecked is None for row in result.rows)


# ---- review fixes ----


def inferred(a: str, b: str) -> GraphEdge:
    return GraphEdge(from_id=a, to_id=b, kind=EdgeKind.HANDOFF, provenance=Provenance.INFERRED)


@pytest.mark.parametrize(
    "edges",
    [
        # a cycle through the start
        [edge("s", "x"), edge("x", "y"), edge("y", "s"), edge("y", "z")],
        # equal-length ties between two routes
        [edge("s", "p"), edge("s", "q"), edge("p", "z"), edge("q", "z"), edge("z", "w")],
        # an inferred shortcut loses to a longer discovered route
        [inferred("s", "z"), edge("s", "p"), edge("p", "z"), edge("z", "w")],
        # two starts, with a dense middle
        [edge("s", "p"), edge("t", "p"), edge("p", "q"), edge("q", "p"), edge("q", "z")],
    ],
)
def test_single_pass_witnesses_equal_the_one_target_search(edges: list[GraphEdge]) -> None:
    names = sorted({e.from_id for e in edges} | {e.to_id for e in edges})
    entries = ["s", "t"] if any(e.from_id == "t" for e in edges) else ["s"]
    graph = make_graph(
        [node(name, entry=name in entries) for name in names], edges, entries=entries
    )
    index = index_graph(graph)
    found = _agent_witnesses(index, entries)
    assert found
    for name in names:
        if name in entries:
            assert name not in found
        else:
            assert found[name] == _agent_witness(index, entries, name)


def test_missing_fixtures_warn_once_with_case_names() -> None:
    plan = [case(f"C{i}", actor="zed", fixture="nope") for i in range(7)]
    plan.append(case("C7", actor="yan", fixture="pay1"))
    result = build(plan)
    assert result.warnings == (
        "actor 'zed' has no fixture; sending only its id and role (cases: C0, C1, C2, C3, C4, ...)",
        "actor 'yan' has no fixture; sending only its id and role (cases: C7)",
        "resource fixture 'nope' is not defined; sending its name as the id, "
        "with no properties (cases: C0, C1, C2, C3, C4, ...)",
    )


def test_missing_agent_fixture_warns_once_in_first_use_order() -> None:
    graph = make_graph(
        [
            node("sup", entry=True, mode="on_behalf_of"),
            node("w1", mode="agent"),
            node("w2", mode=None),
        ],
        [edge("sup", "w1"), edge("w1", "w2")],
    )
    plan = [case("C1", path=("sup", "w1", "w2")), case("C2", path=("sup", "w1"))]
    result = build(plan, graph, pol=policy(ask_every_hop=True))
    # sup only appears in act chains and as an agent resource; w1 and w2 are identities.
    assert result.warnings == (
        "agent 'w1' has no fixture; sending only its id",
        "agent 'w2' has no fixture; sending only its id",
    )
    assert build([case()], simple_graph("agent")).warnings == ()


def test_missing_agent_fixture_from_rows_comes_after_resource_warnings() -> None:
    graph = make_graph(
        [node("sup", entry=True, mode="user"), node("w", mode="agent")],
        [edge("sup", "w"), uses("w", "pay")],
        entries=["sup"],
        roles=["analyst"],
    )
    result = build([case(fixture="nope", agent="sup")], graph)
    assert result.warnings == (
        "resource fixture 'nope' is not defined; sending its name as the id, "
        "with no properties (cases: C1)",
        "agent 'w' has no fixture; sending only its id",
    )


def test_repeated_agent_in_route() -> None:
    graph = make_graph(
        [node("a", entry=True, mode="on_behalf_of"), node("b", mode="on_behalf_of")],
    )
    result = build([case(path=("a", "b", "a", "b"))], graph, pol=policy(ask_every_hop=True))
    (ask,) = result.cases
    assert ask.problems == () and len(ask.hops) == 5
    act = ask.tool_hop.queries[0].subject.properties["act"]
    ids = []
    while act is not None:
        ids.append(act["id"])
        act = act.get("act")
    assert ids == ["b", "a", "b", "a"]


def test_tool_not_in_inventory() -> None:
    result = build([case(tool_id="ghost")], inventory=make_inventory(tool("other")))
    (ask,) = result.cases
    assert ask.risk is Risk.UNKNOWN
    assert ask.problems == ()
    assert ask.tool_hop.queries[0].resource.type == "payment"  # from the fixture
    result = build([case(tool_id="ghost", fixture="nope")], inventory=make_inventory(tool("other")))
    assert result.cases[0].problems == (
        "resource fixture 'nope' has no type, and tool 'ghost' has no resource_type "
        "in the registry",
    )


def test_roles_with_empty_inventory_have_no_rows() -> None:
    result = build([], simple_graph("agent", roles=["analyst"]), inventory=make_inventory())
    assert result.rows == ()
    assert result.warnings == ()


def test_scale() -> None:
    # 200 agents in a fan (each calls up to 3 others), each holding 25 of the 5000 tools.
    names = [f"ag{i}" for i in range(200)]
    tools = [tool(f"tool{i}", risk=("low", "medium", "high")[i % 3]) for i in range(5000)]
    graph_edges = [edge(names[(i - 1) // 3], names[i]) for i in range(1, 200)]
    for i, one in enumerate(tools):
        graph_edges.append(uses(names[i % 200], one.id))
    graph = make_graph(
        [node(name, entry=(i == 0), mode="agent") for i, name in enumerate(names)],
        graph_edges,
        entries=[names[0]],
        roles=["analyst", "viewer", "admin"],
    )
    fixtures = make_fixtures(
        probes={
            "subjects": {"analyst": "alice", "admin": "bob"},
            "resources": {"payment": "pay1"},
        },
    )
    started = time.perf_counter()
    result = build_queries([], graph, make_inventory(*tools), fixtures, policy(max_queries=10**6))
    elapsed = time.perf_counter() - started
    print(f"scale test: {elapsed:.2f}s for {len(result.rows)} rows")
    assert len(result.rows) == 3 * 5000
    # Wall time is the point here (the build must stay fast), but 2.0 s flaked at 2.1 s
    # under parallel load. The normal time is about 1.3 s, so the limit is 10 s (over 5x):
    # it still catches a quadratic blow-up without failing on a busy machine.
    assert elapsed < 10.0
    # The budget skips the work for rows that no longer fit.
    started = time.perf_counter()
    small = build_queries([], graph, make_inventory(*tools), fixtures, policy(max_queries=100))
    assert time.perf_counter() - started < 10.0  # same loose limit as above
    asked = [row for row in small.rows if row.unchecked is None]
    assert 0 < len(asked) <= 50


# ---- roles_property ----


def test_custom_roles_property_in_cases_rows_and_fallback() -> None:
    pol = policy(roles_property="cerbos.roles")
    result = build([case()], row_graph(), pol=pol)
    (ask,) = result.cases
    assert ask.hops[0].queries[0].subject.properties == {
        "cerbos.roles": ["analyst", "viewer"],
        "dept": "fin",
    }
    analyst = result.rows[0]
    assert analyst.user_query is not None
    assert analyst.user_query.subject.properties["cerbos.roles"] == ["analyst", "viewer"]
    assert "roles" not in analyst.user_query.subject.properties
    other = build([case(actor="carol")], pol=pol)
    (carol,) = other.cases
    assert carol.hops[0].queries[0].subject.properties == {"cerbos.roles": ["analyst"]}


def roles_clash_fixtures() -> FixturesFile:
    return make_fixtures(
        subjects={
            "alice": {
                "roles": ["analyst"],
                "properties": {"cerbos.roles": ["x"]},
            }
        }
    )


def test_roles_property_clash_is_a_case_problem() -> None:
    result = build(
        [case()], fixtures=roles_clash_fixtures(), pol=policy(roles_property="cerbos.roles")
    )
    (ask,) = result.cases
    assert ask.hops == ()
    assert ask.problems == (
        "subject 'alice' in the fixtures sets properties.cerbos.roles, "
        "which lockwalk fills from 'roles' ([policy] roles_property)",
    )


def test_roles_property_clash_makes_the_row_unchecked() -> None:
    fixtures = roles_clash_fixtures()
    result = build([], row_graph(), fixtures=fixtures, pol=policy(roles_property="cerbos.roles"))
    analyst = result.rows[0]
    assert analyst.path_query is None and analyst.user_query is None
    assert analyst.unchecked == (
        "subject 'alice' in the fixtures sets properties.cerbos.roles, "
        "which lockwalk fills from 'roles' ([policy] roles_property)"
    )
