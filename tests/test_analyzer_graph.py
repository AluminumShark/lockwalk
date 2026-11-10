"""Tests for applying the agent graph in the planner and the analyzer."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from lockwalk import analyzer
from lockwalk.analyzer import analyze
from lockwalk.config import GateConfig
from lockwalk.graph.analysis import (
    evaluate_rules,
    graph_section,
    identity_summaries,
    identity_warnings,
    index_graph,
    name_list,
    plural,
    role_reachability,
)
from lockwalk.graph.build import build_graph
from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import (
    EMPTY_GRAPH,
    AgentGraph,
    CaseStatus,
    CoverageReport,
    DelegationMode,
    EdgeKind,
    GateViolation,
    GraphEdge,
    GraphFragment,
    GraphNode,
    GraphSection,
    Inventory,
    InventoryTool,
    NodeKind,
    Provenance,
    ReachStatus,
    Risk,
    RuleResult,
    SourceRef,
    SourceResult,
    ToolDescriptor,
)
from lockwalk.planner import plan_cases
from lockwalk.registry import Registry
from lockwalk.spec_loader import SpecFile

REG = "registry:registry.yaml"
PY = "python:app:root"
SUPERVISOR_PATH = ["supervisor", "research-agent"]
DISCOVERY_MESSAGE = "is not declared in the registry and no discovery source reported it"
OWN_IDENTITY = "calls tools with its own identity; the IAM will not see the user"
NO_MODE = "has no declared delegation_mode; the IAM may not see the user"

AGENTS: tuple[dict[str, Any], ...] = (
    {
        "id": "supervisor",
        "entry": True,
        "roles": ["analyst", "trader"],
        "calls": ["research-agent"],
        "delegation_mode": "user",
    },
    {
        "id": "desk",
        "entry": True,
        "roles": ["trader"],
        "calls": ["trade-agent"],
        "delegation_mode": "user",
    },
    {"id": "research-agent", "calls": [], "delegation_mode": "on_behalf_of"},
    {"id": "trade-agent", "calls": [], "delegation_mode": "on_behalf_of"},
)
TOOLS: tuple[dict[str, Any], ...] = (
    {
        "id": "get_stock_price",
        "action": "market:read",
        "risk": "low",
        "supported_agents": ["research-agent"],
    },
    {
        "id": "read_portfolio",
        "action": "portfolio:read",
        "risk": "high",
        "supported_agents": ["research-agent"],
    },
    {
        "id": "execute_trade",
        "action": "trade:execute",
        "risk": "critical",
        "supported_agents": ["trade-agent"],
    },
)


def registry_data(
    *,
    drop_calls: Sequence[str] = (),
    modes: Mapping[str, str | None] | None = None,
    extra_agents: Sequence[dict[str, Any]] = (),
    roles: Sequence[str] | None = ("analyst", "trader"),
) -> dict[str, Any]:
    """The multi-agent registry. Every agent declares its calls unless listed in drop_calls.

    modes replaces delegation modes; None removes one. With roles=None there is no
    top-level roles list, and the agents list no roles either.
    """
    agents: list[dict[str, Any]] = []
    for declared in AGENTS:
        agent = dict(declared)
        if agent["id"] in drop_calls:
            agent.pop("calls")
        if modes is not None and agent["id"] in modes:
            agent["delegation_mode"] = modes[agent["id"]]
        if roles is None:
            agent.pop("roles", None)
        agents.append(agent)
    data: dict[str, Any] = {
        "schema_version": "1",
        "agents": [*agents, *extra_agents],
        "tools": list(TOOLS),
    }
    if roles is not None:
        data["roles"] = list(roles)
    return data


def case(
    case_id: str,
    tool: str,
    action: str,
    expect: str,
    *,
    role: str = "analyst",
    path: Sequence[str] | None = None,
    agent: str | None = None,
) -> dict[str, Any]:
    route: dict[str, Any] = {"agent": agent} if agent is not None else {"path": list(path or ())}
    return {
        "id": case_id,
        "actor": "alice",
        "role": role,
        **route,
        "tool": tool,
        "action": action,
        "resource_fixture": "fixture",
        "expect": expect,
    }


def price(case_id: str = "CASE-001", **fields: Any) -> dict[str, Any]:
    return case(case_id, "get_stock_price", "market:read", "allow", path=SUPERVISOR_PATH) | fields


def portfolio(case_id: str, expect: str, role: str = "analyst") -> dict[str, Any]:
    return case(
        case_id, "read_portfolio", "portfolio:read", expect, role=role, path=SUPERVISOR_PATH
    )


def trade(
    case_id: str, role: str = "trader", path: Sequence[str] = ("desk", "trade-agent")
) -> dict[str, Any]:
    return case(case_id, "execute_trade", "trade:execute", "deny", role=role, path=path)


BASE_CASES = (
    price(),
    portfolio("CASE-002", "allow"),
    portfolio("CASE-003", "deny", role="trader"),
    trade("CASE-004"),
)
BASE_RULES = ({"id": "RULE-001", "role": "analyst", "tool": "execute_trade", "reason": "no"},)


def build(data: Mapping[str, Any] | None, *sources: SourceResult) -> tuple[Inventory, AgentGraph]:
    registry = Registry.model_validate(data) if data is not None else None
    inventory = merge_inventory(list(sources), registry=registry, registry_label=REG)
    return inventory, build_graph(registry, inventory, registry_label=REG)


def make_spec(
    cases: Sequence[Mapping[str, Any]], rules: Sequence[Mapping[str, Any]] = ()
) -> SpecFile:
    return SpecFile.model_validate(
        {
            "schema_version": "1",
            "scenario_suite": "multi-agent-v1",
            "cases": list(cases),
            "never_reaches": list(rules),
        }
    )


def run(
    data: Mapping[str, Any] | None = None,
    *,
    cases: Sequence[Mapping[str, Any]] = BASE_CASES,
    rules: Sequence[Mapping[str, Any]] = BASE_RULES,
    sources: Sequence[SourceResult] = (),
    gate: GateConfig | None = None,
    graph_update: Mapping[str, Any] | None = None,
) -> CoverageReport:
    inventory, graph = build(registry_data() if data is None else data, *sources)
    if graph_update is not None:
        graph = graph.model_copy(update=dict(graph_update))
    spec = make_spec(cases, rules)
    plan = plan_cases(spec, inventory, graph)
    return analyze(inventory, spec, plan, gate or GateConfig(), graph)


def fragment_source(*nodes: GraphNode, edges: Sequence[GraphEdge] = ()) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="python", label=PY),
        ok=True,
        graph=GraphFragment(nodes=nodes, edges=tuple(edges)),
    )


def tools_source(*names: str, agents: Sequence[str] = ("trade-agent",)) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="json", label="json:tools.json"),
        ok=True,
        tools=tuple(ToolDescriptor(name=name) for name in names),
        agents=tuple(agents),
    )


def unavailable_partner(agents: Sequence[str] = ()) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="mcp", label="mcp:partner"),
        ok=False,
        error="connection refused",
        optional=True,
        agents=tuple(agents),
    )


def handoff(from_id: str, to_id: str) -> GraphEdge:
    return GraphEdge(
        from_id=from_id, to_id=to_id, kind=EdgeKind.HANDOFF, provenance=Provenance.DISCOVERED
    )


def role_violation(role: str, tool: str, risk: Risk) -> GateViolation:
    return GateViolation(rule="fail_on_unspecified_role_risk", role=role, tool=tool, risk=risk)


def rule_violation(rule_id: str, result: RuleResult) -> GateViolation:
    return GateViolation(rule="never_reaches", rule_id=rule_id, result=result)


def scale_inputs(agents: int, tools: int, roles: int) -> tuple[AgentGraph, Inventory]:
    """A large graph: one entry agent per role, the other agents share the tools.

    Entry i calls worker j unless (i + j) % 3 == 0, so roles reach different workers.
    Workers cycle through the delegation modes, so both identity texts and the modes
    that give no warning all occur. Every tool is high risk.
    """
    role_names = tuple(f"role-{i}" for i in range(roles))
    entries = [
        GraphNode(id=f"entry-{i}", entry=True, roles=(role,), delegation_mode="user")
        for i, role in enumerate(role_names)
    ]
    cycle: tuple[DelegationMode | None, ...] = (None, "agent", "user", "on_behalf_of")
    workers = [
        GraphNode(id=f"agent-{j:03d}", delegation_mode=cycle[j % len(cycle)])
        for j in range(agents - roles)
    ]
    tool_ids = [f"tool-{k:04d}" for k in range(tools)]
    edges = [
        GraphEdge(
            from_id=entry.id, to_id=worker.id, kind=EdgeKind.CALLS, provenance=Provenance.DECLARED
        )
        for i, entry in enumerate(entries)
        for j, worker in enumerate(workers)
        if (i + j) % 3 != 0
    ]
    edges.extend(
        GraphEdge(
            from_id=workers[k % len(workers)].id,
            to_id=tool_id,
            kind=EdgeKind.USES_TOOL,
            provenance=Provenance.DECLARED,
        )
        for k, tool_id in enumerate(tool_ids)
    )
    graph = AgentGraph(
        nodes=(*entries, *workers),
        edges=tuple(edges),
        entry_agents=tuple(entry.id for entry in entries),
        entry_inferred=False,
        roles=role_names,
        drift=None,
    )
    inventory = Inventory(
        agents=tuple(node.id for node in graph.nodes),
        tools=tuple(
            InventoryTool(
                id=tool_id,
                action=None,
                risk=Risk.HIGH,
                resource_type=None,
                supported_agents=(),
                sources=(),
                description=None,
                hints={},
            )
            for tool_id in tool_ids
        ),
        sources=(),
        drift=None,
        errors=(),
        warnings=(),
    )
    return graph, inventory


# ---- planner ----


def test_a_graph_node_is_a_known_agent():
    inventory, graph = build(
        registry_data(), fragment_source(GraphNode(id="supervisor"), GraphNode(id="helper"))
    )
    spec = make_spec([price(path=["supervisor", "helper"])])
    [planned] = plan_cases(spec, inventory, graph)
    assert planned.status is CaseStatus.UNTESTED
    assert planned.problems == ()
    # Without the graph the same case refers to an agent only discovery knows.
    [without] = plan_cases(spec, inventory)
    assert without.problems == ("agent 'helper' is not declared in the registry",)


def test_unknown_agent_mentions_discovery_when_the_graph_has_discovered_only_nodes():
    inventory, graph = build(registry_data(), fragment_source(GraphNode(id="helper")))
    [planned] = plan_cases(make_spec([price(path=["supervisor", "ghost"])]), inventory, graph)
    assert planned.status is CaseStatus.ERROR
    assert planned.problems == (f"agent 'ghost' {DISCOVERY_MESSAGE}",)


def test_unknown_agent_mentions_discovery_when_the_only_extra_node_is_an_mcp_server():
    inventory, graph = build(registry_data(), unavailable_partner())
    extra = [node for node in graph.nodes if node.id not in inventory.agents]
    assert [(node.id, node.kind) for node in extra] == [("mcp:partner", NodeKind.MCP_SERVER)]
    ghost = case("CASE-001", "get_stock_price", "market:read", "allow", agent="ghost")
    [planned] = plan_cases(make_spec([ghost]), inventory, graph)
    assert planned.problems == (f"agent 'ghost' {DISCOVERY_MESSAGE}",)


def test_unknown_agent_keeps_the_single_agent_message_without_discovered_only_nodes():
    inventory, graph = build(registry_data())
    ghost = case("CASE-001", "get_stock_price", "market:read", "allow", agent="ghost")
    [planned] = plan_cases(make_spec([ghost]), inventory, graph)
    assert planned.problems == ("agent 'ghost' is not declared in the registry",)


def test_without_a_registry_discovered_agents_are_known():
    inventory, graph = build(None, tools_source("get_stock_price", agents=["bot"]))
    spec = make_spec(
        [
            case("C1", "get_stock_price", "market:read", "allow", agent="bot"),
            case("C2", "get_stock_price", "market:read", "allow", agent="ghost"),
        ]
    )
    known, unknown = plan_cases(spec, inventory, graph)
    assert known.status is CaseStatus.UNTESTED
    assert unknown.problems == (f"agent 'ghost' {DISCOVERY_MESSAGE}",)


def test_a_role_outside_the_registry_roles_list_is_an_error():
    inventory, graph = build(registry_data())
    spec = make_spec([price(role="auditor"), price("CASE-002", role="auditor", path=["ghost"])])
    role_only, both = plan_cases(spec, inventory, graph)
    assert role_only.status is CaseStatus.ERROR
    assert role_only.problems == ("role 'auditor' is not in the registry roles list",)
    assert both.problems == (
        "agent 'ghost' is not declared in the registry",
        "role 'auditor' is not in the registry roles list",
    )


def test_roles_are_not_checked_without_a_roles_list_or_without_a_graph():
    inventory, graph = build(registry_data(roles=None))
    spec = make_spec([price(role="auditor")])
    assert plan_cases(spec, inventory, graph)[0].status is CaseStatus.UNTESTED
    inventory, graph = build(registry_data())
    assert plan_cases(spec, inventory)[0].status is CaseStatus.UNTESTED


def test_role_error_reaches_the_report_and_exits_2():
    report = run(cases=[*BASE_CASES, price("CASE-009", role="auditor")])
    assert report.exit_code == 2
    assert report.errors == ("CASE-009: role 'auditor' is not in the registry roles list",)


# ---- analyzer: no graph ----


def test_a_spec_with_no_graph_gives_the_results_it_gave_before_graphs_existed(
    finance_registry, finance_cases
):
    source = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:finance-tools"),
        ok=True,
        tools=tuple(
            ToolDescriptor(name=name)
            for name in ("get_stock_price", "read_portfolio", "execute_trade", "delete_portfolio")
        ),
    )
    inventory = merge_inventory(
        [source], registry=Registry.model_validate(finance_registry), registry_label=REG
    )
    ghost = {**finance_cases[0], "id": "CASE-009", "agent": "ghost"}
    # A never_reaches rule needs the graph, so without one it is ignored as before.
    spec = make_spec([*finance_cases, ghost], rules=BASE_RULES)
    report = analyze(inventory, spec, plan_cases(spec, inventory), GateConfig())
    assert report.agent_graph == GraphSection()
    assert report.rules == ()
    assert report.reachability is None
    assert report.errors == ("CASE-009: agent 'ghost' is not declared in the registry",)
    assert report.exit_code == 2
    assert [violation.rule for violation in report.gate.violations] == [
        "fail_on_unspecified_risk",
        "require_deny_case_for_risk",
    ]


def test_a_config_without_graph_rules_only_gains_graph_warnings_when_given_a_graph(
    finance_registry, finance_cases
):
    source = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:finance-tools"),
        ok=True,
        tools=tuple(
            ToolDescriptor(name=name)
            for name in ("get_stock_price", "read_portfolio", "execute_trade")
        ),
    )
    inventory, graph = build(finance_registry, source)
    spec = make_spec(finance_cases)
    without = analyze(inventory, spec, plan_cases(spec, inventory), GateConfig())
    report = analyze(inventory, spec, plan_cases(spec, inventory, graph), GateConfig(), graph)
    assert report.cases == without.cases
    assert report.inventory == without.inventory
    assert report.gate == without.gate
    assert report.errors == without.errors == ()
    assert report.exit_code == without.exit_code == 0
    assert report.warnings == (*without.warnings, *graph.warnings)
    assert report.reachability is None
    assert report.agent_graph == graph_section(graph)


# ---- analyzer: with a graph ----


def test_a_fully_covered_multi_agent_spec_passes():
    report = run()
    assert report.exit_code == 0
    assert report.gate.passed
    assert report.errors == ()
    assert report.warnings == ()
    assert [(row.id, row.result) for row in report.rules] == [("RULE-001", RuleResult.PASS)]
    assert report.reachability is not None
    assert [(row.role, row.tool, row.covered_by) for row in report.reachability] == [
        ("analyst", "get_stock_price", ("CASE-001",)),
        ("analyst", "read_portfolio", ("CASE-002",)),
        ("trader", "get_stock_price", ()),  # low risk: no violation and no warning
        ("trader", "read_portfolio", ("CASE-003",)),
        ("trader", "execute_trade", ("CASE-004",)),
    ]


def test_the_report_carries_the_graph_section_rules_and_reachability():
    inventory, graph = build(registry_data())
    spec = make_spec(BASE_CASES, BASE_RULES)
    plan = plan_cases(spec, inventory, graph)
    report = analyze(inventory, spec, plan, GateConfig(), graph)
    rules = evaluate_rules(graph, spec.never_reaches, inventory)
    assert report.agent_graph == graph_section(graph)
    assert report.rules == rules
    assert report.reachability == role_reachability(graph, inventory, plan, rules)


def test_a_failing_rule_is_a_gate_violation():
    report = run(rules=[*BASE_RULES, {"id": "RULE-002", "role": "trader", "tool": "execute_trade"}])
    assert report.rules[1].result is RuleResult.FAIL
    assert report.gate.violations == (rule_violation("RULE-002", RuleResult.FAIL),)
    assert report.exit_code == 1
    assert report.errors == ()


def test_a_failing_agent_rule_is_a_gate_violation():
    rule = {"id": "RULE-002", "agent": "supervisor", "target_agent": "research-agent"}
    report = run(rules=[rule])
    assert report.gate.violations == (rule_violation("RULE-002", RuleResult.FAIL),)
    assert report.exit_code == 1


def test_an_inconclusive_rule_is_a_violation_by_default():
    report = run(registry_data(drop_calls=["research-agent"]))
    [row] = report.rules
    assert row.result is RuleResult.INCONCLUSIVE
    assert row.opaque_reached == ("research-agent",)
    assert report.gate.violations == (rule_violation("RULE-001", RuleResult.INCONCLUSIVE),)
    assert report.exit_code == 1


def test_an_inconclusive_rule_passes_when_the_gate_allows_it():
    gate = GateConfig(fail_on_never_reaches_inconclusive=False)
    report = run(registry_data(drop_calls=["research-agent"]), gate=gate)
    assert report.rules[0].result is RuleResult.INCONCLUSIVE
    assert report.gate.violations == ()
    assert report.exit_code == 0
    assert report.errors == ()


def test_a_rule_error_gives_exit_2_even_though_no_case_is_an_error():
    rules = [*BASE_RULES, {"id": "RULE-002", "agent": "ghost", "tool": "ghost_tool"}]
    report = run(rules=rules)
    assert {case.status for case in report.cases} == {CaseStatus.UNTESTED}
    assert report.rules[1].result is RuleResult.ERROR
    assert report.gate.passed  # an ERROR rule is untrusted, not a violation
    assert report.errors == (
        "RULE-002: agent 'ghost' is not in the agent graph",
        "RULE-002: tool 'ghost_tool' is not in the inventory",
    )
    assert report.exit_code == 2


def test_a_rule_naming_the_same_unknown_agent_twice_reports_it_once():
    report = run(rules=[{"id": "RULE-002", "agent": "ghost", "target_agent": "ghost"}])
    assert (report.exit_code, report.errors) == (
        2,
        ("RULE-002: agent 'ghost' is not in the agent graph",),
    )


def test_graph_errors_give_exit_2_even_though_no_case_is_an_error():
    source = fragment_source(GraphNode(id="supervisor"), edges=[handoff("supervisor", "phantom")])
    inventory, graph = build(registry_data(), source)
    assert graph.errors == ("edge supervisor -> phantom refers to an unknown agent 'phantom'",)
    spec = make_spec(BASE_CASES, BASE_RULES)
    report = analyze(inventory, spec, plan_cases(spec, inventory, graph), GateConfig(), graph)
    assert {case.status for case in report.cases} == {CaseStatus.UNTESTED}
    assert all(row.result is not RuleResult.ERROR for row in report.rules)
    assert report.errors == graph.errors
    assert report.exit_code == 2


def test_graph_errors_and_violations_together_exit_2():
    report = run(
        rules=[{"id": "RULE-002", "role": "trader", "tool": "execute_trade"}],
        graph_update={"errors": ("the graph is broken",)},
    )
    assert not report.gate.passed
    assert report.errors == ("the graph is broken",)
    assert report.exit_code == 2


def test_errors_come_in_order_spec_then_graph_then_rules():
    missing = SourceResult(
        source=SourceRef(kind="json", label="json:missing.json"),
        ok=False,
        error="file not found: missing.json",
    )
    dangling = fragment_source(GraphNode(id="supervisor"), edges=[handoff("supervisor", "phantom")])
    report = run(
        cases=[*BASE_CASES, price("CASE-009", role="auditor")],
        rules=[*BASE_RULES, {"id": "RULE-002", "role": "analyst", "tool": "ghost_tool"}],
        sources=[missing, dangling],
    )
    assert (report.exit_code, report.errors) == (
        2,
        (
            "json:missing.json: file not found: missing.json",
            "CASE-009: role 'auditor' is not in the registry roles list",
            "edge supervisor -> phantom refers to an unknown agent 'phantom'",
            "RULE-002: tool 'ghost_tool' is not in the inventory",
        ),
    )


def test_an_uncovered_critical_role_tool_pair_is_a_violation():
    cases = [*BASE_CASES[:3], trade("CASE-004", role="analyst", path=["supervisor"])]
    report = run(cases=cases)
    assert report.gate.violations == (role_violation("trader", "execute_trade", Risk.CRITICAL),)
    assert report.exit_code == 1
    assert report.warnings == ()


def test_an_uncovered_high_role_tool_pair_is_only_a_warning():
    cases = [*BASE_CASES[:2], portfolio("CASE-003", "deny"), BASE_CASES[3]]
    report = run(cases=cases)
    assert report.gate.violations == ()
    assert report.warnings == (
        "role 'trader' can reach 1 high-risk tool that no case or rule covers: "
        "read_portfolio (risk=high)",
    )
    assert report.exit_code == 0


def test_the_role_risk_gate_list_decides_violation_or_warning():
    cases = [
        *BASE_CASES[:2],
        portfolio("CASE-003", "deny"),
        trade("CASE-004", role="analyst", path=["supervisor"]),
    ]
    report = run(cases=cases, gate=GateConfig(fail_on_unspecified_role_risk=(Risk.HIGH,)))
    assert report.gate.violations == (role_violation("trader", "read_portfolio", Risk.HIGH),)
    assert report.warnings == (
        "role 'trader' can reach 1 high-risk tool that no case or rule covers: "
        "execute_trade (risk=critical)",
    )
    assert report.exit_code == 1


def test_an_uncovered_unknown_risk_tool_is_a_role_violation():
    report = run(sources=[tools_source("wire_money")])
    assert report.gate.violations == (
        GateViolation(rule="fail_on_unspecified_risk", tool="wire_money", risk=Risk.UNKNOWN),
        GateViolation(rule="require_deny_case_for_risk", tool="wire_money", risk=Risk.UNKNOWN),
        role_violation("trader", "wire_money", Risk.UNKNOWN),
    )
    assert report.exit_code == 1


def test_role_gap_warnings_are_one_per_role_and_name_at_most_five_tools():
    names = [f"tool-{k}" for k in range(1, 8)]
    quiet = GateConfig(
        fail_on_unspecified_risk=(), require_deny_case_for_risk=(), fail_on_unspecified_role_risk=()
    )
    cases = [*BASE_CASES[:2], portfolio("CASE-003", "deny"), BASE_CASES[3]]
    report = run(cases=cases, sources=[tools_source(*names)], gate=quiet)
    gaps = [line for line in report.warnings if line.startswith("role ")]
    assert gaps == [
        "role 'trader' can reach 8 high-risk tools that no case or rule covers: "
        "read_portfolio (risk=high), tool-1 (risk=unknown), tool-2 (risk=unknown), "
        "tool-3 (risk=unknown), tool-4 (risk=unknown), ..."
    ]
    # Every pair stays in the JSON rows; only the terminal summary is shortened.
    assert report.reachability is not None
    trader_tools = [row.tool for row in report.reachability if row.role == "trader"]
    assert trader_tools == ["get_stock_price", "read_portfolio", "execute_trade", *names]


def test_a_rule_covers_a_role_tool_pair():
    cases = [*BASE_CASES[:3], trade("CASE-004", role="analyst", path=["supervisor"])]
    rules = [*BASE_RULES, {"id": "RULE-002", "role": "trader", "tool": "execute_trade"}]
    report = run(cases=cases, rules=rules)
    # The rule fails, but it covers the pair, so there is no role-risk violation.
    assert report.gate.violations == (rule_violation("RULE-002", RuleResult.FAIL),)


def test_inconclusive_role_tool_pairs_are_not_gaps():
    report = run(registry_data(drop_calls=["research-agent"]), rules=())
    assert report.reachability is not None
    [row] = [
        row for row in report.reachability if row.tool == "execute_trade" and row.role == "analyst"
    ]
    assert row.status is ReachStatus.INCONCLUSIVE
    assert row.covered_by == ()
    assert report.gate.violations == ()
    assert report.warnings == ()
    assert report.exit_code == 0


def test_an_allow_path_that_does_not_match_the_graph_only_warns():
    stray = price("CASE-005", path=["supervisor", "trade-agent"])
    report = run(cases=[*BASE_CASES, stray])
    assert report.cases[-1].status is CaseStatus.UNTESTED
    assert report.warnings == (
        "CASE-005: path step 'supervisor' -> 'trade-agent' is not an edge in the agent graph",
        "CASE-005: agent 'trade-agent' has no known way to use tool 'get_stock_price'",
    )
    assert report.exit_code == 0


def test_warnings_come_in_order_graph_identity_path_then_role_gaps():
    kiosk = {"id": "kiosk", "entry": True, "calls": []}
    data = registry_data(modes={"research-agent": "agent"}, extra_agents=[kiosk])
    cases = [
        *BASE_CASES[:2],
        portfolio("CASE-003", "deny"),
        BASE_CASES[3],
        price("CASE-005", path=["supervisor", "trade-agent"]),
    ]
    report = run(data, cases=cases)
    assert report.warnings == (
        "entry agent 'kiosk' lists no roles, so every role can use it",
        f"agent 'research-agent' {OWN_IDENTITY}. "
        "Through it, roles analyst, trader can reach 1 high-risk tool: read_portfolio",
        "CASE-005: path step 'supervisor' -> 'trade-agent' is not an edge in the agent graph",
        "CASE-005: agent 'trade-agent' has no known way to use tool 'get_stock_price'",
        "role 'trader' can reach 1 high-risk tool that no case or rule covers: "
        "read_portfolio (risk=high)",
    )


def test_identity_warnings_are_one_per_caller_agent():
    data = registry_data(modes={"research-agent": "agent", "trade-agent": None})
    report = run(data)
    assert report.warnings == (
        f"agent 'research-agent' {OWN_IDENTITY}. "
        "Through it, roles analyst, trader can reach 1 high-risk tool: read_portfolio",
        f"agent 'trade-agent' {NO_MODE}. "
        "Through it, role trader can reach 1 high-risk tool: execute_trade",
    )


def test_identity_warnings_name_at_most_five_tools():
    names = [f"tool-{k}" for k in range(1, 8)]
    report = run(registry_data(modes={"trade-agent": "agent"}), sources=[tools_source(*names)])
    identity = [line for line in report.warnings if line.startswith("agent ")]
    assert identity == [
        f"agent 'trade-agent' {OWN_IDENTITY}. Through it, role trader can reach "
        "8 high-risk tools: execute_trade, tool-1, tool-2, tool-3, tool-4, ..."
    ]


def test_identity_summaries_match_the_per_pair_identity_warnings():
    # Both read one rule in graph.analysis; this pins the summary to the per-pair lines.
    graph, inventory = scale_inputs(agents=15, tools=120, roles=3)
    server = GraphNode(id="mcp:shared", kind=NodeKind.MCP_SERVER)
    extra = [
        GraphEdge(
            from_id="agent-000",
            to_id="mcp:shared",
            kind=EdgeKind.REMOTE,
            provenance=Provenance.DECLARED,
        ),
        *(
            GraphEdge(
                from_id="mcp:shared",
                to_id=tool.id,
                kind=EdgeKind.USES_TOOL,
                provenance=Provenance.DECLARED,
            )
            for tool in inventory.tools[:9]
        ),
    ]
    graph = graph.model_copy(
        update={"nodes": (*graph.nodes, server), "edges": (*graph.edges, *extra)}
    )
    rows = role_reachability(graph, inventory, (), ())
    assert rows is not None
    pattern = re.compile(
        r"role '([^']+)' can reach tool '([^']+)' \(risk=\w+\) "
        r"through agent '([^']+)', (which|whose)"
    )
    exposed: dict[str, tuple[dict[str, None], dict[str, None], str]] = {}
    for line in identity_warnings(graph, inventory, rows):
        match = pattern.match(line)
        assert match is not None, line
        role, tool, agent, kind = match.groups()
        roles, tools, _ = exposed.setdefault(agent, ({}, {}, kind))
        roles[role] = None
        tools[tool] = None
    expected = tuple(
        f"agent {agent!r} {OWN_IDENTITY if kind == 'which' else NO_MODE}. "
        f"Through it, {'role' if len(roles) == 1 else 'roles'} {', '.join(roles)} "
        f"can reach {len(tools)} high-risk {'tool' if len(tools) == 1 else 'tools'}: "
        f"{name_list(list(tools))}"
        for agent, (roles, tools, kind) in exposed.items()
    )
    assert any(len(tools) > 5 for _, tools, _ in exposed.values())
    assert any(kind == "whose" for _, _, kind in exposed.values())
    assert identity_summaries(graph, rows) == expected
    assert identity_summaries(graph, rows, index=index_graph(graph)) == expected


def test_identity_summaries_refuse_an_index_of_another_graph():
    graph, inventory = scale_inputs(agents=6, tools=8, roles=2)
    other = graph.model_copy()
    rows = role_reachability(graph, inventory, (), ())
    assert rows is not None
    with pytest.raises(ValueError, match="different graph"):
        identity_summaries(graph, rows, index=index_graph(other))


def test_warnings_stay_few_at_scale():
    agents, tools, roles = 500, 2000, 10
    graph, inventory = scale_inputs(agents=agents, tools=tools, roles=roles)
    spec = make_spec([])
    report = analyze(inventory, spec, plan_cases(spec, inventory, graph), GateConfig(), graph)
    assert report.reachability is not None
    # One line per (role, tool, agent) would be thousands of lines.
    assert len(identity_warnings(graph, inventory, report.reachability)) > 5_000
    assert len(report.warnings) <= agents + roles + 5
    # The gate still lists every high-risk tool without a deny case, one by one.
    assert len(report.gate.violations) == tools


def test_name_list_shows_at_most_five_names():
    assert name_list([]) == ""
    assert name_list(["a", "b", "c", "d", "e"]) == "a, b, c, d, e"
    assert name_list(["a", "b", "c", "d", "e", "f"]) == "a, b, c, d, e, ..."


def test_plural_adds_an_s_unless_there_is_exactly_one():
    assert (plural("tool", 0), plural("tool", 1), plural("role", 2)) == ("tools", "tool", "roles")


def test_path_and_identity_checks_share_one_graph_index(monkeypatch: pytest.MonkeyPatch):
    seen: list[object] = []
    real_path = analyzer.path_warnings
    real_identity = analyzer.identity_summaries

    def path_spy(graph, planned, *, index=None):
        seen.append(index)
        return real_path(graph, planned, index=index)

    def identity_spy(graph, rows, *, index=None):
        seen.append(index)
        return real_identity(graph, rows, index=index)

    monkeypatch.setattr(analyzer, "path_warnings", path_spy)
    monkeypatch.setattr(analyzer, "identity_summaries", identity_spy)
    run()
    assert len(seen) == len(BASE_CASES) + 1
    assert seen[0] is not None
    assert all(index is seen[0] for index in seen)


# ---- end to end: odd inputs ----


def test_an_unavailable_optional_source_with_rules_fails_the_gate_but_is_trusted():
    report = run(sources=[unavailable_partner(agents=["research-agent"])])
    assert (report.exit_code, report.errors) == (1, ())
    assert report.gate.violations == (rule_violation("RULE-001", RuleResult.INCONCLUSIVE),)
    assert report.rules[0].opaque_reached == ("mcp:partner",)


def test_a_role_rule_without_registry_roles_exits_2():
    report = run(registry_data(roles=None))
    assert (report.exit_code, report.errors) == (
        2,
        ("RULE-001: rule uses role 'analyst' but the registry has no top-level roles list",),
    )
    assert report.reachability is None


def test_an_empty_graph_with_rules_exits_2():
    inventory, graph = build(None)
    assert graph == EMPTY_GRAPH
    rules = [*BASE_RULES, {"id": "RULE-002", "agent": "supervisor", "target_agent": "desk"}]
    spec = make_spec([], rules)
    report = analyze(inventory, spec, plan_cases(spec, inventory, graph), GateConfig(), graph)
    assert (report.exit_code, report.errors) == (
        2,
        (
            "RULE-001: rule uses role 'analyst' but the registry has no top-level roles list",
            "RULE-001: tool 'execute_trade' is not in the inventory",
            "RULE-002: agent 'supervisor' is not in the agent graph",
            "RULE-002: agent 'desk' is not in the agent graph",
        ),
    )
    assert report.warnings == ()


def test_errors_and_exit_code_two_agree_in_every_graph_scenario():
    reports = [
        run(),
        run(registry_data(drop_calls=["research-agent"])),
        run(rules=[{"id": "RULE-002", "role": "auditor", "tool": "execute_trade"}]),
        run(graph_update={"errors": ("broken",)}),
        run(cases=[*BASE_CASES, price("CASE-009", role="auditor")]),
        run(cases=[*BASE_CASES[:3], trade("CASE-004", role="analyst", path=["supervisor"])]),
        run(registry_data(roles=None), rules=()),
        run(sources=[unavailable_partner(agents=["research-agent"])]),
    ]
    assert sorted({report.exit_code for report in reports}) == [0, 1, 2]
    for report in reports:
        assert bool(report.errors) == (report.exit_code == 2)
