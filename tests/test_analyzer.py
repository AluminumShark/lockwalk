from lockwalk.config import GateConfig
from lockwalk.models import CaseStatus, GateViolation, Risk, ToolCoverage

DELETE_DENY_CASE = {
    "id": "CASE-005",
    "actor": "alice",
    "role": "analyst",
    "agent": "finance-agent",
    "tool": "delete_portfolio",
    "action": "portfolio:delete",
    "resource_fixture": "bob-portfolio",
    "expect": "deny",
}


def test_complete_spec_passes(make_report):
    report = make_report()
    assert report.exit_code == 0
    assert report.gate.passed
    assert report.mode == "static"
    assert report.scenario_suite == "finance-demo-v1"
    assert report.metrics.registered_tools == 3
    assert report.metrics.specified_cases == 4
    assert report.metrics.executed_cases == 0
    assert report.metrics.execution_coverage == 0.0
    assert report.metrics.verified_pass_rate == 0.0
    assert report.metrics.cases_by_status[CaseStatus.UNTESTED.value] == 4
    assert report.metrics.cases_by_status[CaseStatus.PASS.value] == 0
    assert report.metrics.tools_without_spec == 0
    assert {case.status for case in report.cases} == {CaseStatus.UNTESTED}
    assert report.errors == ()
    assert report.warnings == ()
    assert report.gate.violations == ()


def test_discovered_tool_without_spec_fails_the_gate(make_report):
    report = make_report(extra_tools=["delete_portfolio"])
    assert report.exit_code == 1
    assert report.registered_tools_without_spec == ("delete_portfolio",)
    assert report.high_risk_tools_without_deny_case == ("delete_portfolio",)
    assert report.gate.violations == (
        GateViolation(rule="fail_on_unspecified_risk", tool="delete_portfolio", risk=Risk.UNKNOWN),
        GateViolation(
            rule="require_deny_case_for_risk", tool="delete_portfolio", risk=Risk.UNKNOWN
        ),
    )
    row = next(tool for tool in report.inventory.tools if tool.id == "delete_portfolio")
    assert row.coverage is ToolCoverage.UNSPECIFIED
    assert row.case_ids == ()


def test_adding_a_deny_case_fixes_it(make_report):
    report = make_report(extra_tools=["delete_portfolio"], extra_cases=[DELETE_DENY_CASE])
    assert report.exit_code == 0
    assert report.registered_tools_without_spec == ()
    assert report.warnings[-1] == (
        "CASE-005: action 'portfolio:delete' was not verified because tool "
        "'delete_portfolio' has no registered action"
    )


def test_no_cases_gives_na_metrics(make_report):
    report = make_report(cases=[])
    assert report.metrics.specified_cases == 0
    assert report.metrics.execution_coverage is None
    assert report.metrics.verified_pass_rate is None
    assert report.metrics.tools_without_spec == 3


def test_case_error_means_exit_2_even_if_the_gate_passes(make_report):
    ghost = {**DELETE_DENY_CASE, "id": "CASE-099", "tool": "ghost_tool"}
    report = make_report(extra_cases=[ghost])
    assert report.gate.passed
    assert report.exit_code == 2
    assert "CASE-099: tool 'ghost_tool' is not in the inventory" in report.errors


def test_errors_and_violations_together_exit_2(make_report):
    report = make_report(extra_tools=["delete_portfolio"], failed_source="json:missing.json")
    assert not report.gate.passed
    assert report.exit_code == 2
    assert "json:missing.json: file not found: missing.json" in report.errors


def test_high_risk_list_is_independent_of_the_gate(make_report):
    gate = GateConfig(fail_on_unspecified_risk=(), require_deny_case_for_risk=())
    report = make_report(extra_tools=["delete_portfolio"], gate=gate)
    assert report.exit_code == 0
    assert report.high_risk_tools_without_deny_case == ("delete_portfolio",)


def test_a_deny_case_with_an_error_does_not_count(make_report):
    # CASE-001..003 as in the demo, then a CASE-004 whose action does not match the registry.
    first_three = [
        {
            **DELETE_DENY_CASE,
            "id": "CASE-001",
            "tool": "get_stock_price",
            "action": "market:read",
            "expect": "allow",
        },
        {
            **DELETE_DENY_CASE,
            "id": "CASE-002",
            "tool": "read_portfolio",
            "action": "portfolio:read",
            "expect": "allow",
        },
        {
            **DELETE_DENY_CASE,
            "id": "CASE-003",
            "tool": "read_portfolio",
            "action": "portfolio:read",
            "expect": "deny",
        },
    ]
    broken = {**DELETE_DENY_CASE, "id": "CASE-004", "tool": "execute_trade", "action": "trade:run"}
    report = make_report(cases=[*first_three, broken])
    row = next(tool for tool in report.inventory.tools if tool.id == "execute_trade")
    assert row.has_deny_case is False
    assert (
        GateViolation(rule="require_deny_case_for_risk", tool="execute_trade", risk=Risk.CRITICAL)
        in report.gate.violations
    )
    assert report.exit_code == 2


def test_report_never_contains_a_security_score(make_report):
    assert "security_score" not in make_report().model_dump()


def _case(case_id, tool, action, expect, agent="finance-agent"):
    return {
        **DELETE_DENY_CASE,
        "id": case_id,
        "agent": agent,
        "tool": tool,
        "action": action,
        "expect": expect,
    }


def _allow_cases():
    return [
        _case("CASE-001", "get_stock_price", "market:read", "allow"),
        _case("CASE-002", "read_portfolio", "portfolio:read", "allow"),
    ]


def _trade_violations(report):
    return [
        GateViolation(rule=rule, tool="execute_trade", risk=Risk.CRITICAL)
        for rule in ("fail_on_unspecified_risk", "require_deny_case_for_risk")
    ]


def test_a_tool_with_only_error_cases_is_unspecified(make_report):
    cases = [
        *_allow_cases(),
        _case("CASE-003", "read_portfolio", "portfolio:read", "deny"),
        _case("CASE-004", "execute_trade", "trade:run", "deny"),
    ]
    report = make_report(cases=cases)
    row = next(tool for tool in report.inventory.tools if tool.id == "execute_trade")
    assert row.coverage is ToolCoverage.UNSPECIFIED
    assert row.case_ids == ("CASE-004",)
    assert "execute_trade" in report.registered_tools_without_spec
    for violation in _trade_violations(report):
        assert violation in report.gate.violations
    assert report.exit_code == 2


def test_a_deny_case_with_an_undeclared_agent_does_not_count(make_report):
    cases = [
        *_allow_cases(),
        _case("CASE-003", "read_portfolio", "portfolio:read", "deny"),
        _case("CASE-004", "execute_trade", "trade:execute", "deny", agent="ghost-agent"),
    ]
    report = make_report(cases=cases)
    row = next(tool for tool in report.inventory.tools if tool.id == "execute_trade")
    assert row.has_deny_case is False
    assert (
        GateViolation(rule="require_deny_case_for_risk", tool="execute_trade", risk=Risk.CRITICAL)
        in report.gate.violations
    )
    assert report.exit_code == 2


def test_a_high_risk_tool_with_only_allow_cases_fails_the_deny_rule(make_report):
    cases = [
        *_allow_cases(),
        _case("CASE-004", "execute_trade", "trade:execute", "deny"),
    ]
    report = make_report(cases=cases)
    assert (
        GateViolation(rule="require_deny_case_for_risk", tool="read_portfolio", risk=Risk.HIGH)
        in report.gate.violations
    )
    assert report.exit_code == 1


def test_a_partially_configured_gate(make_report):
    gate = GateConfig(require_deny_case_for_risk=())
    report = make_report(extra_tools=["delete_portfolio"], gate=gate)
    assert report.gate.violations == (
        GateViolation(rule="fail_on_unspecified_risk", tool="delete_portfolio", risk=Risk.UNKNOWN),
    )
    assert report.exit_code == 1


def test_tool_spec_states_uses_one_rule_for_specified():
    from lockwalk.analyzer import tool_spec_states
    from lockwalk.models import CaseStatus, PlannedCase
    from lockwalk.spec_loader import SpecFile

    def case(case_id: str, tool: str, status: CaseStatus) -> PlannedCase:
        spec = SpecFile.model_validate(
            {
                "schema_version": "1",
                "scenario_suite": "s",
                "cases": [
                    {
                        "id": case_id,
                        "actor": "a",
                        "role": "r",
                        "agent": "g",
                        "tool": tool,
                        "action": "x:y",
                        "resource_fixture": "f",
                        "expect": "allow",
                    }
                ],
            }
        )
        return PlannedCase(
            scenario=spec.cases[0],
            status=status,
            problems=("invalid",) if status == CaseStatus.ERROR else (),
            action_verified=False,
        )

    plan = [
        case("C1", "ok_tool", CaseStatus.UNTESTED),
        case("C2", "mixed", CaseStatus.ERROR),
        case("C3", "mixed", CaseStatus.UNTESTED),
        case("C4", "broken", CaseStatus.ERROR),
    ]
    assert tool_spec_states(plan) == {"ok_tool": "yes", "mixed": "yes", "broken": "ERROR"}
    assert tool_spec_states([]) == {}


def test_case_path_is_shown_and_unknown_agent_gives_exit_2(make_report):
    report = make_report(
        extra_cases=[
            {
                "id": "CASE-9",
                "actor": "a",
                "role": "r",
                "agent": "ghost",
                "tool": "execute_trade",
                "action": "trade:execute",
                "resource_fixture": "f",
                "expect": "deny",
            }
        ]
    )
    assert report.exit_code == 2
    assert report.cases[-1].path == ("ghost",)


def _extra_case(case_id, **overrides):
    case = {
        "id": case_id,
        "actor": "a",
        "role": "r",
        "tool": "execute_trade",
        "action": "trade:execute",
        "resource_fixture": "f",
        "expect": "deny",
    }
    return {**case, **overrides}


def test_errors_and_exit_code_two_agree_in_every_scenario(make_report):
    reports = [
        make_report(),
        make_report(extra_tools=["delete_portfolio"]),
        make_report(failed_source="json:missing"),
        make_report(extra_cases=[_extra_case("CASE-9", agent="ghost")]),
        make_report(cases=[]),
    ]
    for report in reports:
        assert bool(report.errors) == (report.exit_code == 2)


def test_repeated_unknown_agent_in_a_path_is_reported_once(make_report):
    report = make_report(
        extra_cases=[_extra_case("CASE-9", path=["ghost", "finance-agent", "ghost"])]
    )
    assert report.cases[-1].problems == ("agent 'ghost' is not declared in the registry",)


def test_multi_step_path_case_row_keeps_the_path(make_report):
    path = ["research-agent", "finance-agent"]
    report = make_report(extra_cases=[_extra_case("CASE-9", path=path)])
    row = report.cases[-1]
    assert row.agent == "finance-agent"
    assert row.path == tuple(path)


def test_failed_optional_source_keeps_exit_zero_and_stays_failed(finance_registry, finance_cases):
    from lockwalk.analyzer import analyze
    from lockwalk.inventory.merge import merge_inventory
    from lockwalk.models import SourceRef, SourceResult
    from lockwalk.planner import plan_cases
    from lockwalk.registry import Registry
    from lockwalk.spec_loader import SpecFile

    inventory = merge_inventory(
        [
            SourceResult(
                source=SourceRef(kind="mcp", label="mcp:partner"),
                ok=False,
                error="connection refused",
                optional=True,
            )
        ],
        registry=Registry.model_validate(finance_registry),
    )
    spec = SpecFile.model_validate(
        {"schema_version": "1", "scenario_suite": "s", "cases": finance_cases}
    )
    report = analyze(inventory, spec, plan_cases(spec, inventory), GateConfig())
    assert report.exit_code == 0
    assert [s.ok for s in inventory.sources if s.source.label == "mcp:partner"] == [False]
    [summary] = [s for s in report.inventory.sources if s.source == "mcp:partner"]
    assert summary.ok is False and summary.optional is True
