import pytest

from lockwalk.diff import diff_reports, head_status
from lockwalk.models import (
    CaseStatus,
    GateResult,
    GateViolation,
    Risk,
    ToolCoverage,
    WaivedViolation,
)


def with_violations(report, *violations, passed=None):
    gate = GateResult(
        passed=(not violations) if passed is None else passed, violations=tuple(violations)
    )
    return report.model_copy(update={"gate": gate})


def with_case_status(report, case_id, status):
    cases = tuple(
        case.model_copy(update={"status": status}) if case.id == case_id else case
        for case in report.cases
    )
    return report.model_copy(update={"cases": cases})


def with_tool(report, tool_id, **changes):
    tools = tuple(
        tool.model_copy(update=changes) if tool.id == tool_id else tool
        for tool in report.inventory.tools
    )
    inventory = report.inventory.model_copy(update={"tools": tools})
    return report.model_copy(update={"inventory": inventory})


def reversed_order(report):
    inventory = report.inventory.model_copy(update={"tools": report.inventory.tools[::-1]})
    return report.model_copy(update={"inventory": inventory, "cases": report.cases[::-1]})


UNSPECIFIED = GateViolation(rule="fail_on_unspecified_risk", tool="x", risk=Risk.CRITICAL)
OTHER = GateViolation(rule="fail_on_unspecified_risk", tool="y", risk=Risk.HIGH)


def test_violation_is_hashable():
    assert len({UNSPECIFIED, UNSPECIFIED.model_copy(), OTHER}) == 2


def test_identical_reports(make_report):
    result = diff_reports(make_report(), make_report())
    assert result.incomplete is False
    assert result.base_given is True
    assert result.warnings == ()
    for name in type(result).model_fields:
        value = getattr(result, name)
        if isinstance(value, tuple):
            assert value == (), name


def test_new_gone_and_shared_violations(make_report):
    base = with_violations(make_report(), OTHER)
    head = with_violations(make_report(), UNSPECIFIED, OTHER)
    result = diff_reports(head, base)
    assert result.new_violations == (UNSPECIFIED,)
    assert result.no_longer_reported == ()
    result = diff_reports(base, head)
    assert result.new_violations == ()
    assert result.no_longer_reported == (UNSPECIFIED,)


def test_violation_with_different_status_is_new_and_fixed(make_report):
    before = GateViolation(rule="case", case_id="CASE-1", status=CaseStatus.FAIL_POLICY)
    after = GateViolation(rule="case", case_id="CASE-1", status=CaseStatus.FAIL_EXECUTION)
    result = diff_reports(
        with_violations(make_report(), after), with_violations(make_report(), before)
    )
    assert result.new_violations == (after,)
    assert result.no_longer_reported == (before,)


def test_tool_added_without_spec(make_report):
    result = diff_reports(make_report(extra_tools=["delete_portfolio"]), make_report())
    assert [(t.id, t.risk) for t in result.tools_added_without_spec] == [
        ("delete_portfolio", Risk.UNKNOWN)
    ]
    assert result.tools_added == ()


def test_tool_added_with_spec_and_removed(make_report):
    base = make_report()
    head = with_tool(make_report(extra_tools=["new_tool"]), "new_tool", coverage="specified")
    head = head.model_copy(
        update={
            "inventory": head.inventory.model_copy(
                update={"tools": tuple(t for t in head.inventory.tools if t.id != "read_portfolio")}
            )
        }
    )
    result = diff_reports(head, base)
    assert [t.id for t in result.tools_added] == ["new_tool"]
    assert result.tools_added_without_spec == ()
    assert [t.id for t in result.tools_removed] == ["read_portfolio"]


def test_lost_and_gained_spec(make_report):
    base = make_report()
    spec_tool = next(t for t in base.inventory.tools if t.coverage is ToolCoverage.SPECIFIED)
    lost = with_tool(base, spec_tool.id, coverage=ToolCoverage.UNSPECIFIED)
    assert [t.id for t in diff_reports(lost, base).tools_lost_spec] == [spec_tool.id]
    assert [t.id for t in diff_reports(base, lost).tools_gained_spec] == [spec_tool.id]
    assert diff_reports(base, lost).tools_lost_spec == ()


def test_risk_change(make_report):
    base = make_report()
    tool = base.inventory.tools[0]
    new_risk = Risk.LOW if tool.risk is not Risk.LOW else Risk.HIGH
    head = with_tool(base, tool.id, risk=new_risk)
    (change,) = diff_reports(head, base).risk_changes
    assert (change.id, change.base, change.head) == (tool.id, tool.risk, new_risk)


def test_cases_added_and_removed(make_report):
    base = make_report()
    head = base.model_copy(update={"cases": base.cases[1:]})
    assert [c.id for c in diff_reports(head, base).cases_removed] == [base.cases[0].id]
    assert [c.id for c in diff_reports(base, head).cases_added] == [base.cases[0].id]


@pytest.mark.parametrize(
    ("base_status", "head_status_", "bucket"),
    [
        (CaseStatus.PASS, CaseStatus.FAIL_POLICY, "cases_worse"),
        (CaseStatus.PASS, CaseStatus.UNTESTED, "cases_worse"),
        (CaseStatus.PASS, CaseStatus.INCONCLUSIVE, "cases_worse"),
        (CaseStatus.UNTESTED, CaseStatus.FAIL_EXECUTION, "cases_worse"),
        (CaseStatus.INCONCLUSIVE, CaseStatus.FAIL_POLICY, "cases_worse"),
        (CaseStatus.FAIL_POLICY, CaseStatus.PASS, "cases_better"),
        (CaseStatus.UNTESTED, CaseStatus.PASS, "cases_better"),
        (CaseStatus.UNTESTED, CaseStatus.ERROR, "cases_other"),
        (CaseStatus.FAIL_POLICY, CaseStatus.FAIL_EXECUTION, "cases_other"),
        (CaseStatus.FAIL_POLICY, CaseStatus.INCONCLUSIVE, "cases_other"),
    ],
)
def test_status_classes(make_report, base_status, head_status_, bucket):
    base = make_report()
    case_id = base.cases[0].id
    result = diff_reports(
        with_case_status(base, case_id, head_status_), with_case_status(base, case_id, base_status)
    )
    buckets = ("cases_worse", "cases_better", "cases_other")
    for name in buckets:
        rows = getattr(result, name)
        if name == bucket:
            assert [(c.id, c.base, c.head) for c in rows] == [(case_id, base_status, head_status_)]
        else:
            assert rows == ()


def test_no_base(make_report):
    head = with_violations(make_report(extra_tools=["delete_portfolio"]), UNSPECIFIED)
    result = diff_reports(head, None)
    assert result.base_given is False
    assert result.new_violations == (UNSPECIFIED,)
    unspecified = tuple(
        t.id for t in head.inventory.tools if t.coverage is ToolCoverage.UNSPECIFIED
    )
    assert tuple(t.id for t in result.tools_added_without_spec) == tuple(sorted(unspecified))
    assert "delete_portfolio" in unspecified
    assert len(result.warnings) == 1
    assert "no base" in result.warnings[0]
    for name in (
        "no_longer_reported",
        "tools_added",
        "tools_removed",
        "tools_lost_spec",
        "tools_gained_spec",
        "risk_changes",
        "cases_added",
        "cases_removed",
        "cases_worse",
        "cases_better",
        "cases_other",
    ):
        assert getattr(result, name) == (), name


def test_modes_differ(make_report):
    base = make_report()
    case_id = base.cases[0].id
    head = with_case_status(base, case_id, CaseStatus.FAIL_POLICY).model_copy(
        update={"mode": "test" if base.mode == "static" else "static", "cases": base.cases[1:]}
    )
    head = with_case_status(head, base.cases[1].id, CaseStatus.FAIL_POLICY)
    result = diff_reports(head, base)
    assert result.cases_worse == result.cases_better == result.cases_other == ()
    assert [c.id for c in result.cases_removed] == [case_id]
    assert any("not compared" in w for w in result.warnings)


def test_suites_differ(make_report):
    base = make_report().model_copy(update={"scenario_suite": "secret-suite-a"})
    head = base.model_copy(update={"scenario_suite": "secret-suite-b"})
    result = diff_reports(head, base)
    assert len(result.warnings) == 1
    assert "scenario suites" in result.warnings[0]
    assert "secret-suite" not in result.warnings[0]
    assert result.incomplete is False


def test_head_errors(make_report):
    head = make_report().model_copy(update={"errors": ("secret text",), "exit_code": 2})
    result = diff_reports(head, make_report())
    assert result.incomplete is True
    assert result.head_status == "ERROR"
    assert len(result.warnings) == 1
    assert "secret text" not in result.warnings[0]
    assert head_status(head) == "ERROR"


def test_head_errors_show_nothing_as_gone(make_report):
    violation = UNSPECIFIED
    base = with_violations(make_report(), violation)
    head = make_report().model_copy(update={"errors": ("boom",), "exit_code": 2})
    assert diff_reports(head, base).no_longer_reported == ()
    clean = diff_reports(make_report(), base)
    assert clean.no_longer_reported == (violation,)


def test_base_errors(make_report):
    base = make_report().model_copy(update={"errors": ("secret text",), "exit_code": 2})
    result = diff_reports(make_report(), base)
    assert result.incomplete is True
    assert result.head_status in ("PASS", "FAIL")
    assert len(result.warnings) == 1
    assert "secret text" not in result.warnings[0]


def test_head_status_from_gate(make_report):
    assert head_status(with_violations(make_report(), passed=True)) == "PASS"
    assert head_status(with_violations(make_report(), UNSPECIFIED)) == "FAIL"


def test_rows_are_sorted(make_report):
    base = make_report()
    head = with_violations(make_report(extra_tools=["b_tool", "a_tool"]), UNSPECIFIED, OTHER)
    forward = diff_reports(head, base)
    backward = diff_reports(reversed_order(head), reversed_order(base))
    assert forward == backward
    assert [t.id for t in forward.tools_added_without_spec] == ["a_tool", "b_tool"]


def test_expired_waiver_is_a_new_problem(make_report):
    waived = WaivedViolation(violation=UNSPECIFIED, waiver_id="W-1")
    base = make_report().model_copy(
        update={"gate": GateResult(passed=True, violations=(), waived=(waived,))}
    )
    head = with_violations(make_report(), UNSPECIFIED)
    assert diff_reports(head, base).new_violations == (UNSPECIFIED,)


def test_violation_waived_on_both_sides_is_in_neither_list(make_report):
    waived = WaivedViolation(violation=UNSPECIFIED, waiver_id="W-1")
    gate = GateResult(passed=True, violations=(), waived=(waived,))
    report = make_report().model_copy(update={"gate": gate})
    result = diff_reports(report, report)
    assert result.new_violations == ()
    assert result.no_longer_reported == ()
    assert result.waived == len(report.gate.waived) == 1


def test_has_changes_covers_every_row_field(make_report):
    from lockwalk.diff import ReportDiff, has_changes

    empty = diff_reports(make_report(), make_report())
    assert not has_changes(empty)
    assert not has_changes(empty.model_copy(update={"warnings": ("w",)}))
    row_fields = [name for name, value in empty if isinstance(value, tuple) and name != "warnings"]
    assert len(row_fields) == 21
    assert set(row_fields) <= set(ReportDiff.model_fields)
    for name in row_fields:
        assert has_changes(empty.model_copy(update={name: ("row",)})), name
