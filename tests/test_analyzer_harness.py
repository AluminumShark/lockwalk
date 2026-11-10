"""with_harness_outcome: fold door results into a test-mode report."""

from lockwalk.analyzer import with_harness_outcome, with_test_outcome
from lockwalk.config import GateConfig
from lockwalk.harness.verdicts import HarnessOutcome
from lockwalk.judge import CaseOutcome, PolicyOutcome
from lockwalk.models import (
    CaseDecision,
    CaseStatus,
    DoorControlRow,
    DoorResult,
    DoorRun,
    DoorStatus,
    GateViolation,
    IdentityCheckRow,
    IdentityResult,
    PathVerdict,
)

ALICE = {"type": "user", "id": "alice"}


def _report(make_report, statuses: dict[str, CaseStatus], gate: GateConfig | None = None):
    base = make_report(gate=gate)
    cases = {
        cid: CaseOutcome(status=status, decision=CaseDecision(verdict=PathVerdict.ALLOW, hops=()))
        for cid, status in statuses.items()
    }
    violations = tuple(
        GateViolation(rule="case", case_id=cid, status=s)
        for cid, s in statuses.items()
        if s is CaseStatus.FAIL_POLICY
    )
    outcome = PolicyOutcome(
        cases=cases, escalations=(), controls=(), errors=(), warnings=(), violations=violations
    )
    return with_test_outcome(base, outcome, policy_adapter="test")


def _run(status: DoorStatus, *notes: str, mode="direct") -> DoorRun:
    return DoorRun(mode=mode, status=status, subject=ALICE, side_effect_calls=0, notes=notes)


def _door(status: DoorStatus, *notes: str) -> DoorResult:
    return DoorResult(status=status, runs=(_run(status, *notes),))


ALL_PASS = {f"CASE-00{n}": CaseStatus.PASS for n in (1, 2, 3, 4)}


def _case(report, cid):
    return next(c for c in report.cases if c.id == cid)


def test_pass_plus_fail_execution_becomes_fail_execution_with_a_violation(make_report):
    report = _report(make_report, ALL_PASS)
    out = HarnessOutcome(doors={"CASE-001": _door(DoorStatus.FAIL_EXECUTION, "ran")})
    result = with_harness_outcome(report, out, GateConfig())
    row = _case(result, "CASE-001")
    assert row.status is CaseStatus.FAIL_EXECUTION
    assert row.door == out.doors["CASE-001"]
    assert row.notes == ("door (direct): ran",)
    assert row.problems == ()
    assert [(v.rule, v.case_id, v.status) for v in result.gate.violations] == [
        ("case", "CASE-001", CaseStatus.FAIL_EXECUTION)
    ]
    assert result.exit_code == 1 and not result.gate.passed
    assert result.metrics.cases_by_status["FAIL_EXECUTION"] == 1
    assert result.metrics.cases_by_status["PASS"] == 3
    assert result.metrics.verified_pass_rate == 0.75


def test_inconclusive_plus_door_error_becomes_error_with_exit_2(make_report):
    report = _report(make_report, {**ALL_PASS, "CASE-002": CaseStatus.INCONCLUSIVE})
    out = HarnessOutcome(
        doors={"CASE-002": _door(DoorStatus.ERROR, "worker died")},
        errors=("CASE-002: door (direct): worker died",),
    )
    result = with_harness_outcome(report, out, GateConfig())
    row = _case(result, "CASE-002")
    assert row.status is CaseStatus.ERROR
    assert row.problems == ("door (direct): worker died",)
    assert result.exit_code == 2
    assert result.errors[-1] == "CASE-002: door (direct): worker died"


def test_fail_policy_stays_over_door_ok_and_door_inconclusive(make_report):
    report = _report(make_report, {**ALL_PASS, "CASE-003": CaseStatus.FAIL_POLICY})
    out = HarnessOutcome(
        doors={
            "CASE-003": _door(DoorStatus.INCONCLUSIVE, "no control"),
            "CASE-004": _door(DoorStatus.OK),
        }
    )
    result = with_harness_outcome(report, out, GateConfig())
    assert _case(result, "CASE-003").status is CaseStatus.FAIL_POLICY
    assert _case(result, "CASE-004").status is CaseStatus.PASS
    assert _case(result, "CASE-004").notes == ()
    assert _case(result, "CASE-003").door is not None


def test_not_tested_door_changes_nothing_but_sets_door(make_report):
    report = _report(make_report, ALL_PASS)
    door = DoorResult(status=DoorStatus.NOT_TESTED, notes=("direct: why",))
    result = with_harness_outcome(report, HarnessOutcome(doors={"CASE-001": door}), GateConfig())
    row = _case(result, "CASE-001")
    assert row.status is CaseStatus.PASS and row.door == door and row.notes == ()


def test_error_door_without_runs_puts_its_notes_in_problems(make_report):
    report = _report(make_report, ALL_PASS)
    door = DoorResult(status=DoorStatus.ERROR, notes=("the door tests could not start: x",))
    result = with_harness_outcome(report, HarnessOutcome(doors={"CASE-001": door}), GateConfig())
    assert _case(result, "CASE-001").status is CaseStatus.ERROR
    assert _case(result, "CASE-001").problems == ("door: the door tests could not start: x",)


def test_violations_are_not_duplicated(make_report):
    report = _report(make_report, {**ALL_PASS, "CASE-003": CaseStatus.FAIL_POLICY})
    assert len(report.gate.violations) == 1
    out = HarnessOutcome(doors={"CASE-003": _door(DoorStatus.FAIL_EXECUTION, "ran")})
    result = with_harness_outcome(report, out, GateConfig())
    case_violations = [v for v in result.gate.violations if v.rule == "case"]
    assert [(v.case_id, v.status) for v in case_violations] == [
        ("CASE-003", CaseStatus.FAIL_EXECUTION)
    ]


def test_inconclusive_violation_follows_the_gate(make_report):
    report = _report(make_report, ALL_PASS)
    out = HarnessOutcome(doors={"CASE-001": _door(DoorStatus.INCONCLUSIVE, "no control")})
    on = with_harness_outcome(report, out, GateConfig(fail_on_inconclusive_case=True))
    off = with_harness_outcome(report, out, GateConfig(fail_on_inconclusive_case=False))
    assert [v.rule for v in on.gate.violations] == ["fail_on_inconclusive_case"]
    assert off.gate.violations == () and off.exit_code == 0


def test_harness_lists_follow_the_reports_and_identity_fields_are_set(make_report):
    base = _report(make_report, ALL_PASS)
    row = IdentityCheckRow(
        case_id="CASE-001", path=("finance-agent",), tool="get_stock_price",
        result=IdentityResult.MISMATCH,
    )  # fmt: skip
    ctrl = DoorControlRow(tool="get_stock_price", proven=True, proven_by="CASE-001 (direct)")
    mismatch = GateViolation(rule="fail_on_identity_mismatch", case_id="CASE-001")
    out = HarnessOutcome(
        identity_checks=(row,),
        door_controls=(ctrl,),
        errors=("e",),
        warnings=("w",),
        violations=(mismatch,),
    )
    result = with_harness_outcome(base, out, GateConfig())
    assert result.identity_checks == (row,) and result.door_controls == (ctrl,)
    assert result.errors == (*base.errors, "e")
    assert result.warnings == (*base.warnings, "w")
    assert result.gate.violations[-1] == mismatch
    assert result.exit_code == 2


def test_no_harness_entries_only_adds_the_empty_fields(make_report):
    report = _report(make_report, {**ALL_PASS, "CASE-003": CaseStatus.FAIL_POLICY})
    result = with_harness_outcome(report, HarnessOutcome(), GateConfig())
    assert result == report


def test_unknown_door_case_id_is_ignored(make_report):
    report = _report(make_report, ALL_PASS)
    out = HarnessOutcome(doors={"NOPE": _door(DoorStatus.FAIL_EXECUTION, "x")})
    assert with_harness_outcome(report, out, GateConfig()) == report


def test_plan_error_note_reaches_problems_next_to_error_run_lines(make_report):
    report = _report(make_report, ALL_PASS)
    door = DoorResult(
        status=DoorStatus.ERROR,
        runs=(_run(DoorStatus.ERROR, "worker died"), _run(DoorStatus.INCONCLUSIVE, "no control")),
        notes=("bad tool_args",),
    )
    result = with_harness_outcome(report, HarnessOutcome(doors={"CASE-001": door}), GateConfig())
    assert _case(result, "CASE-001").problems == (
        "door (direct): worker died",
        "door: bad tool_args",
    )
