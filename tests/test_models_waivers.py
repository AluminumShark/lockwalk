import pytest
from pydantic import ValidationError

from lockwalk.models import (
    CaseRow,
    CaseStatus,
    CoverageReport,
    EscalationResult,
    EscalationRow,
    GateResult,
    GateViolation,
    IdentityCheckRow,
    IdentityResult,
    InventorySection,
    Metrics,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    WaivedViolation,
    WaiverRow,
    WaiverStatus,
)


def _metrics() -> Metrics:
    return Metrics(
        registered_tools=0,
        specified_cases=0,
        executed_cases=0,
        execution_coverage=None,
        verified_pass_rate=None,
        cases_by_status={},
        tools_without_spec=0,
    )


def _report(**extra) -> CoverageReport:
    return CoverageReport(
        mode="static",
        scenario_suite="s",
        spec_schema_version="1",
        inventory=InventorySection(sources=(), agents=(), tools=(), drift=None),
        cases=(),
        metrics=_metrics(),
        registered_tools_without_spec=(),
        high_risk_tools_without_deny_case=(),
        gate=GateResult(passed=True, violations=()),
        errors=(),
        warnings=(),
        exit_code=0,
        **extra,
    )


def _waiver(status: WaiverStatus, **extra) -> WaiverRow:
    return WaiverRow(
        id=f"WAIVE-{status}",
        owner="alice@example.com",
        expires="2026-12-31",
        reason="reviewed",
        match={"rule": "RULE-002"},
        status=status,
        **extra,
    )


def test_new_fields_default_to_empty():
    assert GateResult(passed=True, violations=()).waived == ()
    report = _report()
    assert report.waivers == ()
    row = RuleRow(
        id="RULE-001",
        agent=None,
        role=None,
        tool=None,
        target_agent=None,
        result=RuleResult.FAIL,
    )
    assert row.waived_by is None
    assert (
        ReachRow(role="r", tool="t", risk=Risk.LOW, status=ReachStatus.REACHABLE).waived_by is None
    )


def test_waived_by_exists_on_the_five_row_types():
    for model in (CaseRow, RuleRow, ReachRow, EscalationRow, IdentityCheckRow):
        assert model.model_fields["waived_by"].default is None
    assert EscalationResult.ESCALATION and IdentityResult.MISMATCH and CaseStatus.PASS


def test_waiver_row_statuses():
    for status in ("applied", "expired", "unmatched", "not_allowed"):
        row = _waiver(status)
        assert row.status == status
        assert row.matched == ()
        assert row.note is None
    with pytest.raises(ValidationError):
        _waiver("other")  # ty: ignore[invalid-argument-type]


def test_json_round_trip_with_waived_violation_and_every_status():
    violation = GateViolation(rule="never_reaches", rule_id="RULE-002", result=RuleResult.FAIL)
    report = _report(
        waivers=(
            _waiver("applied", matched=("RULE-002",)),
            _waiver("expired", note="expired on 2026-01-01"),
            _waiver("unmatched", note="nothing matched"),
            _waiver("not_allowed", note="the rule is in ERROR"),
        ),
    ).model_copy(
        update={
            "gate": GateResult(
                passed=True,
                violations=(),
                waived=(WaivedViolation(violation=violation, waiver_id="WAIVE-applied"),),
            )
        }
    )
    again = CoverageReport.model_validate_json(report.model_dump_json())
    assert again == report
    assert again.gate.waived[0].waiver_id == "WAIVE-applied"
    assert [w.status for w in again.waivers] == ["applied", "expired", "unmatched", "not_allowed"]
