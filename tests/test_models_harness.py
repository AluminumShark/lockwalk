"""The report models for the door tests."""

import pytest
from pydantic import ValidationError

from lockwalk.models import (
    CaseRow,
    CoverageReport,
    DoorCall,
    DoorControlRow,
    DoorResult,
    DoorRun,
    DoorStatus,
    GateViolation,
    HopResult,
    IdentityCheckRow,
    IdentityObservation,
    IdentityResult,
    PathVerdict,
)


def test_door_call_has_an_answer_or_an_error() -> None:
    DoorCall(subject={"type": "user", "id": "alice"}, decision=True)
    DoorCall(error="read_door_call returned str")
    with pytest.raises(ValidationError):
        DoorCall(subject={"type": "user", "id": "alice"})
    with pytest.raises(ValidationError):
        DoorCall(subject={"type": "user", "id": "alice"}, decision=True, error="x")
    with pytest.raises(ValidationError):
        DoorCall(decision="yes", subject={"type": "user", "id": "a"})  # StrictBool


def test_door_run_never_not_tested_and_counts_are_not_negative() -> None:
    subject = {"type": "user", "id": "alice", "properties": {"roles": ["analyst"]}}
    DoorRun(mode="direct", status=DoorStatus.OK, subject=subject, side_effect_calls=0)
    with pytest.raises(ValidationError):
        DoorRun(mode="direct", status=DoorStatus.NOT_TESTED, subject=subject, side_effect_calls=0)
    with pytest.raises(ValidationError):
        DoorRun(mode="direct", status=DoorStatus.OK, subject=subject, side_effect_calls=-1)


def test_door_result_defaults() -> None:
    result = DoorResult(status=DoorStatus.NOT_TESTED, notes=("tool 't' is not in SIDE_EFFECTS",))
    assert result.runs == ()


def test_side_effect_calls_is_a_strict_required_int() -> None:
    subject = {"type": "user", "id": "alice"}
    for bad in (True, 1.0):
        with pytest.raises(ValidationError):
            DoorRun(mode="direct", status=DoorStatus.OK, subject=subject, side_effect_calls=bad)
    with pytest.raises(ValidationError):
        DoorRun.model_validate({"mode": "direct", "status": "OK", "subject": subject})


def test_door_call_decision_needs_a_subject() -> None:
    with pytest.raises(ValidationError):
        DoorCall(decision=True)


def _run(status: DoorStatus = DoorStatus.OK) -> DoorRun:
    return DoorRun(
        mode="direct", status=status, subject={"type": "user", "id": "a"}, side_effect_calls=1
    )


def test_door_result_runs_match_status() -> None:
    with pytest.raises(ValidationError):
        DoorResult(status=DoorStatus.NOT_TESTED, runs=(_run(),))
    for status in (DoorStatus.OK, DoorStatus.INCONCLUSIVE, DoorStatus.FAIL_EXECUTION):
        with pytest.raises(ValidationError):
            DoorResult(status=status, notes=("x",))
        DoorResult(status=status, runs=(_run(status),))
    with pytest.raises(ValidationError):
        DoorResult(status=DoorStatus.ERROR)
    DoorResult(status=DoorStatus.ERROR, notes=("plan error",))
    DoorResult(status=DoorStatus.ERROR, runs=(_run(DoorStatus.ERROR),))


def test_models_round_trip_through_json() -> None:
    run = DoorRun(
        mode="scripted",
        status=DoorStatus.OK,
        subject={"type": "user", "id": "a", "properties": {"roles": ["x"]}},
        side_effect_calls=2,
        door_calls=(
            DoorCall(subject={"type": "user", "id": "a"}, decision=True),
            DoorCall(error="boom"),
        ),
    )
    observation = IdentityObservation(
        mode="direct",
        expected={"type": "user", "id": "a"},
        observed=({"type": "user", "id": "a"},),
        result=IdentityResult.MATCH,
    )
    models = [
        run,
        DoorResult(status=DoorStatus.OK, runs=(run,)),
        IdentityCheckRow(
            case_id="CASE-001",
            path=("s",),
            tool="t",
            result=IdentityResult.MATCH,
            observations=(observation,),
        ),
        DoorControlRow(tool="t", proven=True, proven_by="CASE-004 (direct)"),
    ]
    for model in models:
        assert type(model).model_validate(model.model_dump(mode="json")) == model


def test_observed_mode_has_one_answer() -> None:
    answer = {"subject": {"type": "agent", "id": "a"}, "verdict": "allow"}
    HopResult(
        caller="a",
        target="t",
        kind="tool",
        mode="observed",
        verdict=PathVerdict.ALLOW,
        answers=(answer,),
    )
    with pytest.raises(ValidationError):
        HopResult(
            caller="a",
            target="t",
            kind="tool",
            mode="observed",
            verdict=PathVerdict.ALLOW,
            answers=(answer, answer),
        )


def test_identity_mismatch_gate_rule_needs_a_case_id() -> None:
    GateViolation(rule="fail_on_identity_mismatch", case_id="CASE-001")
    with pytest.raises(ValidationError):
        GateViolation(rule="fail_on_identity_mismatch")


def test_new_report_fields_default_empty() -> None:
    fields = CoverageReport.model_fields
    assert fields["identity_checks"].default == ()
    assert fields["door_controls"].default == ()
    assert CaseRow.model_fields["door"].default is None
    row = IdentityCheckRow(
        case_id="CASE-001", path=("supervisor",), tool="t", result=IdentityResult.NOT_RUN
    )
    assert row.observations == () and row.notes == ()
    assert DoorControlRow(tool="t", proven=False).proven_by is None
