"""The report models for the policy checks."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from lockwalk.models import (
    Answer,
    CaseStatus,
    EscalationResult,
    EscalationRow,
    GateViolation,
    HopResult,
    PathVerdict,
    Risk,
    TestScenario,
    Verdict,
)


def test_answer_error_is_set_exactly_for_error_verdicts() -> None:
    with pytest.raises(ValidationError):
        Answer(subject={"type": "user", "id": "alice"}, verdict=Verdict.ERROR)
    with pytest.raises(ValidationError):
        Answer(subject={"type": "user", "id": "alice"}, verdict=Verdict.ALLOW, error="x")
    answer = Answer(
        subject={"type": "user", "id": "alice"}, verdict=Verdict.ERROR, error="timed out"
    )
    assert answer.error == "timed out"


@pytest.mark.parametrize(
    ("rule", "fields"),
    [
        ("case", {"case_id": "CASE-1", "status": CaseStatus.FAIL_POLICY}),
        ("fail_on_inconclusive_case", {"case_id": "CASE-1", "status": CaseStatus.INCONCLUSIVE}),
        ("fail_on_escalation", {"role": "analyst", "tool": "t", "via": "a"}),
        ("fail_on_inconclusive_escalation", {"role": "analyst", "tool": "t", "via": "a"}),
        (
            "fail_on_unchecked_escalation",
            {"role": "analyst", "tool": "t", "via": "a", "risk": Risk.CRITICAL},
        ),
    ],
)
def test_new_gate_rules_need_their_fields(rule: str, fields: dict[str, object]) -> None:
    GateViolation.model_validate({"rule": rule, **fields})
    with pytest.raises(ValidationError):
        GateViolation.model_validate({"rule": rule})


def test_escalation_row_defaults() -> None:
    row = EscalationRow(
        case_id=None,
        role="analyst",
        tool="execute_trade",
        via="trade-agent",
        risk=Risk.CRITICAL,
        mode="agent",
        path=("supervisor", "finance-agent", "trade-agent"),
        result=EscalationResult.UNCHECKED,
        notes=("no probe subject for role 'analyst' (probes.subjects)",),
    )
    assert row.user_answer is None and row.path_answer is None


def test_condition_key_lockwalk_is_reserved() -> None:
    with pytest.raises(ValidationError, match="reserved"):
        TestScenario.model_validate(
            {
                "id": "CASE-1",
                "actor": "alice",
                "role": "analyst",
                "agent": "a",
                "tool": "t",
                "action": "x:y",
                "resource_fixture": "r",
                "expect": "allow",
                "conditions": {"lockwalk": "mine"},
            }
        )


def test_static_report_has_empty_test_sections(make_report) -> None:
    report = make_report()
    assert report.mode == "static"
    assert report.escalations == () and report.controls == ()
    assert all(case.decision is None and case.notes == () for case in report.cases)


def test_answer_error_and_latency_are_strict() -> None:
    subject = {"type": "user", "id": "alice"}
    with pytest.raises(ValidationError):
        Answer(subject=subject, verdict=Verdict.ERROR, error="")
    for bad in (-1.0, float("nan")):
        with pytest.raises(ValidationError):
            Answer(subject=subject, verdict=Verdict.ALLOW, latency_ms=bad)


def _answer() -> Answer:
    return Answer(subject={"type": "user", "id": "alice"}, verdict=Verdict.ALLOW)


def test_hop_answer_count_matches_mode() -> None:
    def hop(mode: str, count: int) -> HopResult:
        return HopResult.model_validate(
            {
                "caller": "user",
                "target": "t",
                "kind": "tool",
                "mode": mode,
                "verdict": PathVerdict.ALLOW,
                "answers": [_answer()] * count,
            }
        )

    hop("undeclared", 2)
    hop("agent", 1)
    for mode, count in (("undeclared", 1), ("agent", 2), ("user", 0)):
        with pytest.raises(ValidationError, match="two answers exactly"):
            hop(mode, count)


def test_escalation_row_rejects_user_mode() -> None:
    with pytest.raises(ValidationError, match="never has mode 'user'"):
        EscalationRow(
            case_id=None,
            role="r",
            tool="t",
            via="a",
            risk=Risk.CRITICAL,
            mode="user",
            path=("a",),
            result=EscalationResult.NONE,
        )


def test_answer_subject_must_be_plain_json() -> None:
    with pytest.raises(ValidationError, match="finite"):
        Answer(subject={"type": "user", "properties": {"x": float("nan")}}, verdict=Verdict.ALLOW)


def test_report_with_the_deepest_allowed_answer_serializes(make_report) -> None:
    from lockwalk.models import MAX_QUERY_DEPTH, CaseDecision, HopResult
    from lockwalk.report import report_to_dict

    value: object = 1
    for _ in range(MAX_QUERY_DEPTH - 1):
        value = [value]
    # the subject is depth 0, so the innermost scalar sits exactly at the cap
    answer = Answer(
        subject={"type": "user", "id": "a", "properties": value},
        verdict=Verdict.ALLOW,
    )
    hop = HopResult(
        caller="user",
        target="t",
        kind="tool",
        mode="agent",
        verdict=PathVerdict.ALLOW,
        answers=(answer,),
    )
    report = make_report()
    case = report.cases[0].model_copy(
        update={"decision": CaseDecision(verdict=PathVerdict.ALLOW, hops=(hop,))}
    )
    report = report.model_copy(update={"cases": (case, *report.cases[1:])})
    document = report_to_dict(report, generated_at=datetime.now(UTC), version="t")
    assert json.dumps(document)
