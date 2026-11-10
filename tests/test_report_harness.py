from datetime import UTC, datetime
from typing import Any

from lockwalk.models import (
    CaseRow,
    CaseStatus,
    ControlRow,
    DoorControlRow,
    DoorResult,
    EscalationResult,
    EscalationRow,
    GateViolation,
    IdentityCheckRow,
    IdentityObservation,
    IdentityResult,
    Risk,
)
from lockwalk.report import _who, render_coverage, report_to_dict, violation_line


def _case(case_id: str, status: CaseStatus = CaseStatus.PASS, **extra) -> CaseRow:
    fields: dict[str, Any] = {
        "id": case_id,
        "agent": "finance-agent",
        "path": ("finance-agent",),
        "tool": "read_portfolio",
        "action": "portfolio:read",
        "expect": "allow",
        "status": status,
        "action_verified": True,
        "problems": (),
    }
    return CaseRow.model_validate({**fields, **extra})


def _test_report(make_report, **update):
    base = make_report()
    counts = {s.value: 0 for s in CaseStatus}
    metrics = base.metrics.model_copy(update={"cases_by_status": counts, "executed_cases": 0})
    fields = {"mode": "test", "policy_adapter": "authzen", "metrics": metrics}
    return base.model_copy(update={**fields, **update})


def _call(kind: str = "agent", ident: str = "finance-agent", **extra) -> dict[str, Any]:
    return {"subject": {"type": kind, "id": ident, **extra}, "decision": True}


def _run(mode="direct", status="OK", n=1, calls=(), notes=(), **extra) -> dict[str, Any]:
    return {
        "mode": mode,
        "status": status,
        "subject": {"type": "agent", "id": "finance-agent"},
        "side_effect_calls": n,
        "door_calls": calls,
        "notes": notes,
        **extra,
    }


def _door(status: str, runs=(), notes=()) -> DoorResult:
    return DoorResult.model_validate({"status": status, "runs": runs, "notes": notes})


def _cases_lines(make_report, door: DoorResult) -> list[str]:
    report = _test_report(make_report, cases=(_case("CASE-001", door=door),))
    lines = render_coverage(report)
    start = lines.index("Cases:")
    return lines[start + 2 :]


def test_run_line_with_door_call_and_more(make_report):
    door = _door("OK", runs=(_run(calls=(_call(), _call("user", "alice"), _call())),))
    lines = _cases_lines(make_report, door)
    assert lines[0] == (
        "    door (direct): OK, side effect ran 1 time(s), door saw agent finance-agent (+2 more)"
    )


def test_run_line_single_door_call_has_no_more(make_report):
    door = _door("OK", runs=(_run(calls=(_call(),)),))
    lines = _cases_lines(make_report, door)
    assert lines[0] == (
        "    door (direct): OK, side effect ran 1 time(s), door saw agent finance-agent"
    )


def test_run_line_without_door_calls_does_not_repeat_the_run_notes(make_report):
    door = _door(
        "FAIL_EXECUTION",
        runs=(_run("scripted", "FAIL_EXECUTION", n=0, notes=("tool raised",)),),
    )
    lines = _cases_lines(make_report, door)
    # The run's notes are printed once, as the case's own notes (analyzer._with_door).
    assert lines[0] == "    door (scripted): FAIL_EXECUTION, side effect ran 0 time(s)"
    assert "tool raised" not in chr(10).join(lines)


def test_ok_run_notes_are_not_shown(make_report):
    door = _door("OK", runs=(_run(notes=("hidden",), calls=(_call(),)),))
    assert "hidden" not in "\n".join(_cases_lines(make_report, door))


def test_not_tested_lines(make_report):
    lines = _cases_lines(make_report, _door("NOT_TESTED", notes=("no fixture", "second")))
    assert lines[:2] == ["    door: NOT_TESTED (no fixture)", "      second"]
    lines = _cases_lines(make_report, _door("NOT_TESTED"))
    assert lines[0] == "    door: NOT_TESTED"


def test_other_door_notes(make_report):
    door = _door("OK", runs=(_run(calls=(_call(),)),), notes=("scripted did not run",))
    lines = _cases_lines(make_report, door)
    assert lines[1] == "    door: scripted did not run"


def test_error_without_runs_shows_notes(make_report):
    lines = _cases_lines(make_report, _door("ERROR", notes=("worker died",)))
    assert lines[0] == "    door: worker died"


def test_control_character_in_subject_id_is_escaped(make_report):
    door = _door("OK", runs=(_run(calls=(_call("user", "al\x1b[2Jice"),)),))
    lines = _cases_lines(make_report, door)
    assert "door saw user al\\x1b[2Jice" in lines[0]
    assert all("\x1b" not in line for line in lines)


def _obs(mode, expected, observed, result=IdentityResult.MISMATCH) -> IdentityObservation:
    return IdentityObservation(mode=mode, expected=expected, observed=observed, result=result)


def _identity_rows() -> tuple[IdentityCheckRow, ...]:
    inner = {"type": "agent", "id": "a"}
    chain = {"type": "user", "id": "alice", "act": {"type": "agent", "id": "b", "act": inner}}
    return (
        IdentityCheckRow(
            case_id="CASE-001",
            path=("finance-agent",),
            tool="read_portfolio",
            result=IdentityResult.MISMATCH,
            observations=(
                _obs("direct", {"type": "agent", "id": "finance-agent"}, (chain,)),
                _obs("scripted", None, ()),
            ),
            notes=("a note",),
        ),
        IdentityCheckRow(
            case_id="CASE-002", path=("a", "b"), tool="t", result=IdentityResult.OBSERVED
        ),
        IdentityCheckRow(case_id="CASE-003", path=("a",), tool="t", result=IdentityResult.MATCH),
        IdentityCheckRow(case_id="CASE-004", path=("a",), tool="t", result=IdentityResult.MATCH),
    )


def test_identity_block(make_report):
    report = _test_report(make_report, identity_checks=_identity_rows())
    lines = render_coverage(report)
    start = lines.index("Identity checks: 1 MISMATCH, 1 OBSERVED, 2 MATCH")
    assert lines[start - 1] == ""
    assert lines[start + 1 : start + 7] == [
        "  MISMATCH  CASE-001: finance-agent -> read_portfolio",
        "    direct: expected agent finance-agent, the door received "
        "user alice via agent b via agent a",
        "    scripted: expected nothing declared, the door received nothing",
        "    a note",
        "  OBSERVED  CASE-002: a -> b -> t",
        "",
    ]


def test_identity_ids_are_escaped(make_report):
    row = IdentityCheckRow(
        case_id="CASE-001",
        path=("a",),
        tool="t",
        result=IdentityResult.MISMATCH,
        observations=(_obs("direct", None, ({"type": "user", "id": "x\ny"},)),),
    )
    lines = render_coverage(_test_report(make_report, identity_checks=(row,)))
    assert any("user x\\x0ay" in line for line in lines)
    assert not any(line in ("y", "y\n") for line in lines)


def test_door_controls_block(make_report):
    rows = (
        DoorControlRow(tool="read_portfolio", proven=True, proven_by="CASE-001 (direct)"),
        DoorControlRow(tool="execute_trade", proven=False),
    )
    lines = render_coverage(_test_report(make_report, door_controls=rows))
    start = lines.index("Door controls missing:")
    assert lines[start - 1] == ""
    assert lines[start + 1 : start + 3] == [
        "  execute_trade: its side effect was never counted",
        "",
    ]
    proven_only = rows[:1]
    lines = render_coverage(_test_report(make_report, door_controls=proven_only))
    assert "Door controls missing:" not in lines


def test_block_order(make_report):
    escalation = EscalationRow(
        case_id=None,
        role="analyst",
        tool="execute_trade",
        via="finance-agent",
        risk=Risk.CRITICAL,
        mode="agent",
        path=("finance-agent",),
        result=EscalationResult.ESCALATION,
    )
    control = ControlRow(action="portfolio:read", resource_type="portfolio", allowed=False)
    report = _test_report(
        make_report,
        cases=(_case("CASE-001"),),
        escalations=(escalation,),
        controls=(control,),
        identity_checks=_identity_rows(),
        door_controls=(DoorControlRow(tool="t", proven=False),),
    )
    lines = render_coverage(report)
    headers = [
        line.split(":")[0] + ":"
        for line in lines
        if line.startswith(
            ("Cases:", "Escalation checks", "Identity checks", "Positive controls", "Door controls")
        )
    ]
    assert headers == [
        "Cases:",
        "Escalation checks:",
        "Identity checks:",
        "Positive controls missing:",
        "Door controls missing:",
    ]


def test_violation_line():
    violation = GateViolation(rule="fail_on_identity_mismatch", case_id="CASE-007")
    assert violation_line(violation) == "  - fail_on_identity_mismatch: CASE-007"


def test_report_without_door_fields_renders_as_stage_one(make_report):
    cases = (_case("CASE-001"), _case("CASE-002", CaseStatus.FAIL_POLICY, notes=("n",)))
    report = _test_report(make_report, cases=cases)
    lines = render_coverage(report)
    assert not any("door" in line.lower() for line in lines)
    assert not any(line.startswith(("Identity checks", "Door controls")) for line in lines)
    start = lines.index("Cases:")
    assert lines[start + 1 : start + 5] == [
        "  CASE-001  PASS            finance-agent -> read_portfolio  (expect allow, IAM -)",
        "  CASE-002  FAIL_POLICY     finance-agent -> read_portfolio  (expect allow, IAM -)",
        "    n",
        "",
    ]


def test_json_holds_door_fields(make_report):
    door = _door("OK", runs=(_run(calls=(_call(),)),))
    report = _test_report(
        make_report,
        cases=(_case("CASE-001", door=door),),
        identity_checks=_identity_rows(),
    )
    document = report_to_dict(report, generated_at=datetime(2026, 1, 1, tzinfo=UTC), version="x")
    assert document["cases"][0]["door"]["status"] == "OK"
    assert document["identity_checks"][0]["result"] == "MISMATCH"
    assert document["door_controls"] == []


def test_error_only_door_call(make_report):
    error_call = {"error": "door blew up"}
    door = _door("INCONCLUSIVE", runs=(_run(status="INCONCLUSIVE", calls=(error_call,)),))
    line = _cases_lines(make_report, door)[0]
    assert line == (
        "    door (direct): INCONCLUSIVE, side effect ran 1 time(s), door call failed: door blew up"
    )
    assert "door saw" not in line


def test_mix_of_error_and_subject_calls(make_report):
    calls = ({"error": "first"}, _call("user", "alice"), {"error": "second"}, _call())
    line = _cases_lines(make_report, _door("OK", runs=(_run(calls=calls),)))[0]
    assert line == (
        "    door (direct): OK, side effect ran 1 time(s), door saw user alice (+1 more), "
        "door call failed: first"
    )


def test_exception_text_is_on_the_run_line(make_report):
    run = _run("scripted", "FAIL_EXECUTION", n=0, exception="ValueError", notes=("n1",))
    lines = _cases_lines(make_report, _door("FAIL_EXECUTION", runs=(run,)))
    assert lines[0] == (
        "    door (scripted): FAIL_EXECUTION, side effect ran 0 time(s) (raised ValueError)"
    )
    assert "n1" not in chr(10).join(lines)


def test_received_subjects_are_capped_at_three(make_report):
    observed = tuple({"type": "user", "id": f"u{i}"} for i in range(5))
    row = IdentityCheckRow(
        case_id="CASE-001",
        path=("a",),
        tool="t",
        result=IdentityResult.MISMATCH,
        observations=(_obs("direct", None, observed),),
    )
    lines = render_coverage(_test_report(make_report, identity_checks=(row,)))
    assert (
        "    direct: expected nothing declared, the door received "
        "user u0, user u1, user u2 (+2 more)"
    ) in lines


def test_who_cuts_long_ids_and_types():
    text = _who({"type": "t" * 100, "id": "i" * 100})
    assert text == "t" * 80 + "... " + "i" * 80 + "..."
    assert _who({"type": "user", "id": "i" * 80}) == "user " + "i" * 80


def test_who_stops_at_the_depth_limit():
    subject: dict = {"type": "agent", "id": "leaf"}
    for i in range(200):
        subject = {"type": "agent", "id": f"n{i}", "act": subject}
    assert len(_who(subject).split(" via ")) == 65


def test_not_run_row_and_row_order(make_report):
    rows = (
        IdentityCheckRow(case_id="CASE-001", path=("a",), tool="t", result=IdentityResult.NOT_RUN),
        IdentityCheckRow(case_id="CASE-002", path=("a",), tool="t", result=IdentityResult.MATCH),
        IdentityCheckRow(case_id="CASE-003", path=("a",), tool="t", result=IdentityResult.MISMATCH),
    )
    lines = render_coverage(_test_report(make_report, identity_checks=rows))
    start = lines.index("Identity checks: 1 MISMATCH, 1 NOT_RUN, 1 MATCH")
    assert lines[start + 1 : start + 3] == [
        "  NOT_RUN   CASE-001: a -> t",
        "  MISMATCH  CASE-003: a -> t",
    ]
