# tests/test_inspection.py
"""lockwalk inspect --case: read the files, render one case."""

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lockwalk.evidence import Event, EventType, Evidence, EvidenceHeader, write_evidence
from lockwalk.inspection import InspectError, inspect_case
from lockwalk.models import (
    CaseStatus,
    ControlRow,
    DoorCall,
    DoorControlRow,
    DoorResult,
    DoorRun,
    DoorStatus,
    EscalationResult,
    EscalationRow,
    IdentityCheckRow,
    IdentityObservation,
    IdentityResult,
    Risk,
)
from lockwalk.report import write_report

RUN = "ab" * 16
NOW = datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
ALICE = {"type": "user", "id": "alice"}


def events() -> tuple[Event, ...]:
    return (
        Event(
            event="E-0001",
            run=RUN,
            time=0.0,
            source="test_runner",
            type="run.started",
            detail={
                "lockwalk_version": "0.1.0",
                "policy_adapter": "authzen:http://pdp",
                "started_at": "2026-11-08T10:00:00Z",
            },
        ),
        Event(
            event="E-0002",
            run=RUN,
            time=0.011,
            source="policy_adapter",
            type="authz.evaluated",
            query="Q-0001",
            detail={
                "request": {
                    "subject": ALICE,
                    "action": {"name": "portfolio:read"},
                    "resource": {"type": "portfolio", "id": "bob-portfolio"},
                    "context": {},
                },
                "verdict": "deny",
                "latency_ms": 12.0,
            },
        ),
        Event(
            event="E-0003",
            run=RUN,
            time=0.4,
            source="harness",
            type="harness.job",
            case="CASE-003",
            mode="direct",
            invocation="I-0001",
            detail={
                "tool": "read_portfolio",
                "arg_names": ["owner"],
                "subject": ALICE,
                "duration_ms": 900.0,
                "status": "ran",
                "side_effect_calls": 1,
            },
        ),
        Event(
            event="E-0004",
            run=RUN,
            time=0.402,
            source="harness",
            type="door.identity_set",
            case="CASE-003",
            mode="direct",
            invocation="I-0001",
            detail={"subject": ALICE},
        ),
        Event(
            event="E-0005",
            run=RUN,
            time=0.403,
            source="harness",
            type="door.called",
            case="CASE-003",
            mode="direct",
            invocation="I-0001",
            detail={"subject": ALICE, "decision": False},
        ),
        Event(
            event="E-0006",
            run=RUN,
            time=0.404,
            source="harness",
            type="effect.counted",
            case="CASE-003",
            mode="direct",
            invocation="I-0001",
            detail={"tool": "read_portfolio"},
        ),
        Event(
            event="E-0007",
            run=RUN,
            time=1.0,
            source="test_runner",
            type="run.finished",
            detail={"exit_code": 1, "cases": 4},
        ),
    )


def write_files(
    tmp_path: Path, make_report, *, evidence: bool = True, run: str = RUN, mode: str = "test"
) -> Path:
    report = make_report()
    door = DoorResult(
        status=DoorStatus.FAIL_EXECUTION,
        runs=(
            DoorRun(
                mode="direct",
                status=DoorStatus.FAIL_EXECUTION,
                subject=ALICE,
                side_effect_calls=1,
                door_calls=(DoorCall(subject=ALICE, decision=False),),
                notes=("the IAM denied this, but the side effect ran",),
            ),
        ),
    )
    cases = tuple(
        row.model_copy(
            update={
                "status": CaseStatus.FAIL_EXECUTION,
                "door": door,
                "evidence": ("E-0002", "E-0003", "E-0004", "E-0005", "E-0006"),
            }
        )
        if row.id == "CASE-003"
        else row.model_copy(update={"evidence": ()})
        for row in report.cases
    )
    report = report.model_copy(
        update={
            "mode": mode,
            "run_id": RUN if mode == "test" else None,
            "cases": cases,
            "controls": (
                ControlRow(
                    action="portfolio:read", resource_type="portfolio", allowed=False, evidence=()
                ),
            ),
            "door_controls": (
                DoorControlRow(
                    tool="read_portfolio", proven=True, proven_by="CASE-002 (direct)", evidence=()
                ),
            ),
        }
    )
    write_report(report, tmp_path, generated_at=NOW, version="x")
    if evidence:
        header = EvidenceHeader(
            run=run, lockwalk_version="0.1.0", started_at="2026-11-08T10:00:00Z", events=7
        )
        found = (
            events()
            if run == RUN
            else tuple(event.model_copy(update={"run": run}) for event in events())
        )
        write_evidence(Evidence(header=header, events=found), tmp_path)
    return tmp_path


def test_a_failing_case_shows_its_timeline(tmp_path: Path, make_report) -> None:
    lines = inspect_case(write_files(tmp_path, make_report), "CASE-003")
    text = "\n".join(lines)
    assert lines[0] == "lockwalk inspect - CASE-003"
    assert "CASE-003  FAIL_EXECUTION" in text
    assert "IAM" in text and "user:alice" in text and "portfolio:read" in text
    assert "-> deny" in text and "Q-0001" in text
    assert "door asked: user:alice -> deny" in text
    assert "side effect of read_portfolio counted" in text
    assert "the IAM denied this, but the side effect ran" in text
    assert "control: portfolio:read + portfolio was never allowed in this run" in text
    assert "door control: read_portfolio proven by CASE-002 (direct)" in text
    assert all(line.isascii() for line in lines)
    order = [text.index(part) for part in ("+0.011s", "+0.400s", "+0.403s", "+0.404s")]
    assert order == sorted(order)


def test_unknown_case_suggests_close_ids(tmp_path: Path, make_report) -> None:
    with pytest.raises(InspectError) as caught:
        inspect_case(write_files(tmp_path, make_report), "CASE-03")
    assert "CASE-003" in str(caught.value)


def test_missing_evidence_is_a_gap_not_an_error(tmp_path: Path, make_report) -> None:
    text = "\n".join(inspect_case(write_files(tmp_path, make_report, evidence=False), "CASE-003"))
    assert "no evidence file" in text


def test_evidence_from_another_run_is_refused(tmp_path: Path, make_report) -> None:
    with pytest.raises(InspectError) as caught:
        inspect_case(write_files(tmp_path, make_report, run="cd" * 16), "CASE-003")
    assert "another run" in str(caught.value)


def test_a_static_report_says_to_run_lockwalk_test(tmp_path: Path, make_report) -> None:
    folder = write_files(tmp_path, make_report, evidence=False, mode="static")
    text = "\n".join(inspect_case(folder, "CASE-001"))
    assert "lockwalk test" in text


def test_a_ref_missing_from_the_evidence_file_is_refused(tmp_path: Path, make_report) -> None:
    folder = write_files(tmp_path, make_report)
    header = EvidenceHeader(
        run=RUN, lockwalk_version="0.1.0", started_at="2026-11-08T10:00:00Z", events=2
    )
    write_evidence(Evidence(header=header, events=events()[:2]), folder)
    with pytest.raises(InspectError):
        inspect_case(folder, "CASE-003")


def test_missing_report_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(InspectError) as caught:
        inspect_case(tmp_path, "CASE-001")
    assert "lockwalk test" in str(caught.value)


def test_terminal_escapes_cannot_get_through(tmp_path: Path, make_report) -> None:
    folder = write_files(tmp_path, make_report)
    path = folder / "evidence.jsonl"
    text = path.read_text(encoding="utf-8").replace("read_portfolio", "read\\u001b[31m")
    path.write_text(text, encoding="utf-8")
    lines = inspect_case(folder, "CASE-003")
    assert all("\x1b" not in line for line in lines)


# --- hand-made evidence for odd values, caps, and the other row kinds ---


def job(number: int, detail: dict, *, type_: EventType = "harness.job", time: float = 1.0) -> Event:
    return Event(
        event=f"E-{number:04d}",
        run=RUN,
        time=time,
        source="harness",
        type=type_,
        case="CASE-003",
        mode="direct",
        invocation="I-0001",
        detail=detail,
    )


def authz(number: int, detail: dict, time: float = 0.5) -> Event:
    return Event(
        event=f"E-{number:04d}",
        run=RUN,
        time=time,
        source="policy_adapter",
        type="authz.evaluated",
        query=f"Q-{number:04d}",
        detail=detail,
    )


def write_custom(
    tmp_path: Path,
    make_report,
    found: tuple[Event, ...],
    refs: tuple[str, ...] | None = None,
    case_changes: dict | None = None,
    **changes,
) -> Path:
    """A test report whose CASE-003 points at `refs` (default: all of `found`)."""
    report = make_report()
    row_changes = {
        "evidence": tuple(event.event for event in found) if refs is None else refs,
        **(case_changes or {}),
    }
    cases = tuple(
        row.model_copy(update=row_changes) if row.id == "CASE-003" else row for row in report.cases
    )
    report = report.model_copy(update={"mode": "test", "run_id": RUN, "cases": cases, **changes})
    write_report(report, tmp_path, generated_at=NOW, version="x")
    header = EvidenceHeader(
        run=RUN, lockwalk_version="0.1.0", started_at="2026-11-08T10:00:00Z", events=len(found)
    )
    write_evidence(Evidence(header=header, events=found), tmp_path)
    return tmp_path


def render(folder: Path) -> str:
    return "\n".join(inspect_case(folder, "CASE-003"))


def test_odd_value_types_render_as_question_marks(tmp_path: Path, make_report) -> None:
    found = (
        authz(
            1,
            {
                "request": {"subject": "nobody", "action": {"name": ["x"]}, "resource": 5},
                "verdict": {"nested": "secret-nested"},
                "latency_ms": 10**400,
                "error": {"leak": "secret-error"},
            },
        ),
        authz(2, {"request": {}, "verdict": "allow", "latency_ms": True}, time=0.6),
        job(3, {"tool": {"a": 1}, "route": "not a list", "status": ["x"]}, time=0.7),
        job(4, {"tool": "t", "route": ["a", 5], "status": "ran"}, time=0.8),
        job(5, {"subject": [1], "error": {"deep": "secret-door"}}, type_="door.called", time=0.9),
    )
    text = render(write_custom(tmp_path, make_report, found))
    assert "secret" not in text
    assert "1 ms" not in text
    assert "?" in text
    assert " via " not in text


def test_act_chain_is_shown(tmp_path: Path, make_report) -> None:
    subject = {
        "type": "agent",
        "id": "a1",
        "properties": {"act": {"type": "agent", "id": "a2", "act": {"type": "user", "id": "u"}}},
    }
    found = (job(1, {"subject": subject}, type_="door.identity_set"),)
    text = render(write_custom(tmp_path, make_report, found))
    assert "agent:a1 [act: agent:a2 < user:u]" in text


def test_a_long_act_chain_is_shown_whole_and_a_cut_is_marked(
    tmp_path: Path, make_report, monkeypatch: pytest.MonkeyPatch
) -> None:
    act: dict = {"type": "user", "id": "l40"}
    for number in range(39, 0, -1):
        act = {"type": "agent", "id": f"l{number}", "act": act}
    subject = {"type": "agent", "id": "a1", "properties": {"act": act}}
    found = (job(1, {"subject": subject}, type_="door.identity_set"),)
    folder = write_custom(tmp_path, make_report, found)
    text = render(folder)
    assert "[act: agent:l1 < agent:l2 <" in text
    assert "agent:l39 < user:l40]" in text and "..." not in text
    monkeypatch.setattr("lockwalk.inspection.MAX_ACT_LINKS", 5)
    assert "agent:l5 < ...]" in render(folder)


def test_a_long_route_is_cut_with_a_marker(
    tmp_path: Path, make_report, monkeypatch: pytest.MonkeyPatch
) -> None:
    route = [f"agent-{number}" for number in range(1, 8)]
    found = (job(1, {"route": route}),)
    folder = write_custom(tmp_path, make_report, found)
    assert "agent-7" in render(folder) and "-> ..." not in render(folder)
    monkeypatch.setattr("lockwalk.inspection.MAX_ROUTE_AGENTS", 3)
    assert "agent-1 -> agent-2 -> agent-3 -> ..." in render(folder)


def test_long_values_are_cut_at_200_characters(tmp_path: Path, make_report) -> None:
    found = (job(1, {"tool": "x" * 5000, "status": "ran"}),)
    text = render(write_custom(tmp_path, make_report, found))
    assert "x" * 200 + "..." in text
    assert "x" * 201 not in text


def test_escalation_identity_and_control_rows(tmp_path: Path, make_report) -> None:
    found = (
        authz(
            1,
            {
                "request": {
                    "subject": ALICE,
                    "action": {"name": "portfolio:read"},
                    "resource": {"type": "portfolio", "id": "p"},
                },
                "verdict": "allow",
            },
        ),
    )
    escalation = EscalationRow(
        case_id="CASE-003",
        role="analyst",
        tool="read_portfolio",
        via="finance-agent",
        risk=Risk.HIGH,
        mode="agent",
        path=("finance-agent",),
        result=EscalationResult.NONE,
        notes=("escalation note",),
    )
    seen = IdentityObservation(
        mode="direct", expected=ALICE, observed=(ALICE,), result=IdentityResult.MATCH
    )
    identity = IdentityCheckRow(
        case_id="CASE-003",
        path=("finance-agent",),
        tool="read_portfolio",
        result=IdentityResult.MATCH,
        observations=(seen,),
    )
    not_run = IdentityCheckRow(
        case_id="CASE-003",
        path=("finance-agent",),
        tool="read_portfolio",
        result=IdentityResult.NOT_RUN,
        notes=("no harness",),
    )
    control = ControlRow(
        action="portfolio:read", resource_type="portfolio", allowed=True, allowed_by="CASE-001"
    )
    folder = write_custom(
        tmp_path,
        make_report,
        found,
        escalations=(escalation,),
        identity_checks=(identity, not_run),
        controls=(control,),
    )
    text = render(folder)
    assert "escalation: NONE via finance-agent; user -> ?, route identity -> ?" in text
    assert "    escalation note" in text
    assert "identity: MATCH" in text
    assert "direct: expected user:alice, saw user:alice" in text
    assert "identity: NOT_RUN" in text
    assert "- identity check: no harness" in text
    assert "control: portfolio:read + portfolio allowed by CASE-001" in text
    assert "no positive control" not in text


def test_a_not_tested_door_is_a_gap(tmp_path: Path, make_report) -> None:
    door = DoorResult(status=DoorStatus.NOT_TESTED)
    folder = write_custom(
        tmp_path, make_report, (job(1, {"tool": "t"}),), case_changes={"door": door}
    )
    assert "- door test: not tested" in render(folder)


def test_timeline_dropped_is_a_gap_and_bool_is_not(tmp_path: Path, make_report) -> None:
    found = (job(1, {"tool": "t", "status": "ran", "timeline_dropped": 3}),)
    text = render(write_custom(tmp_path, make_report, found))
    assert "I-0001: 3 more door or side effect moments were not kept" in text
    other = tmp_path / "b"
    other.mkdir()
    found = (job(1, {"tool": "t", "status": "ran", "timeline_dropped": True}),)
    assert "were not kept" not in render(write_custom(other, make_report, found))


def test_a_repeated_ref_is_shown_once(tmp_path: Path, make_report) -> None:
    found = (job(1, {"tool": "t", "status": "ran"}),)
    folder = write_custom(tmp_path, make_report, found, refs=("E-0001", "E-0001"))
    assert render(folder).count("run I-0001") == 1


def test_the_timeline_is_capped_at_200_events(tmp_path: Path, make_report) -> None:
    found = tuple(
        job(number, {}, type_="effect.counted", time=number / 1000) for number in range(1, 251)
    )
    text = render(write_custom(tmp_path, make_report, found))
    assert text.count("side effect of") == 200
    assert "50 more events are not shown; see evidence.jsonl" in text


def test_twenty_thousand_events_finish_quickly(tmp_path: Path, make_report) -> None:
    found = tuple(
        authz(
            number,
            {
                "request": {
                    "subject": ALICE,
                    "action": {"name": f"a{number}"},
                    "resource": {"type": f"r{number}", "id": "x"},
                },
                "verdict": "deny",
            },
            time=number / 1000,
        )
        for number in range(1, 20001)
    )
    folder = write_custom(tmp_path, make_report, found)
    start = time.perf_counter()
    text = render(folder)
    assert time.perf_counter() - start < 15
    assert "19800 more events are not shown" in text


def test_closest_match_hint_is_exact(tmp_path: Path, make_report) -> None:
    with pytest.raises(InspectError) as caught:
        inspect_case(write_files(tmp_path, make_report), "CASE-03")
    message = str(caught.value)
    assert message.startswith("coverage.json has no case 'CASE-03'; closest: CASE-00")
    assert "CASE-003" in message


def test_a_static_report_ignores_stale_or_garbage_evidence(tmp_path: Path, make_report) -> None:
    folder = write_files(tmp_path, make_report, run="cd" * 16, mode="static")
    text = "\n".join(inspect_case(folder, "CASE-001"))
    assert "lockwalk test" in text
    assert "never allowed" not in text
    (folder / "evidence.jsonl").write_bytes(b"\xff garbage {")
    assert "lockwalk test" in "\n".join(inspect_case(folder, "CASE-001"))
