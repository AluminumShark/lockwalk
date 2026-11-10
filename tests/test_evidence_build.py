"""build_evidence: events and report refs from one run's facts."""

import json
import time as clock_module
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from conftest import ReportFactory, finance_case

from lockwalk.evidence import (
    MAX_LINE_BYTES,
    Event,
    Evidence,
    event_line_bytes,
    id_number,
    read_evidence,
    write_evidence,
)
from lockwalk.evidence_build import (
    DoorJob,
    RunRecorder,
    _Draft,
    _make_event,
    build_evidence,
)
from lockwalk.harness.protocol import DirectJob, Observed, ScriptedJob, TimelineItem
from lockwalk.inspection import inspect_case
from lockwalk.models import (
    ControlRow,
    CoverageReport,
    DoorCall,
    DoorControlRow,
    EscalationResult,
    EscalationRow,
    IdentityCheckRow,
    IdentityResult,
    Risk,
    Verdict,
)
from lockwalk.policy.base import Decision, Entity, Query, QueryAction
from lockwalk.queries import CaseAsk, HopAsk, QueryPlan, RowAsk
from lockwalk.report import write_report

ALICE = {"type": "user", "id": "alice"}


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def query(user: str, action: str = "trade:execute") -> Query:
    return Query(
        subject=Entity(type="user", id=user, properties={"url": "https://u:p@iam.example/x"}),
        action=QueryAction(name=action),
        resource=Entity(type="order", id="o-1"),
        context={"lockwalk": {"case": "CASE-003"}},
    )


def case_ask(case_id: str, expect: str, asked: tuple[Query, ...]) -> CaseAsk:
    hop = HopAsk(
        caller="user",
        target="execute_trade",
        kind="tool",
        mode="user",
        queries=asked,
        control=("trade:execute", "order"),
    )
    return CaseAsk(
        case_id=case_id,
        role="analyst",
        tool="execute_trade",
        expect="allow" if expect == "allow" else "deny",
        route=("finance-agent",),
        risk=Risk.CRITICAL,
        hops=(hop,),
        plain_user=None,
    )


def plan_for(q_allow: Query, q_deny: Query) -> QueryPlan:
    return QueryPlan(
        cases=(case_ask("CASE-001", "allow", (q_allow,)), case_ask("CASE-003", "deny", (q_deny,))),
        rows=(),
        warnings=(),
    )


def direct_job(case_id: str) -> DirectJob:
    return DirectJob(
        case_id=case_id, tool="execute_trade", args={"order_id": "SECRET-ARG"}, subject=ALICE
    )


def observed_run(*, counted: bool, decision: bool) -> Observed:
    call = DoorCall(subject=ALICE, decision=decision)
    timeline = (
        TimelineItem(seq=1, at_ms=0.0, kind="identity", subject=ALICE),
        TimelineItem(seq=2, at_ms=1.0, kind="door", call=call),
    )
    if counted:
        timeline += (TimelineItem(seq=3, at_ms=2.0, kind="effect", tool="execute_trade"),)
    return Observed(
        side_effect_calls=1 if counted else 0,
        door_calls=(call,),
        timeline=timeline,
        elapsed_ms=4.0,
    )


class Runner:
    def __init__(self, clock: Clock, results: dict[str, Observed]) -> None:
        self.clock, self.results = clock, results

    def run(self, job: DoorJob) -> Observed:
        self.clock.now += 0.5
        return self.results[job.case_id]


def build(make_report: ReportFactory) -> tuple[Evidence, CoverageReport]:
    clock = Clock()
    recorder = RunRecorder(
        clock=clock, now=lambda: datetime(2026, 11, 8, 10, 0, tzinfo=UTC), run_id="ab" * 16
    )
    q_allow, q_deny = query("bob"), query("alice")
    plan = plan_for(q_allow, q_deny)
    clock.now = 0.1
    recorder.batch_sent([q_allow.key(), q_deny.key()])
    answers = {
        q_allow.key(): Decision(verdict=Verdict.ALLOW, latency_ms=3.25),
        q_deny.key(): Decision(verdict=Verdict.DENY, reason="not a trader"),
    }
    runner = Runner(
        clock,
        {
            "CASE-001": observed_run(counted=True, decision=True),
            "CASE-003": observed_run(counted=True, decision=False),
        },
    )
    recorder.run_job(runner, direct_job("CASE-001"))
    recorder.run_job(runner, direct_job("CASE-003"))
    clock.now = 2.0
    recorder.finish()
    base = make_report(
        cases=[
            finance_case(
                "CASE-001",
                "finance-agent",
                "execute_trade",
                "trade:execute",
                "dummy-order",
                "allow",
            ),
            finance_case(
                "CASE-003",
                "finance-agent",
                "execute_trade",
                "trade:execute",
                "dummy-order",
                "deny",
            ),
        ]
    )
    report = base.model_copy(
        update={
            "controls": (
                ControlRow(
                    action="trade:execute",
                    resource_type="order",
                    allowed=True,
                    allowed_by="CASE-001",
                ),
            ),
            "door_controls": (
                DoorControlRow(tool="execute_trade", proven=True, proven_by="CASE-001 (direct)"),
            ),
            "identity_checks": (
                IdentityCheckRow(
                    case_id="CASE-003",
                    path=("finance-agent",),
                    tool="execute_trade",
                    result=IdentityResult.MATCH,
                ),
            ),
        }
    )
    return build_evidence(
        recorder,
        queries=plan,
        answers=answers,
        report=report,
        policy_adapter="authzen:x",
        version="0.1.0",
    )


def test_events_are_numbered_in_time_order(make_report: ReportFactory) -> None:
    evidence, _ = build(make_report)
    types = [event.type for event in evidence.events]
    assert types[0] == "run.started" and types[-1] == "run.finished"
    assert types.count("authz.evaluated") == 2
    assert types.count("harness.job") == 2
    times = [event.time for event in evidence.events]
    assert times == sorted(times)
    assert [id_number(event.event) for event in evidence.events] == list(
        range(1, len(evidence.events) + 1)
    )
    assert evidence.header.events == len(evidence.events)
    assert evidence.header.run == "ab" * 16
    assert all(isinstance(event.time, float) for event in evidence.events)


def test_authz_events_hold_the_masked_request_and_the_answer(
    make_report: ReportFactory,
) -> None:
    evidence, _ = build(make_report)
    authz = [event for event in evidence.events if event.type == "authz.evaluated"]
    assert [event.query for event in authz] == ["Q-0001", "Q-0002"]
    assert authz[0].detail["verdict"] == "allow" and authz[0].detail["latency_ms"] == 3.25
    assert authz[1].detail["reason"] == "not a trader"
    text = json.dumps([event.model_dump(mode="json") for event in evidence.events])
    assert "u:p@" not in text  # URL credentials are masked
    assert "SECRET-ARG" not in text  # tool argument values are never kept
    job = next(event for event in evidence.events if event.type == "harness.job")
    assert job.detail["arg_names"] == ["order_id"]


def test_timeline_events_follow_their_job(make_report: ReportFactory) -> None:
    evidence, _ = build(make_report)
    runs = [event for event in evidence.events if event.invocation == "I-0002"]
    assert [event.type for event in runs] == [
        "harness.job",
        "door.identity_set",
        "door.called",
        "effect.counted",
    ]
    assert all(event.case == "CASE-003" and event.mode == "direct" for event in runs)
    assert runs[2].detail == {"subject": ALICE, "decision": False}


def test_report_rows_point_at_their_events(make_report: ReportFactory) -> None:
    evidence, report = build(make_report)
    by_id = {event.event: event for event in evidence.events}
    assert report.run_id == "ab" * 16
    case3 = next(row for row in report.cases if row.id == "CASE-003")
    assert case3.evidence is not None
    kinds = [by_id[ref].type for ref in case3.evidence]
    assert kinds[0] == "authz.evaluated" and by_id[case3.evidence[0]].query == "Q-0002"
    assert "effect.counted" in kinds and "harness.job" in kinds
    control = report.controls[0]
    assert control.evidence is not None
    assert [by_id[ref].query for ref in control.evidence] == ["Q-0001"]
    door_control = report.door_controls[0]
    assert door_control.evidence is not None
    assert [by_id[ref].type for ref in door_control.evidence] == ["effect.counted"]
    assert by_id[door_control.evidence[0]].case == "CASE-001"
    identity = report.identity_checks[0]
    assert identity.evidence is not None
    assert {by_id[ref].type for ref in identity.evidence} == {"door.identity_set", "door.called"}


def test_build_evidence_never_changes_verdicts_or_the_gate(make_report: ReportFactory) -> None:
    clock = Clock()
    recorder = RunRecorder(clock=clock, run_id="ab" * 16)
    recorder.finish()
    before = make_report()
    _, after = build_evidence(
        recorder,
        queries=QueryPlan(cases=(), rows=(), warnings=()),
        answers={},
        report=before,
        policy_adapter="x",
        version="v",
    )
    assert [row.status for row in after.cases] == [row.status for row in before.cases]
    assert after.gate == before.gate
    assert after.exit_code == before.exit_code
    stripped = after.model_copy(
        update={
            "run_id": None,
            "cases": tuple(row.model_copy(update={"evidence": None}) for row in after.cases),
        }
    )
    assert stripped == before


def test_a_job_without_elapsed_time_puts_its_timeline_at_the_end(
    make_report: ReportFactory,
) -> None:
    clock = Clock()
    recorder = RunRecorder(clock=clock, run_id="cd" * 16)
    observed = Observed(
        timeline=(TimelineItem(seq=1, at_ms=0.0, kind="effect", tool="t"),), elapsed_ms=None
    )

    class One:
        def run(self, job: DoorJob) -> Observed:
            clock.now += 1.0
            return observed

    recorder.run_job(
        One(), ScriptedJob(case_id="C", route=("a",), tool="t", args={}, subject=ALICE)
    )
    recorder.finish()
    evidence, _ = build_evidence(
        recorder,
        queries=QueryPlan(cases=(), rows=(), warnings=()),
        answers={},
        report=make_report(),
        policy_adapter="x",
        version="v",
    )
    effect = next(event for event in evidence.events if event.type == "effect.counted")
    assert effect.time == 1.0
    job = next(event for event in evidence.events if event.type == "harness.job")
    assert job.detail["route"] == ["a"]


def test_many_queries_and_jobs_build_quickly(make_report: ReportFactory) -> None:
    recorder = RunRecorder(run_id="ef" * 16)
    asked = [query(f"user-{n}") for n in range(3000)]
    recorder.batch_sent([q.key() for q in asked])
    plan = QueryPlan(cases=(case_ask("CASE-001", "allow", tuple(asked)),), rows=(), warnings=())
    answers: dict[str, Any] = {q.key(): Decision(verdict=Verdict.DENY) for q in asked}
    recorder.finish()
    start = clock_module.perf_counter()
    evidence, _ = build_evidence(
        recorder,
        queries=plan,
        answers=answers,
        report=make_report(),
        policy_adapter="x",
        version="v",
    )
    assert clock_module.perf_counter() - start < 10
    assert len(evidence.events) == 3002


# ---- hardening ----


def deep(levels: int) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for _ in range(levels - 1):
        value = {"k": value}
    return value


def finish_build(
    recorder: RunRecorder,
    plan: QueryPlan,
    answers: dict[str, Decision],
    report: CoverageReport,
) -> tuple[Evidence, CoverageReport]:
    return build_evidence(
        recorder, queries=plan, answers=answers, report=report, policy_adapter="x", version="v"
    )


def test_a_too_deep_detail_is_replaced_not_fatal(
    make_report: ReportFactory, tmp_path: Path
) -> None:
    # Entity properties may be MAX_QUERY_DEPTH deep; the request adds three levels in a detail.
    deep_query = Query(
        subject=Entity(type="user", id="d", properties=deep(65)),
        action=QueryAction(name="trade:execute"),
        resource=Entity(type="order", id="o-1"),
    )
    recorder = RunRecorder(run_id="aa" * 16)
    recorder.batch_sent([deep_query.key()])
    recorder.finish()
    plan = QueryPlan(cases=(case_ask("CASE-001", "allow", (deep_query,)),), rows=(), warnings=())
    answers = {deep_query.key(): Decision(verdict=Verdict.ALLOW)}
    evidence, _ = finish_build(recorder, plan, answers, make_report())
    authz = next(event for event in evidence.events if event.type == "authz.evaluated")
    assert (
        authz.detail["request"]["subject"]["id"] == "d"
    )  # the deepest allowed properties still fit

    # A detail the format rejects is replaced, with the same event fields.
    draft = _Draft(
        time=0.0,
        source="policy_adapter",
        type="authz.evaluated",
        query="Q-0001",
        detail={"request": deep(80)},
    )
    event = _make_event("E-0001", "aa" * 16, draft)
    assert event.detail == {"error": "the detail could not be kept"}
    assert event.type == "authz.evaluated" and event.query == "Q-0001"
    path = write_evidence(evidence, tmp_path)
    assert read_evidence(path).header.events == len(evidence.events)


def test_an_oversized_event_keeps_only_an_error_note(
    make_report: ReportFactory, tmp_path: Path
) -> None:
    big = Query(
        subject=Entity(type="user", id="big", properties={"blob": "x" * (2 * 1024 * 1024)}),
        action=QueryAction(name="trade:execute"),
        resource=Entity(type="order", id="o-1"),
    )
    recorder = RunRecorder(
        run_id="aa" * 16, clock=lambda: 0.0, now=lambda: datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
    )
    recorder.batch_sent([big.key()])
    recorder.finish()
    plan = QueryPlan(cases=(case_ask("CASE-001", "allow", (big,)),), rows=(), warnings=())
    answers = {big.key(): Decision(verdict=Verdict.ALLOW)}
    evidence, _ = finish_build(recorder, plan, answers, make_report())
    authz = next(event for event in evidence.events if event.type == "authz.evaluated")
    assert authz.detail == {"error": "the detail was too large to keep"}
    assert authz.query is not None
    path = write_evidence(evidence, tmp_path)
    assert read_evidence(path).header.events == len(evidence.events)
    assert path.stat().st_size < 1024 * 1024


def _one_query_build(
    make_report: ReportFactory, subject_properties: dict[str, Any]
) -> tuple[Evidence, CoverageReport]:
    asked = Query(
        subject=Entity(type="user", id="edge", properties=subject_properties),
        action=QueryAction(name="trade:execute"),
        resource=Entity(type="order", id="o-1"),
    )
    recorder = RunRecorder(
        run_id="aa" * 16, clock=lambda: 0.0, now=lambda: datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
    )
    recorder.batch_sent([asked.key()])
    recorder.finish()
    plan = QueryPlan(cases=(case_ask("CASE-001", "allow", (asked,)),), rows=(), warnings=())
    answers = {asked.key(): Decision(verdict=Verdict.ALLOW)}
    return finish_build(recorder, plan, answers, make_report())


def test_a_lone_surrogate_does_not_break_the_build(
    make_report: ReportFactory, tmp_path: Path
) -> None:
    evidence, _ = _one_query_build(make_report, {"k": "\udc80"})
    path = write_evidence(evidence, tmp_path)
    assert read_evidence(path).header.events == len(evidence.events)


def test_the_line_size_limit_is_exact_on_disk(make_report: ReportFactory, tmp_path: Path) -> None:
    def authz_event(padding: int) -> Event:
        evidence, _ = _one_query_build(make_report, {"p": "x" * padding})
        return next(e for e in evidence.events if e.type == "authz.evaluated")

    exact = MAX_LINE_BYTES - event_line_bytes(authz_event(0))
    assert event_line_bytes(authz_event(exact)) == MAX_LINE_BYTES
    evidence, _ = _one_query_build(make_report, {"p": "x" * exact})
    authz = next(e for e in evidence.events if e.type == "authz.evaluated")
    assert "request" in authz.detail
    path = write_evidence(evidence, tmp_path)
    assert b"\r" not in path.read_bytes()
    assert read_evidence(path).header.events == len(evidence.events)
    assert authz_event(exact + 1).detail == {"error": "the detail was too large to keep"}


def test_inspect_works_on_a_run_with_an_oversized_event(
    make_report: ReportFactory, tmp_path: Path
) -> None:
    big = Query(
        subject=Entity(type="user", id="big", properties={"blob": "x" * (2 * 1024 * 1024)}),
        action=QueryAction(name="trade:execute"),
        resource=Entity(type="order", id="o-1"),
    )
    recorder = RunRecorder(
        run_id="aa" * 16, clock=lambda: 0.0, now=lambda: datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
    )
    recorder.batch_sent([big.key()])
    recorder.finish()
    plan = QueryPlan(cases=(case_ask("CASE-001", "allow", (big,)),), rows=(), warnings=())
    answers = {big.key(): Decision(verdict=Verdict.ALLOW)}
    evidence, report = finish_build(recorder, plan, answers, make_report())
    report = report.model_copy(update={"mode": "test"})
    write_report(report, tmp_path, generated_at=datetime(2026, 11, 8, tzinfo=UTC), version="x")
    write_evidence(evidence, tmp_path)
    case_id = report.cases[0].id
    assert inspect_case(tmp_path, case_id)  # no InspectError


def test_a_rebuild_failure_leaves_no_rejected_input_in_the_context() -> None:
    draft = _Draft(
        time=float("nan"), source="policy_adapter", type="authz.evaluated", detail={"a": 1}
    )
    try:
        _make_event("E-0001", "aa" * 16, draft)
    except Exception as exc:
        assert exc.__context__ is None or exc.__suppress_context__
    else:
        raise AssertionError("expected a failure")


def test_the_elapsed_time_is_a_float_even_for_an_integer_clock() -> None:
    ticks = iter([0, 3])
    recorder = RunRecorder(clock=lambda: next(ticks), run_id="aa" * 16)
    assert isinstance(recorder.elapsed(), float)


def test_a_question_never_sent_is_marked_and_placed_at_the_end(make_report: ReportFactory) -> None:
    clock = Clock()
    recorder = RunRecorder(clock=clock, run_id="bb" * 16)
    sent, unsent = query("sent"), query("unsent")
    clock.now = 0.5
    recorder.batch_sent([sent.key()])
    clock.now = 3.0
    recorder.finish()
    plan = QueryPlan(cases=(case_ask("CASE-001", "allow", (sent, unsent)),), rows=(), warnings=())
    evidence, _ = finish_build(recorder, plan, {}, make_report())
    authz = [event for event in evidence.events if event.type == "authz.evaluated"]
    assert authz[0].time == 0.5 and "sent" not in authz[0].detail
    assert authz[1].time == 3.0 and authz[1].detail["sent"] is False
    # No answer was recorded: the error detail, no exception.
    assert authz[1].detail["verdict"] == "error"


def agent_hop(asked: Query) -> HopAsk:
    return HopAsk(
        caller="user",
        target="finance-agent",
        kind="agent",
        mode="user",
        queries=(asked,),
        control=("agent:invoke", "agent"),
    )


def escalation_row(case_id: str | None, via: str = "finance-agent") -> EscalationRow:
    return EscalationRow(
        case_id=case_id,
        role="analyst",
        tool="execute_trade",
        via=via,
        risk=Risk.CRITICAL,
        mode="agent",
        path=("finance-agent",),
        result=EscalationResult.NONE,
    )


def test_every_kind_of_row_gets_its_references(make_report: ReportFactory) -> None:
    clock = Clock()
    recorder = RunRecorder(clock=clock, run_id="cc" * 16)
    hop_q = query("hop", "agent:invoke").model_copy(
        update={"resource": Entity(type="agent", id="finance-agent")}
    )
    tool_q = query("tool")
    plain_q = query("plain")
    path_q, user_q = query("path"), query("user")
    case = case_ask("CASE-001", "allow", (tool_q,))
    case = replace(case, hops=(agent_hop(hop_q), *case.hops), plain_user=plain_q)
    row_ask = RowAsk(
        role="analyst",
        tool="execute_trade",
        via="finance-agent",
        risk=Risk.CRITICAL,
        mode="agent",
        path=("finance-agent",),
        path_query=path_q,
        user_query=user_q,
        control=("trade:execute", "order"),
    )
    plan = QueryPlan(cases=(case,), rows=(row_ask,), warnings=())
    everything = [hop_q, tool_q, plain_q, path_q, user_q]
    recorder.batch_sent([q.key() for q in everything])
    answers = {q.key(): Decision(verdict=Verdict.ALLOW) for q in everything}
    scripted = ScriptedJob(
        case_id="CASE-001",
        route=("finance-agent",),
        tool="execute_trade",
        args={},
        subject=ALICE,
    )

    class Fixed:
        def run(self, job: DoorJob) -> Observed:
            return observed_run(counted=True, decision=True)

    recorder.run_job(Fixed(), scripted)
    recorder.finish()
    report = make_report(
        cases=[
            finance_case(
                "CASE-001", "finance-agent", "execute_trade", "trade:execute", "dummy", "allow"
            )
        ]
    ).model_copy(
        update={
            "escalations": (escalation_row("CASE-001"), escalation_row(None)),
            "controls": (
                ControlRow(action="trade:execute", resource_type="order", allowed=True),
                ControlRow(action="agent:invoke", resource_type="agent", allowed=True),
                ControlRow(action="never:allowed", resource_type="thing", allowed=False),
            ),
            "door_controls": (
                DoorControlRow(tool="execute_trade", proven=True, proven_by="CASE-001 (scripted)"),
                DoorControlRow(tool="other", proven=False),
            ),
        }
    )
    evidence, built = finish_build(recorder, plan, answers, report)
    qid = {event.event: event.query for event in evidence.events if event.type == "authz.evaluated"}
    by_id = {event.event: event for event in evidence.events}

    def queries_of(refs: tuple[str, ...] | None) -> list[str | None]:
        assert refs is not None
        return [qid.get(ref) for ref in refs if ref in qid]

    # The case: every hop's questions (agent hop too) plus plain_user, then its job events.
    case_refs = built.cases[0].evidence
    assert case_refs is not None
    assert queries_of(case_refs) == ["Q-0001", "Q-0002", "Q-0003"]
    assert any(by_id[ref].type == "harness.job" for ref in case_refs)
    # Escalation from a case: tool hop + plain_user. Second escalation: path + user query.
    assert queries_of(built.escalations[0].evidence) == ["Q-0002", "Q-0003"]
    assert queries_of(built.escalations[1].evidence) == ["Q-0004", "Q-0005"]
    # Controls: the first allowed question of the pair; never allowed means no evidence.
    assert queries_of(built.controls[0].evidence) == ["Q-0002"]
    assert queries_of(built.controls[1].evidence) == ["Q-0001"]
    assert built.controls[2].evidence == ()
    # A scripted run proves the door control.
    proof = built.door_controls[0].evidence
    assert proof is not None and by_id[proof[0]].type == "effect.counted"
    assert by_id[proof[0]].mode == "scripted"
    assert built.door_controls[1].evidence == ()


def test_a_shared_question_has_one_id_and_both_rows_point_at_it(
    make_report: ReportFactory,
) -> None:
    recorder = RunRecorder(run_id="dd" * 16)
    shared_a, shared_b = query("shared"), query("shared")  # equal, but two objects
    other = query("other")
    plan = QueryPlan(
        cases=(
            case_ask("CASE-001", "allow", (shared_a,)),
            case_ask("CASE-003", "deny", (shared_b, other)),
        ),
        rows=(),
        warnings=(),
    )
    recorder.finish()
    answers = {q.key(): Decision(verdict=Verdict.ALLOW) for q in (shared_a, other)}
    evidence, built = finish_build(recorder, plan, answers, make_report())
    assert sum(event.type == "authz.evaluated" for event in evidence.events) == 2
    first = next(row for row in built.cases if row.id == "CASE-001")
    third = next(row for row in built.cases if row.id == "CASE-003")
    assert first.evidence is not None and third.evidence is not None
    assert set(first.evidence) < set(third.evidence)


def test_credentials_in_errors_and_exceptions_are_masked(make_report: ReportFactory) -> None:
    clock = Clock()
    recorder = RunRecorder(clock=clock, run_id="ee" * 16)
    secret = "https://user:hunter2@host.example/p"
    call = DoorCall(error=f"cannot reach {secret}")
    observed = Observed(
        door_calls=(call,),
        timeline=(TimelineItem(seq=1, at_ms=0.0, kind="door", call=call),),
        exception=f"Err({secret})",
        error=f"failed at {secret}",
        elapsed_ms=1.0,
    )

    class One:
        def run(self, job: DoorJob) -> Observed:
            return observed

    recorder.run_job(One(), direct_job("CASE-001"))
    recorder.finish()
    plan = QueryPlan(cases=(), rows=(), warnings=())
    evidence, _ = finish_build(recorder, plan, {}, make_report())
    kinds = {event.type for event in evidence.events}
    assert {"door.called", "tool.raised", "run.error"} <= kinds
    text = json.dumps([event.model_dump(mode="json") for event in evidence.events])
    assert "hunter2" not in text
