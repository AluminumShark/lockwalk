"""Build the evidence of one `lockwalk test` run.

RunRecorder notes when each batch of questions went to the IAM and when each harness job
ran. build_evidence turns those notes, the questions, the answers, and the finished report
into the events of evidence.jsonl, and returns the report with run_id and each row's
`evidence` ids. It never changes a verdict or the gate: it only adds references.
"""

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import ValidationError

from lockwalk.evidence import (
    MAX_LINE_BYTES,
    Event,
    EventSource,
    EventType,
    Evidence,
    EvidenceHeader,
    event_id,
    event_line_bytes,
    id_number,
    invocation_id,
    new_run_id,
    query_id,
)
from lockwalk.harness.protocol import DirectJob, Observed, ScriptedJob, TimelineItem, reduce_subject
from lockwalk.harness.verdicts import proves_door_control
from lockwalk.models import (
    ControlRow,
    CoverageReport,
    DoorControlRow,
    EscalationRow,
    HarnessMode,
    Verdict,
)
from lockwalk.output_files import utc_timestamp
from lockwalk.policy.base import Decision, Query
from lockwalk.queries import CaseAsk, QueryPlan
from lockwalk.urls import redact_urls

DoorJob = DirectJob | ScriptedJob


class JobRunner(Protocol):
    def run(self, job: DoorJob) -> Observed: ...


@dataclass(frozen=True)
class JobRecord:
    job: DoorJob
    started: float  # seconds since the run started
    ended: float
    observed: Observed


class RunRecorder:
    """The clock of one run, and what happened when. Times are seconds since the start."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] | None = None,
        run_id: str | None = None,
    ) -> None:
        self.run_id = run_id if run_id is not None else new_run_id()
        self.started_at = (now or (lambda: datetime.now(UTC)))()
        self._clock = clock
        self._t0 = clock()
        self.sent_at: dict[str, float] = {}  # query key -> when its batch was sent
        self.jobs: list[JobRecord] = []
        self.finished: float | None = None

    def elapsed(self) -> float:
        return float(round(max(0.0, self._clock() - self._t0), 3))

    def batch_sent(self, keys: Sequence[str]) -> None:
        """ask_all's on_batch: these questions go to the IAM now."""
        moment = self.elapsed()
        for key in keys:
            self.sent_at.setdefault(key, moment)

    def run_job(self, runner: JobRunner, job: DoorJob) -> Observed:
        """Run one harness job and note when it started and ended."""
        started = self.elapsed()
        observed = runner.run(job)
        self.jobs.append(
            JobRecord(job=job, started=started, ended=self.elapsed(), observed=observed)
        )
        return observed

    def finish(self) -> None:
        self.finished = self.elapsed()


@dataclass
class _Draft:
    time: float
    source: EventSource
    type: EventType
    detail: dict[str, Any]
    case: str | None = None
    mode: HarnessMode | None = None
    invocation: str | None = None
    query: str | None = None
    job: int | None = None  # index into RunRecorder.jobs
    key: str | None = None  # the query key of an authz.evaluated event


_TIMELINE_TYPES: dict[str, EventType] = {
    "identity": "door.identity_set",
    "door": "door.called",
    "effect": "effect.counted",
}
_DOOR_TYPES = frozenset({"door.identity_set", "door.called"})
_DETAIL_LOST = {"error": "the detail could not be kept"}
_DETAIL_TOO_LARGE = {"error": "the detail was too large to keep"}


def build_evidence(
    recorder: RunRecorder,
    *,
    queries: QueryPlan,
    answers: Mapping[str, Decision],
    report: CoverageReport,
    policy_adapter: str,
    version: str,
) -> tuple[Evidence, CoverageReport]:
    """The run's events, and the report with run_id and every row's evidence ids."""
    asked = queries.queries()
    key_of = {id(item): item.key() for item in asked}  # one json.dumps per Query object
    unique: dict[str, Query] = {}
    for item in asked:
        unique.setdefault(key_of[id(item)], item)
    # The end of the run: no event is later than this, and unsent questions sit here.
    end = max(
        [
            recorder.finished or 0.0,
            *(record.ended for record in recorder.jobs),
            *recorder.sent_at.values(),
        ]
    )

    drafts: list[_Draft] = [
        _Draft(
            time=0.0,
            source="test_runner",
            type="run.started",
            detail={
                "lockwalk_version": version,
                "policy_adapter": policy_adapter,
                "started_at": utc_timestamp(recorder.started_at),
            },
        )
    ]
    for number, (key, question) in enumerate(unique.items(), 1):
        detail = _authz_detail(question, answers.get(key))
        sent = recorder.sent_at.get(key)
        if sent is None:
            detail["sent"] = False
        drafts.append(
            _Draft(
                time=end if sent is None else sent,
                source="policy_adapter",
                type="authz.evaluated",
                query=query_id(number),
                key=key,
                detail=detail,
            )
        )
    for index, record in enumerate(recorder.jobs):
        drafts.extend(_job_drafts(index, record))
    drafts.append(
        _Draft(
            time=end,
            source="test_runner",
            type="run.finished",
            detail={"exit_code": report.exit_code, "cases": len(report.cases)},
        )
    )
    drafts.sort(key=lambda draft: draft.time)  # stable: ties keep the order they were added

    events: list[Event] = []
    by_query: dict[str, str] = {}
    by_job: dict[int, list[str]] = {}
    door_events: dict[int, list[str]] = {}
    first_effect: dict[int, str] = {}
    for number, draft in enumerate(drafts, 1):
        event = _make_event(event_id(number), recorder.run_id, draft)
        events.append(event)
        if draft.key is not None:
            by_query[draft.key] = event.event
        if draft.job is not None:
            by_job.setdefault(draft.job, []).append(event.event)
            if draft.type in _DOOR_TYPES:
                door_events.setdefault(draft.job, []).append(event.event)
            if draft.type == "effect.counted":
                first_effect.setdefault(draft.job, event.event)

    refs = _Refs(
        recorder, queries, answers, unique, key_of, by_query, by_job, door_events, first_effect
    )
    header = EvidenceHeader(
        run=recorder.run_id,
        lockwalk_version=version,
        started_at=utc_timestamp(recorder.started_at),
        events=len(events),
    )
    return Evidence(header=header, events=tuple(events)), refs.apply(report)


def _make_event(eid: str, run: str, draft: _Draft) -> Event:
    """The event of a draft. A detail the file format rejects is replaced, never fatal.

    Losing the whole run's report over one odd detail would be worse than losing that
    detail. The replacement echoes nothing of the rejected input.
    """
    fields: dict[str, Any] = {
        "event": eid,
        "run": run,
        "time": draft.time,
        "source": draft.source,
        "type": draft.type,
        "case": draft.case,
        "mode": draft.mode,
        "invocation": draft.invocation,
        "query": draft.query,
    }
    try:
        event = Event.model_validate({**fields, "detail": draft.detail})
    except ValidationError:
        event = None
    if event is None:  # outside the handler, so the rejected input is not in __context__
        return _replacement(fields, _DETAIL_LOST)
    # A line longer than MAX_LINE_BYTES would make read_evidence refuse the whole file.
    if event_line_bytes(event) > MAX_LINE_BYTES:
        return _replacement(fields, _DETAIL_TOO_LARGE)
    return event


def _replacement(fields: dict[str, Any], detail: dict[str, str]) -> Event:
    try:
        return Event.model_validate({**fields, "detail": dict(detail)})
    except ValidationError as exc:
        raise exc from None  # no rejected input stays in __context__


def _job_drafts(index: int, record: JobRecord) -> list[_Draft]:
    """The harness.job event of one run, then its timeline, exception, and error."""
    job, observed = record.job, record.observed

    def draft(moment: float, kind: EventType, detail: dict[str, Any]) -> _Draft:
        return _Draft(
            time=moment,
            source="harness",
            type=kind,
            detail=detail,
            case=job.case_id,
            mode=job.mode,
            invocation=invocation_id(index + 1),
            job=index,
        )

    found = [draft(record.started, "harness.job", _job_detail(record))]
    for item in sorted(observed.timeline, key=lambda entry: entry.seq):
        found.append(
            draft(_align(record, item.at_ms), _TIMELINE_TYPES[item.kind], _timeline_detail(item))
        )
    if observed.exception is not None:
        found.append(
            draft(record.ended, "tool.raised", {"exception": redact_urls(observed.exception)})
        )
    if observed.error is not None:
        found.append(draft(record.ended, "run.error", {"error": redact_urls(observed.error)}))
    return found


class _Refs:
    """Which events each report row was judged from."""

    def __init__(
        self,
        recorder: RunRecorder,
        queries: QueryPlan,
        answers: Mapping[str, Decision],
        unique: Mapping[str, Query],
        key_of: Mapping[int, str],
        by_query: Mapping[str, str],
        by_job: Mapping[int, list[str]],
        door_events: Mapping[int, list[str]],
        first_effect: Mapping[int, str],
    ) -> None:
        self.recorder = recorder
        self.key_of = key_of  # id(Query object) -> its key, computed once
        self.by_query = by_query
        self.by_job = by_job
        self.door_events = door_events
        self.first_effect = first_effect
        self.cases = {case.case_id: case for case in queries.cases}
        self.rows = {(row.role, row.tool, row.via, row.path): row for row in queries.rows}
        self.jobs_of: dict[str, list[int]] = {}
        for index, record in enumerate(recorder.jobs):
            self.jobs_of.setdefault(record.job.case_id, []).append(index)
        self.first_allow: dict[tuple[str, str], str] = {}
        for key, asked in unique.items():
            decision = answers.get(key)
            if decision is not None and decision.verdict is Verdict.ALLOW:
                pair = (asked.action.name, asked.resource.type)
                self.first_allow.setdefault(pair, by_query[key])

    def apply(self, report: CoverageReport) -> CoverageReport:
        return report.model_copy(
            update={
                "run_id": self.recorder.run_id,
                "cases": tuple(
                    row.model_copy(update={"evidence": self.case(row.id)}) for row in report.cases
                ),
                "escalations": tuple(
                    row.model_copy(update={"evidence": self.escalation(row)})
                    for row in report.escalations
                ),
                "identity_checks": tuple(
                    row.model_copy(update={"evidence": self.identity(row.case_id)})
                    for row in report.identity_checks
                ),
                "controls": tuple(
                    row.model_copy(update={"evidence": self.control(row)})
                    for row in report.controls
                ),
                "door_controls": tuple(
                    row.model_copy(update={"evidence": self.door_control(row)})
                    for row in report.door_controls
                ),
            }
        )

    def queries_of(self, items: Iterable[Query | None]) -> list[str]:
        found: list[str] = []
        for item in items:
            key = self.key_of.get(id(item)) if item is not None else None
            if key is not None and key in self.by_query:
                found.append(self.by_query[key])
        return found

    def case(self, case_id: str) -> tuple[str, ...]:
        ask = self.cases.get(case_id)
        found = self.queries_of(_case_queries(ask)) if ask is not None else []
        for index in self.jobs_of.get(case_id, []):
            found.extend(self.by_job.get(index, []))
        return _ordered(found)

    def escalation(self, row: EscalationRow) -> tuple[str, ...]:
        if row.case_id is not None:
            ask = self.cases.get(row.case_id)
            items = [*ask.tool_hop.queries, ask.plain_user] if ask is not None and ask.hops else []
        else:
            found = self.rows.get((row.role, row.tool, row.via, row.path))
            items = [found.path_query, found.user_query] if found is not None else []
        return _ordered(self.queries_of(items))

    def identity(self, case_id: str) -> tuple[str, ...]:
        found: list[str] = []
        for index in self.jobs_of.get(case_id, []):
            found.extend(self.door_events.get(index, []))
        return _ordered(found)

    def control(self, row: ControlRow) -> tuple[str, ...]:
        if not row.allowed:
            return ()
        # first_allow is keyed by (query action name, query resource type). That is the same
        # pair judge counts per hop: (invoke_action, "agent") for agent hops and
        # (case action, resource type) for the tool hop.
        eid = self.first_allow.get((row.action, row.resource_type))
        return (eid,) if eid is not None else ()

    def door_control(self, row: DoorControlRow) -> tuple[str, ...]:
        if not row.proven or row.proven_by is None:
            return ()
        case_id, _, rest = row.proven_by.partition(" (")
        mode = rest.removesuffix(")")
        for index in self.jobs_of.get(case_id, []):
            record = self.recorder.jobs[index]
            if (
                record.job.mode == mode
                and record.job.tool == row.tool
                and proves_door_control(record.observed)
            ):
                eid = self.first_effect.get(index) or self.by_job[index][0]
                return (eid,)
        return ()


def _case_queries(case: CaseAsk) -> list[Query | None]:
    return [*(q for hop in case.hops for q in hop.queries), case.plain_user]


def _ordered(ids: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(ids), key=id_number))


def _masked(value: Any) -> Any:
    """A copy with URL credentials masked in every string, keys included."""
    if isinstance(value, str):
        return redact_urls(value)
    if isinstance(value, dict):
        return {(redact_urls(k) if isinstance(k, str) else k): _masked(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_masked(item) for item in value]
    return value


def _authz_detail(asked: Query, decision: Decision | None) -> dict[str, Any]:
    detail: dict[str, Any] = {"request": _masked(asked.to_authzen())}
    if decision is None:
        detail.update(verdict="error", error="no answer was recorded for this question")
        return detail
    detail["verdict"] = decision.verdict.value
    if decision.reason is not None:
        detail["reason"] = redact_urls(decision.reason)
    if decision.error is not None:
        detail["error"] = redact_urls(decision.error)
    if decision.latency_ms is not None:
        detail["latency_ms"] = round(decision.latency_ms, 3)
    return detail


def _job_detail(record: JobRecord) -> dict[str, Any]:
    job, observed = record.job, record.observed
    if observed.error is not None:
        status = "error"
    elif observed.not_run is not None:
        status = "not_run"
    else:
        status = "ran"
    detail: dict[str, Any] = {
        "tool": job.tool,
        "arg_names": sorted(redact_urls(name) for name in job.args),
        "subject": _masked(reduce_subject(job.subject)),
        "duration_ms": round((record.ended - record.started) * 1000, 3),
        "status": status,
        "side_effect_calls": observed.side_effect_calls,
    }
    if isinstance(job, ScriptedJob):
        detail["route"] = list(job.route)
    if observed.not_run is not None:
        detail["not_run"] = redact_urls(observed.not_run)
    if observed.blocked_hosts:
        detail["blocked_hosts"] = len(observed.blocked_hosts)
    if observed.timeline_dropped:
        detail["timeline_dropped"] = observed.timeline_dropped
    return detail


def _align(record: JobRecord, at_ms: float) -> float:
    """A worker offset as run time: the worker's clock is lined up with the job's end."""
    elapsed = record.observed.elapsed_ms
    if elapsed is None:
        return record.ended
    moment = record.ended - max(0.0, elapsed - at_ms) / 1000
    return round(min(record.ended, max(record.started, moment)), 3)


def _timeline_detail(item: TimelineItem) -> dict[str, Any]:
    if item.kind == "identity":
        return {"subject": _masked(item.subject)}
    if item.kind == "door":
        if item.call is None:
            return {"error": "the door call is missing"}
        return _masked(item.call.model_dump(mode="json", exclude_none=True))
    return {"tool": item.tool}


def without_evidence(report: CoverageReport, warning: str) -> CoverageReport:
    """The report with no run_id and no evidence refs, plus one warning. Verdicts are kept."""
    return report.model_copy(
        update={
            "run_id": None,
            "warnings": (*report.warnings, warning),
            "cases": tuple(row.model_copy(update={"evidence": None}) for row in report.cases),
            "escalations": tuple(
                row.model_copy(update={"evidence": None}) for row in report.escalations
            ),
            "identity_checks": tuple(
                row.model_copy(update={"evidence": None}) for row in report.identity_checks
            ),
            "controls": tuple(row.model_copy(update={"evidence": None}) for row in report.controls),
            "door_controls": tuple(
                row.model_copy(update={"evidence": None}) for row in report.door_controls
            ),
        }
    )
