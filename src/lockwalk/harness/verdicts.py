"""Judge the door test runs. Pure."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from lockwalk.config import GateConfig
from lockwalk.graph.analysis import name_list, plural
from lockwalk.harness.plan import DirectPlan, ScriptedPlan
from lockwalk.harness.protocol import Observed, Survey, reduce_subject
from lockwalk.models import (
    DoorCall,
    DoorControlRow,
    DoorResult,
    DoorRun,
    DoorStatus,
    GateViolation,
    HarnessMode,
    IdentityCheckRow,
    IdentityObservation,
    IdentityResult,
    Verdict,
)
from lockwalk.policy.base import Decision, Query, error_decision
from lockwalk.queries import CaseAsk, QueryPlan

_NO_DOOR_NOTE = "no DOOR in the hooks file, so lockwalk cannot see which identity the door received"
_MISSING_ANSWER = "no answer was recorded for this question"
_NO_RESULT = "no result was recorded for this run"
_SPLIT_NOTE = (
    "the IAM answers the user and the agent identity differently, so this run cannot be judged"
)
# Most severe first.
_SEVERITY = (DoorStatus.FAIL_EXECUTION, DoorStatus.ERROR, DoorStatus.INCONCLUSIVE, DoorStatus.OK)


@dataclass(frozen=True)
class HarnessOutcome:
    doors: Mapping[str, DoorResult] = field(default_factory=dict)  # case id -> door result
    identity_checks: tuple[IdentityCheckRow, ...] = ()
    door_controls: tuple[DoorControlRow, ...] = ()
    errors: tuple[str, ...] = ()  # one line per ERROR run
    warnings: tuple[str, ...] = ()
    violations: tuple[GateViolation, ...] = ()  # fail_on_identity_mismatch only


@dataclass(frozen=True)
class _Judged:
    """One run that was judged (or found ERROR), with what the identity check needs."""

    run: DoorRun | None  # None: the IAM part was ERROR or split, so the run was not judged
    observed: Observed
    subject: dict[str, Any]


def _reached(observed: Observed | None) -> bool:
    return observed is not None and observed.error is None and observed.not_run is None


def _answered(door_calls: Sequence[DoorCall]) -> list[DoorCall]:
    return [call for call in door_calls if call.error is None]


def _lookup(answers: Mapping[str, Decision], query: Query) -> Decision:
    found = answers.get(query.key())
    return found if found is not None else error_decision(_MISSING_ANSWER)


def _hop_iam(case: CaseAsk, answers: Mapping[str, Decision]) -> str:
    """The IAM verdict of the tool hop: "allow", "deny", "error", or "split" (undeclared)."""
    verdicts = {_lookup(answers, query).verdict for query in case.tool_hop.queries}
    if Verdict.ERROR in verdicts:
        return "error"
    if len(verdicts) > 1:
        return "split"
    return next(iter(verdicts)).value


def _exception_notes(observed: Observed, kind: str | None, status: DoorStatus) -> tuple[str, ...]:
    if status is DoorStatus.OK:
        return ()
    if observed.exception:
        text = f"the tool raised {observed.exception}"
        if observed.exception_message:
            text += f": {observed.exception_message}"
        return (text,)
    if kind in ("openai_agents", "agno"):
        return (f"{kind} hides tool exceptions, so the exception type is unknown",)
    return ()


def _status_and_note(
    observed: Observed, *, mode: HarnessMode, iam: str, tool: str, door: bool, proven: bool
) -> tuple[DoorStatus, str | None] | None:
    """The row of the run table that applies, or None when the run is not judged."""
    n = observed.side_effect_calls
    if observed.error is not None:
        return DoorStatus.ERROR, observed.error
    for call in observed.door_calls:
        if call.error is not None:
            return (
                DoorStatus.ERROR,
                f"the door recorder could not read a door call: {call.error}",
            )
    if observed.blocked_hosts:
        text = (
            f"the code tried to connect to {', '.join(observed.blocked_hosts)}; "
            "door tests block the network"
        )
        if mode == "scripted":
            text += ", so the fake model may not have taken effect"
        return DoorStatus.ERROR, text
    if iam == "deny":
        if n > 0:
            text = f"the IAM denied this, but the side effect of {tool!r} ran {n} time(s)"
            if observed.bypass:
                text += " before the door asked the IAM"
            return DoorStatus.FAIL_EXECUTION, text
        if door:
            answered = _answered(observed.door_calls)
            if not answered:
                return (
                    DoorStatus.ERROR,
                    "the IAM denied this and the side effect did not run, but the door was "
                    "never asked; the tool failed before reaching the door",
                )
            if not any(call.decision is False for call in answered):
                return (
                    DoorStatus.FAIL_EXECUTION,
                    "the IAM denied this, but the door allowed it; the side effect did not run "
                    "only because the tool failed for another reason",
                )
        if proven:
            return DoorStatus.OK, None
        return (
            DoorStatus.INCONCLUSIVE,
            f"no door control: the side effect of {tool!r} was never counted in this run, "
            "so lockwalk cannot tell that SIDE_EFFECTS replaced the right function; "
            "add a case the IAM allows, with tool_args",
        )
    if iam != "allow":
        return None
    if n > 0:
        if door and observed.bypass:
            return (
                DoorStatus.FAIL_EXECUTION,
                f"the side effect of {tool!r} ran before the door asked the IAM "
                "(the door was bypassed)",
            )
        return DoorStatus.OK, None
    if not door:
        return (
            DoorStatus.FAIL_EXECUTION,
            "the IAM allowed this, but the side effect did not run; without DOOR lockwalk "
            "cannot tell whether the door denied it or the tool failed earlier",
        )
    if any(call.decision is False for call in _answered(observed.door_calls)):
        return (
            DoorStatus.FAIL_EXECUTION,
            "the IAM allowed this, but the door denied it; the door may send the wrong identity",
        )
    return (
        DoorStatus.ERROR,
        "the IAM allowed this, but the side effect did not run and the door did not deny it; "
        "the tool failed for another reason",
    )


def _judge_run(
    observed: Observed,
    *,
    mode: HarnessMode,
    iam: str,
    tool: str,
    subject: dict[str, Any],
    survey: Survey,
    proven: bool,
) -> DoorRun | None:
    found = _status_and_note(
        observed, mode=mode, iam=iam, tool=tool, door=survey.door, proven=proven
    )
    if found is None:
        return None
    status, note = found
    info = survey.tools.get(tool)
    notes = ((note,) if note else ()) + _exception_notes(
        observed, info.kind if info else None, status
    )
    return DoorRun(
        mode=mode,
        status=status,
        subject=subject,
        side_effect_calls=observed.side_effect_calls,
        door_calls=observed.door_calls,
        exception=observed.exception,
        notes=notes,
    )


def _compare(expected: dict[str, Any] | None, subjects: list[dict[str, Any]]) -> IdentityResult:
    if expected is None:
        return IdentityResult.OBSERVED
    if all(subject == expected for subject in subjects):
        return IdentityResult.MATCH
    return IdentityResult.MISMATCH


def _row_result(observations: Sequence[IdentityObservation]) -> IdentityResult:
    results = {obs.result for obs in observations}
    for result in (IdentityResult.MISMATCH, IdentityResult.MATCH, IdentityResult.OBSERVED):
        if result in results:
            return result
    return IdentityResult.NOT_RUN


def _identity_row(
    case: CaseAsk,
    *,
    survey: Survey,
    scripted_plan: ScriptedPlan,
    scripted: _Judged | None,
    scripted_job: bool,
    direct: Sequence[_Judged],
) -> IdentityCheckRow:
    if not survey.door:
        return IdentityCheckRow(
            case_id=case.case_id,
            path=case.route,
            tool=case.tool,
            result=IdentityResult.NOT_RUN,
            notes=(_NO_DOOR_NOTE,),
        )
    observations: list[IdentityObservation] = []
    notes: list[str] = []
    for item in direct:
        if item.run is None or not _reached(item.observed):
            continue
        expected = reduce_subject(item.subject)
        subjects = [c.subject for c in _answered(item.observed.door_calls) if c.subject]
        if not subjects:
            if "direct: the door was not called" not in notes:
                notes.append("direct: the door was not called")
            continue
        observations.append(
            IdentityObservation(
                mode="direct",
                expected=expected,
                observed=tuple(subjects),
                result=_compare(expected, subjects),
            )
        )
    if scripted is not None and _reached(scripted.observed):
        subjects = [c.subject for c in _answered(scripted.observed.door_calls) if c.subject]
        if not subjects:
            notes.append("scripted: the door was not called for the tool")
        else:
            if case.case_id in scripted_plan.expected:
                expected = scripted_plan.expected[case.case_id]
                observations.append(
                    IdentityObservation(
                        mode="scripted",
                        expected=expected,
                        observed=tuple(subjects),
                        result=_compare(expected, subjects),
                    )
                )
    if scripted_job and (scripted is None or not _reached(scripted.observed)):
        notes.append("scripted: no usable observation")
    return IdentityCheckRow(
        case_id=case.case_id,
        path=case.route,
        tool=case.tool,
        result=_row_result(observations),
        observations=tuple(observations),
        notes=tuple(notes),
    )


def _survey_failed(queries: QueryPlan, text: str) -> HarnessOutcome:
    note = f"the door tests could not start: {text}"
    doors: dict[str, DoorResult] = {}
    errors: list[str] = []
    for case in queries.cases:
        if case.problems or not case.hops:
            continue
        doors[case.case_id] = DoorResult(status=DoorStatus.ERROR, notes=(note,))
        errors.append(f"{case.case_id}: door: {note}")
    return HarnessOutcome(doors=doors, errors=tuple(errors))


def proves_door_control(observed: Observed) -> bool:
    """Whether this run proves the tool's door control: the side effect was
    counted in a run that reached the tool, blocked no host, and read every door call."""
    return (
        _reached(observed)
        and not observed.blocked_hosts
        and all(call.error is None for call in observed.door_calls)
        and observed.side_effect_calls > 0
    )


def _door_controls(
    queries: QueryPlan,
    scripted: Mapping[str, Observed],
    direct: Mapping[str, tuple[Observed, ...]],
) -> dict[str, str | None]:
    """tool -> the first run that counted its side effect, e.g. "CASE-004 (direct)".

    Every tool with a reached run is a key; its value is None when no run counted a call.
    """
    proven: dict[str, str | None] = {}
    for case in queries.cases:
        runs = [("scripted", scripted.get(case.case_id))]
        runs.extend(("direct", item) for item in direct.get(case.case_id, ()))
        for mode, observed in runs:
            if observed is None or not _reached(observed):
                continue
            proven.setdefault(case.tool, None)
            if proven[case.tool] is None and proves_door_control(observed):
                proven[case.tool] = f"{case.case_id} ({mode})"
    return proven


def _case_result(
    runs: Sequence[DoorRun], notes: Sequence[str], plan_error: str | None
) -> DoorResult | None:
    statuses = {run.status for run in runs}
    if plan_error is not None:
        statuses.add(DoorStatus.ERROR)
    for status in _SEVERITY:
        if status in statuses:
            return DoorResult(status=status, runs=tuple(runs), notes=tuple(notes))
    if notes:
        return DoorResult(status=DoorStatus.NOT_TESTED, notes=tuple(notes))
    return None


def judge_harness(
    *,
    queries: QueryPlan,
    answers: Mapping[str, Decision],
    survey: Survey | str,
    scripted_plan: ScriptedPlan,
    scripted: Mapping[str, Observed],
    direct_plan: DirectPlan,
    direct: Mapping[str, tuple[Observed, ...]],
    gate: GateConfig,
) -> HarnessOutcome:
    if isinstance(survey, str):
        return _survey_failed(queries, survey)
    if survey.problems:
        return _survey_failed(queries, "; ".join(survey.problems))

    proven = _door_controls(queries, scripted, direct)
    controls = tuple(
        DoorControlRow(tool=tool, proven=proven[tool] is not None, proven_by=proven[tool])
        for tool in sorted(proven)
    )

    doors: dict[str, DoorResult] = {}
    identity_rows: list[IdentityCheckRow] = []
    errors: list[str] = []
    violations: list[GateViolation] = []
    not_run_groups: dict[str, list[str]] = {}

    for case in queries.cases:
        if case.problems or not case.hops:
            continue
        cid = case.case_id
        runs: list[DoorRun] = []
        notes: list[str] = []
        scripted_judged: _Judged | None = None
        direct_judged: list[_Judged] = []
        is_proven = proven.get(case.tool) is not None

        # Scripted.
        job = scripted_plan.jobs.get(cid)
        if cid in scripted_plan.not_run:
            reason = scripted_plan.not_run[cid]
            notes.append(f"scripted: {reason}")
            not_run_groups.setdefault(reason, []).append(cid)
        if job is not None:
            observed = scripted.get(cid)
            if observed is None:
                observed = Observed(error=_NO_RESULT)
            if observed.not_run is not None:
                notes.append(f"scripted: {observed.not_run}")
                not_run_groups.setdefault(observed.not_run, []).append(cid)
            else:
                iam = _hop_iam(case, answers)
                subject = job.subject
                run = _judge_run(
                    observed,
                    mode="scripted",
                    iam=iam,
                    tool=case.tool,
                    subject=subject,
                    survey=survey,
                    proven=is_proven,
                )
                if run is None and iam == "split":
                    notes.append(_SPLIT_NOTE)
                scripted_judged = _Judged(run, observed, subject)
                if run is not None:
                    runs.append(run)
                    if run.status is DoorStatus.ERROR:
                        errors.append(f"{cid}: door (scripted): {run.notes[0]}")

        # Direct.
        if cid in direct_plan.not_tested:
            notes.append(f"direct: {direct_plan.not_tested[cid]}")
        plan_error = direct_plan.errors.get(cid)
        if plan_error is not None:
            notes.append(plan_error)
            errors.append(f"{cid}: door (direct): {plan_error}")
        jobs = direct_plan.jobs.get(cid, ())
        results = direct.get(cid, ())
        for i, djob in enumerate(jobs):
            observed = results[i] if i < len(results) else Observed(error=_NO_RESULT)
            if observed.not_run is not None:
                notes.append(f"direct: {observed.not_run}")
                continue
            plan_queries = direct_plan.queries.get(cid, ())
            if i < len(plan_queries):
                decision = _lookup(answers, plan_queries[i])
            else:
                decision = error_decision(_MISSING_ANSWER)
            run = _judge_run(
                observed,
                mode="direct",
                iam=decision.verdict.value,
                tool=case.tool,
                subject=djob.subject,
                survey=survey,
                proven=is_proven,
            )
            if run is None:
                continue
            runs.append(run)
            direct_judged.append(_Judged(run, observed, djob.subject))
            if run.status is DoorStatus.ERROR:
                errors.append(f"{cid}: door (direct): {run.notes[0]}")

        result = _case_result(runs, notes, plan_error)
        if result is not None:
            doors[cid] = result

        has_entry = (
            job is not None
            or bool(jobs)
            or cid in scripted_plan.not_run
            or cid in direct_plan.not_tested
        )
        if (
            survey.door
            and scripted_judged is not None
            and _reached(scripted_judged.observed)
            and any(c.error is None for c in scripted_judged.observed.door_calls)
            and cid not in scripted_plan.expected
        ):
            errors.append(
                f"{cid}: door: internal error: no expected identity was planned for the "
                "scripted run"
            )
        if has_entry:
            row = _identity_row(
                case,
                survey=survey,
                scripted_plan=scripted_plan,
                scripted=scripted_judged if job is not None else None,
                scripted_job=job is not None,
                direct=direct_judged,
            )
            identity_rows.append(row)
            if row.result is IdentityResult.MISMATCH and gate.fail_on_identity_mismatch:
                violations.append(GateViolation(rule="fail_on_identity_mismatch", case_id=cid))

    warnings = [*survey.warnings, *scripted_plan.warnings, *direct_plan.warnings]
    for reason, ids in not_run_groups.items():
        warnings.append(
            f"scripted mode did not run {len(ids)} {plural('case', len(ids))} "
            f"({name_list(ids)}): {reason}"
        )
    return HarnessOutcome(
        doors=doors,
        identity_checks=tuple(identity_rows),
        door_controls=controls,
        errors=tuple(errors),
        warnings=tuple(warnings),
        violations=tuple(violations),
    )
