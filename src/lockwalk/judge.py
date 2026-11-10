"""Judge the IAM's answers: case status, escalations, positive controls.

Pure: no file, network, or clock access. Fail-closed: anything that is not a clear answer
never becomes a PASS.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from lockwalk.config import GateConfig
from lockwalk.graph.analysis import name_list, plural
from lockwalk.models import (
    Answer,
    CaseDecision,
    CaseStatus,
    ControlRow,
    EscalationResult,
    EscalationRow,
    GateRule,
    GateViolation,
    HopResult,
    IdentityMode,
    PathVerdict,
    Risk,
    Verdict,
)
from lockwalk.policy.base import Decision, Query, error_decision
from lockwalk.queries import CaseAsk, ControlKey, HopAsk, QueryPlan, RowAsk

_ESCALATION_NOTE = "the IAM denies the user but allows the identity the route uses"
_HINT_NOTE = "the IAM allows the user but denies the identity the route uses; normal use may fail"
_MISSING_NOTE = "no answer was recorded for this question"


@dataclass(frozen=True)
class CaseOutcome:
    status: CaseStatus
    decision: CaseDecision | None  # None when the case is ERROR before anything was asked
    problems: tuple[str, ...] = ()  # why the case is ERROR
    notes: tuple[str, ...] = ()  # why the case is FAIL_POLICY or INCONCLUSIVE


@dataclass(frozen=True)
class PolicyOutcome:
    # case id -> outcome; planned ERROR cases are absent. A CaseAsk with problems becomes
    # CaseOutcome(status=ERROR, decision=None, problems=...), and its problems also go into
    # errors as "{case_id}: {problem}".
    cases: Mapping[str, CaseOutcome]
    escalations: tuple[EscalationRow, ...]
    controls: tuple[ControlRow, ...]
    errors: tuple[str, ...]  # one line per ERROR case problem and per ERROR escalation
    warnings: tuple[str, ...]
    violations: tuple[GateViolation, ...]

    @property
    def untrusted(self) -> bool:
        """Some answer was an error: the run must exit 2."""
        return bool(self.errors)


def _no_control_note(control: ControlKey) -> str:
    action, resource_type = control
    return (
        f"no positive control: no question about {action} on {resource_type} got an allow in "
        "this run, so lockwalk cannot tell that the IAM understood it; add a case the IAM "
        "should allow"
    )


def _unknown_note(caller: str) -> str:
    return (
        f"the delegation_mode of {caller!r} is not declared, and the IAM answers the user and "
        "the agent identity differently; declare delegation_mode in the registry"
    )


def _lookup(answers: Mapping[str, Decision], query: Query) -> Decision:
    found = answers.get(query.key())
    return found if found is not None else error_decision(_MISSING_NOTE)


def _to_answer(answers: Mapping[str, Decision], query: Query) -> Answer:
    decision = _lookup(answers, query)
    return Answer(
        subject=query.subject.model_dump(mode="json"),
        verdict=decision.verdict,
        reason=decision.reason,
        error=decision.error,
        latency_ms=decision.latency_ms,
    )


def _hop_verdict(given: tuple[Answer, ...]) -> PathVerdict:
    verdicts = {answer.verdict for answer in given}
    if Verdict.ERROR in verdicts:
        return PathVerdict.ERROR
    if len(verdicts) == 1:
        return PathVerdict.ALLOW if Verdict.ALLOW in verdicts else PathVerdict.DENY
    return PathVerdict.UNKNOWN


def _judge_hop(hop: HopAsk, answers: Mapping[str, Decision]) -> HopResult:
    given = tuple(_to_answer(answers, query) for query in hop.queries)
    return HopResult(
        caller=hop.caller,
        target=hop.target,
        kind=hop.kind,
        mode=hop.mode,
        verdict=_hop_verdict(given),
        answers=given,
    )


def _route_verdict(hops: tuple[HopResult, ...]) -> tuple[PathVerdict, int | None]:
    """The route verdict, and the index of the first denying hop (None unless DENY)."""
    verdicts = [hop.verdict for hop in hops]
    if PathVerdict.ERROR in verdicts:
        return PathVerdict.ERROR, None
    if PathVerdict.DENY in verdicts:
        return PathVerdict.DENY, verdicts.index(PathVerdict.DENY)
    if PathVerdict.UNKNOWN in verdicts:
        return PathVerdict.UNKNOWN, None
    return PathVerdict.ALLOW, None


def _judge_case(
    case: CaseAsk, answers: Mapping[str, Decision], allowed: set[ControlKey]
) -> CaseOutcome:
    if case.problems or not case.hops:
        problems = case.problems or ("no questions were built for this case",)
        return CaseOutcome(status=CaseStatus.ERROR, decision=None, problems=problems)
    hops = tuple(_judge_hop(hop, answers) for hop in case.hops)
    verdict, denied_index = _route_verdict(hops)
    denied_hop = None
    if denied_index is not None:
        denied_hop = f"{hops[denied_index].caller} -> {hops[denied_index].target}"
    decision = CaseDecision(verdict=verdict, hops=hops, denied_hop=denied_hop)

    if verdict is PathVerdict.ERROR:
        problems = tuple(
            f"{hop.caller} -> {hop.target}: {answer.error}"
            for hop in hops
            for answer in hop.answers
            if answer.verdict is Verdict.ERROR
        )
        return CaseOutcome(status=CaseStatus.ERROR, decision=decision, problems=problems)
    if verdict is PathVerdict.UNKNOWN:
        first = next(hop for hop in hops if hop.verdict is PathVerdict.UNKNOWN)
        return CaseOutcome(
            status=CaseStatus.INCONCLUSIVE, decision=decision, notes=(_unknown_note(first.caller),)
        )
    if verdict is PathVerdict.ALLOW:
        if case.expect == "allow":
            return CaseOutcome(status=CaseStatus.PASS, decision=decision)
        note = "expected deny, but the IAM allowed it"
        return CaseOutcome(status=CaseStatus.FAIL_POLICY, decision=decision, notes=(note,))
    if case.expect == "allow":
        note = f"expected allow, but the IAM denied {denied_hop}"
        return CaseOutcome(status=CaseStatus.FAIL_POLICY, decision=decision, notes=(note,))
    control = case.hops[denied_index or 0].control
    if control in allowed:
        return CaseOutcome(status=CaseStatus.PASS, decision=decision)
    return CaseOutcome(
        status=CaseStatus.INCONCLUSIVE, decision=decision, notes=(_no_control_note(control),)
    )


def _controls(queries: QueryPlan, answers: Mapping[str, Decision]) -> tuple[ControlRow, ...]:
    """One row per asked control pair; allowed_by is the first allow in plan order."""
    state: dict[ControlKey, str | None] = {}

    def note(control: ControlKey, query: Query, label: str) -> None:
        state.setdefault(control, None)
        if state[control] is None and _lookup(answers, query).verdict is Verdict.ALLOW:
            state[control] = label

    for case in queries.cases:
        for hop in case.hops:
            state.setdefault(hop.control, None)
            label = case.case_id
            if hop.kind == "agent":
                label = f"{case.case_id} ({hop.caller} -> {hop.target})"
            for query in hop.queries:
                note(hop.control, query, label)
        if case.plain_user is not None and case.hops:
            note(case.tool_hop.control, case.plain_user, case.case_id)
    for row in queries.rows:
        if row.control is None:
            continue
        state.setdefault(row.control, None)
        for query in (row.path_query, row.user_query):
            if query is not None:
                note(row.control, query, f"{row.role}/{row.tool} via {row.via}")
    return tuple(
        ControlRow(
            action=control[0],
            resource_type=control[1],
            allowed=state[control] is not None,
            allowed_by=state[control],
        )
        for control in sorted(state)
    )


class _Escalation(NamedTuple):
    result: EscalationResult
    notes: tuple[str, ...]
    hint: bool = False  # NONE, but the IAM allows the user and denies the route's identity


def _escalation_result(
    user: Answer,
    path: Answer,
    *,
    undeclared: bool,
    via: str,
    control: ControlKey,
    allowed: set[ControlKey],
) -> _Escalation:
    if user.verdict is Verdict.ERROR or path.verdict is Verdict.ERROR:
        notes = tuple(
            f"{side}: {answer.error}"
            for side, answer in (("user identity", user), ("route identity", path))
            if answer.error is not None
        )
        return _Escalation(EscalationResult.ERROR, notes)
    if user.verdict is Verdict.ALLOW:
        if path.verdict is Verdict.ALLOW:
            return _Escalation(EscalationResult.NONE, ())
        return _Escalation(EscalationResult.NONE, (_HINT_NOTE,), hint=True)
    if path.verdict is Verdict.ALLOW:
        if undeclared:
            note = (
                f"if {via!r} calls the tool with its own identity, this is an escalation; "
                "declare its delegation_mode"
            )
            return _Escalation(EscalationResult.INCONCLUSIVE, (note,))
        return _Escalation(EscalationResult.ESCALATION, (_ESCALATION_NOTE,))
    if control in allowed:
        return _Escalation(EscalationResult.NONE, ())
    return _Escalation(EscalationResult.INCONCLUSIVE, (_no_control_note(control),))


def _escalation_row(
    *,
    case_id: str | None,
    role: str,
    tool: str,
    via: str,
    risk: Risk,
    mode: IdentityMode,
    path: tuple[str, ...],
    found: _Escalation | None = None,
    note: str | None = None,
    user_answer: Answer | None = None,
    path_answer: Answer | None = None,
) -> EscalationRow:
    """One row: judged (found) or UNCHECKED (note is the reason)."""
    if found is None:
        result, notes = EscalationResult.UNCHECKED, (note or "this route was not checked",)
    else:
        result, notes = found.result, found.notes
    return EscalationRow(
        case_id=case_id,
        role=role,
        tool=tool,
        via=via,
        risk=risk,
        mode=mode,
        path=path,
        result=result,
        user_answer=user_answer,
        path_answer=path_answer,
        notes=notes,
    )


def _case_escalation(
    case: CaseAsk, answers: Mapping[str, Decision], allowed: set[ControlKey]
) -> tuple[EscalationRow, bool] | None:
    if case.problems or not case.hops or case.plain_user is None:
        return None
    hop = case.tool_hop
    user_answer = _to_answer(answers, case.plain_user)
    path_answer = _to_answer(answers, hop.queries[-1])
    via = case.route[-1]
    found = _escalation_result(
        user_answer,
        path_answer,
        undeclared=hop.mode == "undeclared",
        via=via,
        control=hop.control,
        allowed=allowed,
    )
    row = _escalation_row(
        case_id=case.case_id,
        role=case.role,
        tool=case.tool,
        via=via,
        risk=case.risk,
        mode=hop.mode,
        path=case.route,
        found=found,
        user_answer=user_answer,
        path_answer=path_answer,
    )
    return row, found.hint


def _row_escalation(
    ask: RowAsk, answers: Mapping[str, Decision], allowed: set[ControlKey]
) -> tuple[EscalationRow, bool]:
    if (
        ask.unchecked is not None
        or ask.path_query is None
        or ask.user_query is None
        or ask.control is None
    ):
        # Fail closed: a row without questions is never judged.
        row = _escalation_row(
            case_id=None,
            role=ask.role,
            tool=ask.tool,
            via=ask.via,
            risk=ask.risk,
            mode=ask.mode,
            path=ask.path,
            note=ask.unchecked,
        )
        return row, False
    user_answer = _to_answer(answers, ask.user_query)
    path_answer = _to_answer(answers, ask.path_query)
    found = _escalation_result(
        user_answer,
        path_answer,
        undeclared=ask.mode == "undeclared",
        via=ask.via,
        control=ask.control,
        allowed=allowed,
    )
    row = _escalation_row(
        case_id=None,
        role=ask.role,
        tool=ask.tool,
        via=ask.via,
        risk=ask.risk,
        mode=ask.mode,
        path=ask.path,
        found=found,
        user_answer=user_answer,
        path_answer=path_answer,
    )
    return row, found.hint


def _label(row: EscalationRow) -> str:
    return row.case_id or f"{row.role}/{row.tool} via {row.via}"


def _unchecked_gated(risk: Risk, gate: GateConfig) -> bool:
    return risk in gate.fail_on_unchecked_escalation


def _violation(rule: GateRule, row: EscalationRow, **extra: Risk) -> GateViolation:
    return GateViolation(
        rule=rule, role=row.role, tool=row.tool, via=row.via, case_id=row.case_id, **extra
    )


def _escalation_violation(row: EscalationRow, gate: GateConfig) -> GateViolation | None:
    if row.result is EscalationResult.ESCALATION and gate.fail_on_escalation:
        return _violation("fail_on_escalation", row)
    if row.result is EscalationResult.INCONCLUSIVE and gate.fail_on_inconclusive_escalation:
        return _violation("fail_on_inconclusive_escalation", row)
    if row.result is EscalationResult.UNCHECKED and _unchecked_gated(row.risk, gate):
        return _violation("fail_on_unchecked_escalation", row, risk=row.risk)
    return None


def _errors(
    queries: QueryPlan, outcomes: Mapping[str, CaseOutcome], escalations: list[EscalationRow]
) -> tuple[str, ...]:
    errors: list[str] = []
    for case in queries.cases:
        outcome = outcomes[case.case_id]
        if outcome.status is CaseStatus.ERROR:
            errors.extend(f"{case.case_id}: {problem}" for problem in outcome.problems)
    for esc in escalations:
        if esc.result is not EscalationResult.ERROR:
            continue
        if esc.case_id is not None and outcomes[esc.case_id].status is CaseStatus.ERROR:
            continue  # the case's own errors already say it
        errors.extend(f"escalation {_label(esc)}: {note}" for note in esc.notes)
    return tuple(errors)


def _warnings(
    escalations: list[EscalationRow], hints: list[bool], gate: GateConfig
) -> tuple[str, ...]:
    warnings = [
        f"{_label(esc)}: {_HINT_NOTE}" for esc, hint in zip(escalations, hints, strict=True) if hint
    ]
    ungated: dict[str, list[str]] = {}
    for esc in escalations:
        if esc.result is EscalationResult.UNCHECKED and not _unchecked_gated(esc.risk, gate):
            ungated.setdefault(esc.role, []).append(f"{esc.tool} via {esc.via}")
    for role, names in ungated.items():
        count = len(names)
        warnings.append(
            f"role {role!r}: {count} escalation {plural('check', count)} not run: "
            f"{name_list(names)}"
        )
    return tuple(warnings)


def case_violations(
    cases: Sequence[tuple[str, CaseStatus]], gate: GateConfig
) -> list[GateViolation]:
    """The gate violations of case statuses, in case order (also used for door statuses)."""
    violations: list[GateViolation] = []
    for case_id, status in cases:
        if status in (CaseStatus.FAIL_POLICY, CaseStatus.FAIL_EXECUTION):
            violations.append(GateViolation(rule="case", case_id=case_id, status=status))
        elif status is CaseStatus.INCONCLUSIVE and gate.fail_on_inconclusive_case:
            violations.append(
                GateViolation(rule="fail_on_inconclusive_case", case_id=case_id, status=status)
            )
    return violations


def _violations(
    queries: QueryPlan,
    outcomes: Mapping[str, CaseOutcome],
    escalations: list[EscalationRow],
    gate: GateConfig,
) -> tuple[GateViolation, ...]:
    violations = case_violations(
        [(c.case_id, outcomes[c.case_id].status) for c in queries.cases], gate
    )
    for esc in escalations:
        violation = _escalation_violation(esc, gate)
        if violation is not None:
            violations.append(violation)
    return tuple(violations)


def judge(queries: QueryPlan, answers: Mapping[str, Decision], gate: GateConfig) -> PolicyOutcome:
    """Turn the answers into case outcomes, escalation rows, controls, and violations.

    answers maps Query.key() to the Decision from runner.ask_all. A query whose key is
    missing counts as an ERROR answer. Case ids must be unique (the spec loader rejects
    duplicates).
    """
    controls = _controls(queries, answers)
    allowed = {(c.action, c.resource_type) for c in controls if c.allowed}
    outcomes = {case.case_id: _judge_case(case, answers, allowed) for case in queries.cases}

    found = [_case_escalation(case, answers, allowed) for case in queries.cases]
    pairs = [pair for pair in found if pair is not None]
    pairs.extend(_row_escalation(ask, answers, allowed) for ask in queries.rows)
    escalations = [row for row, _ in pairs]
    hints = [hint for _, hint in pairs]

    return PolicyOutcome(
        cases=outcomes,
        escalations=tuple(escalations),
        controls=controls,
        errors=_errors(queries, outcomes, escalations),
        warnings=_warnings(escalations, hints, gate),
        violations=_violations(queries, outcomes, escalations, gate),
    )
