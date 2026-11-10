"""Waivers: accepted risks with an owner and an expiry date.

A waived finding stays in the report but no longer blocks the gate. A waiver acts on gate
violations: an applied waiver moves its violations from `gate.violations` to `gate.waived`
and sets `waived_by` on the matching report rows. The finding's own status is unchanged.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, ValidationError, field_validator, model_validator

from lockwalk.config import GateConfig
from lockwalk.errors import StructuralError, format_validation_error
from lockwalk.models import (
    MAX_ROUTE_AGENTS,
    OBSERVE_ONLY_NOTE,
    TEST_ONLY_NOTE,
    CaseStatus,
    CoverageReport,
    EscalationResult,
    Frozen,
    GateResult,
    GateViolation,
    NonEmptyStr,
    RuleResult,
    SchemaVersion,
    WaivedViolation,
    WaiverRow,
)
from lockwalk.observe.results import (
    GuardRow,
    ObserveGate,
    ObserveReport,
    ObserveViolation,
    ObserveWaived,
)
from lockwalk.yamlio import load_yaml

_ESCALATION_RULES = frozenset(
    {"fail_on_escalation", "fail_on_inconclusive_escalation", "fail_on_unchecked_escalation"}
)
# Kinds only `lockwalk test` can check: in static mode they are not reported as stale.
_TEST_ONLY_KINDS = frozenset({"case", "escalation", "identity"})

Key = tuple[str, ...]


def today() -> date:
    """The current UTC date. The only clock waivers use, so tests can replace it."""
    return datetime.now(UTC).date()


class EscalationMatch(Frozen):
    case: NonEmptyStr | None = None
    role: NonEmptyStr | None = None
    tool: NonEmptyStr | None = None
    via: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _one_shape(self) -> Self:
        triple = (self.role, self.tool, self.via)
        if self.case is not None:
            if any(item is not None for item in triple):
                raise ValueError("escalation takes either 'case' or all of role, tool and via")
        elif any(item is None for item in triple):
            raise ValueError("escalation takes either 'case' or all of role, tool and via")
        return self


class RoleGapMatch(Frozen):
    role: NonEmptyStr
    tool: NonEmptyStr


class RouteMatch(Frozen):
    """An off-map route: from is "user" or an agent id (written `from`)."""

    from_: NonEmptyStr = Field(alias="from")
    to: NonEmptyStr


class UnknownMatch(Frozen):
    kind: Literal["agent", "tool", "caller"]
    name: NonEmptyStr


class AgentToolMatch(Frozen):
    agent: NonEmptyStr  # "(none)" for a tool call with no calling agent
    tool: NonEmptyStr


class PathToolMatch(Frozen):
    """A path given exactly (no wildcards; "?" is matched literally, as the unknown-step marker
    lockwalk itself writes) and a tool. tool may be null for observed_identity."""

    path: Annotated[tuple[NonEmptyStr, ...], Field(min_length=1, max_length=MAX_ROUTE_AGENTS)]
    tool: NonEmptyStr | None = None


class UntestedPathMatch(Frozen):
    """Like PathToolMatch, but the tool is required."""

    path: Annotated[tuple[NonEmptyStr, ...], Field(min_length=1, max_length=MAX_ROUTE_AGENTS)]
    tool: NonEmptyStr


# Kinds only `lockwalk observe` can check.
OBSERVE_KINDS = frozenset({"route", "unknown", "unguarded", "observed_identity", "untested_path"})
COVERAGE_KINDS = frozenset(
    {"case", "rule", "escalation", "identity", "role_gap", "tool_gap"}
)  # kinds only lockwalk coverage or lockwalk test can check
COVERAGE_OR_TEST_ONLY_NOTE = "checked only by lockwalk coverage or lockwalk test"


class WaiverMatch(Frozen):
    """Exactly one kind, and plain strings only: no wildcards."""

    case: NonEmptyStr | None = None
    rule: NonEmptyStr | None = None
    escalation: EscalationMatch | None = None
    identity: NonEmptyStr | None = None
    role_gap: RoleGapMatch | None = None
    tool_gap: NonEmptyStr | None = None
    route: RouteMatch | None = None  # {from, to}
    unknown: UnknownMatch | None = None  # {kind, name}
    unguarded: AgentToolMatch | None = None  # {agent, tool}; agent may be "(none)"
    observed_identity: PathToolMatch | None = None  # {path: [...], tool: str | null}
    untested_path: UntestedPathMatch | None = None  # {path: [...], tool}

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        set_kinds = [name for name in type(self).model_fields if getattr(self, name) is not None]
        if len(set_kinds) != 1:
            raise ValueError(
                "match must have exactly one of case, rule, escalation, identity, "
                "role_gap, tool_gap, route, unknown, unguarded, observed_identity, "
                f"untested_path (found {len(set_kinds)})"
            )
        return self

    @property
    def kind(self) -> str:
        return next(name for name in type(self).model_fields if getattr(self, name) is not None)


class Waiver(Frozen):
    id: NonEmptyStr
    match: WaiverMatch
    reason: NonEmptyStr
    owner: NonEmptyStr
    expires: date

    @field_validator("expires", mode="before")
    @classmethod
    def _date_only(cls, value: object) -> object:
        # datetime is a date subclass, and YAML turns "2026-12-31 10:00:00" into one.
        if isinstance(value, datetime):
            raise ValueError("expires must be a date (YYYY-MM-DD), not a date and time")
        return value


class WaiversFile(Frozen):
    schema_version: SchemaVersion
    waivers: tuple[Waiver, ...]


def load_waivers(path: Path, gate: GateConfig, today: date) -> WaiversFile:
    """Read and validate a waivers file. Every problem raises StructuralError (exit 2)."""
    data = load_yaml(path)
    if data is None:
        raise StructuralError(str(path), ["the file is empty"])
    if not isinstance(data, dict):
        raise StructuralError(str(path), ["the file must contain a mapping with schema_version"])
    try:
        parsed = WaiversFile.model_validate(data)
    except ValidationError as exc:
        raise StructuralError(str(path), format_validation_error(exc)) from exc
    problems: list[str] = []
    first_seen: dict[str, int] = {}
    latest = today + timedelta(days=gate.max_waiver_days)
    for index, waiver in enumerate(parsed.waivers):
        if waiver.id in first_seen:
            problems.append(
                f"waivers[{index}] {waiver.id}: duplicate id (first used by "
                f"waivers[{first_seen[waiver.id]}])"
            )
        else:
            first_seen[waiver.id] = index
        if waiver.expires > latest:
            problems.append(
                f"waivers[{index}] {waiver.id}: expires {waiver.expires.isoformat()} is more "
                f"than [gate] max_waiver_days = {gate.max_waiver_days} days after today "
                f"({today.isoformat()})"
            )
    if problems:
        raise StructuralError(str(path), problems)
    return parsed


def _violation_key(violation: GateViolation) -> Key:
    rule = violation.rule
    if rule in ("case", "fail_on_inconclusive_case"):
        return ("case", str(violation.case_id))
    if rule == "never_reaches":
        return ("rule", str(violation.rule_id))
    if rule in _ESCALATION_RULES:
        if violation.case_id is not None:
            return ("esc_case", violation.case_id)
        return ("esc_triple", str(violation.role), str(violation.tool), str(violation.via))
    if rule == "fail_on_identity_mismatch":
        return ("identity", str(violation.case_id))
    if rule == "fail_on_unspecified_role_risk":
        return ("role_gap", str(violation.role), str(violation.tool))
    return ("tool_gap", str(violation.tool))


def _waiver_key(match: WaiverMatch) -> Key:
    if match.case is not None:
        return ("case", match.case)
    if match.rule is not None:
        return ("rule", match.rule)
    if match.escalation is not None:
        esc = match.escalation
        if esc.case is not None:
            return ("esc_case", esc.case)
        return ("esc_triple", str(esc.role), str(esc.tool), str(esc.via))
    if match.identity is not None:
        return ("identity", match.identity)
    if match.role_gap is not None:
        return ("role_gap", match.role_gap.role, match.role_gap.tool)
    if match.route is not None:
        return ("route", match.route.from_, match.route.to)
    if match.unknown is not None:
        return ("unknown", match.unknown.kind, match.unknown.name)
    if match.unguarded is not None:
        return ("unguarded", match.unguarded.agent, match.unguarded.tool)
    if match.observed_identity is not None:
        oid = match.observed_identity
        return ("observed_identity", oid.tool or "", *oid.path)
    if match.untested_path is not None:
        return ("untested_path", match.untested_path.tool, *match.untested_path.path)
    return ("tool_gap", str(match.tool_gap))


def _label(key: Key) -> str:
    kind = key[0]
    if kind == "role_gap":
        return f"{key[1]}/{key[2]}"
    if kind == "esc_triple":
        return f"{key[1]}/{key[2]} via {key[3]}"
    if kind == "route":
        return f"{key[1]} -> {key[2]}"
    if kind == "unknown":
        return f"{key[1]} {key[2]}"
    if kind == "unguarded":
        return f"{key[1]}/{key[2]}"
    if kind in ("observed_identity", "untested_path"):
        path = " > ".join(key[2:])
        return f"{path} ({key[1]})" if key[1] else path
    return key[1]


def _error_targets(report: CoverageReport) -> dict[Key, str]:
    """Rows that are ERROR, which a waiver may not cover, by waiver key."""
    targets: dict[Key, str] = {}
    for case in report.cases:
        if case.status == CaseStatus.ERROR:
            targets.setdefault(("case", case.id), f"case {case.id}")
            targets.setdefault(("identity", case.id), f"case {case.id}")
    for rule in report.rules:
        if rule.result == RuleResult.ERROR:
            targets.setdefault(("rule", rule.id), f"rule {rule.id}")
    for esc in report.escalations:
        if esc.result == EscalationResult.ERROR:
            key = (
                ("esc_case", esc.case_id)
                if esc.case_id is not None
                else ("esc_triple", esc.role, esc.tool, esc.via)
            )
            targets.setdefault(key, f"escalation {_label(key)}")
    return targets


@dataclass
class _Outcome:
    """What the shared loop decided: rows, warnings, which violations were taken, by whom."""

    taken: dict[int, str] = field(default_factory=dict)  # violation index -> waiver id
    # (violation index, waiver id), in the order waivers took them
    order: list[tuple[int, str]] = field(default_factory=list)
    row_marks: dict[Key, str] = field(default_factory=dict)  # waiver key -> waiver id
    rows: list[WaiverRow] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _run_waivers(
    waivers: WaiversFile,
    violations: Sequence[Any],
    violation_key: Callable[[Any], Key],
    today: date,
    *,
    error_targets: dict[Key, str],
    silent_kinds: frozenset[str],
    silent_note: str,
    static_quiet_kinds: frozenset[str] = frozenset(),
    static: bool = False,
) -> _Outcome:
    """The loop both commands share. Statuses: applied, expired, unmatched, not_allowed."""
    out = _Outcome()
    taken, rows, warnings = out.taken, out.rows, out.warnings
    by_key: dict[Key, list[int]] = {}
    for index, violation in enumerate(violations):
        by_key.setdefault(violation_key(violation), []).append(index)
    # Expired waivers with hits: (row index, warning index, hits). Their wording depends on
    # waivers that come later in the file, so it is settled after the loop.
    expired_hits: list[tuple[int, int, list[int]]] = []

    for waiver in waivers.waivers:
        expires = waiver.expires.isoformat()
        match_dump = waiver.match.model_dump(exclude_none=True, by_alias=True)
        if waiver.match.kind in silent_kinds:
            # Another command checks these kinds: unmatched, with a note and no warning.
            rows.append(
                WaiverRow(
                    id=waiver.id,
                    owner=waiver.owner,
                    expires=expires,
                    reason=waiver.reason,
                    match=match_dump,
                    status="unmatched",
                    note=silent_note,
                )
            )
            continue
        key = _waiver_key(waiver.match)
        label = _label(key)
        hits = by_key.get(key, [])
        free = [index for index in hits if index not in taken]
        status = "unmatched"
        matched: tuple[str, ...] = ()
        note: str | None = None
        if waiver.expires < today:
            status = "expired"
            head = f"waiver {waiver.id} expired on {expires} (owner {waiver.owner})"
            if hits:
                matched = (label,)
                note = f"{head}; {label} blocks the gate again"
                expired_hits.append((len(rows), len(warnings), hits))
            else:
                note = head
            warnings.append(note)
        elif free:
            status = "applied"
            matched = (label,)
            for index in free:
                taken[index] = waiver.id
                out.order.append((index, waiver.id))
            out.row_marks.setdefault(key, waiver.id)
        elif not hits and key in error_targets:
            status = "not_allowed"
            note = (
                f"waiver {waiver.id} matches {error_targets[key]}, which is ERROR; "
                "an ERROR means the test itself is broken and cannot be waived"
            )
            warnings.append(note)
        elif not hits and static and waiver.match.kind in static_quiet_kinds:
            note = TEST_ONLY_NOTE
        else:
            if hits:
                # Every matching violation was taken by an earlier waiver.
                matched = (label,)
                note = (
                    f"waiver {waiver.id} adds nothing: its findings are already waived by "
                    f"{taken[hits[0]]} (owner {waiver.owner})"
                )
            else:
                note = (
                    f"waiver {waiver.id} matches nothing in this run; it may be stale "
                    f"(owner {waiver.owner})"
                )
            warnings.append(note)
        rows.append(
            WaiverRow(
                id=waiver.id,
                owner=waiver.owner,
                expires=expires,
                reason=waiver.reason,
                match=match_dump,
                status=status,
                matched=matched,
                note=note,
            )
        )

    for row_index, warn_index, hits in expired_hits:
        if all(index in taken for index in hits):
            row = rows[row_index]
            covering = ", ".join(dict.fromkeys(taken[index] for index in hits))
            note = (
                f"waiver {row.id} expired on {row.expires} (owner {row.owner}); "
                f"its findings are covered by {covering}"
            )
            rows[row_index] = row.model_copy(update={"note": note})
            warnings[warn_index] = note
    return out


def apply_waivers(report: CoverageReport, waivers: WaiversFile, today: date) -> CoverageReport:
    """Return the report with the waivers applied. Pure, and linear in violations + waivers."""
    violations = report.gate.violations
    out = _run_waivers(
        waivers,
        violations,
        _violation_key,
        today,
        error_targets=_error_targets(report),
        silent_kinds=OBSERVE_KINDS,
        silent_note=OBSERVE_ONLY_NOTE,
        static_quiet_kinds=_TEST_ONLY_KINDS,
        static=report.mode == "static",
    )
    taken = out.taken
    waived = [
        WaivedViolation(violation=violations[index], waiver_id=wid) for index, wid in out.order
    ]
    remaining = tuple(v for i, v in enumerate(violations) if i not in taken)
    gate = GateResult(passed=not remaining, violations=remaining, waived=tuple(waived))
    # ERROR results create no gate violations, so a waiver can never cover them. The exit code
    # therefore relies on every ERROR result also having a line in `errors` (the analyzer adds
    # a line when one is missing, see UNEXPLAINED_ERROR).
    update: dict[str, Any] = {
        "gate": gate,
        "waivers": tuple(out.rows),
        "warnings": report.warnings + tuple(out.warnings),
        "exit_code": 2 if report.errors else (1 if remaining else 0),
    }
    if out.row_marks:
        update.update(_mark_rows(report, out.row_marks))
    return report.model_copy(update=update)


# The gate rules each row status can produce; marking follows these.
_ROUTE_RULES: dict[str, tuple[str, ...]] = {"ON_MAP": (), "OFF_MAP": ("fail_on_off_map_route",)}
_IDENTITY_RULES: dict[str, tuple[str, ...]] = {
    "MATCH": (),
    "OBSERVED": (),
    "MISMATCH": ("fail_on_identity_mismatch",),
    "INCONCLUSIVE": ("fail_on_inconclusive_observation",),
}
_PATH_RULES: dict[str, tuple[str, ...]] = {
    "TESTED": (),
    "TESTED_OTHER_PATH": (),
    "UNTESTED": ("fail_on_untested_path",),
}
_GUARD_RULES = {
    "BYPASS": "bypass",
    "UNGUARDED": "fail_on_unguarded_call",
    "INCONCLUSIVE": "fail_on_inconclusive_observation",
}


def _guard_rules(row: GuardRow) -> tuple[str, ...]:
    return tuple(rule for status, rule in _GUARD_RULES.items() if status in row.counts)


def _observe_violation_key(violation: ObserveViolation) -> Key:
    rule = violation.rule
    if rule == "fail_on_off_map_route":
        return ("route", str(violation.from_id), str(violation.to_id))
    if rule == "fail_on_unknown_component":
        return ("unknown", str(violation.kind), str(violation.name))
    guard = ("unguarded", violation.agent or "(none)", str(violation.tool))
    if rule in ("bypass", "fail_on_unguarded_call"):
        return guard
    if rule == "fail_on_inconclusive_observation" and violation.subject == "guard":
        return guard
    path = violation.path or ()
    if rule == "fail_on_untested_path":
        return ("untested_path", str(violation.tool), *path)
    return ("observed_identity", violation.tool or "", *path)


def apply_observe_waivers(
    report: ObserveReport, waivers: WaiversFile, today: date
) -> ObserveReport:
    """Return the observe report with the waivers applied. Pure."""
    violations = report.gate.violations
    out = _run_waivers(
        waivers,
        violations,
        _observe_violation_key,
        today,
        error_targets={},
        silent_kinds=COVERAGE_KINDS,
        silent_note=COVERAGE_OR_TEST_ONLY_NOTE,
    )
    taken = out.taken
    waived = tuple(
        ObserveWaived(violation=violations[index], waiver_id=wid) for index, wid in out.order
    )
    remaining = tuple(v for i, v in enumerate(violations) if i not in taken)
    # (key, rule) of every waived violation -> the waiver that took it
    waived_by: dict[tuple[Key, str], str] = {}
    for index, wid in out.order:
        violation = violations[index]
        waived_by.setdefault((_observe_violation_key(violation), violation.rule), wid)

    def mark(row: Any, key: Key, rules: tuple[str, ...]) -> Any:
        # A row is marked only when a waived violation has its key and a rule its status makes.
        return _mark(row, next((waived_by[(key, r)] for r in rules if (key, r) in waived_by), None))

    gate = ObserveGate(
        passed=not remaining, violations=remaining, waived=report.gate.waived + waived
    )
    exit_code = 2 if report.errors else (1 if remaining else 0)
    data: dict[str, Any] = {name: getattr(report, name) for name in type(report).model_fields}
    data.update(
        gate=gate,
        waivers=tuple(out.rows),
        warnings=report.warnings + tuple(out.warnings),
        exit_code=exit_code,
    )
    if waived_by:
        data["routes"] = tuple(
            mark(r, ("route", r.from_id, r.to_id), _ROUTE_RULES[r.status]) for r in report.routes
        )
        data["unknown"] = tuple(
            mark(u, ("unknown", u.kind, u.name), ("fail_on_unknown_component",))
            for u in report.unknown
        )
        data["identities"] = tuple(
            mark(i, ("observed_identity", i.tool or "", *i.path), _IDENTITY_RULES[i.result])
            for i in report.identities
        )
        data["guards"] = tuple(
            mark(g, ("unguarded", g.agent or "(none)", g.tool), _guard_rules(g))
            for g in report.guards
        )
        data["paths"] = tuple(
            mark(p, ("untested_path", p.tool, *p.path), _PATH_RULES[p.status]) for p in report.paths
        )
    return ObserveReport.model_validate(data)


def _mark(row: Any, waiver_id: str | None) -> Any:
    return row if waiver_id is None else row.model_copy(update={"waived_by": waiver_id})


def _mark_rows(report: CoverageReport, marks: dict[Key, str]) -> dict[str, Any]:
    def mark(row: Any, key: Key) -> Any:
        return _mark(row, marks.get(key))

    update: dict[str, Any] = {
        "cases": tuple(mark(c, ("case", c.id)) for c in report.cases),
        "rules": tuple(mark(r, ("rule", r.id)) for r in report.rules),
        "escalations": tuple(
            mark(
                e,
                ("esc_case", e.case_id)
                if e.case_id is not None
                else ("esc_triple", e.role, e.tool, e.via),
            )
            for e in report.escalations
        ),
        "identity_checks": tuple(mark(i, ("identity", i.case_id)) for i in report.identity_checks),
    }
    if report.reachability is not None:
        update["reachability"] = tuple(
            mark(r, ("role_gap", r.role, r.tool)) for r in report.reachability
        )
    return update
