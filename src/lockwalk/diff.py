"""Compare two lockwalk reports and say what changed.

A pure comparison: it never decides pass or fail. The head report's own gate does that.
"""

from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from lockwalk.models import (
    CaseRow,
    CaseStatus,
    CoverageReport,
    Frozen,
    GateViolation,
    Risk,
    RuleResult,
    RuleRow,
    ToolCoverage,
    ToolRow,
    WaiverRow,
)
from lockwalk.report import read_report

DIFF_SCHEMA_VERSION = "2"
READ_HINT = "run lockwalk coverage or lockwalk test"
NO_BASE = "no base report was given: this shows the head report only"
MODES_DIFFER = (
    "the reports come from different commands (coverage and test), "
    "so case statuses are not compared"
)
SUITES_DIFFER = "the reports have different scenario suites"
HEAD_INCOMPLETE = (
    "the head report has errors: it is incomplete, so this comparison may be wrong "
    "and problems that went away are not listed"
)
BASE_INCOMPLETE = "the base report has errors: it is incomplete, so this comparison may be wrong"
_FAILED = frozenset({CaseStatus.FAIL_POLICY, CaseStatus.FAIL_EXECUTION})

HeadStatus = Literal["PASS", "FAIL", "ERROR"]

# Field names come from these fixed lists, so a row can name a field without quoting anything.
CaseField = Literal["tool", "agent", "path", "action", "expect", "actor", "role"]
RuleField = Literal["result", "agent", "role", "tool", "target_agent"]
WaiverField = Literal["owner", "expires", "reason", "match"]
_CASE_FIELDS: tuple[CaseField, ...] = ("expect", "tool", "agent", "path", "action", "role", "actor")
_RULE_FIELDS: tuple[RuleField, ...] = ("result", "agent", "role", "tool", "target_agent")
_WAIVER_FIELDS: tuple[WaiverField, ...] = ("owner", "expires", "reason", "match")
# An actor may be a person's id: a change is reported by field name only, never by value.
_NAME_ONLY = frozenset({"actor"})


class ToolRef(Frozen):
    id: str
    risk: Risk


class RiskChange(Frozen):
    id: str
    base: Risk
    head: Risk


class CaseRef(Frozen):
    id: str
    tool: str
    status: CaseStatus


class CaseChange(Frozen):
    id: str
    tool: str
    base: CaseStatus
    head: CaseStatus


class WaivedRef(Frozen):
    violation: GateViolation
    waiver_id: str


class WaiverRef(Frozen):
    id: str
    expires: str


class WaiverChange(Frozen):
    """A waiver in both reports whose text in the waivers file differs.

    owner and reason are free text that may name a person, so only the names of the changed
    fields are kept. The expiry dates are set only when the expiry changed.
    """

    id: str
    fields: tuple[WaiverField, ...]
    base_expires: str | None = None
    head_expires: str | None = None


class FieldChange(Frozen):
    """One changed field. base and head are None when unset, and always None for an actor."""

    field: CaseField | RuleField
    base: str | None
    head: str | None


class CaseSpecChange(Frozen):
    id: str
    tool: str
    changes: tuple[FieldChange, ...]


class RuleRef(Frozen):
    id: str
    result: RuleResult


class RuleChange(Frozen):
    id: str
    changes: tuple[FieldChange, ...]


class ReportDiff(Frozen):
    head_status: HeadStatus
    head_violations: int
    waived: int
    base_given: bool
    incomplete: bool
    warnings: tuple[str, ...]
    new_violations: tuple[GateViolation, ...]
    # Waived in the head and not in the base, with the waiver that covers each one.
    newly_waived: tuple[WaivedRef, ...]
    # In the base (active or waived) and neither active nor waived in the head.
    # lockwalk cannot tell why: a real fix, a removed tool or case, or a gate rule that was
    # switched off. Always empty when the head has errors: a broken run may only be missing
    # problems.
    no_longer_reported: tuple[GateViolation, ...]
    waivers_added: tuple[WaiverRef, ...]
    waivers_removed: tuple[WaiverRef, ...]
    waivers_changed: tuple[WaiverChange, ...]
    tools_added_without_spec: tuple[ToolRef, ...]
    tools_added: tuple[ToolRef, ...]
    tools_removed: tuple[ToolRef, ...]
    tools_lost_spec: tuple[ToolRef, ...]
    tools_gained_spec: tuple[ToolRef, ...]
    risk_changes: tuple[RiskChange, ...]
    rules_added: tuple[RuleRef, ...]
    rules_removed: tuple[RuleRef, ...]
    rules_changed: tuple[RuleChange, ...]
    cases_added: tuple[CaseRef, ...]
    cases_removed: tuple[CaseRef, ...]
    cases_worse: tuple[CaseChange, ...]
    cases_better: tuple[CaseChange, ...]
    cases_changed: tuple[CaseSpecChange, ...]
    cases_other: tuple[CaseChange, ...]


def load_report(path: Path) -> CoverageReport:
    """Read one report. Raises ReportFileError with a message that never quotes the file."""
    return read_report(path, hint=READ_HINT)


def head_status(report: CoverageReport) -> HeadStatus:
    if report.errors:
        return "ERROR"
    return "PASS" if report.gate.passed else "FAIL"


NOT_RELIABLE = "No changes found, but this comparison is not reliable (see warnings)."
NO_CHANGES = "No changes in gate problems, waivers, tools, rules or cases."


def has_changes(diff: ReportDiff) -> bool:
    """True when any row list (not the warnings) has an entry."""
    # Every tuple field except the warnings is a row list, so a new list is never forgotten.
    return any(value and name != "warnings" for name, value in diff if isinstance(value, tuple))


def no_changes_line(diff: ReportDiff) -> str:
    """What to say when there is nothing to list; never plain when the diff is incomplete."""
    return NOT_RELIABLE if diff.incomplete else NO_CHANGES


def _violation_key(violation: GateViolation) -> tuple[str, ...]:
    # Stringify so optional fields (None or a value) still sort in one stable order.
    return tuple(str(value) for value in violation.model_dump(mode="json").values())


def _sorted_violations(items: Iterable[GateViolation]) -> tuple[GateViolation, ...]:
    return tuple(sorted(items, key=_violation_key))


def _tool_ref(tool: ToolRow) -> ToolRef:
    return ToolRef(id=tool.id, risk=tool.risk)


def _case_ref(case: CaseRow) -> CaseRef:
    return CaseRef(id=case.id, tool=case.tool, status=case.status)


def _bucket(base: CaseStatus, head: CaseStatus) -> Literal["worse", "better", "other"]:
    if base is CaseStatus.PASS or (head in _FAILED and base not in _FAILED):
        return "worse"
    if head is CaseStatus.PASS:
        return "better"
    return "other"


def _shown(value: object) -> str | None:
    """A field value as the text a row shows; None stays None (unset)."""
    if value is None:
        return None
    if isinstance(value, tuple):
        return " > ".join(str(item) for item in value)
    return str(getattr(value, "value", value))


def _field_changes(
    before: object, after: object, names: tuple[str, ...]
) -> tuple[FieldChange, ...]:
    found: list[FieldChange] = []
    for name in names:
        old, new = getattr(before, name), getattr(after, name)
        if old != new:
            hide = name in _NAME_ONLY
            # The field name is validated against the fixed lists by the model.
            found.append(
                FieldChange.model_validate(
                    {
                        "field": name,
                        "base": None if hide else _shown(old),
                        "head": None if hide else _shown(new),
                    }
                )
            )
    return tuple(found)


def _waiver_changes(
    head: Iterable[WaiverRow], base: Iterable[WaiverRow]
) -> tuple[tuple[WaiverRef, ...], tuple[WaiverRef, ...], tuple[WaiverChange, ...]]:
    now, before = {r.id: r for r in head}, {r.id: r for r in base}
    added = [
        WaiverRef(id=key, expires=row.expires) for key, row in now.items() if key not in before
    ]
    removed = [
        WaiverRef(id=key, expires=row.expires) for key, row in before.items() if key not in now
    ]
    changed: list[WaiverChange] = []
    for key in now.keys() & before.keys():
        fields = tuple(f for f in _WAIVER_FIELDS if getattr(before[key], f) != getattr(now[key], f))
        if fields:
            moved = "expires" in fields
            changed.append(
                WaiverChange(
                    id=key,
                    fields=fields,
                    base_expires=before[key].expires if moved else None,
                    head_expires=now[key].expires if moved else None,
                )
            )
    return (
        tuple(sorted(added, key=lambda ref: ref.id)),
        tuple(sorted(removed, key=lambda ref: ref.id)),
        tuple(sorted(changed, key=lambda change: change.id)),
    )


def _rule_changes(
    head: Iterable[RuleRow], base: Iterable[RuleRow]
) -> tuple[tuple[RuleRef, ...], tuple[RuleRef, ...], tuple[RuleChange, ...]]:
    now, before = {r.id: r for r in head}, {r.id: r for r in base}
    added = [RuleRef(id=key, result=row.result) for key, row in now.items() if key not in before]
    removed = [RuleRef(id=key, result=row.result) for key, row in before.items() if key not in now]
    changed: list[RuleChange] = []
    for key in now.keys() & before.keys():
        changes = _field_changes(before[key], now[key], _RULE_FIELDS)
        if changes:
            changed.append(RuleChange(id=key, changes=changes))
    return (
        tuple(sorted(added, key=lambda ref: ref.id)),
        tuple(sorted(removed, key=lambda ref: ref.id)),
        tuple(sorted(changed, key=lambda change: change.id)),
    )


def _warnings(head: CoverageReport, base: CoverageReport | None) -> tuple[str, ...]:
    found: list[str] = []
    if base is None:
        found.append(NO_BASE)
    else:
        if base.mode != head.mode:
            found.append(MODES_DIFFER)
        if base.scenario_suite != head.scenario_suite:
            found.append(SUITES_DIFFER)
        if base.errors:
            found.append(BASE_INCOMPLETE)
    if head.errors:
        found.append(HEAD_INCOMPLETE)
    return tuple(found)


def _tool_refs(tools: Iterable[ToolRow]) -> tuple[ToolRef, ...]:
    return tuple(sorted((_tool_ref(tool) for tool in tools), key=lambda ref: ref.id))


def _case_refs(cases: Iterable[CaseRow]) -> tuple[CaseRef, ...]:
    return tuple(sorted((_case_ref(case) for case in cases), key=lambda ref: ref.id))


def diff_reports(head: CoverageReport, base: CoverageReport | None) -> ReportDiff:
    """Compare head with base. With no base, only the head's own problems are listed.

    The producer never writes duplicate tool ids, case ids or violations, so collapsing
    them into dicts and sets loses nothing.
    """
    head_tools = {tool.id: tool for tool in head.inventory.tools}
    base_tools = {tool.id: tool for tool in base.inventory.tools} if base is not None else {}
    head_cases = {case.id: case for case in head.cases}
    base_cases = {case.id: case for case in base.cases} if base is not None else {}
    head_set = set(head.gate.violations)
    base_set = set(base.gate.violations) if base is not None else set()
    head_waived = {item.violation for item in head.gate.waived}
    base_waived = {item.violation for item in base.gate.waived} if base is not None else set()

    added = [tool for key, tool in head_tools.items() if key not in base_tools]
    both = [(base_tools[key], tool) for key, tool in head_tools.items() if key in base_tools]
    changes: dict[str, list[CaseChange]] = {"worse": [], "better": [], "other": []}
    spec_changes: list[CaseSpecChange] = []
    for key in sorted(head_cases.keys() & base_cases.keys()):
        before, after = base_cases[key], head_cases[key]
        # What a case checks comes from the spec, so it is compared in every mode.
        spec = _field_changes(before, after, _CASE_FIELDS)
        if spec:
            spec_changes.append(CaseSpecChange(id=key, tool=after.tool, changes=spec))
        if base is not None and base.mode == head.mode and before.status is not after.status:
            changes[_bucket(before.status, after.status)].append(
                CaseChange(id=key, tool=after.tool, base=before.status, head=after.status)
            )
    risk_changes = [
        RiskChange(id=after.id, base=before.risk, head=after.risk)
        for before, after in both
        if before.risk is not after.risk
    ]
    risk_changes.sort(key=lambda change: change.id)
    waivers_added, waivers_removed, waivers_changed = (
        _waiver_changes(head.waivers, base.waivers) if base is not None else ((), (), ())
    )
    rules_added, rules_removed, rules_changed = (
        _rule_changes(head.rules, base.rules) if base is not None else ((), (), ())
    )
    # With no base the first line already counts the waived violations.
    newly_waived = (
        sorted(
            (
                item
                for item in head.gate.waived
                if item.violation not in base_waived and item.violation not in head_set
            ),
            key=lambda item: (*_violation_key(item.violation), item.waiver_id),
        )
        if base is not None
        else []
    )
    status = head_status(head)
    head_failed = status == "ERROR"
    return ReportDiff(
        head_status=status,
        head_violations=len(head.gate.violations),
        waived=len(head.gate.waived),
        base_given=base is not None,
        incomplete=bool(head.errors or (base is not None and base.errors)),
        warnings=_warnings(head, base),
        new_violations=_sorted_violations(head_set - base_set),
        newly_waived=tuple(
            WaivedRef(violation=item.violation, waiver_id=item.waiver_id) for item in newly_waived
        ),
        # Everything in the base, active or waived, that is neither active nor waived in
        # the head. A broken head run may only be missing problems because it stopped early.
        no_longer_reported=()
        if head_failed
        else _sorted_violations((base_set | base_waived) - head_set - head_waived),
        waivers_added=waivers_added,
        waivers_removed=waivers_removed,
        waivers_changed=waivers_changed,
        tools_added_without_spec=_tool_refs(
            tool for tool in added if tool.coverage is ToolCoverage.UNSPECIFIED
        ),
        # With no base, only the tools without a spec are worth showing.
        tools_added=_tool_refs(
            tool
            for tool in added
            if base is not None and tool.coverage is not ToolCoverage.UNSPECIFIED
        ),
        tools_removed=_tool_refs(tool for key, tool in base_tools.items() if key not in head_tools),
        tools_lost_spec=_tool_refs(
            after
            for before, after in both
            if before.coverage is ToolCoverage.SPECIFIED
            and after.coverage is ToolCoverage.UNSPECIFIED
        ),
        tools_gained_spec=_tool_refs(
            after
            for before, after in both
            if before.coverage is ToolCoverage.UNSPECIFIED
            and after.coverage is ToolCoverage.SPECIFIED
        ),
        risk_changes=tuple(risk_changes),
        rules_added=rules_added,
        rules_removed=rules_removed,
        rules_changed=rules_changed,
        # With no base, every case would be "added": the violations already show the failures.
        cases_added=_case_refs(
            case for key, case in head_cases.items() if base is not None and key not in base_cases
        ),
        cases_removed=_case_refs(case for key, case in base_cases.items() if key not in head_cases),
        cases_worse=tuple(changes["worse"]),
        cases_better=tuple(changes["better"]),
        cases_changed=tuple(spec_changes),
        cases_other=tuple(changes["other"]),
    )
