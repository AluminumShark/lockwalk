"""Text and JSON output of `lockwalk diff`."""

import json
from datetime import datetime

from lockwalk.diff import (
    DIFF_SCHEMA_VERSION,
    FieldChange,
    ReportDiff,
    WaiverChange,
    has_changes,
    no_changes_line,
)
from lockwalk.output_files import utc_timestamp
from lockwalk.report import RULE, to_ascii, violation_line


def head_line(diff: ReportDiff) -> str:
    """The first line: the head gate, counts only (no counts when the head run broke)."""
    if diff.head_status == "ERROR":
        return "head gate: ERROR - see warnings"
    text = f"head gate: {diff.head_status} ({diff.head_violations} violation(s)"
    text += f", {diff.waived} waived)" if diff.waived else ")"
    return text + (" - see warnings" if diff.incomplete else "")


def _section(title: str, rows: list[str]) -> list[str]:
    return [f"{title} ({len(rows)}):", *rows, ""] if rows else []


NOT_SET = "(not set)"


def _value(value: str | None) -> str:
    if value is None:
        return NOT_SET
    return value or "(empty)"


def _change_text(change: FieldChange) -> str:
    """One changed field. An actor is named but its values are never shown."""
    if change.field == "actor":
        return "actor changed"
    label = change.field.upper() if change.field == "expect" else change.field
    return f"{label} {_value(change.base)} -> {_value(change.head)}"


def _waiver_change_text(change: WaiverChange) -> str:
    parts = [
        f"expires {change.base_expires} -> {change.head_expires}" if field == "expires" else field
        for field in change.fields
    ]
    return f"  - changed: {change.id}: {', '.join(parts)}"


def render_diff_text(diff: ReportDiff) -> list[str]:
    """Render the diff as plain ASCII lines."""
    lines = [f"lockwalk diff - {head_line(diff)}", RULE]
    body: list[str] = []
    if diff.warnings:
        body += ["Warnings:", *(f"  - {warning}" for warning in diff.warnings), ""]
    body += _section("New problems", [violation_line(v) for v in diff.new_violations])
    body += _section(
        "Newly waived",
        [f"{violation_line(w.violation)} [waiver {w.waiver_id}]" for w in diff.newly_waived],
    )
    body += _section("No longer reported", [violation_line(v) for v in diff.no_longer_reported])
    waiver_rows = [f"  - added: {w.id} (expires {w.expires})" for w in diff.waivers_added]
    waiver_rows += [f"  - removed: {w.id} (expires {w.expires})" for w in diff.waivers_removed]
    waiver_rows += [_waiver_change_text(c) for c in diff.waivers_changed]
    body += _section("Waiver changes", waiver_rows)
    body += _section(
        "New tools without spec",
        [f"  - {t.id} (risk={t.risk.value})" for t in diff.tools_added_without_spec],
    )
    other_tools = [f"  - added: {t.id} (risk={t.risk.value})" for t in diff.tools_added]
    other_tools += [f"  - removed: {t.id} (risk={t.risk.value})" for t in diff.tools_removed]
    other_tools += [
        f"  - lost its spec: {t.id} (risk={t.risk.value})" for t in diff.tools_lost_spec
    ]
    other_tools += [f"  - got a spec: {t.id} (risk={t.risk.value})" for t in diff.tools_gained_spec]
    other_tools += [f"  - risk: {c.id} {c.base.value} -> {c.head.value}" for c in diff.risk_changes]
    body += _section("Other tool changes", other_tools)
    rule_rows = [f"  - added: {r.id} ({r.result.value})" for r in diff.rules_added]
    rule_rows += [f"  - removed: {r.id} ({r.result.value})" for r in diff.rules_removed]
    rule_rows += [
        f"  - changed: {r.id}: {'; '.join(_change_text(c) for c in r.changes)}"
        for r in diff.rules_changed
    ]
    body += _section("Rule changes", rule_rows)
    body += _section(
        "Cases that got worse",
        [f"  - {c.id} ({c.tool}): {c.base.value} -> {c.head.value}" for c in diff.cases_worse],
    )
    body += _section(
        "Cases that got better",
        [f"  - {c.id} ({c.tool}): {c.base.value} -> {c.head.value}" for c in diff.cases_better],
    )
    body += _section(
        "Changes to what a case checks",
        [
            f"  - {c.id} ({c.tool}): {'; '.join(_change_text(x) for x in c.changes)}"
            for c in diff.cases_changed
        ],
    )
    other_cases = [
        f"  - {c.id} ({c.tool}): {c.base.value} -> {c.head.value}" for c in diff.cases_other
    ]
    other_cases += [f"  - added: {c.id} ({c.tool}): {c.status.value}" for c in diff.cases_added]
    other_cases += [f"  - removed: {c.id} ({c.tool}): {c.status.value}" for c in diff.cases_removed]
    body += _section("Other case changes", other_cases)
    if not has_changes(diff):
        body += [no_changes_line(diff)]
    while body and body[-1] == "":
        body.pop()
    return [to_ascii(line) for line in [*lines, *body]]


def diff_to_json(diff: ReportDiff, *, generated_at: datetime, version: str) -> str:
    """The complete diff as JSON (ASCII only, never capped)."""
    document = {
        "schema_version": DIFF_SCHEMA_VERSION,
        "lockwalk_version": version,
        "generated_at": utc_timestamp(generated_at, name="generated_at"),
        **diff.model_dump(mode="json"),
    }
    return json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
