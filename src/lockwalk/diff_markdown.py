"""Markdown output of `lockwalk diff`, written to be safe as a pull request comment.

Every value that comes from a report is shown inside a code span, where nothing is a
mention, an issue reference, an HTML tag or a link. Only fixed text is outside code spans.
"""

import re

from lockwalk.diff import FieldChange, ReportDiff, WaiverChange, has_changes, no_changes_line
from lockwalk.report import violation_line

MARKER = "<!-- lockwalk-diff -->"
MAX_ROWS = 50
MAX_BODY = 60_000
MAX_VALUE = 200
FOOTER = "The full report is in the CI artifact."
NOT_SET = "(not set)"


def _escape(char: str) -> str:
    """Spell one character as \\uXXXX, or \\UXXXXXXXX above U+FFFF."""
    point = ord(char)
    return f"\\u{point:04x}" if point <= 0xFFFF else f"\\U{point:08x}"


def _spelled(char: str) -> bool:
    """True for every character that is not printable ASCII, and for ASCII controls."""
    return ord(char) > 0x7E or ord(char) < 0x20


def _shorten(value: str) -> str:
    """Spell non-ASCII characters, then cut at a whole piece so no escape is split."""
    pieces = [_escape(char) if _spelled(char) else char for char in value]
    if sum(len(piece) for piece in pieces) <= MAX_VALUE:
        return "".join(pieces)
    kept: list[str] = []
    size = 0
    for piece in pieces:
        if size + len(piece) > MAX_VALUE - 3:
            break
        kept.append(piece)
        size += len(piece)
    return "".join(kept) + "..."


def code(value: str) -> str:
    """Show an untrusted value inline. Inside a code span, nothing is a mention, tag or link.

    Every character that is not printable ASCII is written as a \\uXXXX escape (\\UXXXXXXXX
    above U+FFFF). A name with a Cyrillic letter in it looks the same as the real name in a
    comment, and a report about which tool is authorised must not allow that. Names in other
    scripts therefore show as escape codes. A long value is cut between whole pieces, so an
    escape is never split, and the result stays within MAX_VALUE.
    """
    text = _shorten(value)
    if not text:
        return "`(empty)`"
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _heading(diff: ReportDiff) -> str:
    if diff.head_status == "ERROR":
        # The count of a broken run is partial, so it is not shown as the result.
        return "**lockwalk: gate ERROR** - incomplete, see warnings"
    count = diff.head_violations
    noun = "violation" if count == 1 else "violations"
    text = f"**lockwalk: gate {diff.head_status}** ({count} {noun}"
    text += f", {diff.waived} waived)" if diff.waived else ")"
    if diff.incomplete:
        text += " - incomplete, see warnings"
    return text


def _section(title: str, rows: list[str], limit: int) -> list[str]:
    if not rows:
        return []
    lines = [f"### {title} ({len(rows)})", ""]
    lines += [f"- {row}" for row in rows[:limit]]
    if len(rows) > limit:
        lines.append(f"- ...and {len(rows) - limit} more")
    return [*lines, ""]


def _tool(label: str, tool_id: str, risk: str) -> str:
    return f"{label}{code(tool_id)} (risk: {code(risk)})"


def _case(case_id: str, tool: str, left: str, right: str | None = None) -> str:
    text = f"{code(case_id)} on {code(tool)}: {code(left)}"
    return text if right is None else f"{text} -> {code(right)}"


def _value(value: str | None) -> str:
    return NOT_SET if value is None else code(value)


def _change(change: FieldChange) -> str:
    """One changed field. The field name is fixed text; an actor's values are never shown."""
    if change.field == "actor":
        return "actor changed"
    label = "**expect**" if change.field == "expect" else change.field
    return f"{label} {_value(change.base)} -> {_value(change.head)}"


def _waiver_change(change: WaiverChange) -> str:
    parts = [
        f"expires {_value(change.base_expires)} -> {_value(change.head_expires)}"
        if field == "expires"
        else field
        for field in change.fields
    ]
    return f"changed: {code(change.id)}: {', '.join(parts)}"


def _render(diff: ReportDiff, limit: int) -> str:
    lines = [MARKER, "", _heading(diff), ""]
    lines += [f"> {warning}" for warning in diff.warnings]
    if diff.warnings:
        lines.append("")
    lines += _section(
        "New problems",
        [code(violation_line(v).strip().removeprefix("- ")) for v in diff.new_violations],
        limit,
    )
    lines += _section(
        "Newly waived",
        [
            f"{code(violation_line(w.violation).strip().removeprefix('- '))} "
            f"waived by {code(w.waiver_id)}"
            for w in diff.newly_waived
        ],
        limit,
    )
    lines += _section(
        "No longer reported",
        [code(violation_line(v).strip().removeprefix("- ")) for v in diff.no_longer_reported],
        limit,
    )
    waiver_rows = [f"added: {code(w.id)} (expires {code(w.expires)})" for w in diff.waivers_added]
    waiver_rows += [
        f"removed: {code(w.id)} (expires {code(w.expires)})" for w in diff.waivers_removed
    ]
    waiver_rows += [_waiver_change(c) for c in diff.waivers_changed]
    lines += _section("Waiver changes", waiver_rows, limit)
    lines += _section(
        "New tools without spec",
        [_tool("", t.id, t.risk.value) for t in diff.tools_added_without_spec],
        limit,
    )
    other_tools = [_tool("added: ", t.id, t.risk.value) for t in diff.tools_added]
    other_tools += [_tool("removed: ", t.id, t.risk.value) for t in diff.tools_removed]
    other_tools += [_tool("lost its spec: ", t.id, t.risk.value) for t in diff.tools_lost_spec]
    other_tools += [_tool("got a spec: ", t.id, t.risk.value) for t in diff.tools_gained_spec]
    other_tools += [
        f"risk of {code(c.id)}: {code(c.base.value)} -> {code(c.head.value)}"
        for c in diff.risk_changes
    ]
    lines += _section("Other tool changes", other_tools, limit)
    rule_rows = [f"added: {code(r.id)} ({code(r.result.value)})" for r in diff.rules_added]
    rule_rows += [f"removed: {code(r.id)} ({code(r.result.value)})" for r in diff.rules_removed]
    rule_rows += [
        f"changed: {code(r.id)}: {'; '.join(_change(c) for c in r.changes)}"
        for r in diff.rules_changed
    ]
    lines += _section("Rule changes", rule_rows, limit)
    lines += _section(
        "Cases that got worse",
        [_case(c.id, c.tool, c.base.value, c.head.value) for c in diff.cases_worse],
        limit,
    )
    lines += _section(
        "Cases that got better",
        [_case(c.id, c.tool, c.base.value, c.head.value) for c in diff.cases_better],
        limit,
    )
    lines += _section(
        "Changes to what a case checks",
        [
            f"{code(c.id)} on {code(c.tool)}: {'; '.join(_change(x) for x in c.changes)}"
            for c in diff.cases_changed
        ],
        limit,
    )
    other_cases = [_case(c.id, c.tool, c.base.value, c.head.value) for c in diff.cases_other]
    other_cases += [f"added: {_case(c.id, c.tool, c.status.value)}" for c in diff.cases_added]
    other_cases += [f"removed: {_case(c.id, c.tool, c.status.value)}" for c in diff.cases_removed]
    lines += _section("Other case changes", other_cases, limit)
    if not has_changes(diff):
        lines += [no_changes_line(diff), ""]
    lines.append(FOOTER)
    return "\n".join(lines) + "\n"


def render_diff_markdown(diff: ReportDiff) -> str:
    """Render the diff as a Markdown comment body, shrinking the lists until it fits."""
    limit = MAX_ROWS
    while True:
        text = _render(diff, limit)
        # Limit 1 always fits; stop there anyway so the loop cannot spin.
        if len(text) <= MAX_BODY or limit == 1:
            return text
        limit //= 2
