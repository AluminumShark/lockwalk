"""Write observe.json and render the observe terminal report."""

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, get_args

from pydantic import ValidationError

from lockwalk.jsonvalues import DuplicateKeyError, reject_duplicate_keys
from lockwalk.masking import describe_validation_error
from lockwalk.observe.results import (
    OBSERVE_FILE_NAME,
    OBSERVE_SCHEMA_VERSION,
    GuardRow,
    GuardStatus,
    IdentityRow,
    ObserveReport,
    ObserveViolation,
    PathRow,
    PathStatus,
)
from lockwalk.output_files import utc_timestamp, write_text_atomic
from lockwalk.report import (
    RULE,
    attention_block_lines,
    attention_note_texts,
    capped_category,
    quiet_waiver_line,
    to_ascii,
    waived_block_lines,
    waived_suffix,
)
from lockwalk.waivers import COVERAGE_OR_TEST_ONLY_NOTE

MAX_OBSERVE_BYTES = 256 * 1024 * 1024
SOURCE_WIDTH = 80
MAX_SOURCES = 5
MAX_LISTED = 20
_HEADER_KEYS = ("schema_version", "lockwalk_version", "generated_at")
_IDENTITY_ORDER = ("MATCH", "OBSERVED", "MISMATCH", "INCONCLUSIVE")
# Same order as the Literal types; the identity order differs, so a test pins it.
_GUARD_ORDER: tuple[str, ...] = get_args(GuardStatus)
_PATH_ORDER: tuple[str, ...] = get_args(PathStatus)


class ObserveFileError(Exception):
    """observe.json is missing or cannot be trusted. The message never quotes the file."""


def observe_to_dict(
    report: ObserveReport, *, generated_at: datetime, version: str
) -> dict[str, Any]:
    """Return the observe.json document. generated_at must be timezone-aware."""
    return {
        "schema_version": OBSERVE_SCHEMA_VERSION,
        "lockwalk_version": version,
        "generated_at": utc_timestamp(generated_at, name="generated_at"),
        **report.model_dump(mode="json"),
    }


def write_observe(
    report: ObserveReport, output_dir: Path, *, generated_at: datetime, version: str
) -> Path:
    """Write <output_dir>/observe.json (UTF-8, replaced on every run) and return its path."""
    path = output_dir / OBSERVE_FILE_NAME
    document = observe_to_dict(report, generated_at=generated_at, version=version)
    text = json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    write_text_atomic(path, text, prefix=".observe-")
    return path


def read_observe(path: Path) -> ObserveReport:
    """Read an observe.json that write_observe of this lockwalk version wrote."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise ObserveFileError(f"{path} does not exist; run lockwalk observe first") from None
    except OSError as exc:
        raise ObserveFileError(f"{path} cannot be read ({type(exc).__name__})") from None
    if size > MAX_OBSERVE_BYTES:
        raise ObserveFileError(f"{path} is larger than {MAX_OBSERVE_BYTES >> 20} MiB")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except DuplicateKeyError:
        raise ObserveFileError(f"{path} repeats a JSON key") from None
    except OSError as exc:
        raise ObserveFileError(f"{path} cannot be read ({type(exc).__name__})") from None
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ObserveFileError(f"{path} is not valid JSON") from None
    if not isinstance(document, dict):
        raise ObserveFileError(f"{path} is not a lockwalk observe report")
    if document.get("schema_version") != OBSERVE_SCHEMA_VERSION:
        raise ObserveFileError(
            f"{path} was written by another lockwalk version (schema_version is not "
            f"{OBSERVE_SCHEMA_VERSION}); run lockwalk observe again"
        )
    body = {key: value for key, value in document.items() if key not in _HEADER_KEYS}
    try:
        return ObserveReport.model_validate(body)
    except ValidationError as exc:
        raise ObserveFileError(
            f"{path} is not a valid observe report: {describe_validation_error(exc)}"
        ) from None


def _cut(text: str) -> str:
    return text if len(text) <= SOURCE_WIDTH else text[: SOURCE_WIDTH - 3] + "..."


def _count(number: int, word: str) -> str:
    return f"{number} {word}" if number == 1 else f"{number} {word}s"


def _list_section(title: str, items: Sequence[str]) -> list[str]:
    if not items:
        return []
    lines = [title, *(f"  - {item}" for item in items[:MAX_LISTED])]
    if len(items) > MAX_LISTED:
        lines.append(f"  - ... (+{len(items) - MAX_LISTED} more; see {OBSERVE_FILE_NAME})")
    return lines


def _path(path: Sequence[str]) -> str:
    return " -> ".join(path)


def _example(traces: Sequence[str]) -> str:
    return f", e.g. trace {traces[0]}" if traces else ""


def _attention(report: ObserveReport) -> list[str]:
    return attention_block_lines(report.waivers, COVERAGE_OR_TEST_ONLY_NOTE)


def _quiet_line(report: ObserveReport) -> str | None:
    return quiet_waiver_line(report.waivers, COVERAGE_OR_TEST_ONLY_NOTE)


def _shown_notes(report: ObserveReport) -> set[str]:
    """Warnings equal to these are printed in the attention block, so they are not repeated."""
    return attention_note_texts(report.waivers, COVERAGE_OR_TEST_ONLY_NOTE)


def _violation_text(v: ObserveViolation) -> str:
    where = _path(v.path) if v.path else "?"
    tool = v.tool or "(no tool)"
    agent = v.agent or "(no calling agent)"
    if v.rule == "fail_on_off_map_route":
        return f"OFF_MAP route: {v.from_id} -> {v.to_id}"
    if v.rule == "fail_on_unknown_component":
        return f"UNKNOWN {v.kind}: {v.name}"
    if v.rule == "bypass":
        return f"BYPASS: {agent} / {tool}"
    if v.rule == "fail_on_unguarded_call":
        return f"UNGUARDED: {agent} / {tool}"
    if v.rule == "fail_on_identity_mismatch":
        return f"identity MISMATCH: {where} / {tool}"
    if v.rule == "fail_on_inconclusive_observation":
        if v.subject == "identity":
            return f"identity INCONCLUSIVE: {where} / {tool}"
        return f"guard INCONCLUSIVE: {agent} / {tool}"
    if v.rule == "fail_on_untested_path":
        return f"UNTESTED path: {where} / {tool}"
    return str(v.rule)


def _waived_lines(report: ObserveReport) -> list[str]:
    lines = waived_block_lines(report.waivers, report.gate.waived, _violation_text)
    return [f"  - {line}" for line in lines]


def _identity_lines(rows: Iterable[IdentityRow]) -> list[str]:
    lines: list[str] = []
    for row in rows:
        tool = row.tool if row.tool is not None else "(no tool)"
        lines.append(
            f"  {row.result}  {_path(row.path)}, tool {tool}, mode {row.mode}: "
            f"{row.count} time(s){_example(row.traces)}{waived_suffix(row.waived_by)}"
        )
        lines.append(f"    expected: {row.expected}")
        lines.append(f"    observed: {row.observed}")
        lines.extend(f"    test: {text}" for text in row.test_results)
        lines.extend(f"    note: {text}" for text in row.notes)
    return lines


def _guard_lines(rows: Iterable[GuardRow]) -> list[str]:
    lines: list[str] = []
    for row in rows:
        counts = ", ".join(f"{status} {n}" for status, n in row.counts.items())
        agent = row.agent if row.agent is not None else "(no calling agent)"
        lines.append(f"  {agent} / {row.tool}: {counts}{waived_suffix(row.waived_by)}")
        detail = []
        if row.by_time:
            detail.append(f"linked by time {row.by_time}")
        if row.effect_without_record:
            detail.append(f"effect without record {row.effect_without_record}")
        text = "; ".join(detail) + _example(row.traces)
        if detail or row.traces:
            lines.append(f"    {text.removeprefix(', ')}")
    return lines


def _path_lines(rows: Iterable[PathRow]) -> list[str]:
    lines = []
    for row in rows:
        start = " (start of the path not in the data)" if row.incomplete else ""
        lines.append(
            f"  {_path(row.path)} / {row.tool}{start}: {row.count} time(s)"
            f"{_example(row.traces)}{waived_suffix(row.waived_by)}"
        )
    return lines


def _tally(
    pairs: Iterable[tuple[str, int]], order: Sequence[str], only: Sequence[str] | None
) -> str:
    total: Counter[str] = Counter()
    for status, n in pairs:
        total[status] += n
    keep = only if only is not None else order
    return ", ".join(f"{total[s]} {s}" for s in order if s in keep and total[s])


def _count_lines(report: ObserveReport, *, everything: bool) -> list[str]:
    """Identity, guard and path counts. The full report lists only the OK statuses (the others
    have sections of their own); the summary lists every status."""
    identity = _tally(
        ((r.result, r.count) for r in report.identities),
        _IDENTITY_ORDER,
        None if everything else ("MATCH", "OBSERVED"),
    )
    guard = _tally(
        (item for r in report.guards for item in r.counts.items()),
        _GUARD_ORDER,
        None if everything else ("GUARDED", "DENIED"),
    )
    paths = _tally(
        ((r.status, r.count) for r in report.paths),
        _PATH_ORDER,
        None if everything else ("TESTED", "TESTED_OTHER_PATH"),
    )
    labelled = (("Identity", identity), ("Guarded calls", guard), ("Tested paths", paths))
    return [f"{label}: {text}" for label, text in labelled if text]


def _unverified_note(report: ObserveReport) -> str | None:
    calls = sum(r.counts.get("DENIED_UNVERIFIED", 0) for r in report.guards)
    if not calls:
        return None
    tools = sorted({r.tool for r in report.guards if "DENIED_UNVERIFIED" in r.counts})
    shown = ", ".join(tools[:5]) + (", ..." if len(tools) > 5 else "")
    return (
        f"{calls} denied call(s) of {shown} are DENIED_UNVERIFIED: no effect marker was seen "
        "for the tool, so the denial is not proven"
    )


def _verdict(report: ObserveReport) -> str:
    # Same verdict forms as the coverage report: a run with errors has no gate line.
    if report.exit_code == 2:
        return "Result: ERROR (exit 2) - the report is incomplete; fix the errors above"
    if report.exit_code == 1:
        return f"Gate: FAIL (exit 1) - {len(report.gate.violations)} violation(s)"
    return "Gate: PASS (exit 0)"


def _read_text(report: ObserveReport) -> str:
    totals = report.totals
    return (
        f"{_count(totals.traces, 'trace')}, {_count(totals.spans, 'span')} "
        f"({_count(totals.agent_spans, 'agent span')}, {_count(totals.tool_calls, 'tool call')})"
    )


def _door_text(report: ObserveReport) -> str | None:
    totals = report.totals
    if totals.door_records == 0:
        return None
    return (
        f"Door records: {totals.door_records} ({totals.calls_with_record} tool call(s) have one; "
        f"{totals.records_without_call} not tied to a tool call, "
        f"{totals.records_by_time} linked by time)"
    )


def render_observe(
    report: ObserveReport, notes: Sequence[str] = (), *, summary: bool = False
) -> list[str]:
    """Render the terminal report. Every line is plain ASCII (see report.to_ascii).

    Rows are rendered in the order of the report (the checks sort them). The full form caps
    only the Notes, Warnings and Errors lists; the summary caps every category. observe.json
    keeps everything. summary=True renders the short form.
    """
    lines = _render_summary(report, notes) if summary else _render_full(report, notes)
    return [to_ascii(line) for line in lines]


def _render_full(report: ObserveReport, notes: Sequence[str]) -> list[str]:
    totals = report.totals
    shown = [_cut(source) for source in report.sources[:MAX_SOURCES]]
    if len(report.sources) > MAX_SOURCES:
        shown.append(f"... (+{len(report.sources) - MAX_SOURCES} more)")
    lines = [
        f"lockwalk observe - {report.scenario_suite}",
        "Sources:      " + (", ".join(shown) or "(none)"),
        f"Read:         {_read_text(report)}",
    ]
    door_text = _door_text(report)
    if door_text:
        lines.append(door_text)
    if totals.incomplete_traces:
        lines.append(f"Incomplete:   {_count(totals.incomplete_traces, 'trace')}")
    window = report.window
    if window.first is not None or window.last is not None:
        lines.append(f"Window:       {window.first or '?'} .. {window.last or '?'}")
    lines.append(RULE)
    off_map = [row for row in report.routes if row.status == "OFF_MAP"]
    if off_map:
        lines.append("Routes not on the map (OFF_MAP):")
        for row in off_map:
            lines.append(
                f"  {row.from_id} -> {row.to_id} ({row.to_kind})  {row.count} time(s), "
                f"e.g. trace {row.traces[0]}{waived_suffix(row.waived_by)}"
            )
            lines.append(f"    fix: {row.suggestion}")
    if report.unknown:
        lines.append("Not on the map (UNKNOWN):")
        for unknown in report.unknown:
            who = (
                f"tool {unknown.name} (no calling agent)"
                if unknown.kind == "caller"
                else f"{unknown.kind} {unknown.name}"
            )
            lines.append(
                f"  {who}  {unknown.count} time(s), e.g. trace {unknown.traces[0]}"
                f"{waived_suffix(unknown.waived_by)}"
            )
    bad_identity = [r for r in report.identities if r.result in ("MISMATCH", "INCONCLUSIVE")]
    if bad_identity:
        lines.append("Identity sent to the IAM (MISMATCH / INCONCLUSIVE):")
        lines += _identity_lines(bad_identity)
    bad_guard = [
        r for r in report.guards if set(r.counts) & {"BYPASS", "UNGUARDED", "INCONCLUSIVE"}
    ]
    if bad_guard:
        lines.append("Tool calls without a working door (BYPASS / UNGUARDED / INCONCLUSIVE):")
        lines += _guard_lines(bad_guard)
    untested = [r for r in report.paths if r.status == "UNTESTED"]
    if untested:
        lines.append("Real paths no case tests (UNTESTED):")
        lines += _path_lines(untested)
    on_map = sum(1 for row in report.routes if row.status == "ON_MAP")
    lines.append(f"Routes on the map (ON_MAP): {on_map}")
    lines += _count_lines(report, everything=False)
    waived = _waived_lines(report)
    if waived:
        lines += ["Waived:", *waived]
    attention = _attention(report)
    if attention:
        lines += ["Waivers needing attention:", *(f"  {line}" for line in attention)]
    quiet = _quiet_line(report)
    if quiet:
        lines.append(quiet)
    unverified = _unverified_note(report)
    lines += _list_section("Notes:", [*notes, *([unverified] if unverified else [])])
    # A warning that equals a waiver note shown above is not repeated.
    shown_notes = _shown_notes(report)
    lines += _list_section("Warnings:", [w for w in report.warnings if w not in shown_notes])
    lines += _list_section("Errors:", report.errors)
    lines.append(RULE)
    lines.append(_verdict(report))
    return lines


def _render_summary(report: ObserveReport, notes: Sequence[str]) -> list[str]:
    on_map = sum(1 for row in report.routes if row.status == "ON_MAP")
    off_map = sum(1 for row in report.routes if row.status == "OFF_MAP")
    lines = [
        f"lockwalk observe - {report.scenario_suite}",
        f"Read: {_read_text(report)}",
        *([door_text] if (door_text := _door_text(report)) else []),
        f"Routes: {on_map} ON_MAP, {off_map} OFF_MAP, {len(report.unknown)} UNKNOWN",
        *_count_lines(report, everything=True),
        _verdict(report),
    ]
    shown_notes = _shown_notes(report)
    warnings = [*notes, *(w for w in report.warnings if w not in shown_notes)]
    unverified = _unverified_note(report)
    if unverified:
        warnings.append(unverified)
    quiet = _quiet_line(report)

    def capped(title: str, items: Sequence[str]) -> list[str]:
        return capped_category(title, items, OBSERVE_FILE_NAME)

    categories = [
        capped("Errors", [f"  - {e}" for e in report.errors]),
        capped("Blocking", [f"  - {_violation_text(v)}" for v in report.gate.violations]),
        capped("Waived", _waived_lines(report)) + ([quiet] if quiet else []),
        capped("Waivers needing attention", [f"  - {t}" for t in _attention(report)]),
        capped("Warnings", [f"  - {w}" for w in warnings]),
    ]
    for block in categories:
        if block:
            lines += ["", *block]
    return lines
