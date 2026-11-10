"""`lockwalk inspect --case`: show what lockwalk recorded about one case.

Nothing runs: inspect reads coverage.json and evidence.jsonl from the output directory.
A file that cannot be trusted is an InspectError (the CLI prints it and exits 2). Every
line returned is ASCII, through report.to_ascii, because the files hold text from the
user's IAM, hooks, and tools. Every rendered value goes through _text, _num, or _who, so
an odd value prints as "?" instead of crashing or leaking nested content.
"""

import difflib
import math
from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from lockwalk.evidence import (
    EVIDENCE_FILE_NAME,
    Event,
    Evidence,
    EvidenceFileError,
    id_number,
    read_evidence,
)
from lockwalk.harness.protocol import reduce_subject
from lockwalk.models import (
    MAX_QUERY_DEPTH,
    MAX_ROUTE_AGENTS,
    CaseRow,
    CoverageReport,
    DoorResult,
    DoorStatus,
    IdentityResult,
)
from lockwalk.observe.catalog import Catalog
from lockwalk.observe.checks import is_on_map, observed_form, shown_name
from lockwalk.observe.links import RecordLink, TraceLinks
from lockwalk.observe.output import OBSERVE_FILE_NAME, ObserveFileError, read_observe
from lockwalk.observe.pipeline import run_observe, wanted_trace_id
from lockwalk.observe.results import ObserveReport
from lockwalk.observe.tree import AgentVisit, ToolCall, TraceView
from lockwalk.report import REPORT_FILE_NAME, ReportFileError, read_report, to_ascii
from lockwalk.settings import RunSettings
from lockwalk.urls import redact_urls

MAX_VALUE_CHARS = 200
MAX_TIMELINE_EVENTS = 200
MAX_TRAFFIC_LINES = 20
MAX_ACT_LINKS = MAX_QUERY_DEPTH  # reduce_subject allows MAX_QUERY_DEPTH + 1 links in all


class InspectError(Exception):
    """The files cannot answer the question. The message never quotes the files."""


def _clip(value: str) -> str:
    return value if len(value) <= MAX_VALUE_CHARS else value[:MAX_VALUE_CHARS] + "..."


def _text(value: Any) -> str:
    """A string value, clipped; anything else (even a dict or list) is "?"."""
    return _clip(value) if isinstance(value, str) else "?"


def _num(value: Any) -> str:
    """A plain int or float, formatted; a bool, a huge int, nan, or inf is "?"."""
    if type(value) not in (int, float):
        return "?"
    try:
        if not math.isfinite(value):
            return "?"
        return f"{value:g}"
    except (OverflowError, ValueError):
        return "?"


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _who(value: Any) -> str:
    subject = reduce_subject(value)
    if subject is None:
        return "?"
    text = f"{_text(subject['type'])}:{_text(subject['id'])}"
    chain: list[str] = []
    link = subject.get("act")
    while isinstance(link, dict) and len(chain) < MAX_ACT_LINKS:
        chain.append(f"{_text(link.get('type'))}:{_text(link.get('id'))}")
        link = link.get("act")
    if not chain:
        return text
    cut = " < ..." if isinstance(link, dict) else ""
    return f"{text} [act: {' < '.join(chain)}{cut}]"


def _route(value: Any) -> str:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        shown = " -> ".join(_text(item) for item in value[:MAX_ROUTE_AGENTS])
        return shown + (" -> ..." if len(value) > MAX_ROUTE_AGENTS else "")
    return ""


def inspect_case(output_dir: Path, case_id: str) -> list[str]:
    try:
        report = read_report(output_dir / REPORT_FILE_NAME)
    except ReportFileError as exc:
        raise InspectError(str(exc)) from None
    row = next((item for item in report.cases if item.id == case_id), None)
    if row is None:
        close = difflib.get_close_matches(
            case_id, [item.id for item in report.cases], n=3, cutoff=0.5
        )
        hint = f"; closest: {', '.join(close)}" if close else ""
        raise InspectError(f"coverage.json has no case {_clip(case_id)!r}{hint}")
    # Only a lockwalk test run has evidence; a static report never reads the file.
    evidence = _load_evidence(output_dir, report) if report.mode == "test" else None
    traffic = _load_observe(output_dir)
    return [to_ascii(line) for line in _render(report, row, evidence, traffic)]


def _load_observe(output_dir: Path) -> ObserveReport | str | None:
    """observe.json when it exists and reads; a reason string when it cannot be used."""
    path = output_dir / OBSERVE_FILE_NAME
    if not path.exists() and not path.is_symlink():
        return None
    try:
        return read_observe(path)
    except ObserveFileError as exc:
        return str(exc)


def _load_evidence(output_dir: Path, report: CoverageReport) -> Evidence | None:
    path = output_dir / EVIDENCE_FILE_NAME
    try:
        evidence = read_evidence(path)
    except FileNotFoundError:
        return None
    except (EvidenceFileError, OSError) as exc:
        raise InspectError(f"{EVIDENCE_FILE_NAME} cannot be used: {exc}") from None
    if evidence.header.run != report.run_id:
        raise InspectError(
            f"{EVIDENCE_FILE_NAME} is from another run than coverage.json; run lockwalk test again"
        )
    return evidence


def _render(
    report: CoverageReport,
    row: CaseRow,
    evidence: Evidence | None,
    traffic: ObserveReport | str | None = None,
) -> list[str]:
    is_test = report.mode == "test"
    lines = [f"lockwalk inspect - {_clip(row.id)}"]
    waived = f"  [waived: {_clip(row.waived_by)}]" if row.waived_by else ""
    lines.append(f"{_clip(row.id)}  {row.status}{waived}")
    lines.append(f"  spec:     {_spec(row)}")
    for note in (*row.problems, *row.notes):
        lines.append(f"  why:      {_clip(note)}")
    gaps: list[str] = []
    case_events = _case_events(row, evidence, gaps, report)
    if case_events and evidence is not None:
        started = _text(evidence.header.started_at)
        run = _text(evidence.header.run[:8])
        lines.append(f"  timeline (lockwalk test, started {started}, run {run}):")
        lines.extend(f"    {_event_line(event)}" for event in case_events[:MAX_TIMELINE_EVENTS])
        hidden = len(case_events) - MAX_TIMELINE_EVENTS
        if hidden > 0:
            gaps.append(f"{hidden} more events are not shown; see {EVIDENCE_FILE_NAME}")
    lines.extend(_door_lines(row.door, gaps, is_test))
    lines.extend(_related_lines(report, row, case_events, gaps, is_test))
    if isinstance(traffic, str):
        gaps.append(f"{OBSERVE_FILE_NAME} cannot be used: {_clip(traffic)}")
    elif traffic is not None:
        lines.extend(_traffic_lines(row, traffic))
    lines.append("  gaps:")
    if gaps:
        lines.extend(f"    - {gap}" for gap in gaps)
    else:
        lines.append("    none")
    return lines


def _spec(row: CaseRow) -> str:
    who = _clip(row.actor or "?")
    if row.role:
        who += f" ({_clip(row.role)})"
    route = " -> ".join(_clip(item) for item in row.path) if row.path else _clip(row.agent)
    return f"{who}  {route}  {_clip(row.tool)} ({_clip(row.action)})  expect {row.expect}"


def _case_events(
    row: CaseRow, evidence: Evidence | None, gaps: list[str], report: CoverageReport
) -> list[Event]:
    if report.mode != "test":
        gaps.append(
            "this coverage.json comes from lockwalk coverage; run lockwalk test to see the "
            "IAM's answers, the door runs, and the evidence"
        )
        return []
    if evidence is None:
        gaps.append(f"no evidence file ({EVIDENCE_FILE_NAME}); run lockwalk test again")
        return []
    by_id = {event.event: event for event in evidence.events}
    found: list[Event] = []
    for ref in dict.fromkeys(row.evidence or ()):
        event = by_id.get(ref)
        if event is None:
            raise InspectError(f"coverage.json points at {ref}, which {EVIDENCE_FILE_NAME} lacks")
        found.append(event)
    for event in found:
        dropped = event.detail.get("timeline_dropped") if event.type == "harness.job" else None
        if type(dropped) is int and dropped > 0:
            gaps.append(
                f"{event.invocation}: {_num(dropped)} more door or side effect moments "
                "were not kept"
            )
    return sorted(found, key=lambda event: (event.time, id_number(event.event)))


def _authz_line(event: Event, detail: dict[str, Any]) -> str:
    request = _obj(detail.get("request"))
    action = _obj(request.get("action"))
    resource = _obj(request.get("resource"))
    extra = []
    latency = _num(detail.get("latency_ms"))
    if latency != "?":
        extra.append(f"{latency} ms")
    extra.append(_text(event.query))
    text = (
        f"IAM       {_who(request.get('subject'))}  {_text(action.get('name'))} "
        f"{_text(resource.get('type'))}:{_text(resource.get('id'))}  -> "
        f"{_text(detail.get('verdict'))}  ({', '.join(extra)})"
    )
    if detail.get("error"):
        text += f"  error: {_text(detail.get('error'))}"
    elif detail.get("reason"):
        text += f"  reason: {_text(detail.get('reason'))}"
    return text


def _job_line(event: Event, detail: dict[str, Any]) -> str:
    route = _route(detail.get("route"))
    via = f" via {route}" if route else ""
    text = (
        f"{event.mode or '':<9} run {event.invocation}: {_text(detail.get('tool'))}{via}, "
        f"{_text(detail.get('status'))}"
    )
    if detail.get("not_run"):
        text += f" ({_text(detail.get('not_run'))})"
    return text


def _identity_line(event: Event, detail: dict[str, Any]) -> str:
    return f"{event.mode or '':<9} set identity: {_who(detail.get('subject'))}"


def _door_called_line(event: Event, detail: dict[str, Any]) -> str:
    mode = event.mode or ""
    if detail.get("error"):
        return f"{mode:<9} door call unreadable: {_text(detail.get('error'))}"
    answer = "allow" if detail.get("decision") is True else "deny"
    return f"{mode:<9} door asked: {_who(detail.get('subject'))} -> {answer}"


def _effect_line(event: Event, detail: dict[str, Any]) -> str:
    return f"{event.mode or '':<9} side effect of {_text(detail.get('tool'))} counted"


def _raised_line(event: Event, detail: dict[str, Any]) -> str:
    return f"{event.mode or '':<9} tool raised {_text(detail.get('exception'))}"


def _error_line(event: Event, detail: dict[str, Any]) -> str:
    return f"{event.mode or '':<9} error: {_text(detail.get('error'))}"


_LINE_OF = {
    "authz.evaluated": _authz_line,
    "harness.job": _job_line,
    "door.identity_set": _identity_line,
    "door.called": _door_called_line,
    "effect.counted": _effect_line,
    "tool.raised": _raised_line,
    "run.error": _error_line,
}


def _event_line(event: Event) -> str:
    when = f"+{event.time:.3f}s"
    make = _LINE_OF.get(event.type)
    text = make(event, event.detail) if make else event.type
    return f"{when:>9}  {text}"


def _door_lines(door: DoorResult | None, gaps: list[str], is_test: bool) -> list[str]:
    if door is None:
        if is_test:
            gaps.append("no door test for this case (no [harness], or --no-harness)")
        return []
    lines = [f"  door:     {door.status}"]
    for run in door.runs:
        lines.append(f"    {run.mode}: {run.status}, side effect calls {run.side_effect_calls}")
        lines.extend(f"      {_clip(note)}" for note in run.notes)
    for note in door.notes:
        lines.append(f"    {_clip(note)}")
        if door.status == DoorStatus.NOT_TESTED or note.startswith("scripted:"):
            gaps.append(f"door test: {_clip(note)}")
    if door.status == DoorStatus.NOT_TESTED and not door.notes:
        gaps.append("door test: not tested")
    return lines


def _pairs(events: Iterable[Event]) -> list[tuple[str, str]]:
    found: dict[tuple[str, str], None] = {}
    for event in events:
        if event.type != "authz.evaluated":
            continue
        request = _obj(event.detail.get("request"))
        action, resource = request.get("action"), request.get("resource")
        if isinstance(action, dict) and isinstance(resource, dict):
            found[(str(action.get("name")), str(resource.get("type")))] = None
    return list(found)


def _related_lines(
    report: CoverageReport,
    row: CaseRow,
    case_events: Sequence[Event],
    gaps: list[str],
    is_test: bool,
) -> list[str]:
    lines: list[str] = []
    controls = {(item.action, item.resource_type): item for item in report.controls}
    for pair in _pairs(case_events):
        control = controls.get(pair)
        if control is None:
            continue
        name = f"{_clip(pair[0])} + {_clip(pair[1])}"
        if control.allowed:
            lines.append(f"  control: {name} allowed by {_clip(control.allowed_by or '?')}")
        else:
            lines.append(f"  control: {name} was never allowed in this run")
            if is_test:
                gaps.append(f"no positive control for {name}")
    for escalation in report.escalations:
        if escalation.case_id != row.id:
            continue
        user = escalation.user_answer.verdict if escalation.user_answer else "?"
        path = escalation.path_answer.verdict if escalation.path_answer else "?"
        lines.append(
            f"  escalation: {escalation.result} via {_clip(escalation.via)}; "
            f"user -> {user}, route identity -> {path}"
        )
        lines.extend(f"    {_clip(note)}" for note in escalation.notes)
    for check in report.identity_checks:
        if check.case_id != row.id:
            continue
        lines.append(f"  identity: {check.result}")
        for seen in check.observations:
            observed = ", ".join(_who(item) for item in seen.observed) or "nothing"
            lines.append(f"    {seen.mode}: expected {_who(seen.expected)}, saw {observed}")
        lines.extend(f"    {_clip(note)}" for note in check.notes)
        if check.result == IdentityResult.NOT_RUN:
            gaps.extend(f"identity check: {_clip(note)}" for note in check.notes)
            if not check.notes:
                gaps.append("identity check: not run")
    for door_control in report.door_controls:
        if door_control.tool != row.tool:
            continue
        tool = _clip(row.tool)
        if door_control.proven:
            lines.append(f"  door control: {tool} proven by {_clip(door_control.proven_by or '?')}")
        else:
            lines.append(f"  door control: {tool} was never counted in this run")
            if is_test:
                gaps.append(f"no door control for {tool}")
    return lines


def _traffic_lines(row: CaseRow, observe: ObserveReport) -> list[str]:
    """The observe rows whose path (or calling agent) and tool are the case's."""
    route = row.path or (row.agent,)
    tool = row.tool
    found: list[str] = []
    for ident in observe.identities:
        if ident.path == route and ident.tool == tool:
            found.append(
                f"identity ({_clip(ident.mode)}): {ident.result} {ident.count}, "
                f"expected {_clip(ident.expected)}, saw {_clip(ident.observed)}"
            )
    for guard in observe.guards:
        if guard.agent == route[-1] and guard.tool == tool:
            counts = ", ".join(f"{status} {n}" for status, n in guard.counts.items())
            found.append(f"door: {counts}")
    for path_row in observe.paths:
        if path_row.path == route and path_row.tool == tool:
            found.append(f"path: {path_row.status} {path_row.count}")
    window = observe.window
    head = f"  real traffic (observe, {window.first or '?'} .. {window.last or '?'}):"
    if not found:
        if observe.errors:
            return [
                head,
                "    the last observe run had errors; real traffic may be incomplete",
            ]
        return [head, "    real traffic did not take this path"]
    lines = [head, *(f"    {item}" for item in found[:MAX_TRAFFIC_LINES])]
    if len(found) > MAX_TRAFFIC_LINES:
        lines.append(f"    ... and {len(found) - MAX_TRAFFIC_LINES} more; see {OBSERVE_FILE_NAME}")
    return lines


def inspect_trace(settings: RunSettings, trace_id: str) -> list[str]:
    """Show how observe read one trace. Runs the observe pipeline on the traces.

    OTLP trace ids are compared in lower case; a reader function's ids exactly. Names of
    agents and tools the map does not know are shown (URL credentials masked, cut to 200
    characters); names of other spans are never shown.
    The door records and effect markers are shown below the tool calls they belong to; user
    ids are never shown.
    """
    wanted = wanted_trace_id(settings, trace_id)
    run = run_observe(settings, only_trace=wanted)
    view = next((item for item in run.views if item.trace_id == wanted), None)
    if view is None:
        message = f"no trace {_clip(trace_id)!r} in the traces"
        problems = [item for item in run.report.errors if item != "no traces were read"]
        if problems:
            message += ": " + "; ".join(_clip(redact_urls(item)) for item in problems)
        raise InspectError(message)
    has_user = any(span.user_id is not None for span in view.spans.values())  # never the id
    lines = [
        f"lockwalk inspect - trace {_clip(view.trace_id)} "
        f"({'complete' if view.complete else 'incomplete'})  "
        f"user: {'present' if has_user else 'missing'}"
    ]
    if view.error is not None:
        lines.append("  (the trace could not be walked)")
        lines.append(f"  error: {_clip(redact_urls(view.error))}")
    else:
        links = next((item for item in run.links if item.trace_id == view.trace_id), None)
        lines.extend(_trace_lines(view, run.catalog, links))
    # The trace's own error is shown above; the run's errors list it again as "trace <id>: ...".
    own = f"trace {view.trace_id}: "
    errors = [item for item in run.report.errors if not (view.error and item.startswith(own))]
    if errors:
        lines.append("errors:")
        lines.extend(f"  - {_clip(redact_urls(item))}" for item in errors)
    return [to_ascii(line) for line in lines]


def _row(indent: int, text: str, note: str) -> str:
    return f"{'  ' * (indent + 1)}{text:<34}{note}".rstrip()


_LINKED_BY = {"ancestry": "ancestry", "tool_call_id": "tool call id", "time": "time"}
_NOT_LINKED = {
    "none": "no tool call found",
    "covers_tools": "its span contains tool calls",
}


def _record_form(view: TraceView, link: RecordLink, catalog: Catalog) -> str | None:
    """The decision and the subject in the same shown form the identity rows use."""
    span = view.spans.get(link.span_id)
    record = span.door if span is not None else None
    if record is None:
        return None
    if record.subject_type is None or record.subject_id is None:
        return f"{record.decision} (decision only, no subject)"
    who = observed_form(record.subject_type, record.subject_id, record.act, link.user_id, catalog)
    return f"{record.decision} for {who}"


def _door_notes(
    view: TraceView, catalog: Catalog, links: TraceLinks
) -> tuple[dict[str, list[str]], dict[str, list[str]], list[str]]:
    """Door and effect lines by tool call span, by agent visit span, and the rest."""
    by_call: defaultdict[str, list[str]] = defaultdict(list)
    by_agent: defaultdict[str, list[str]] = defaultdict(list)
    loose: list[str] = []
    for link in links.records:
        form = _record_form(view, link, catalog)
        if form is None:
            continue
        if link.call is not None and link.kind in _LINKED_BY:
            by_call[link.call].append(f"door: {form} (linked by {_LINKED_BY[link.kind]})")
            continue
        if link.kind == "ambiguous":
            # No count: the candidates list is capped, so a length would be a wrong total.
            text = f"door: {form} (several tool calls match by time; not linked)"
        else:
            why = _NOT_LINKED.get(link.kind, "no tool call found")
            text = f"door record not linked to a tool call: {form} ({why})"
        if link.agent is not None and not link.agent_ambiguous:
            by_agent[link.agent.span_id].append(text)
        else:
            loose.append(text)
    for link in links.effects:
        if link.call is not None and link.kind in _LINKED_BY:
            by_call[link.call].append(f"effect marker (linked by {_LINKED_BY[link.kind]})")
        elif link.agent is not None and not link.agent_ambiguous:
            by_agent[link.agent.span_id].append("effect marker not linked to a tool call")
        else:
            loose.append("effect marker not linked to a tool call")
    return by_call, by_agent, loose


def _trace_lines(view: TraceView, catalog: Catalog, links: TraceLinks | None = None) -> list[str]:
    by_call, by_agent, loose = (
        _door_notes(view, catalog, links) if links is not None else ({}, {}, [])
    )
    lines: list[str] = []
    enclosing: list[tuple[int, int]] = []  # (raw depth, shown depth) of shown ancestors
    skipped = 0
    for span_id in view.order:
        level = view.depth[span_id]
        # Raw depth counts the collapsed other spans too, so ancestors are popped by raw depth
        # while the indent comes from the shown ancestors only.
        while enclosing and enclosing[-1][0] >= level:
            enclosing.pop()
        indent = enclosing[-1][1] + 1 if enclosing else 0
        visit = view.visits.get(span_id)
        call = view.calls.get(span_id)
        if visit is not None and visit.span_id != span_id:
            who = visit.agent_id if visit.agent_id is not None else f"? {shown_name(visit.name)}"
            text = _row(indent, f"(same agent again: {who})", "")
        elif visit is not None:
            text = _agent_line(indent, visit, catalog)
        elif call is not None:
            text = _tool_line(indent, call, catalog)
        else:
            skipped += 1
            continue
        if skipped:
            # Other spans are collapsed into one line at the level of the next shown span.
            lines.append(_row(indent, f"({skipped} other span{'s' if skipped != 1 else ''})", ""))
            skipped = 0
        lines.append(text)
        extra = by_call.get(span_id, []) if call is not None else []
        if visit is not None and visit.span_id == span_id:
            extra = by_agent.get(span_id, [])
        lines.extend(_row(indent + 1, item, "") for item in extra)
        enclosing.append((level, indent))
    if skipped:
        lines.append(_row(0, f"({skipped} other span{'s' if skipped != 1 else ''})", ""))
    lines.extend(_row(0, item, "") for item in loose)
    return lines


def _agent_line(indent: int, visit: AgentVisit, catalog: Catalog) -> str:
    if visit.agent_id is None:
        return _row(indent, f"agent ? {shown_name(visit.name)}", "UNKNOWN agent")
    text = f"agent {visit.agent_id}"
    if visit.caller is None:
        origin = visit.caller_name or "?"
        return _row(indent, text, f"from {shown_name(origin)}: caller not known")
    status = "ON_MAP" if is_on_map((visit.caller, visit.agent_id, "agent"), catalog) else "OFF_MAP"
    return _row(indent, text, f"from {visit.caller}: {status}")


def _tool_line(indent: int, call: ToolCall, catalog: Catalog) -> str:
    if call.wrapper:
        if call.name not in catalog.wrappers:
            return _row(
                indent, f"tool ? {shown_name(call.name)}", "UNKNOWN tool (agent-as-tool wrapper)"
            )
        return _row(indent, f"tool {shown_name(call.name)}", "agent-as-tool wrapper")
    if call.tool_id is None:
        return _row(indent, f"tool ? {shown_name(call.name)}", "UNKNOWN tool")
    text = f"tool {call.tool_id}"
    if call.agent is None or call.agent.agent_id is None:
        return _row(indent, text, "no known calling agent")
    status = (
        "ON_MAP" if is_on_map((call.agent.agent_id, call.tool_id, "tool"), catalog) else "OFF_MAP"
    )
    return _row(indent, text, f"used by {call.agent.agent_id}: {status}")
