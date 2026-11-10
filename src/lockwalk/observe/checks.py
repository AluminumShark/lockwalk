"""The route check: observed edges against the map."""

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from lockwalk.config import GateConfig
from lockwalk.inventory.base import truncate
from lockwalk.models import CoverageReport, IdentityCheckRow, IdentityResult, Risk
from lockwalk.observe.catalog import Catalog
from lockwalk.observe.links import RecordLink, TraceLinks
from lockwalk.observe.results import (
    MAX_EXAMPLES,
    TIMESTAMP,
    GuardRow,
    GuardStatus,
    IdentityResultName,
    IdentityRow,
    ObserveGate,
    ObserveTotals,
    ObserveViolation,
    ObserveWindow,
    PathRow,
    RouteRow,
    UnknownRow,
)
from lockwalk.observe.spans import ReadResult, Span
from lockwalk.observe.tree import UNKNOWN_STEP, AgentVisit, ToolCall, TraceView
from lockwalk.output_files import utc_timestamp
from lockwalk.report import ReportFileError, read_report
from lockwalk.urls import redact_urls

NAME_LIMIT = 200
_TIMESTAMP = re.compile(TIMESTAMP)

# (from_id, to_id, to_kind)
_Edge = tuple[str, str, Literal["agent", "tool"]]
_UnknownKey = tuple[Literal["agent", "tool", "caller"], str]


def shown_name(name: str) -> str:
    return truncate(redact_urls(name), NAME_LIMIT) or "(empty)"


def is_on_map(edge: _Edge, catalog: Catalog) -> bool:
    from_id, to_id, to_kind = edge
    if from_id == "user":
        return to_id in catalog.entry_agents
    if to_kind == "agent":
        return (from_id, to_id) in catalog.agent_edges
    return (from_id, to_id) in catalog.tool_edges


def _suggestion(edge: _Edge) -> str:
    from_id, to_id, to_kind = edge
    if from_id == "user":
        return (
            f"mark agent {to_id} as an entry agent: set 'entry: true' on {to_id} in registry.yaml"
        )
    if to_kind == "agent":
        return f"declare the call: add {to_id} to 'calls' of agent {from_id} in registry.yaml"
    return (
        f"declare the tool use: add {from_id} to 'supported_agents' of tool {to_id} "
        "in registry.yaml"
    )


@dataclass
class _Tally:
    """How often one row was seen, and the first MAX_EXAMPLES distinct traces it was seen in."""

    count: int = 0
    traces: list[str] = field(default_factory=list)

    def add(self, trace_id: str) -> None:
        self.count += 1
        if len(self.traces) < MAX_EXAMPLES and trace_id not in self.traces:
            self.traces.append(trace_id)


def route_findings(
    views: Sequence[TraceView], catalog: Catalog
) -> tuple[tuple[RouteRow, ...], tuple[UnknownRow, ...]]:
    edges: defaultdict[_Edge, _Tally] = defaultdict(_Tally)
    unknown: defaultdict[_UnknownKey, _Tally] = defaultdict(_Tally)
    for view in views:
        if view.error is not None:
            continue
        trace_id = view.trace_id
        for span_id, visit in view.visits.items():
            if visit.span_id != span_id:
                continue  # a merged span: counted with the visit it joined
            if visit.agent_id is None:
                unknown[("agent", shown_name(visit.name))].add(trace_id)
            elif visit.caller == "user":
                edges[("user", visit.agent_id, "agent")].add(trace_id)
            elif visit.caller is not None:
                edges[(visit.caller, visit.agent_id, "agent")].add(trace_id)
            if visit.caller_name is not None:
                unknown[("agent", shown_name(visit.caller_name))].add(trace_id)
        for call in view.calls.values():
            if call.wrapper:
                # A registered delegation tool is an agent seen as a tool. A name that is not
                # registered and only has an agent below it is a tool lockwalk does not know:
                # it is UNKNOWN, while the agent and tools below it are checked as before.
                if call.name not in catalog.wrappers:
                    unknown[("tool", shown_name(call.name))].add(trace_id)
                continue
            if call.tool_id is None:
                unknown[("tool", shown_name(call.name))].add(trace_id)
            if call.agent is None:
                # A different fact from an unknown name: nobody is known to have called it.
                if view.complete:
                    unknown[("caller", shown_name(call.tool_id or call.name))].add(trace_id)
            elif call.agent.agent_id is not None and call.tool_id is not None:
                edges[(call.agent.agent_id, call.tool_id, "tool")].add(trace_id)
    routes: list[RouteRow] = []
    for edge, tally in edges.items():
        on_map = is_on_map(edge, catalog)
        routes.append(
            RouteRow(
                from_id=edge[0],
                to_id=edge[1],
                to_kind=edge[2],
                status="ON_MAP" if on_map else "OFF_MAP",
                count=tally.count,
                traces=tuple(tally.traces),
                suggestion=None if on_map else _suggestion(edge),
            )
        )
    routes.sort(key=lambda r: (r.status == "ON_MAP", r.from_id, r.to_kind, r.to_id))
    rows = [
        UnknownRow(kind=key[0], name=key[1], count=tally.count, traces=tuple(tally.traces))
        for key, tally in sorted(unknown.items(), key=lambda item: item[0])
    ]
    return tuple(routes), tuple(rows)


@dataclass(frozen=True, slots=True)
class LinkCounts:
    """Counts over every door record and effect marker link, from one pass."""

    records_without_call: int = 0
    records_by_time: int = 0
    covers_records: int = 0  # records on spans that contain tool calls
    covers_effects: int = 0  # effect markers on spans that contain tool calls
    user_conflicts: int = 0
    no_known_agent: int = 0  # records that are not identity rows
    calls_with_record: int = 0  # non-wrapper tool calls with at least one linked record
    no_subject: int = 0  # decision-only records (a door rule); not identity rows


def count_links(views: Sequence[TraceView], links: Sequence[TraceLinks]) -> LinkCounts:
    """One walk over the links for the totals and the warnings."""
    without_call = by_time = covers = conflicts = no_agent = with_record = no_subject = 0
    by_trace = {item.trace_id: item for item in links}
    for view in views:
        trace_links = by_trace.get(view.trace_id)
        if trace_links is None:
            continue
        linked_calls: set[str] = set()
        for link in trace_links.records:
            without_call += link.call is None
            if link.call is not None:
                linked_calls.add(link.call)
            by_time += link.kind == "time"
            covers += link.kind == "covers_tools"
            conflicts += link.user_conflict
            span = view.spans.get(link.span_id)
            if span is not None and span.door is not None and not span.door.has_subject:
                no_subject += 1
            elif (
                view.error is None
                and span is not None
                and span.door is not None
                and _pick_agent(link, view) is None
            ):
                no_agent += 1
        with_record += len(linked_calls)
    effects = sum(1 for tl in links for e in tl.effects if e.kind == "covers_tools")
    return LinkCounts(
        records_without_call=without_call,
        records_by_time=by_time,
        covers_records=covers,
        covers_effects=effects,
        user_conflicts=conflicts,
        no_known_agent=no_agent,
        calls_with_record=with_record,
        no_subject=no_subject,
    )


def observe_totals(
    read: ReadResult,
    views: Sequence[TraceView],
    spans: Sequence[Span],
    counts: LinkCounts | None = None,
) -> ObserveTotals:
    counts = counts or LinkCounts()
    agent_spans = tool_calls = 0
    for view in views:
        agent_spans += sum(1 for span_id, visit in view.visits.items() if visit.span_id == span_id)
        tool_calls += sum(1 for call in view.calls.values() if not call.wrapper)
    return ObserveTotals(
        files=len(read.sources),
        traces=len(views),
        spans=len(spans),
        agent_spans=agent_spans,
        tool_calls=tool_calls,
        incomplete_traces=sum(1 for view in views if not view.complete),
        error_traces=sum(1 for view in views if view.error is not None),
        unnamed_markers=sum(1 for span in spans if span.unnamed_marker),
        door_records=sum(1 for span in spans if span.door is not None),
        records_without_call=counts.records_without_call,
        records_by_time=counts.records_by_time,
        calls_with_record=counts.calls_with_record,
    )


def _format_ns(value: int) -> str | None:
    try:
        text = utc_timestamp(datetime.fromtimestamp(value // 1_000_000_000, UTC))
    except (OverflowError, OSError, ValueError):
        return None
    # ObserveWindow accepts four-digit years only; a reader's odd time must not crash it.
    return text if _TIMESTAMP.fullmatch(text) else None


def observe_window(spans: Sequence[Span]) -> ObserveWindow:
    starts = [span.start_ns for span in spans if span.start_ns is not None]
    if not starts:
        return ObserveWindow()
    return ObserveWindow(first=_format_ns(min(starts)), last=_format_ns(max(starts)))


# ---- Identity, guard and path checks ----

_LINKED = ("ancestry", "tool_call_id", "time")
_IDENTITY_RANK: dict[str, int] = {"MISMATCH": 0, "INCONCLUSIVE": 1, "OBSERVED": 2, "MATCH": 3}
CONFLICT_NOTE = "the trace holds two different user ids; the nearest one is used"
TEST_DIFFERS_NOTE = "the test environment and the real environment behave differently"
AMBIGUOUS_EXPECTED = "cannot be tied to one tool call"
AMBIGUOUS_NOTE = (
    "the record cannot be tied to one tool call; it is shown under the first candidate's path"
)
STATIC_REPORT_WARNING = (
    "the test report comes from lockwalk coverage; run lockwalk test for the side-by-side"
)
MAX_TEST_RESULTS = 10
_Mode = Literal["user", "agent", "on_behalf_of", "undeclared"]


def _links_for(
    views: Sequence[TraceView], links: Sequence[TraceLinks]
) -> list[tuple[TraceView, TraceLinks]]:
    by_trace = {item.trace_id: item for item in links}
    return [
        (view, by_trace[view.trace_id])
        for view in views
        if view.error is None and view.trace_id in by_trace
    ]


def _act_form(act: tuple[tuple[str, str], ...], catalog: Catalog) -> str:
    # Only ids of known agents are shown; every other link is "?".
    shown = [
        item_id if item_type == "agent" and item_id in catalog.agents else UNKNOWN_STEP
        for item_type, item_id in act
    ]
    return " < ".join(shown)


def observed_form(
    subject_type: str,
    subject_id: str,
    act: tuple[tuple[str, str], ...],
    user_id: str | None,
    catalog: Catalog,
) -> str:
    if subject_type == "user":
        if user_id is None:
            text = "a user (cannot compare)"
        else:
            text = "the trace's user" if subject_id == user_id else "another user"
    elif subject_type == "agent" and subject_id in catalog.agents:
        text = f"agent:{subject_id}"
    else:
        text = f"{shown_name(subject_type)}:hidden"
    if act:
        text += f", acting through {_act_form(act, catalog)}"
    return shown_name(text)


@dataclass(frozen=True)
class _Judged:
    expected: str
    observed: str
    result: IdentityResultName
    notes: tuple[str, ...] = ()


def _act_verdict(
    act: tuple[tuple[str, str], ...], agent: AgentVisit
) -> Literal["match", "mismatch", "unsure"]:
    """Compare an act chain with the path, outermost link first (the calling agent)."""
    want = list(reversed(agent.path))
    if len(act) < len(want):
        return "mismatch"  # the known part of the path is not all there
    for link, step in zip(act, want, strict=False):
        if step != UNKNOWN_STEP and link != ("agent", step):
            return "mismatch"
    if len(act) > len(want) and not agent.incomplete:
        return "mismatch"  # a complete path says where the chain ends
    return "unsure" if agent.incomplete or UNKNOWN_STEP in want else "match"


def _judge(link: RecordLink, view: TraceView, agent: AgentVisit, catalog: Catalog) -> _Judged:
    """One record against the calling agent's mode. Unknown never becomes MATCH."""
    door = view.spans[link.span_id].door
    if door is None:
        raise ValueError("the callers only pass links of spans that hold a record")
    if door.subject_type is None or door.subject_id is None:
        raise ValueError("the callers only pass links of records with a subject")
    mode: _Mode = catalog.modes.get(agent.agent_id or "") or "undeclared"
    agent_id = agent.agent_id or UNKNOWN_STEP
    user_id = link.user_id  # on a conflict the nearest id wins
    observed = observed_form(door.subject_type, door.subject_id, door.act, user_id, catalog)
    conflict = (CONFLICT_NOTE,) if link.user_conflict else ()
    if mode == "undeclared":
        return _Judged("no delegation mode declared", observed, "OBSERVED", conflict)
    mismatch = False
    unsure: list[str] = []
    if mode == "agent":
        expected = f"agent:{agent_id}"
        mismatch = (door.subject_type, door.subject_id) != ("agent", agent_id) or bool(door.act)
    else:
        expected = "the trace's user"
        if door.subject_type != "user":
            mismatch = True
        elif user_id is None:
            unsure.append("the trace has no user id to compare with")
        elif door.subject_id != user_id:
            mismatch = True
        if mode == "user":
            mismatch = mismatch or bool(door.act)
        else:
            expected += f", acting through {' < '.join(reversed(agent.path))}"
            verdict = _act_verdict(door.act, agent)
            mismatch = mismatch or verdict == "mismatch"
            if verdict == "unsure":
                unsure.append("the call path is incomplete, so the act chain cannot be compared")
    expected = shown_name(expected)  # the whole text, so ids cannot push it past its cap
    if mismatch:
        return _Judged(expected, observed, "MISMATCH", conflict)
    if unsure:
        return _Judged(expected, observed, "INCONCLUSIVE", (*unsure, *conflict))
    return _Judged(expected, observed, "MATCH", conflict)


def _pick_agent(link: RecordLink, view: TraceView) -> AgentVisit | None:
    """The calling agent visit of a record, or None when it is not a known agent.

    An ambiguous record takes the first listed candidate whose calling agent is known;
    candidates are in trace order, so the choice is deterministic.
    """
    if link.agent_ambiguous:
        for candidate in link.candidates:
            call = view.calls.get(candidate)
            if call is not None and call.agent is not None and call.agent.agent_id is not None:
                return call.agent
        return None
    agent = link.agent
    return agent if agent is not None and agent.agent_id is not None else None


def records_without_known_agent(views: Sequence[TraceView], links: Sequence[TraceLinks]) -> int:
    """How many door records are not identity rows because no calling agent is known."""
    return count_links(views, links).no_known_agent


_CheckIndex = dict[tuple[tuple[str, ...], str], list[IdentityCheckRow]]


def _index_checks(report: CoverageReport | None) -> _CheckIndex:
    index: _CheckIndex = defaultdict(list)
    if report is not None and report.mode == "test":
        for check in report.identity_checks:
            index[(check.path, check.tool)].append(check)
    return index


def _test_results(
    index: _CheckIndex, path: tuple[str, ...], tool: str | None
) -> tuple[tuple[str, ...], bool]:
    """The lockwalk test results for the same path and tool, and whether all of them are MATCH."""
    checks = index.get((path, tool)) if tool is not None else None
    if not checks:
        return (), False
    lines: list[str] = []
    for check in checks:
        if not check.observations:
            lines.append(f"{check.case_id}: {check.result.value}")
        lines.extend(
            f"{check.case_id} {obs.mode}: {obs.result.value}" for obs in check.observations
        )
    shown = [truncate(line, NAME_LIMIT) for line in lines[:MAX_TEST_RESULTS]]
    if len(lines) > MAX_TEST_RESULTS:
        shown.append(f"... and {len(lines) - MAX_TEST_RESULTS} more")
    return tuple(shown), all(check.result is IdentityResult.MATCH for check in checks)


def identity_findings(
    views: Sequence[TraceView],
    links: Sequence[TraceLinks],
    catalog: Catalog,
    test_report: CoverageReport | None,
) -> tuple[IdentityRow, ...]:
    groups: dict[tuple, _Tally] = defaultdict(_Tally)
    for view, trace_links in _links_for(views, links):
        for link in trace_links.records:
            span = view.spans.get(link.span_id)
            agent = _pick_agent(link, view)
            if span is None or span.door is None or agent is None:
                continue  # an unknown calling agent is not an identity row
            if not span.door.has_subject:
                continue  # a decision-only record (a door rule) is not an identity row
            judged = _judge(link, view, agent, catalog)
            call = view.calls.get(link.call) if link.call is not None else None
            tool = call.tool_id if call is not None else None
            if link.agent_ambiguous:
                judged = replace(
                    judged,
                    expected=AMBIGUOUS_EXPECTED,
                    result="INCONCLUSIVE",
                    notes=(AMBIGUOUS_NOTE,),
                )
                tool = None
            mode = catalog.modes.get(agent.agent_id or "") or "undeclared"
            groups[(agent.path, tool, mode, judged)].add(view.trace_id)
    index = _index_checks(test_report)
    rows: list[IdentityRow] = []
    for (path, tool, mode, judged), tally in groups.items():
        test_results, all_match = _test_results(index, path, tool)
        notes = list(judged.notes)
        if all_match and judged.result == "MISMATCH":
            notes.append(TEST_DIFFERS_NOTE)
        rows.append(
            IdentityRow(
                path=path,
                tool=tool,
                mode=mode,
                expected=judged.expected,
                observed=judged.observed,
                result=judged.result,
                count=tally.count,
                traces=tuple(tally.traces),
                notes=tuple(notes),
                test_results=test_results,
            )
        )
    rows.sort(key=lambda r: (_IDENTITY_RANK[r.result], r.path, r.tool or "", r.mode, r.observed))
    return tuple(rows)


def load_test_report(path: Path | None) -> tuple[CoverageReport | None, str | None]:
    """The last lockwalk test report for the side-by-side, or (None, a warning)."""
    if path is None:
        return None, None
    try:
        report = read_report(path)
    except ReportFileError as exc:
        if not path.exists():
            return None, None
        return None, f"the test report cannot be used: {truncate(redact_urls(str(exc)), 300)}"
    if report.mode != "test":
        return None, STATIC_REPORT_WARNING
    return report, None


# ---- Guard ----

# ("id", tool id) for a known tool, ("name", shown name) for an unknown one.
_ToolKey = tuple[Literal["id", "name"], str]


@dataclass(slots=True)
class _Seen:
    """What the door and the effect markers say about one tool call (one trace at a time)."""

    call: ToolCall
    records: int = 0
    denied: bool = False  # a deny or error record
    by_time: bool = False
    effect: bool = False


@dataclass
class _GuardGroup:
    known: bool
    counts: defaultdict[GuardStatus, int] = field(default_factory=lambda: defaultdict(int))
    pending_denied: int = 0  # denied, no linked effect: DENIED or DENIED_UNVERIFIED at the end
    by_time: int = 0
    effect_without_record: int = 0
    traces: list[str] = field(default_factory=list)


def _tool_key(call: ToolCall) -> _ToolKey:
    if call.tool_id is not None:
        return ("id", shown_name(call.tool_id))
    return ("name", shown_name(call.name))


def _scan_trace(view: TraceView, trace_links: TraceLinks) -> dict[str, _Seen]:
    by_call = {span_id: _Seen(call) for span_id, call in view.calls.items() if not call.wrapper}
    for link in trace_links.records:
        span = view.spans.get(link.span_id)
        if span is None or span.door is None or link.kind not in _LINKED:
            continue
        entry = by_call.get(link.call or "")
        if entry is not None:
            entry.records += 1
            entry.denied = entry.denied or span.door.decision != "allow"
            entry.by_time = entry.by_time or link.kind == "time"
    for link in trace_links.effects:
        entry = by_call.get(link.call or "") if link.kind in _LINKED else None
        if entry is not None:
            entry.effect = True
    return by_call


def guard_findings(
    views: Sequence[TraceView], links: Sequence[TraceLinks], catalog: Catalog
) -> tuple[GuardRow, ...]:
    groups: dict[tuple[str | None, _ToolKey], _GuardGroup] = {}
    # An effect marker no one can place does not count as proof that markers are in use.
    effect_tools: set[_ToolKey] = set()
    for view, trace_links in _links_for(views, links):
        # Every call active at an ambiguous record or marker, not only the listed candidates
        # (RecordLink.candidates is capped; links.py computes the full sets).
        candidates = trace_links.ambiguous_calls
        possible_effect = trace_links.ambiguous_effect_calls
        for span_id, entry in _scan_trace(view, trace_links).items():
            key = _tool_key(entry.call)
            if entry.effect:
                effect_tools.add(key)
            agent = entry.call.agent
            gkey = (agent.agent_id if agent is not None else None, key)
            group = groups.get(gkey)
            if group is None:
                group = groups[gkey] = _GuardGroup(known=key[0] == "id")
            status: GuardStatus | None
            if entry.records == 0:
                status = "INCONCLUSIVE" if span_id in candidates else "UNGUARDED"
            elif not entry.denied:
                status = "GUARDED"
            elif entry.effect:
                status = "BYPASS"
            elif span_id in possible_effect:
                status = "INCONCLUSIVE"
            else:
                status = None  # DENIED or DENIED_UNVERIFIED, decided at the end
            if status is None:
                group.pending_denied += 1
            else:
                group.counts[status] += 1
            group.by_time += 1 if entry.by_time else 0
            if status == "UNGUARDED" and entry.effect:
                group.effect_without_record += 1
            if (
                status != "GUARDED"
                and len(group.traces) < MAX_EXAMPLES
                and view.trace_id not in group.traces
            ):
                group.traces.append(view.trace_id)
    rows: list[GuardRow] = []
    for (agent_id, key), group in groups.items():
        if group.pending_denied:
            settled: GuardStatus = "DENIED" if key in effect_tools else "DENIED_UNVERIFIED"
            group.counts[settled] += group.pending_denied
        rows.append(
            GuardRow(
                agent=agent_id,
                tool=key[1],
                tool_known=group.known,
                counts=dict(group.counts),
                by_time=group.by_time,
                effect_without_record=group.effect_without_record,
                traces=tuple(group.traces),
            )
        )
    rows.sort(key=lambda r: (r.agent or "", r.tool))
    return tuple(rows)


# ---- Paths ----


def path_findings(views: Sequence[TraceView], catalog: Catalog) -> tuple[PathRow, ...]:
    groups: dict[tuple[tuple[str, ...], str, bool], _Tally] = defaultdict(_Tally)
    for view in views:
        if view.error is not None:
            continue
        for call in view.calls.values():
            agent = call.agent
            if call.wrapper or agent is None or agent.agent_id is None or call.tool_id is None:
                continue
            groups[(agent.path, call.tool_id, agent.incomplete)].add(view.trace_id)
    rows: list[PathRow] = []
    for (path, tool, incomplete), tally in groups.items():
        if not incomplete and (path, tool) in catalog.case_routes:
            status: Literal["TESTED", "TESTED_OTHER_PATH", "UNTESTED"] = "TESTED"
        elif (path[-1], tool) in catalog.case_agents:
            status = "TESTED_OTHER_PATH"
        else:
            status = "UNTESTED"
        rows.append(
            PathRow(
                path=path,
                tool=shown_name(tool),
                incomplete=incomplete,
                status=status,
                count=tally.count,
                traces=tuple(tally.traces),
            )
        )
    rows.sort(key=lambda r: (r.status != "UNTESTED", r.path, r.tool, r.incomplete))
    return tuple(rows)


# ---- Gate ----


def observe_gate(
    routes: Sequence[RouteRow],
    unknown: Sequence[UnknownRow],
    gate: GateConfig,
    *,
    identities: Sequence[IdentityRow] = (),
    guards: Sequence[GuardRow] = (),
    paths: Sequence[PathRow] = (),
    risks: Mapping[str, Risk] | None = None,
) -> ObserveGate:
    violations: list[ObserveViolation] = []
    if gate.fail_on_off_map_route:
        violations.extend(
            ObserveViolation(rule="fail_on_off_map_route", from_id=row.from_id, to_id=row.to_id)
            for row in routes
            if row.status == "OFF_MAP"
        )
    if gate.fail_on_unknown_component:
        violations.extend(
            ObserveViolation(rule="fail_on_unknown_component", kind=row.kind, name=row.name)
            for row in unknown
        )
    risk_of = risks or {}

    def risk(tool: str, known: bool) -> Risk:
        return risk_of.get(tool, Risk.UNKNOWN) if known else Risk.UNKNOWN

    violations.extend(
        ObserveViolation(rule="bypass", agent=row.agent, tool=row.tool)
        for row in guards
        if "BYPASS" in row.counts
    )
    if gate.fail_on_identity_mismatch:
        violations.extend(
            ObserveViolation(rule="fail_on_identity_mismatch", path=row.path, tool=row.tool)
            for row in identities
            if row.result == "MISMATCH"
        )
    if gate.fail_on_inconclusive_observation:
        violations.extend(
            ObserveViolation(
                rule="fail_on_inconclusive_observation",
                subject="identity",
                path=row.path,
                tool=row.tool,
            )
            for row in identities
            if row.result == "INCONCLUSIVE"
        )
        violations.extend(
            ObserveViolation(
                rule="fail_on_inconclusive_observation",
                subject="guard",
                agent=row.agent,
                tool=row.tool,
            )
            for row in guards
            if "INCONCLUSIVE" in row.counts
        )
    violations.extend(
        ObserveViolation(rule="fail_on_unguarded_call", agent=row.agent, tool=row.tool)
        for row in guards
        if "UNGUARDED" in row.counts
        and risk(row.tool, row.tool_known) in gate.fail_on_unguarded_call
    )
    violations.extend(
        ObserveViolation(rule="fail_on_untested_path", path=row.path, tool=row.tool)
        for row in paths
        if row.status == "UNTESTED" and risk(row.tool, True) in gate.fail_on_untested_path
    )
    unique = tuple(dict.fromkeys(violations))
    return ObserveGate(passed=not unique, violations=unique)
