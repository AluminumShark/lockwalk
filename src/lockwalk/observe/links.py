"""Which tool call each door record and effect marker belongs to."""

import bisect
import heapq
import math
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from lockwalk.observe.tree import AgentVisit, TraceView

MAX_CANDIDATES = 5

LinkKind = Literal["ancestry", "tool_call_id", "time", "ambiguous", "none", "covers_tools"]
_Found = tuple[LinkKind, str | None]
_Bound = int | float  # a time, or an infinity for an open end


@dataclass(frozen=True, slots=True)
class RecordLink:
    span_id: str  # the span holding the record or the marker
    kind: LinkKind
    call: str | None  # the tool call's span id when linked (ancestry, tool_call_id, time)
    candidates: tuple[str, ...]  # when ambiguous: at most MAX_CANDIDATES call span ids
    agent: AgentVisit | None  # the calling agent visit
    agent_ambiguous: bool  # ambiguous candidates with different agents or paths
    user_id: str | None = field(repr=False)  # nearest user id at or above the record's span
    user_conflict: bool  # two different user ids on the way up
    more_candidates: int = 0  # ambiguous candidates beyond MAX_CANDIDATES, not listed


@dataclass(frozen=True, slots=True)
class TraceLinks:
    trace_id: str
    records: tuple[RecordLink, ...]  # in trace order
    effects: tuple[RecordLink, ...]
    covers_tools: int  # records whose span has a tool span below it (never time-linked)
    # Every non-wrapper tool call active at the start of at least one ambiguous door record.
    ambiguous_calls: frozenset[str] = frozenset()
    # The same for effect markers: calls active at the start of an ambiguous effect marker.
    ambiguous_effect_calls: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _Up:
    """What a span inherits from the spans above it (one preorder pass)."""

    call: str | None = None  # nearest non-wrapper tool call at or above, within the same visit
    # A call above was dropped on entering a new agent visit. Time may link a record here only
    # to the calls of its own visit, never to a call across the agent boundary.
    fenced: bool = False
    visit: AgentVisit | None = None  # nearest agent visit at or above
    user_id: str | None = None
    user_conflict: bool = False


def _inherit(view: TraceView, keep: set[str]) -> dict[str, _Up]:
    """Step 1: iterative preorder pass; one state per depth, so the cost is linear. Only the
    states of the spans in keep are returned."""
    states: list[_Up] = []
    result: dict[str, _Up] = {}
    for span_id in view.order:
        span = view.spans[span_id]
        level = view.depth[span_id]
        del states[level:]
        up = states[level - 1] if level > 0 else _Up()
        call = view.calls.get(span_id)
        if call is not None and not call.wrapper:
            up = _Up(span_id, up.fenced, up.visit, up.user_id, up.user_conflict)
        visit = view.visits.get(span_id)
        if visit is not None:
            # A call above an agent is not a call of that agent. A merged span is the same
            # visit as the one above it, so it keeps the call.
            if span_id in view.merged or up.call is None:
                up = _Up(up.call, up.fenced, visit, up.user_id, up.user_conflict)
            else:
                up = _Up(None, True, visit, up.user_id, up.user_conflict)
        if span.user_id is not None:
            conflict = up.user_conflict or (up.user_id is not None and up.user_id != span.user_id)
            up = _Up(up.call, up.fenced, up.visit, span.user_id, conflict)
        states.append(up)
        if span_id in keep:
            result[span_id] = up
    return result


def _tool_below(view: TraceView) -> set[str]:
    """Step 2: spans with a tool span (wrapper or not) somewhere below them."""
    below: set[str] = set()
    for span_id in reversed(view.order):
        parent_id = view.spans[span_id].parent_id
        if parent_id is None or parent_id not in view.spans:
            continue
        if span_id in view.calls or span_id in below:
            below.add(parent_id)
    return below


@dataclass(frozen=True, slots=True)
class _Hit:
    """The non-wrapper tool calls active at one record's start, bounded."""

    first: tuple[str, ...]  # at most MAX_CANDIDATES, earliest in trace order
    more: int  # active calls not listed
    visit: AgentVisit | None  # the shared visit when every active call agrees
    mixed: bool  # active calls differ in agent id or path


def _agent_key(visit: AgentVisit | None) -> tuple[str | None, tuple[str, ...]] | None:
    return None if visit is None else (visit.agent_id, visit.path)


def _interval(start: int | None, end: int | None) -> tuple[_Bound, _Bound]:
    """A non-wrapper call's interval for time linking (fail closed): a
    missing start is -infinity; a missing end, or an end before the start, is +infinity. Such
    calls stay candidates, so a record inside them is never credited to another call."""
    low: _Bound = -math.inf if start is None else start
    high: _Bound = math.inf if end is None or (start is not None and end < start) else end
    return low, high


def _calls_at(timed: list[tuple[_Bound, _Bound, int, str]], starts: list[int]) -> frozenset[str]:
    """The calls whose inclusive interval contains at least one of the sorted starts."""
    calls: set[str] = set()
    for low, high, _, call_id in timed:
        i = bisect.bisect_left(starts, low)
        if i < len(starts) and starts[i] <= high:
            calls.add(call_id)
    return frozenset(calls)


_Timed = tuple[_Bound, _Bound, int, str]  # (low, high, trace position, span id)


def _timed_calls(view: TraceView) -> list[_Timed]:
    """Every non-wrapper tool call with its interval (see _interval), in trace order."""
    timed: list[_Timed] = []
    for index, span_id in enumerate(view.order):
        call = view.calls.get(span_id)
        if call is not None and not call.wrapper:
            span = view.spans[span_id]
            low, high = _interval(span.start_ns, span.end_ns)
            timed.append((low, high, index, span_id))
    return timed


def _sweep(
    view: TraceView,
    timed: list[_Timed],
    wanted: Iterable[str],
    door_spans: set[str],
    effect_spans: set[str],
) -> tuple[dict[str, _Hit], frozenset[str], frozenset[str]]:
    """Step 4: for each wanted span that has a start, the calls in timed (non-wrapper tool calls
    with their intervals) whose interval contains that start. Sweep line with a heap of active
    calls by end: n log n. Candidates are bounded: a second heap by trace position (lazy
    deletion) gives the first MAX_CANDIDATES, and a counter of agent keys over the active set
    answers the agent question in O(1).

    Also returns every call active at the start of at least one ambiguous door record, and the
    same for ambiguous effect markers."""
    timed = sorted(timed)
    points = sorted(
        (start, span_id)
        for span_id in wanted
        if (start := view.spans[span_id].start_ns) is not None
    )
    ends: list[tuple[_Bound, str]] = []  # (end, span id)
    order_heap: list[tuple[int, str]] = []  # (trace position, span id); may hold stale entries
    active: set[str] = set()
    keys: Counter[tuple[str | None, tuple[str, ...]] | None] = Counter()
    result: dict[str, _Hit] = {}
    door_starts: list[int] = []  # starts of ambiguous door records, in sweep order
    effect_starts: list[int] = []  # starts of ambiguous effect markers, in sweep order
    next_call = 0
    for start, span_id in points:
        while next_call < len(timed) and timed[next_call][0] <= start:
            _, high, index, call_id = timed[next_call]
            next_call += 1
            if high >= start:
                heapq.heappush(ends, (high, call_id))
                heapq.heappush(order_heap, (index, call_id))
                active.add(call_id)
                keys[_agent_key(view.calls[call_id].agent)] += 1
        while ends and ends[0][0] < start:
            call_id = heapq.heappop(ends)[1]
            active.discard(call_id)
            key = _agent_key(view.calls[call_id].agent)
            keys[key] -= 1
            if keys[key] == 0:
                del keys[key]
        if not active:
            continue
        if len(active) == 1:
            (only,) = active
            result[span_id] = _Hit((only,), 0, view.calls[only].agent, False)
            continue
        taken: list[tuple[int, str]] = []
        while order_heap and len(taken) < MAX_CANDIDATES:
            entry = heapq.heappop(order_heap)
            if entry[1] in active:  # an ended call never becomes active again
                taken.append(entry)
        for entry in taken:
            heapq.heappush(order_heap, entry)
        first = tuple(call_id for _, call_id in taken)
        visit = view.calls[first[0]].agent
        result[span_id] = _Hit(first, len(active) - len(first), visit, len(keys) > 1)
        if span_id in door_spans:
            door_starts.append(start)
        if span_id in effect_spans:
            effect_starts.append(start)
    # Both lists are sorted because points are.
    return result, _calls_at(timed, door_starts), _calls_at(timed, effect_starts)


def _sweep_by_visit(
    view: TraceView, up: dict[str, _Up], door_spans: set[str], effect_spans: set[str]
) -> tuple[dict[str, _Hit], frozenset[str], frozenset[str]]:
    """Run the sweep. A record that is not fenced is swept against every call. A fenced record
    (a call above its agent was dropped) is swept only against the calls of its own agent
    visit, so time can never hand it to a call across an agent boundary. The calls are bucketed
    by agent visit once and each bucket is sorted once by _sweep; every call and every record is
    in exactly one sweep, so the total stays n log n."""
    wanted = door_spans | effect_spans
    free = {s for s in wanted if not up[s].fenced}
    timed = _timed_calls(view)
    hits, ambiguous, ambiguous_effect = _sweep(
        view, timed, free, door_spans & free, effect_spans & free
    )
    fenced_by_visit: dict[AgentVisit | None, set[str]] = {}
    for span_id in wanted - free:
        fenced_by_visit.setdefault(up[span_id].visit, set()).add(span_id)
    if not fenced_by_visit:
        return hits, ambiguous, ambiguous_effect
    buckets: dict[AgentVisit | None, list[_Timed]] = {}
    for item in timed:
        buckets.setdefault(view.calls[item[3]].agent, []).append(item)
    calls: set[str] = set(ambiguous)
    effect_calls: set[str] = set(ambiguous_effect)
    for visit, group in fenced_by_visit.items():
        found, door_calls, marker_calls = _sweep(
            view, buckets.get(visit, []), group, door_spans & group, effect_spans & group
        )
        hits.update(found)
        calls |= door_calls
        effect_calls |= marker_calls
    return hits, frozenset(calls), frozenset(effect_calls)


def _calls_by_id(view: TraceView) -> dict[str, list[str]]:
    """Non-wrapper tool calls by their gen_ai.tool.call.id."""
    by_call_id: dict[str, list[str]] = {}
    for call in view.calls.values():
        call_id = view.spans[call.span_id].tool_call_id
        if not call.wrapper and call_id is not None:
            by_call_id.setdefault(call_id, []).append(call.span_id)
    return by_call_id


def _direct(
    span_id: str,
    up: _Up,
    below: set[str],
    by_call_id: Mapping[str, list[str]],
    record_call_id: str | None,
) -> _Found | None:
    """Steps 3a-3c: ancestry, tool_call_id, covers_tools; None when time must decide.
    record_call_id is the door record's tool_call_id (None for an effect marker)."""
    if up.call is not None:
        return "ancestry", up.call
    if record_call_id is not None:
        matches = by_call_id.get(record_call_id, [])
        if len(matches) == 1:
            return "tool_call_id", matches[0]
    if span_id in below:
        return "covers_tools", None
    return None


def _make_link(
    view: TraceView, span_id: str, up: _Up, found: _Found | None, hit: _Hit | None
) -> RecordLink:
    kind: LinkKind
    call: str | None = None
    candidates: tuple[str, ...] = ()
    agent = up.visit
    agent_ambiguous = False
    more = 0
    if found is not None:
        kind, call = found
        if call is not None:
            agent = view.calls[call].agent
    elif hit is None:
        kind = "none"
    elif not hit.more and len(hit.first) == 1:
        kind, call = "time", hit.first[0]
        agent = view.calls[call].agent
    else:
        kind, candidates, more = "ambiguous", hit.first, hit.more
        agent, agent_ambiguous = (None, True) if hit.mixed else (hit.visit, False)
    return RecordLink(
        span_id=span_id,
        kind=kind,
        call=call,
        candidates=candidates,
        agent=agent,
        agent_ambiguous=agent_ambiguous,
        user_id=up.user_id,
        user_conflict=up.user_conflict,
        more_candidates=more,
    )


def link_trace(view: TraceView) -> TraceLinks:
    """Link every door record and effect marker to a tool call."""
    if view.error is not None:
        return TraceLinks(view.trace_id, (), (), 0)
    holders = [s for s in view.order if view.spans[s].door is not None or view.spans[s].effect]
    up = _inherit(view, set(holders))
    below = _tool_below(view)
    by_call_id = _calls_by_id(view)

    # Steps 3a-3c once per holder, for the door and for the effect marker.
    door_found: dict[str, _Found | None] = {}
    effect_found: dict[str, _Found | None] = {}
    for span_id in holders:
        span = view.spans[span_id]
        if span.door is not None:
            door_found[span_id] = _direct(
                span_id, up[span_id], below, by_call_id, span.door.tool_call_id
            )
        if span.effect:
            effect_found[span_id] = _direct(span_id, up[span_id], below, by_call_id, None)

    door_spans = {s for s, found in door_found.items() if found is None}
    effect_spans = {s for s, found in effect_found.items() if found is None}
    hits, ambiguous_calls, ambiguous_effect_calls = _sweep_by_visit(
        view, up, door_spans, effect_spans
    )

    records = tuple(
        _make_link(view, s, up[s], door_found[s], hits.get(s)) for s in holders if s in door_found
    )
    effects = tuple(
        _make_link(view, s, up[s], effect_found[s], hits.get(s))
        for s in holders
        if s in effect_found
    )
    return TraceLinks(
        trace_id=view.trace_id,
        records=records,
        effects=effects,
        covers_tools=sum(1 for r in records if r.kind == "covers_tools"),
        ambiguous_calls=ambiguous_calls,
        ambiguous_effect_calls=ambiguous_effect_calls,
    )
