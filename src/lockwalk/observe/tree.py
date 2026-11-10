"""Per-trace trees: agent visits with their paths, and tool calls.

All walks are iterative and linear in the number of spans.
"""

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from lockwalk.models import MAX_ROUTE_AGENTS
from lockwalk.observe.catalog import Catalog
from lockwalk.observe.spans import Span

UNKNOWN_STEP = "?"


@dataclass(frozen=True)
class AgentVisit:
    span_id: str
    name: str  # as written in the trace
    agent_id: str | None  # None: the map does not know this name
    caller: str | None  # "user", an agent id, or None (unknown or incomplete)
    caller_name: str | None  # the explicit caller's name when it is not a known agent
    path: tuple[str, ...]  # agent ids from the start; "?" stands for an unknown agent
    incomplete: bool  # the start of the path is not in the data
    start_ns: int | None


@dataclass(frozen=True)
class ToolCall:
    span_id: str
    name: str
    tool_id: str | None
    agent: AgentVisit | None  # the calling agent visit
    wrapper: bool  # an agent-as-tool wrapper: not a tool call


@dataclass(frozen=True)
class TraceView:
    trace_id: str
    complete: bool  # every span's parent is in the data
    error: str | None  # duplicate span ids, a parent loop, or a path longer than MAX_ROUTE_AGENTS
    order: tuple[str, ...]  # span ids, depth-first, children by start time then span id
    depth: Mapping[str, int]
    spans: Mapping[str, Span]
    visits: Mapping[str, AgentVisit]  # by span id; a merged span maps to the visit it joins
    merged: frozenset[str]  # agent spans merged into the same agent above them
    calls: Mapping[str, ToolCall]


@dataclass
class _Walk:
    """Mutable state of one trace while it is built."""

    visits: dict[str, AgentVisit] = field(default_factory=dict)
    merged: set[str] = field(default_factory=set)
    calls: dict[str, ToolCall] = field(default_factory=dict)


def _sort_key(span: Span) -> tuple[bool, int, str]:
    return (span.start_ns is None, span.start_ns or 0, span.span_id)


def build_traces(spans: Iterable[Span], catalog: Catalog) -> list[TraceView]:
    """Group by trace id (sorted), then build each trace. Linear in the number of spans."""
    groups: dict[str, list[Span]] = defaultdict(list)
    for span in spans:
        groups[span.trace_id].append(span)
    return [_build_trace(trace_id, groups[trace_id], catalog) for trace_id in sorted(groups)]


def _failed(trace_id: str, by_id: Mapping[str, Span], complete: bool, error: str) -> TraceView:
    return TraceView(
        trace_id=trace_id,
        complete=complete,
        error=error,
        order=(),
        depth={},
        spans=by_id,
        visits={},
        merged=frozenset(),
        calls={},
    )


def _build_trace(trace_id: str, spans: list[Span], catalog: Catalog) -> TraceView:
    by_id: dict[str, Span] = {}
    for span in spans:
        if span.span_id in by_id:
            # Completeness is unknown when the parent links cannot be trusted.
            return _failed(trace_id, {}, False, "the trace repeats a span id")
        by_id[span.span_id] = span

    children: dict[str, list[Span]] = defaultdict(list)
    roots: list[Span] = []
    complete = True
    for span in spans:
        if span.parent_id is not None and span.parent_id in by_id:
            children[span.parent_id].append(span)
        else:
            roots.append(span)
            if span.parent_id is not None:
                complete = False
    roots.sort(key=_sort_key)

    # Depth-first order, iterative. part_incomplete is inherited from the root.
    order: list[str] = []
    depth: dict[str, int] = {}
    part_incomplete: dict[str, bool] = {}
    stack: list[Span] = []
    for root in reversed(roots):
        depth[root.span_id] = 0
        part_incomplete[root.span_id] = root.parent_id is not None
        stack.append(root)
        # Roots are pushed together so they pop in sorted order.
    while stack:
        span = stack.pop()
        order.append(span.span_id)
        kids = children.get(span.span_id)
        if kids:
            kids.sort(key=_sort_key)
            for kid in reversed(kids):
                depth[kid.span_id] = depth[span.span_id] + 1
                part_incomplete[kid.span_id] = part_incomplete[span.span_id]
                stack.append(kid)
    if len(order) < len(by_id):
        return _failed(trace_id, by_id, complete, "the spans' parents form a loop")

    walk = _Walk()
    ctx = _Context(
        order=order,
        depth=depth,
        by_id=by_id,
        part_incomplete=part_incomplete,
        catalog=catalog,
        handoff=_handoff_callers(order, by_id, catalog),
        below=_agent_below(order, children),
    )
    error = _walk_spans(ctx, walk)
    if error is not None:
        return _failed(trace_id, by_id, complete, error)
    return TraceView(
        trace_id=trace_id,
        complete=complete,
        error=None,
        order=tuple(order),
        depth=depth,
        spans=by_id,
        visits=walk.visits,
        merged=frozenset(walk.merged),
        calls=walk.calls,
    )


def _handoff_callers(
    order: list[str], by_id: Mapping[str, Span], catalog: Catalog
) -> dict[str, str]:
    """Agent span id -> the name of the agent that handed off to it."""
    positions: dict[str, deque[int]] = defaultdict(deque)
    for index, span_id in enumerate(order):
        span = by_id[span_id]
        if span.kind == "agent" and span.caller is None:
            name = span.name or ""
            positions[catalog.agent_id(name) or name].append(index)
    callers: dict[str, str] = {}
    for index, span_id in enumerate(order):
        span = by_id[span_id]
        if span.kind != "handoff" or span.handoff_to is None or span.handoff_from is None:
            continue
        queue = positions.get(catalog.agent_id(span.handoff_to) or span.handoff_to)
        if queue is None:
            continue
        # Handoffs are met in order, so earlier positions are useless for later ones too.
        while queue and queue[0] < index:
            queue.popleft()
        if queue:
            callers[order[queue.popleft()]] = span.handoff_from
    return callers


def _agent_below(order: list[str], children: Mapping[str, list[Span]]) -> set[str]:
    """Spans with an agent span below them before any other tool span (post-order pass)."""
    below: set[str] = set()
    for span_id in reversed(order):
        for kid in children.get(span_id, ()):
            if kid.kind == "agent" or (kid.kind != "tool" and kid.span_id in below):
                below.add(span_id)
                break
    return below


@dataclass
class _Context:
    """What the walk over one trace's spans needs, in one place."""

    order: list[str]
    depth: Mapping[str, int]
    by_id: Mapping[str, Span]
    part_incomplete: Mapping[str, bool]
    catalog: Catalog
    handoff: Mapping[str, str]  # agent span id -> name of the agent that handed off to it
    below: set[str]  # spans with an agent below them before another tool span
    latest: dict[str, AgentVisit] = field(default_factory=dict)  # agent id -> latest visit


def _merges_into(
    parent: AgentVisit | None, agent_id: str | None, name: str, explicit: bool
) -> bool:
    """Self-nesting: the same agent directly inside itself, with no explicit caller."""
    if parent is None or explicit:
        return False
    if agent_id is not None:
        return parent.agent_id == agent_id
    return parent.agent_id is None and parent.name == name


def _resolve_path(
    ctx: _Context,
    span_id: str,
    step: str,
    explicit: str | None,
    parent: AgentVisit | None,
) -> tuple[tuple[str, ...], str | None, str | None, bool]:
    """The (path, caller, caller_name, incomplete) of a new agent visit."""
    if explicit is not None:
        caller = ctx.catalog.agent_id(explicit)
        if caller is None:
            return (step,), None, explicit, True
        caller_visit = ctx.latest.get(caller)
        if caller_visit is None:
            return (step,), caller, None, True
        return (*caller_visit.path, step), caller, None, caller_visit.incomplete
    if parent is not None:
        # An unknown enclosing agent gives caller None: the edge A -> ? -> B is not judged.
        return (*parent.path, step), parent.agent_id, None, parent.incomplete
    if ctx.part_incomplete[span_id]:
        return (step,), None, None, True
    return (step,), "user", None, False


def _walk_spans(ctx: _Context, walk: _Walk) -> str | None:
    enclosing: list[tuple[int, AgentVisit]] = []  # (depth, visit), increasing depth
    for span_id in ctx.order:
        span = ctx.by_id[span_id]
        level = ctx.depth[span_id]
        while enclosing and enclosing[-1][0] >= level:
            enclosing.pop()
        parent = enclosing[-1][1] if enclosing else None
        name = span.name or ""
        if span.kind == "tool":
            tool_id = ctx.catalog.tool_id(name)
            wrapper = tool_id is None and (name in ctx.catalog.wrappers or span_id in ctx.below)
            walk.calls[span_id] = ToolCall(span_id, name, tool_id, parent, wrapper)
            continue
        if span.kind != "agent":
            continue
        agent_id = ctx.catalog.agent_id(name)
        explicit = span.caller if span.caller is not None else ctx.handoff.get(span_id)
        if parent is not None and _merges_into(parent, agent_id, name, explicit is not None):
            walk.merged.add(span_id)
            walk.visits[span_id] = parent
            enclosing.append((level, parent))
            continue
        path, caller, caller_name, incomplete = _resolve_path(
            ctx, span_id, agent_id or UNKNOWN_STEP, explicit, parent
        )
        if len(path) > MAX_ROUTE_AGENTS:
            return f"a call path is longer than {MAX_ROUTE_AGENTS} agents (at span {span_id})"
        visit = AgentVisit(
            span_id=span_id,
            name=name,
            agent_id=agent_id,
            caller=caller,
            caller_name=caller_name,
            path=path,
            incomplete=incomplete,
            start_ns=span.start_ns,
        )
        walk.visits[span_id] = visit
        enclosing.append((level, visit))
        if agent_id is not None:
            ctx.latest[agent_id] = visit
    return None
