"""`lockwalk observe`: read traces, rebuild call paths, compare them with the map.

One function ties the steps together; the `observe` command and `inspect --trace` both use it.
"""

from dataclasses import dataclass, replace

from lockwalk import waivers as waivers_module
from lockwalk.analyzer import analyze
from lockwalk.errors import COMMAND_LINE, StructuralError
from lockwalk.observe.catalog import Catalog, build_catalog
from lockwalk.observe.checks import (
    LinkCounts,
    count_links,
    guard_findings,
    identity_findings,
    load_test_report,
    observe_gate,
    observe_totals,
    observe_window,
    path_findings,
    route_findings,
)
from lockwalk.observe.conventions import recognize
from lockwalk.observe.door import DoorKeys
from lockwalk.observe.links import TraceLinks, link_trace
from lockwalk.observe.otlp import read_otlp
from lockwalk.observe.reader import run_reader
from lockwalk.observe.results import ObserveReport
from lockwalk.observe.spans import Limits, ReadResult, allowlist
from lockwalk.observe.tree import TraceView, build_traces
from lockwalk.pipeline import collect, load_waivers_for, require_registry_and_spec
from lockwalk.planner import plan_cases
from lockwalk.settings import RunSettings
from lockwalk.waivers import apply_observe_waivers

NO_SPANS_ERROR = (
    "no agent or tool spans were recognized; check the instrumentation, [observe.rules] "
    "and the agent names (see docs/lockwalk-observe.md)"
)
COVERS_TOOLS_RECORDS = (
    "{n} door records sit on spans that contain tool calls; "
    "record them with lockwalk.record.record_authz or a span of their own"
)
COVERS_TOOLS_EFFECTS = (
    "{n} effect markers sit on spans that contain tool calls, so they are not tied to a tool call"
)
USER_CONFLICT = "{n} door records saw two different user ids; the nearest one was used"
NO_KNOWN_AGENT = (
    "{n} door records have no known calling agent, so they are not identity rows "
    "(see docs/lockwalk-observe.md)"
)
NO_SUBJECT = (
    "{n} door records have no subject (for example a person's approval); "
    "they count for guard checks only"
)


@dataclass(frozen=True)
class ObserveRun:
    report: ObserveReport
    notes: tuple[str, ...]
    views: tuple[TraceView, ...]  # for inspect --trace
    catalog: Catalog
    links: tuple[TraceLinks, ...]  # one per view, for inspect --trace


def wanted_trace_id(settings: RunSettings, trace_id: str) -> str:
    """The id as it is compared: lower case for OTLP input, exact for a reader function."""
    return trace_id if settings.observe.reader is not None else trace_id.lower()


def _link_warnings(counts: LinkCounts) -> list[str]:
    """The warnings from linking, from counts only; never an id."""
    out: list[str] = []
    if counts.covers_records or counts.covers_effects:
        parts = []
        if counts.covers_records:
            parts.append(COVERS_TOOLS_RECORDS.format(n=counts.covers_records))
        if counts.covers_effects:
            parts.append(COVERS_TOOLS_EFFECTS.format(n=counts.covers_effects))
        out.append(". ".join(parts))
    if counts.user_conflicts:
        out.append(USER_CONFLICT.format(n=counts.user_conflicts))
    if counts.no_known_agent:
        out.append(NO_KNOWN_AGENT.format(n=counts.no_known_agent))
    if counts.no_subject:
        out.append(NO_SUBJECT.format(n=counts.no_subject))
    return out


def run_observe(settings: RunSettings, *, only_trace: str | None = None) -> ObserveRun:
    """Run the whole observe pipeline. Raises StructuralError for a broken map or settings.

    only_trace must already be normalized with wanted_trace_id.
    """
    registry, spec = require_registry_and_spec(settings, "observe")
    # One date for the whole run, read through the module. inspect --trace (only_trace) shows
    # one trace and never loads waivers, so a bad waivers file cannot block it.
    run_date = waivers_module.today()
    # Loaded before any trace is read.
    waivers = None if only_trace is not None else load_waivers_for(settings, run_date)
    inventory, graph = collect(settings, registry)
    static = analyze(inventory, spec, plan_cases(spec, inventory, graph), settings.gate, graph)
    errors = list(static.errors)
    catalog = build_catalog(inventory, graph, registry, settings.observe, spec)
    config = settings.observe
    if not settings.trace_args and config.reader is None:
        raise StructuralError(
            COMMAND_LINE,
            ["observe needs --traces, or [observe] traces or reader in .lockwalk.toml"],
        )
    if settings.trace_base is None:  # resolve_settings always sets it
        raise StructuralError(COMMAND_LINE, ["observe: the trace base directory is unknown"])
    limits = Limits.from_config(config)
    read: ReadResult
    if config.reader is not None:
        read = run_reader(
            config.reader,
            cwd=settings.trace_base,
            paths=settings.trace_args,
            timeout_s=config.reader_timeout_s,
            limits=limits,
            only_trace=only_trace,
        )
        spans = list(read.spans)
    else:
        read = read_otlp(
            [settings.trace_base / arg for arg in settings.trace_args],
            labels=settings.trace_args,  # sources are shown as given, never as absolute paths
            keys=allowlist(config),
            limits=limits,
            only_trace=only_trace,
        )
        recognized = recognize(
            read.raw,
            rules=config.rules,
            agent_names=catalog.agent_names,
            door_keys=DoorKeys.from_config(config),
        )
        spans = recognized.spans
        # The raw spans (with all their attributes) are not needed after recognition.
        read = replace(read, raw=())
        errors.extend(f"{p.where}: {p.message}" for p in recognized.problems)
    views = build_traces(spans, catalog)
    routes, unknown = route_findings(views, catalog)
    links = [link_trace(view) for view in views]
    counts = count_links(views, links)
    totals = observe_totals(read, views, spans, counts)
    errors.extend(
        f"{problem.where}: {problem.message}" if problem.where else problem.message
        for problem in read.problems
    )
    errors.extend(f"trace {view.trace_id}: {view.error}" for view in views if view.error)
    if not views:
        errors.append("no traces were read")
    elif totals.agent_spans == 0 and totals.tool_calls == 0:
        errors.append(NO_SPANS_ERROR)
    warnings = list(read.warnings)
    if totals.unnamed_markers > 0:
        warnings.append(
            f"{totals.unnamed_markers} span(s) have an agent or tool marker but no name; "
            "they were not counted (see docs/lockwalk-observe.md)"
        )
    warnings.extend(_link_warnings(counts))
    test_report, test_warning = load_test_report(settings.test_report)
    if test_warning is not None:
        warnings.append(test_warning)
    identities = identity_findings(views, links, catalog, test_report)
    guards = guard_findings(views, links, catalog)
    paths = path_findings(views, catalog)
    gate = observe_gate(
        routes,
        unknown,
        settings.gate,
        identities=identities,
        guards=guards,
        paths=paths,
        risks=catalog.risks,
    )
    report = ObserveReport(
        scenario_suite=spec.scenario_suite,
        sources=read.sources,
        totals=totals,
        window=observe_window(spans),
        routes=routes,
        unknown=unknown,
        identities=identities,
        guards=guards,
        paths=paths,
        gate=gate,
        errors=tuple(errors),
        warnings=tuple(warnings),
        exit_code=2 if errors else (0 if gate.passed else 1),
    )
    if waivers is not None:
        report = apply_observe_waivers(report, waivers, run_date)
    return ObserveRun(
        report=report,
        notes=settings.notes,
        views=tuple(views),
        catalog=catalog,
        links=tuple(links),
    )
