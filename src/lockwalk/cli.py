"""Command-line interface: `lockwalk discover`, `coverage`, `test`, `inspect` and `diff`."""

import contextlib
import errno
import json
import os
import sys
import traceback
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NamedTuple, NoReturn, TextIO

import typer
from rich.console import Console

from lockwalk import __version__
from lockwalk.analyzer import analyze, tool_spec_states
from lockwalk.diff import diff_reports, load_report
from lockwalk.diff_markdown import render_diff_markdown
from lockwalk.diff_output import diff_to_json, render_diff_text
from lockwalk.errors import COMMAND_LINE, StructuralError
from lockwalk.evidence import EVIDENCE_FILE_NAME, Evidence, write_evidence
from lockwalk.evidence_build import without_evidence
from lockwalk.graph.analysis import (
    evaluate_rules,
    graph_section,
    holderless_warnings,
    identity_summaries,
    index_graph,
    role_reachability,
    startless_warnings,
)
from lockwalk.inspection import InspectError, inspect_case, inspect_trace
from lockwalk.inventory.normalize import describe_error
from lockwalk.models import (
    AgentGraph,
    CoverageReport,
    Inventory,
    PlannedCase,
    ReachRow,
    RuleRow,
    SpecState,
)
from lockwalk.observe.output import render_observe, write_observe
from lockwalk.observe.pipeline import run_observe
from lockwalk.observe.results import OBSERVE_FILE_NAME
from lockwalk.pipeline import collect, finish, load_waivers_for, require_registry_and_spec
from lockwalk.planner import plan_cases
from lockwalk.registry import Registry, load_registry
from lockwalk.report import (
    REPORT_FILE_NAME,
    ReportFileError,
    render_coverage,
    render_discover,
    render_structural_error,
    to_ascii,
    write_report,
)
from lockwalk.settings import RunSettings, fallback_output_dir, resolve_settings
from lockwalk.snapshot import SNAPSHOT_KEY, SnapshotRefused, write_snapshot
from lockwalk.spec_loader import SpecFile, load_spec
from lockwalk.testing import run_policy_test
from lockwalk.urls import redact_urls

app = typer.Typer(
    add_completion=False,
    pretty_exceptions_enable=False,
    no_args_is_help=True,
    help="Authorization test coverage for AI agent tools.",
)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", help="Path to .lockwalk.toml (default: ./.lockwalk.toml if present)."),
]
RegistryOption = Annotated[str | None, typer.Option("--registry", help="Path to registry.yaml.")]
SpecOption = Annotated[str | None, typer.Option("--spec", help="Path to security-spec.yaml.")]
McpOption = Annotated[
    list[str] | None,
    typer.Option("--mcp", help="MCP server: stdio://path/server.py or http(s)://host/mcp."),
]
PythonOption = Annotated[
    list[str] | None,
    typer.Option("--python", help="Python tools: module:attribute or file.py:attribute; add ()."),
]
ToolsJsonOption = Annotated[
    list[str] | None, typer.Option("--tools-json", help="JSON file with tool descriptions.")
]
OutputDirOption = Annotated[
    str | None, typer.Option("--output-dir", help="Where coverage.json goes (default: .lockwalk).")
]
ObserveOutputDirOption = Annotated[
    str | None, typer.Option("--output-dir", help="Where observe.json goes (default: .lockwalk).")
]
FixturesOption = Annotated[str | None, typer.Option("--fixtures", help="Path to fixtures.yaml.")]
WaiversOption = Annotated[
    str | None,
    typer.Option(
        "--waivers", help=r"Waivers file (default: \[lockwalk] waivers in .lockwalk.toml)."
    ),
]
SummaryOption = Annotated[
    bool,
    typer.Option(
        "--summary",
        help="Print only the counts and what needs action; coverage.json is always complete.",
    ),
]
PolicyOption = Annotated[
    str | None,
    typer.Option(
        "--policy",
        help=r"IAM to ask: authzen:URL or python:module:function (replaces \[policy]).",
    ),
]
NoHarnessOption = Annotated[
    bool,
    typer.Option("--no-harness", help=r"Only ask the IAM; skip the door tests in \[harness]."),
]
SnapshotOption = Annotated[
    str | None,
    typer.Option(
        "--save-snapshot",
        help="Also save the tool list of every source to this JSON file "
        "(read it back later with --tools-json).",
    ),
]

TracesOption = Annotated[
    list[str] | None,
    typer.Option(
        "--traces",
        help=r"Trace file or directory (repeatable; replaces \[observe] traces).",
    ),
]
TraceIdOption = Annotated[
    str | None, typer.Option("--trace", help="The trace id to show.", show_default=False)
]
CaseIdOption = Annotated[
    str | None,
    typer.Option("--case", help="The case to show, for example CASE-003.", show_default=False),
]


def _version_callback(value: bool) -> None:
    if value:
        # The version is the whole product of --version: a lost write is not success.
        raise typer.Exit(2 if _write_out(f"lockwalk {__version__}\n") else 0)


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Authorization test coverage for AI agent tools."""


@app.command()
def discover(
    config: ConfigOption = None,
    registry: RegistryOption = None,
    spec: SpecOption = None,
    mcp: McpOption = None,
    python: PythonOption = None,
    tools_json: ToolsJsonOption = None,
    save_snapshot: SnapshotOption = None,
) -> None:
    """List agents and tools from every source, draw the agent graph, and show spec gaps."""
    try:
        settings = _settings(config, registry, spec, mcp, python, tools_json, None)
        if settings.registry is None and not settings.sources:
            raise StructuralError(
                COMMAND_LINE,
                [
                    "no inventory source: give --registry, --mcp, --python, or --tools-json "
                    "(or set them in .lockwalk.toml)"
                ],
            )
        if save_snapshot is not None:
            _check_snapshot_path(save_snapshot)  # before discovery, so a typo fails fast
        registry_file = load_registry(settings.registry) if settings.registry else None
        spec_file = load_spec(settings.spec) if settings.spec else None
        inventory, graph = collect(settings, registry_file)
        found = _discover_findings(spec_file, inventory, registry_file, graph)
        # One list for both the listing and the exit code. The gate does not apply to
        # discover: only untrustworthy input fails it, and a rule ERROR is shown in its line.
        errors = (*inventory.errors, *graph.errors)
        lines = render_discover(
            inventory,
            found.spec_states,
            settings.notes,
            graph=graph_section(graph),
            reachability=found.reachability,
            rules=found.rules,
            errors=errors,
            warnings=(*inventory.warnings, *graph.warnings, *found.warnings),
        )
        refused = False
        if save_snapshot is not None:
            # Written before anything is shown, so a failed write is the only output.
            shown, refused = _save_snapshot(inventory, save_snapshot)
            lines += ["", *shown]
        lost = _emit(lines)
        # With a snapshot file, that file is the product that outlives the listing, as the
        # report is for coverage. Without one, the listing is the only output.
        lost_all = lost and save_snapshot is None
        code = 2 if errors or refused or lost_all else 0
    except StructuralError as exc:
        _emit(render_structural_error(exc))
        raise typer.Exit(2) from exc
    except Exception as exc:
        _crash(exc)
    raise typer.Exit(code)


class RunOutput(NamedTuple):
    report: CoverageReport
    notes: Sequence[str]
    evidence: Evidence | None = None  # only lockwalk test writes evidence.jsonl


@app.command()
def coverage(
    config: ConfigOption = None,
    registry: RegistryOption = None,
    spec: SpecOption = None,
    mcp: McpOption = None,
    python: PythonOption = None,
    tools_json: ToolsJsonOption = None,
    output_dir: OutputDirOption = None,
    waivers: WaiversOption = None,
    summary: SummaryOption = False,
) -> None:
    """Check spec coverage without running any tool (static mode) and apply the CI gate."""

    def run(settings: RunSettings) -> RunOutput:
        registry_file, spec_file = require_registry_and_spec(settings, "coverage")
        waivers_file = load_waivers_for(settings)
        inventory, graph = collect(settings, registry_file)
        # One graph object for both: the plan must know the discovered agents and roles.
        plan = plan_cases(spec_file, inventory, graph)
        report = analyze(inventory, spec_file, plan, settings.gate, graph)
        return RunOutput(finish(report, waivers_file), settings.notes)

    _run_and_report(
        lambda: _settings(
            config, registry, spec, mcp, python, tools_json, output_dir, waivers=waivers
        ),
        run,
        config,
        output_dir,
        summary=summary,
    )


@app.command("test")
def policy_test(
    config: ConfigOption = None,
    registry: RegistryOption = None,
    spec: SpecOption = None,
    fixtures: FixturesOption = None,
    policy: PolicyOption = None,
    mcp: McpOption = None,
    python: PythonOption = None,
    tools_json: ToolsJsonOption = None,
    output_dir: OutputDirOption = None,
    no_harness: NoHarnessOption = False,
    waivers: WaiversOption = None,
    summary: SummaryOption = False,
) -> None:
    """Ask your IAM about every case and escalation route, and apply the CI gate."""

    def run(settings: RunSettings) -> RunOutput:
        done = run_policy_test(settings)
        return RunOutput(done.report, done.notes, done.evidence)

    _run_and_report(
        lambda: _settings(
            config,
            registry,
            spec,
            mcp,
            python,
            tools_json,
            output_dir,
            fixtures=fixtures,
            waivers=waivers,
            policy=policy,
            no_harness=no_harness,
        ),
        run,
        config,
        output_dir,
        summary=summary,
    )


@app.command()
def observe(
    config: ConfigOption = None,
    registry: RegistryOption = None,
    spec: SpecOption = None,
    mcp: McpOption = None,
    python: PythonOption = None,
    tools_json: ToolsJsonOption = None,
    output_dir: ObserveOutputDirOption = None,
    traces: TracesOption = None,
    waivers: WaiversOption = None,
    summary: SummaryOption = False,
) -> None:
    """Read real-environment traces and check routes, identities, guards and untested paths."""

    def execute(settings: RunSettings) -> int:
        done = run_observe(settings)
        path = write_observe(
            done.report, settings.output_dir, generated_at=datetime.now(UTC), version=__version__
        )
        _emit(
            [
                *render_observe(done.report, done.notes, summary=summary),
                "",
                to_ascii(f"Report written to {path}"),
            ]
        )
        return done.report.exit_code

    _guarded_run(
        lambda: _settings(
            config,
            registry,
            spec,
            mcp,
            python,
            tools_json,
            output_dir,
            traces=traces,
            waivers=waivers,
        ),
        execute,
        config,
        output_dir,
        files=(OBSERVE_FILE_NAME,),
    )


class DiffFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"


HeadReportOption = Annotated[
    Path, typer.Option("--head", help="The report to check, for example the pull request's.")
]
BaseReportOption = Annotated[
    Path | None,
    typer.Option(
        "--base",
        help="The report to compare with, for example the target branch's. "
        "Leave it out when there is none yet.",
    ),
]
DiffFormatOption = Annotated[DiffFormat, typer.Option("--format", help="text, json or markdown.")]


@app.command("diff")
def diff_command(
    head: HeadReportOption,
    base: BaseReportOption = None,
    output_format: DiffFormatOption = DiffFormat.TEXT,
) -> None:
    """Compare two coverage.json reports and show what changed (exit 2 if one cannot be read)."""
    try:
        head_report = load_report(head)
        base_report = load_report(base) if base is not None else None
    except ReportFileError as exc:
        _emit([to_ascii(f"Error: {exc}"), "", "Result: ERROR (exit 2)"])
        raise typer.Exit(2) from None
    except Exception as exc:
        _crash(exc)
    # Build the whole output first, so a crash while rendering is exit 2 and redacted.
    text: str | None = None
    markdown: bytes | None = None
    lines: list[str] = []
    try:
        result = diff_reports(head_report, base_report)
        if output_format is DiffFormat.JSON:
            text = diff_to_json(result, generated_at=datetime.now(UTC), version=__version__)
        elif output_format is DiffFormat.MARKDOWN:
            markdown = render_diff_markdown(result).encode("utf-8")
        else:
            lines = render_diff_text(result)
    except Exception as exc:
        _crash(exc)
    # The diff writes no file: its stdout is the only output, so a lost write is exit 2.
    if text is not None:
        lost = _write_out(text)
    elif markdown is not None:
        lost = _write_out(markdown)
    else:
        lost = _emit(lines)
    raise typer.Exit(2 if lost else 0)


TRACE_ONLY_OPTIONS = ("traces", "registry", "spec", "mcp", "python", "tools_json")


@app.command("inspect")
def inspect_command(
    case: CaseIdOption = None,
    trace: TraceIdOption = None,
    config: ConfigOption = None,
    output_dir: OutputDirOption = None,
    registry: RegistryOption = None,
    spec: SpecOption = None,
    mcp: McpOption = None,
    python: PythonOption = None,
    tools_json: ToolsJsonOption = None,
    traces: TracesOption = None,
) -> None:
    """Show what lockwalk recorded about one case (--case), or how one trace was read (--trace)."""
    if (case is None) == (trace is None):
        _inspect_usage_error("inspect needs exactly one of --case <case id> and --trace <trace id>")
    given = {
        "traces": traces,
        "registry": registry,
        "spec": spec,
        "mcp": mcp,
        "python": python,
        "tools_json": tools_json,
    }
    extra = [name.replace("_", "-") for name in TRACE_ONLY_OPTIONS if given[name]]
    if case is not None and extra:
        _inspect_usage_error(
            f"--case does not take --{', --'.join(extra)}; those options are for --trace"
        )
    try:
        if trace is not None:
            settings = _settings(
                config, registry, spec, mcp, python, tools_json, output_dir, traces=traces
            )
            lines = inspect_trace(settings, trace)
        elif case is not None:
            lines = _inspect_case_lines(config, output_dir, case)
        else:  # unreachable: exactly one of the two is set
            lines = []
    except InspectError as exc:
        _emit([to_ascii(f"Error: {exc}"), "", "Result: ERROR (exit 2)"])
        raise typer.Exit(2) from None
    except StructuralError as exc:
        _emit(render_structural_error(exc))
        raise typer.Exit(2) from exc
    except Exception as exc:
        _crash(exc)
    # inspect writes no file: what it shows is all it produces, so a lost write is exit 2.
    raise typer.Exit(2 if _emit(lines) else 0)


def _inspect_usage_error(message: str) -> NoReturn:
    _emit([f"Error: {message}", "", "Result: ERROR (exit 2)"])
    raise typer.Exit(2)


def _inspect_case_lines(config: Path | None, output_dir: str | None, case: str) -> list[str]:
    directory = fallback_output_dir(cwd=Path.cwd(), config_path=config, output_dir=output_dir)
    return inspect_case(directory, case)


def _guarded_run(
    resolve: Callable[[], RunSettings],
    execute: Callable[[RunSettings], int],
    config: Path | None,
    output_dir: str | None,
    *,
    files: tuple[str, ...],
) -> NoReturn:
    """What every report command shares: settings, stale files removed, the run, exit 2 on error.

    `execute` runs and shows the report, and returns the exit code. A structural error is
    shown as exit 2, anything else as a crash (exit 2). When the settings could not even be
    resolved, the files at the best-known location are removed too, so a failed run never
    leaves a stale report.
    """
    settings: RunSettings | None = None
    try:
        settings = resolve()
        # Remove the previous report first, so a failed run never leaves a stale one behind.
        _remove_files(settings.output_dir, files)
        code = execute(settings)
    except StructuralError as exc:
        if settings is None:
            _drop_fallback_report(config, output_dir, files)
        _emit(render_structural_error(exc))
        raise typer.Exit(2) from exc
    except Exception as exc:
        if settings is None:
            _drop_fallback_report(config, output_dir, files)
        _crash(exc)
    raise typer.Exit(code)


def _remove_files(directory: Path, files: tuple[str, ...]) -> None:
    for name in files:
        (directory / name).unlink(missing_ok=True)


def _run_and_report(
    resolve: Callable[[], RunSettings],
    run: Callable[[RunSettings], RunOutput],
    config: Path | None,
    output_dir: str | None,
    *,
    summary: bool = False,
) -> NoReturn:
    """What `coverage` and `test` share: the guarded run, then the report and its evidence."""

    def execute(settings: RunSettings) -> int:
        output = run(settings)
        report, notes = output.report, output.notes
        if output.evidence is not None:
            try:
                write_evidence(output.evidence, settings.output_dir)
            except OSError as exc:
                # The report still matters more than the timeline: write it without refs.
                report = without_evidence(
                    report,
                    f"the evidence file could not be written ({type(exc).__name__}); "
                    "lockwalk inspect has no timeline for this run",
                )
        path = write_report(
            report, settings.output_dir, generated_at=datetime.now(UTC), version=__version__
        )
        _emit(
            [
                *render_coverage(report, notes, summary=summary),
                "",
                to_ascii(f"Report written to {path}"),
            ]
        )
        return report.exit_code

    _guarded_run(resolve, execute, config, output_dir, files=(REPORT_FILE_NAME, EVIDENCE_FILE_NAME))


def _drop_fallback_report(
    config: Path | None, output_dir: str | None, files: tuple[str, ...]
) -> None:
    """Remove the report files at the best-known location when the settings could not be resolved.

    See settings.fallback_output_dir for how the location is chosen. This runs while
    another error is being reported, so failing to find or delete a file must not
    hide that error.
    """
    with contextlib.suppress(Exception):
        directory = fallback_output_dir(cwd=Path.cwd(), config_path=config, output_dir=output_dir)
        _remove_files(directory, files)


class DiscoverFindings(NamedTuple):
    """What discover shows beyond the inventory and the graph itself."""

    spec_states: dict[str, SpecState] | None  # None without a spec
    rules: tuple[RuleRow, ...]
    reachability: tuple[ReachRow, ...] | None  # None without registry roles
    # Roles no entry agent lists, tools no agent is known to use, then identity warnings.
    warnings: tuple[str, ...]


def _discover_findings(
    spec_file: SpecFile | None,
    inventory: Inventory,
    registry_file: Registry | None,
    graph: AgentGraph,
) -> DiscoverFindings:
    """Spec states, rule results, role x tool rows, and graph warnings, as coverage has them.

    The plan, the rules, and the rows all use this one graph, with the same functions that
    analyze calls, so rule results and covered_by are the same in both commands. Without a
    spec, there are no spec states or rules, and nothing is covered. The warnings that only
    the gate gives (path warnings and uncovered role x tool pairs) are left to coverage.
    """
    plan: tuple[PlannedCase, ...] = ()
    rules: tuple[RuleRow, ...] = ()
    states: dict[str, SpecState] | None = None
    if spec_file is not None:
        plan = plan_cases(spec_file, inventory, graph)
        rules = evaluate_rules(graph, spec_file.never_reaches, inventory)
        if registry_file is None:
            # Without a registry, agents cannot be validated: any case naming the tool
            # counts. (Without a registry there are no roles, so no rows either.)
            states = {name: SpecState.YES for name in spec_file.tool_names()}
        else:
            states = tool_spec_states(plan)
    rows = role_reachability(graph, inventory, plan, rules)
    index = index_graph(graph)
    has_rules = spec_file is not None and bool(spec_file.never_reaches)
    return DiscoverFindings(
        spec_states=states,
        rules=rules,
        reachability=rows,
        warnings=(
            *startless_warnings(graph, index=index),
            *holderless_warnings(graph, inventory, has_rules=has_rules, index=index),
            *identity_summaries(graph, rows or (), index=index),
        ),
    )


def _check_snapshot_path(value: str) -> None:
    """Reject a --save-snapshot value that can never be written, before discovery runs."""
    if not value.strip():
        raise StructuralError(COMMAND_LINE, ["--save-snapshot: the file name must not be empty"])
    if (Path.cwd() / value).is_dir():
        raise StructuralError(
            COMMAND_LINE, [f"--save-snapshot {value}: is a directory; give a file name"]
        )
    _check_not_foreign_file(value)


def _is_snapshot_file(path: Path) -> bool:
    """True only when the file is readable JSON holding the snapshot key.

    Anything else (unreadable, not JSON, another shape) counts as not a snapshot, so the
    caller errs toward leaving the file alone.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and SNAPSHOT_KEY in data


def _check_not_foreign_file(value: str) -> None:
    """Refuse a --save-snapshot path that holds a file that is not a lockwalk snapshot.

    Writing there would destroy it, for example a spec or registry named by mistake.
    """
    path = Path.cwd() / value
    if path.exists() and not _is_snapshot_file(path):
        raise StructuralError(
            COMMAND_LINE,
            [
                f"--save-snapshot {value}: the file exists and is not a lockwalk snapshot; "
                "it is left untouched. Give another file name, or remove it first"
            ],
        )


def _save_snapshot(inventory: Inventory, value: str) -> tuple[list[str], bool]:
    """Write the snapshot; return the lines to show (already escaped) and whether it was
    refused.

    A failed write is a command-line error (exit 2) that names the file, not a crash. A
    snapshot is refused (not written, exit 2) when some source failed: leaving it out could
    make a replay pass where this run did not. Then an older file at that path is removed,
    as coverage removes its old report, so it is never taken for this run's snapshot. A
    file that is not a lockwalk snapshot is never removed or overwritten: it is an error.
    """
    path = Path.cwd() / value
    _check_not_foreign_file(value)  # again: discovery may have taken a while
    try:
        notes = write_snapshot(inventory, path, captured_at=datetime.now(UTC))
    except SnapshotRefused as exc:
        shown = [f"Snapshot not written to {path}: {exc}"]
        if path.exists():
            try:
                path.unlink()
            except OSError as error:
                shown.append(
                    f"Note: the older file at {path} could not be removed "
                    f"({error.strerror or error}); it is not this run's snapshot"
                )
            else:
                shown.append(f"Note: removed the older file at {path}")
        return [to_ascii(line) for line in shown], True
    except OSError as exc:
        raise StructuralError(
            COMMAND_LINE,
            [f"--save-snapshot {value}: cannot write the file: {exc.strerror or exc}"],
        ) from exc
    shown = [f"Snapshot written to {path}", *(f"Note: {note}" for note in notes)]
    return [to_ascii(line) for line in shown], False


def _crash(exc: Exception) -> NoReturn:
    """Report an unexpected error as exit 2 so CI can tell it from a gate failure (exit 1).

    The message can quote user data, so it goes through describe_error: URLs lose their
    credentials, query, and fragment, as in every other error lockwalk shows. The
    traceback on stderr, which repeats the message, gets the same redaction.
    """
    _emit([to_ascii(f"Error: {describe_error(exc)}"), "", "Result: ERROR (exit 2)"])
    for line in traceback.format_exc().splitlines():
        _stderr_line(redact_urls(line))
    raise typer.Exit(2) from exc


def _settings(
    config: Path | None,
    registry: str | None,
    spec: str | None,
    mcp: list[str] | None,
    python: list[str] | None,
    tools_json: list[str] | None,
    output_dir: str | None,
    *,
    fixtures: str | None = None,
    waivers: str | None = None,
    policy: str | None = None,
    no_harness: bool = False,
    traces: list[str] | None = None,
) -> RunSettings:
    return resolve_settings(
        cwd=Path.cwd(),
        config_path=config,
        registry=registry,
        spec=spec,
        mcp=mcp or (),
        python=python or (),
        tools_json=tools_json or (),
        output_dir=output_dir,
        fixtures=fixtures,
        waivers=waivers,
        policy=policy,
        no_harness=no_harness,
        traces=traces or (),
    )


def _emit(lines: Sequence[str]) -> bool:
    """Show lines on stdout. Return True when they were lost for a reason other than a closed pipe.

    A stdout that cannot take the lines never makes a traceback, a click exit 1, or the
    interpreter's exit 120. What the exit code then says is up to the caller, by one rule:
    a command that wrote a report or snapshot file (coverage, test, observe, discover
    --save-snapshot) ignores the return value and keeps its gate code, because the result
    is on disk. A command whose stdout is its only output (diff, inspect, discover without
    a snapshot) exits 2 when this returns True, so a full disk never reads as success. A
    closed pipe (`lockwalk diff | head`) is the reader's choice and returns False.

    Only OSError is treated this way; a bug in rendering is not about stdout and still
    surfaces as a crash.
    """
    # Created per call so it writes to whatever sys.stdout is now (CliRunner swaps it).
    console = _StdoutConsole(highlight=False, soft_wrap=True, emoji=False)
    try:
        for line in lines:
            style = None
            if line.startswith(("Gate: FAIL", "Result: ERROR")):
                style = "bold red"
            elif line.startswith(("Gate: PASS", "Result: OK")):
                style = "bold green"
            console.print(line, markup=False, style=style)
        sys.stdout.flush()
    except OSError as exc:
        return _abandon(sys.stdout, "stdout", exc)
    return False


class _StdoutConsole(Console):
    def on_broken_pipe(self) -> None:
        # Rich's default exits the process with status 1 here, which would report findings
        # for a run whose gate may have passed. Re-raise so _emit decides instead.
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")


_QUIET_ERRNOS = (errno.EPIPE, errno.EINVAL)  # a reader that went away; EINVAL is Windows' form


def _abandon(stream: TextIO, name: str, exc: OSError) -> bool:
    """Point a failed stream at the null device; return True unless the reader just went away.

    Text still buffered in the stream would otherwise fail again when Python flushes it at
    exit, and that turns the exit code into 120. Every later write goes to the void. This
    is done for stderr as well as stdout: a crash must stay exit 2 when stderr is closed.
    A note goes to stderr for a failure that is not a closed pipe (unless it is stderr).
    """
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, stream.fileno())
        finally:
            os.close(null)
    except Exception:  # no real descriptor behind the stream (or it is already gone)
        with contextlib.suppress(Exception):
            replacement = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115
            if name == "stdout":
                sys.stdout = replacement
            else:
                sys.stderr = replacement
    lost = not isinstance(exc, BrokenPipeError) and exc.errno not in _QUIET_ERRNOS
    if lost and name == "stdout":
        _stderr_line(f"lockwalk: could not write to stdout ({type(exc).__name__}); output dropped")
    return lost


def _stderr_line(text: str) -> None:
    """Write one line to stderr; a stderr that is gone too is not worth failing over."""
    try:
        sys.stderr.write(to_ascii(text) + "\n")
        sys.stderr.flush()
    except OSError as exc:
        _abandon(sys.stderr, "stderr", exc)


def _write_out(text: str | bytes) -> bool:
    """Write raw output (diff --format json or markdown) to stdout; True when it was lost.

    Protected like _emit, and the return value means the same.
    """
    try:
        if isinstance(text, bytes):
            sys.stdout.buffer.write(text)
        else:
            sys.stdout.write(text)
        sys.stdout.flush()
    except OSError as exc:
        return _abandon(sys.stdout, "stdout", exc)
    return False


def main() -> None:
    """Console-script entry point."""
    # Never crash on characters the console encoding (for example cp950) cannot show.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(errors="replace")
    app()
