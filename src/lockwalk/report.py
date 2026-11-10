"""Write coverage.json and render the terminal output.

All rendered lines are plain ASCII, so output never fails on legacy consoles (for example
cp950 on Traditional Chinese Windows) or when it is redirected to a file in CI.
"""

import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from lockwalk.errors import StructuralError
from lockwalk.graph.analysis import name_list
from lockwalk.jsonvalues import DuplicateKeyError, reject_duplicate_keys
from lockwalk.masking import describe_validation_error
from lockwalk.models import (
    MAX_QUERY_DEPTH,
    OBSERVE_ONLY_NOTE,
    TEST_ONLY_NOTE,
    CaseStatus,
    CoverageReport,
    DoorResult,
    DoorStatus,
    Drift,
    EdgeKind,
    EscalationResult,
    GateViolation,
    GraphEdge,
    GraphNode,
    GraphSection,
    IdentityCheckRow,
    IdentityResult,
    Inventory,
    Provenance,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    WaiverRow,
)
from lockwalk.output_files import utc_timestamp, write_text_atomic

REPORT_SCHEMA_VERSION = "5"
REPORT_FILE_NAME = "coverage.json"
MAX_REPORT_BYTES = 256 * 1024 * 1024
_HEADER_KEYS = ("schema_version", "lockwalk_version", "generated_at")
RULE = "-" * 40
LABEL_WIDTH = 36
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def to_ascii(text: str) -> str:
    """Escape non-ASCII and ASCII control characters.

    Non-ASCII characters become backslash-u escapes (for example the character U+522A becomes
    \\u522a). Control characters (including tab, CR, LF and ESC) become \\xNN escapes,
    so each rendered line stays exactly one line and text from untrusted sources (for example
    an MCP server) cannot steer the terminal.
    """
    escaped = text.encode("ascii", "backslashreplace").decode("ascii")
    return _CONTROL.sub(lambda match: f"\\x{ord(match.group()):02x}", escaped)


def report_to_dict(
    report: CoverageReport, *, generated_at: datetime, version: str
) -> dict[str, Any]:
    """Return the coverage.json document. generated_at must be timezone-aware."""
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "lockwalk_version": version,
        "generated_at": utc_timestamp(generated_at, name="generated_at"),
        **report.model_dump(mode="json"),
    }


def write_report(
    report: CoverageReport, output_dir: Path, *, generated_at: datetime, version: str
) -> Path:
    """Write <output_dir>/coverage.json (UTF-8, replaced on every run) and return its path."""
    path = output_dir / REPORT_FILE_NAME
    document = report_to_dict(report, generated_at=generated_at, version=version)
    text = json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    write_text_atomic(path, text, prefix=".coverage-")
    return path


class ReportFileError(Exception):
    """coverage.json is missing or cannot be trusted. The message never quotes the file."""


def read_report(path: Path, *, hint: str = "run lockwalk test") -> CoverageReport:
    """Read a coverage.json that write_report of this lockwalk version wrote."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise ReportFileError(f"{path} does not exist; {hint} first") from None
    except OSError as exc:
        raise ReportFileError(f"{path} cannot be read ({type(exc).__name__})") from None
    if size > MAX_REPORT_BYTES:
        raise ReportFileError(f"{path} is larger than {MAX_REPORT_BYTES >> 20} MiB")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except DuplicateKeyError:
        raise ReportFileError(f"{path} repeats a JSON key") from None
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        raise ReportFileError(f"{path} is not valid JSON") from None
    if not isinstance(document, dict):
        raise ReportFileError(f"{path} is not a lockwalk report")
    if document.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ReportFileError(
            f"{path} was written by another lockwalk version (schema_version is not "
            f"{REPORT_SCHEMA_VERSION}); {hint} again"
        )
    body = {key: value for key, value in document.items() if key not in _HEADER_KEYS}
    try:
        return CoverageReport.model_validate(body)
    except ValidationError as exc:
        raise ReportFileError(
            f"{path} is not a valid report: {describe_validation_error(exc)}"
        ) from None


def render_coverage(
    report: CoverageReport, notes: Sequence[str] = (), *, summary: bool = False
) -> list[str]:
    """Render the coverage summary shown by `lockwalk coverage`.

    summary=True renders the short form instead: counts, then what needs action.
    """
    if summary:
        return _render_summary(report)
    metrics = report.metrics
    section = report.inventory
    sources = ", ".join(
        s.source
        if s.ok
        else f"{s.source} (unavailable, optional)"
        if s.unavailable
        else f"{s.source} (FAILED)"
        for s in section.sources
    )
    test_mode = report.mode == "test"
    if test_mode:
        executed = f"{metrics.executed_cases}/{metrics.specified_cases}"
        mode_line = f"Mode: test (asked the IAM through {report.policy_adapter or 'unknown'})"
    else:
        executed = (
            f"{metrics.executed_cases}/{metrics.specified_cases} (not run)"
            if metrics.specified_cases
            else "N/A (no specified scenarios)"
        )
        mode_line = "Mode: static (no tests executed)"
    lines = [
        f"lockwalk {'test' if test_mode else 'coverage'} - {report.scenario_suite}",
        mode_line,
        f"Inventory sources: {sources or '(none)'}",
        *(f"Note: {note}" for note in notes),
        RULE,
        _row("Registered tools", metrics.registered_tools),
        _row("Specified scenarios", metrics.specified_cases),
        _row("Executed scenarios", executed),
    ]
    by_status = metrics.cases_by_status
    if test_mode:
        lines += [
            _row("Passed", by_status.get(CaseStatus.PASS.value, 0)),
            _row("Failed (policy)", by_status.get(CaseStatus.FAIL_POLICY.value, 0)),
            _row("Inconclusive", by_status.get(CaseStatus.INCONCLUSIVE.value, 0)),
        ]
        failed_execution = by_status.get(CaseStatus.FAIL_EXECUTION.value, 0)
        if failed_execution:
            lines.append(_row("Failed (execution)", failed_execution))
    if not test_mode or by_status.get(CaseStatus.UNTESTED.value, 0):
        lines.append(_row("Untested", by_status[CaseStatus.UNTESTED.value]))
    case_errors = by_status[CaseStatus.ERROR.value]
    if case_errors:
        lines.append(_row("Case errors", case_errors))
    rows = {row.id: row for row in section.tools}
    unspecified = report.registered_tools_without_spec
    lines.append(
        _row(
            "Tools without spec",
            len(unspecified),
            "; ".join(
                f"{tool}, risk={rows[tool].risk}, source={', '.join(rows[tool].sources)}"
                for tool in unspecified
            ),
        )
    )
    no_deny = report.high_risk_tools_without_deny_case
    lines.append(_row("High-risk tools without deny case", len(no_deny), ", ".join(no_deny)))
    if section.drift is not None:
        failed = [s.source for s in section.sources if not s.ok]
        lines.append(_row("Inventory drift", _drift_text(section.drift, failed)))
    risks = {row.id: row.risk for row in section.tools}
    lines += _graph_blocks(
        render_graph(report.agent_graph, risks),
        render_reachability(report.reachability),
        render_rules(report.rules),
        render_graph_notes(report.agent_graph),
    )
    if test_mode:
        lines += _case_block(report)
        lines += _escalation_block(report)
        lines += _identity_block(report)
        lines += _control_block(report)
        lines += _door_control_block(report)
    lines += _list_section("Errors", report.errors)
    # Warnings that are a waiver note shown under "Waivers needing attention" are not repeated.
    shown = _attention_notes(report)
    lines += _list_section("Warnings", [w for w in report.warnings if w not in shown])
    lines.append("")
    lines += _verdict(report)
    return [to_ascii(line) for line in lines]


def render_discover(
    inventory: Inventory,
    spec_states: Mapping[str, str] | None,
    notes: Sequence[str] = (),
    *,
    graph: GraphSection | None = None,
    reachability: Sequence[ReachRow] | None = None,
    rules: Sequence[RuleRow] = (),
    errors: Sequence[str] | None = None,
    warnings: Sequence[str] | None = None,
) -> list[str]:
    """Render the listing shown by `lockwalk discover`.

    errors and warnings are the lines to list; None lists the inventory's own. The result
    line is ERROR exactly when errors is not empty, so a caller that adds errors (for
    example the agent graph's) should pass the same list it takes its exit code from.
    A rule that is ERROR shows only in its own rule line.
    """
    sources = ", ".join(
        s.source.label
        if s.ok
        else f"{s.source.label} (unavailable, optional)"
        if s.unavailable
        else f"{s.source.label} (FAILED)"
        for s in inventory.sources
    )
    lines = [
        "lockwalk discover",
        f"Inventory sources: {sources or '(none)'}",
        *(f"Note: {note}" for note in notes),
        RULE,
        f"Agents ({len(inventory.agents)}): {', '.join(inventory.agents) or '(none declared)'}",
        f"Tools ({len(inventory.tools)}):",
    ]
    tool_ids = {tool.id: to_ascii(tool.id) for tool in inventory.tools}
    width = max((len(text) for text in tool_ids.values()), default=0)
    for tool in inventory.tools:
        parts = [
            f"  {tool_ids[tool.id]:<{width}}",
            f"risk={tool.risk}",
            f"sources={', '.join(tool.sources)}",
        ]
        if spec_states is not None:
            parts.append(f"spec={spec_states.get(tool.id, 'NO')}")
        if tool.hints:
            parts.append(
                "hints="
                + ",".join(f"{key}={str(value).lower()}" for key, value in tool.hints.items())
            )
        lines.append("  ".join(parts))
    if inventory.drift is not None:
        failed = [s.source.label for s in inventory.sources if not s.ok]
        lines.append(f"Inventory drift: {_drift_text(inventory.drift, failed)}")
    risks = {tool.id: tool.risk for tool in inventory.tools}
    lines += _graph_blocks(
        render_graph(graph, risks) if graph is not None else [],
        render_reachability(reachability),
        render_rules(rules),
        render_graph_notes(graph) if graph is not None else [],
    )
    if errors is None:
        errors = inventory.errors
    lines += _list_section("Errors", errors)
    lines += _list_section("Warnings", inventory.warnings if warnings is None else warnings)
    lines.append("")
    lines.append("Result: ERROR (exit 2)" if errors else "Result: OK (exit 0)")
    return [to_ascii(line) for line in lines]


def render_structural_error(error: StructuralError) -> list[str]:
    """Render a configuration error that stopped the run."""
    lines = [
        f"Configuration error in {error.source}:",
        *(f"  - {problem}" for problem in error.problems),
        "",
        "Result: ERROR (exit 2)",
    ]
    return [to_ascii(line) for line in lines]


def _graph_blocks(*blocks: Sequence[str]) -> list[str]:
    """Return a blank line plus the non-empty blocks, or nothing if all are empty."""
    shown = [block for block in blocks if block]
    if not shown:
        return []
    lines = [""]
    for block in shown:
        lines += block
    return lines


def format_witness(witness: Sequence[GraphEdge]) -> str:
    """Format a call path as: first -[kind, provenance]-> next -[...]-> last."""
    if not witness:
        return ""
    parts = [witness[0].from_id]
    parts += [f"-[{e.kind.value}, {e.provenance.value}]-> {e.to_id}" for e in witness]
    return " ".join(parts)


def _node_tags(node: GraphNode | None) -> str:
    """Tags shown after an agent id: delegation mode and opacity."""
    if node is None:
        return ""
    text = ""
    if node.delegation_mode is not None:
        text += f"  [delegation_mode={node.delegation_mode}]"
    if node.opaque:
        text += "  (opaque)"
    return text


def _arrow(edge: GraphEdge) -> str:
    return f"-[{edge.kind.value}, {edge.provenance.value}]-> {edge.to_id}"


def _children(edges: Sequence[GraphEdge]) -> list[GraphEdge]:
    """Order the edges of one agent: agent edges first, then tool edges."""
    agent_edges = sorted(
        (e for e in edges if e.kind != EdgeKind.USES_TOOL),
        key=lambda e: (e.to_id, e.kind, e.provenance),
    )
    tool_edges = sorted(
        (e for e in edges if e.kind == EdgeKind.USES_TOOL), key=lambda e: (e.to_id, e.provenance)
    )
    return agent_edges + tool_edges


def render_graph(section: GraphSection, risks: Mapping[str, Risk]) -> list[str]:
    """Draw one ASCII tree per entry agent. Lines are not yet escaped."""
    if not section.nodes:
        return []
    if not section.entry_agents:
        return ["Agent graph: (no entry agents)"]
    nodes = {node.id: node for node in section.nodes}
    outgoing: dict[str, list[GraphEdge]] = {}
    for edge in section.edges:
        outgoing.setdefault(edge.from_id, []).append(edge)
    if section.entry_inferred:
        count = len(section.entry_agents)
        lines = [f"Agent graph (no entry agent marked; treating all {count} agents as entries):"]
    else:
        lines = [f"Agent graph (entry agents: {', '.join(section.entry_agents)}):"]
    expanded: set[str] = set()
    for entry in section.entry_agents:
        text = f"  {entry}" + _node_tags(nodes.get(entry))
        if entry in expanded:
            lines.append(text + "  (see above)")
            continue
        lines.append(text)
        expanded.add(entry)
        on_path = {entry}
        stack = [(entry, iter(_children(outgoing.get(entry, []))))]
        while stack:
            agent_id, children = stack[-1]
            edge = next(children, None)
            if edge is None:
                stack.pop()
                on_path.discard(agent_id)
                continue
            indent = " " * (2 + 2 * len(stack))
            if edge.kind == EdgeKind.USES_TOOL:
                risk = risks.get(edge.to_id, Risk.UNKNOWN)
                lines.append(f"{indent}{_arrow(edge)}  (risk={risk})")
                continue
            text = f"{indent}{_arrow(edge)}" + _node_tags(nodes.get(edge.to_id))
            if edge.to_id in on_path:
                lines.append(text + "  (cycle)")
            elif edge.to_id in expanded:
                lines.append(text + "  (see above)")
            else:
                lines.append(text)
                expanded.add(edge.to_id)
                on_path.add(edge.to_id)
                stack.append((edge.to_id, iter(_children(outgoing.get(edge.to_id, [])))))
    return lines


def render_reachability(rows: Sequence[ReachRow] | None) -> list[str]:
    """Render the role x tool table.

    Cells are escaped to measure widths; the caller still escapes each line.
    """
    if rows is None:
        return []
    if not rows:
        return ["Role reachability: (no role reaches any tool)"]
    lines = ["Role reachability:"]
    cells = [
        (
            [
                to_ascii(row.role),
                to_ascii(row.tool),
                to_ascii(str(row.risk)),
                "REACHABLE",
                to_ascii(f"delegation_mode={row.delegation_mode or 'unknown'}"),
            ],
            "covered_by=" + (", ".join(row.covered_by) or "NONE") + _marker(row),
        )
        for row in rows
        if row.status == ReachStatus.REACHABLE
    ]
    widths = [max(len(values[i]) for values, _ in cells) for i in range(5)] if cells else []
    for values, covered in cells:
        padded = [f"{value:<{width}}" for value, width in zip(values, widths, strict=True)]
        lines.append("  " + "  ".join(padded) + "  " + covered)
    inconclusive: dict[str, list[ReachRow]] = {}
    for row in rows:
        if row.status == ReachStatus.INCONCLUSIVE:
            inconclusive.setdefault(row.role, []).append(row)
    for role, group in inconclusive.items():
        opaque = sorted({name for row in group for name in row.opaque_reached})
        lines.append(
            f"  {role}  ({len(group)} more tool(s))  "
            f"INCONCLUSIVE: route passes through opaque {', '.join(opaque)}"
        )
    return lines


def render_rules(rows: Sequence[RuleRow]) -> list[str]:
    """Render the never_reaches results. Lines are not yet escaped."""
    if not rows:
        return []
    lines = ["Never-reaches rules:"]
    for row in rows:
        start = f"role:{row.role}" if row.role is not None else f"agent:{row.agent}"
        target = f"tool:{row.tool}" if row.tool is not None else f"agent:{row.target_agent}"
        line = f"  {row.id}  {row.result.value:<12}  {start} -> {target}"
        if row.result == RuleResult.INCONCLUSIVE:
            if row.opaque_reached:
                line += f" (passes through opaque: {', '.join(row.opaque_reached)})"
            if row.problems:
                line += " - " + "; ".join(row.problems)
        elif row.result == RuleResult.ERROR:
            line += " - " + "; ".join(row.problems)
        lines.append(line + _marker(row))
        if row.result == RuleResult.FAIL:
            if row.role is not None:
                empty = "(the role can use this entry agent directly)"
            else:
                empty = "(no edges in the witness)"
            lines.append("    " + (format_witness(row.witness) or empty))
    return lines


def render_graph_notes(section: GraphSection) -> list[str]:
    """Render cycles, opaque and unreachable nodes, inferred edges, and graph drift.

    At most five unreachable agents are named; coverage.json lists them all. Not yet escaped.
    """
    lines = []
    if section.cycles:
        lines.append("  Cycles: " + "; ".join(" -> ".join(cycle) for cycle in section.cycles))
    if section.opaque:
        lines.append("  Opaque: " + ", ".join(section.opaque))
    if section.unreachable:
        lines.append("  Not reachable from entry agents: " + name_list(section.unreachable))
    inferred = sum(1 for e in section.edges if e.provenance == Provenance.INFERRED)
    if inferred:
        lines.append(f"  Inferred edges: {inferred}")
    drift = section.drift
    if drift is not None:
        parts = []
        if drift.discovered_only_agents:
            parts.append("discovered only: " + ", ".join(drift.discovered_only_agents))
        if drift.declared_only_agents:
            parts.append("declared only: " + ", ".join(drift.declared_only_agents))
        if drift.undeclared_edges:
            parts.append(
                "undeclared edges: "
                + ", ".join(f"{e.from_id} -> {e.to_id}" for e in drift.undeclared_edges)
            )
        if parts:
            lines.append("  Graph drift: " + "; ".join(parts))
    return ["Graph notes:", *lines] if lines else []


def _case_block(report: CoverageReport) -> list[str]:
    """The Cases: block of a test-mode report. Lines are not yet escaped."""
    if not report.cases:
        return []
    lines = ["", "Cases:"]
    for case in report.cases:
        verdict = case.decision.verdict.value if case.decision is not None else "-"
        lines.append(
            f"  {case.id}  {case.status.value:<14}  {' -> '.join((*case.path, case.tool))}"
            f"  (expect {case.expect}, IAM {verdict})" + _marker(case)
        )
        lines += [f"    {note}" for note in case.notes]
        if case.status == CaseStatus.ERROR:
            lines += [f"    {problem}" for problem in case.problems]
        if case.door is not None:
            lines += _door_lines(case.door)
    return lines


def _who(subject: Mapping[str, Any] | None) -> str:
    """Format a reduced subject as `type id`, with its act chain as `via type id` links."""
    parts: list[str] = []
    current: object = subject
    while isinstance(current, Mapping) and len(parts) <= MAX_QUERY_DEPTH:
        parts.append(f"{_cut(current.get('type'))} {_cut(current.get('id'))}")
        current = current.get("act")
    return " via ".join(parts)


def _cut(value: object, limit: int = 80) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _door_lines(door: DoorResult) -> list[str]:
    """The door part of one case. Lines are not yet escaped."""
    lines: list[str] = []
    if door.status == DoorStatus.NOT_TESTED:
        if door.notes:
            lines.append(f"    door: NOT_TESTED ({door.notes[0]})")
            lines += [f"      {note}" for note in door.notes[1:]]
        else:
            lines.append("    door: NOT_TESTED")
        return lines
    for run in door.runs:
        seen = ""
        with_subject = [c for c in run.door_calls if c.subject is not None]
        if with_subject:
            seen = f", door saw {_who(with_subject[0].subject)}"
            if len(with_subject) > 1:
                seen += f" (+{len(with_subject) - 1} more)"
        failed = next((c.error for c in run.door_calls if c.error is not None), None)
        if failed is not None:
            seen += f", door call failed: {failed}"
        raised = f" (raised {run.exception})" if run.exception else ""
        lines.append(
            f"    door ({run.mode}): {run.status.value}, "
            f"side effect ran {run.side_effect_calls} time(s){seen}{raised}"
        )
        # The notes of a run that is not OK are already printed once, with the mode, as the
        # case's own notes (analyzer._with_door), so they are not repeated here.
    lines += [f"    door: {note}" for note in door.notes]
    return lines


def _identity_block(report: CoverageReport) -> list[str]:
    """The Identity checks: block, only when there are identity rows."""
    if not report.identity_checks:
        return []
    order = (
        IdentityResult.MISMATCH,
        IdentityResult.OBSERVED,
        IdentityResult.NOT_RUN,
        IdentityResult.MATCH,
    )
    header, shown = _checks_header("Identity checks", report.identity_checks, order)
    lines = ["", header]
    for row in shown:
        lines += _identity_row_lines(row)
    return lines


def _checks_header(
    title: str, rows: Sequence[Any], order: Sequence[StrEnum]
) -> tuple[str, list[Any]]:
    """The count header of a check block, and the rows to list.

    Counts follow `order`; the last result in `order` is the good one and its rows are
    counted but not listed.
    """
    counts = [
        f"{n} {result.value}"
        for result in order
        if (n := sum(1 for row in rows if row.result == result))
    ]
    shown = [row for row in rows if row.result != order[-1]]
    return f"{title}: " + ", ".join(counts), shown


def _identity_row_lines(row: IdentityCheckRow) -> list[str]:
    lines = [
        f"  {row.result.value:<9} {row.case_id}: {' -> '.join((*row.path, row.tool))}"
        + _marker(row)
    ]
    for obs in row.observations:
        received = ", ".join(_who(o) for o in obs.observed[:3]) or "nothing"
        if len(obs.observed) > 3:
            received += f" (+{len(obs.observed) - 3} more)"
        lines.append(
            f"    {obs.mode}: expected {_who(obs.expected) or 'nothing declared'}, "
            f"the door received {received}"
        )
    lines += [f"    {note}" for note in row.notes]
    return lines


def _door_control_block(report: CoverageReport) -> list[str]:
    """The Door controls missing: block, only when a tool's side effect was never counted."""
    missing = [c for c in report.door_controls if not c.proven]
    if not missing:
        return []
    return [
        "",
        "Door controls missing:",
        *(f"  {c.tool}: its side effect was never counted" for c in missing),
    ]


def _escalation_block(report: CoverageReport) -> list[str]:
    """The Escalation checks: block, only when there are escalation rows."""
    if not report.escalations:
        return []
    order = (
        EscalationResult.ESCALATION,
        EscalationResult.INCONCLUSIVE,
        EscalationResult.UNCHECKED,
        EscalationResult.ERROR,
        EscalationResult.NONE,
    )
    header, shown = _checks_header("Escalation checks", report.escalations, order)
    lines = ["", header]
    for row in shown:
        prefix = f"{row.case_id}: " if row.case_id is not None else ""
        lines.append(
            f"  {row.result.value:<13} {prefix}{row.role} -> {row.tool} via {row.via} ({row.mode})"
            + _marker(row)
        )
        lines += [f"    {note}" for note in row.notes]
    return lines


def _control_block(report: CoverageReport) -> list[str]:
    """The Positive controls missing: block, only when some control got no allow."""
    missing = [c for c in report.controls if not c.allowed]
    if not missing:
        return []
    return [
        "",
        "Positive controls missing:",
        *(f"  {c.action} on {c.resource_type}" for c in missing),
    ]


def violation_line(v: GateViolation) -> str:
    if v.rule == "case":
        status = v.status.value if v.status is not None else "?"
        return f"  - case: {v.case_id} ({status})"
    if v.rule == "fail_on_identity_mismatch":
        return f"  - fail_on_identity_mismatch: {v.case_id}"
    if v.rule == "fail_on_inconclusive_case":
        return f"  - fail_on_inconclusive_case: {v.case_id}"
    if v.rule in ("fail_on_escalation", "fail_on_inconclusive_escalation"):
        case = f" ({v.case_id})" if v.case_id is not None else ""
        return f"  - {v.rule}: {v.role} -> {v.tool} via {v.via}{case}"
    if v.rule == "fail_on_unchecked_escalation":
        return f"  - {v.rule}: {v.role} -> {v.tool} via {v.via} (risk={v.risk})"
    if v.rule == "never_reaches" and v.result is not None:
        return f"  - never_reaches: {v.rule_id} ({v.result.value})"
    if v.rule == "fail_on_unspecified_role_risk":
        return f"  - fail_on_unspecified_role_risk: {v.role} -> {v.tool} (risk={v.risk})"
    return f"  - {v.rule}: {v.tool} (risk={v.risk})"


def _row(label: str, value: object, detail: str = "") -> str:
    line = f"{label + ':':<{LABEL_WIDTH}}{value}"
    return f"{line}   ({detail})" if detail else line


def _drift_text(drift: Drift, failed_sources: Sequence[str]) -> str:
    parts = []
    if drift.discovered_only:
        parts.append("discovered only: " + ", ".join(drift.discovered_only))
    if drift.registry_only:
        parts.append("registry only: " + ", ".join(drift.registry_only))
    text = "; ".join(parts) or "none"
    if not drift.complete:
        text += f" (incomplete: {', '.join(failed_sources)} failed)"
    return text


def _list_section(title: str, items: Sequence[str]) -> list[str]:
    if not items:
        return []
    return ["", f"{title}:", *(f"  - {item}" for item in items)]


def _verdict(report: CoverageReport) -> list[str]:
    """The closing verdict line. Labels (the summary uses the same ones):

    Gate: PASS (exit 0) / Gate: FAIL (exit 1) - the gate ran and gave a verdict.
    Result: ERROR (exit 2) - no trustworthy verdict; discover ends with Result: OK (exit 0)
    because it has no gate. A CI step can grep "Result: ERROR" in either output mode.
    """
    violations = [violation_line(v) for v in report.gate.violations]
    if report.exit_code == 2:
        lines = ["Result: ERROR (exit 2) - the report is incomplete; fix the errors above"]
        if violations:
            lines += ["Gate violations:", *violations]
    elif report.exit_code == 1:
        lines = ["Gate: FAIL (exit 1)", *violations]
    else:
        lines = ["Gate: PASS (exit 0)"]
    if report.gate.waived:
        lines += ["Waived:", *_waived_lines(report)]
    attention = _attention_lines(report)
    if attention:
        lines += ["Waivers needing attention:", *(f"  {line}" for line in attention)]
    lines.extend(_quiet_lines(report))
    return lines


def waived_suffix(waiver_id: str | None) -> str:
    """The ` [waived: ID]` suffix of a report row that a waiver covers, or nothing."""
    return f" [waived: {waiver_id}]" if waiver_id else ""


def _marker(row: object) -> str:
    return waived_suffix(getattr(row, "waived_by", None))


def waived_block_lines(
    waivers: Sequence[WaiverRow], waived: Sequence[Any], describe: Callable[[Any], str]
) -> list[str]:
    """One `  - violation (ID, owner O, until D)` line per waived violation.

    waived holds items with `.violation` and `.waiver_id`; describe renders a violation.
    Shared by the coverage, test and observe reports.
    """
    rows = {w.id: w for w in waivers}
    lines = []
    for item in waived:
        row = rows.get(item.waiver_id)
        detail = (
            f"{item.waiver_id}, owner {row.owner}, until {row.expires}"
            if row is not None
            else item.waiver_id
        )
        lines.append(f"{describe(item.violation)} ({detail})")
    return lines


def _waived_lines(report: CoverageReport) -> list[str]:
    return waived_block_lines(report.waivers, report.gate.waived, violation_line)


# Notes of waivers that only another command checks; coverage and test show them quietly.
_COVERAGE_SILENT = (TEST_ONLY_NOTE, OBSERVE_ONLY_NOTE)


def is_silent_waiver(row: WaiverRow, silent_note: str | tuple[str, ...]) -> bool:
    """A waiver another command checks: quiet, not an alert."""
    notes = (silent_note,) if isinstance(silent_note, str) else silent_note
    return row.status == "unmatched" and row.note in notes


def quiet_waiver_line(waivers: Sequence[WaiverRow], silent_note: str) -> str | None:
    count = sum(1 for row in waivers if is_silent_waiver(row, silent_note))
    return f"  {count} waiver(s) are {silent_note}" if count else None


def _quiet_lines(report: CoverageReport) -> list[str]:
    lines = (quiet_waiver_line(report.waivers, note) for note in _COVERAGE_SILENT)
    return [line for line in lines if line]


def attention_note_texts(
    waivers: Sequence[WaiverRow], silent_note: str | tuple[str, ...]
) -> set[str]:
    """The note texts shown in the attention block (they equal the matching warnings)."""
    return {
        row.note
        for row in waivers
        if row.note is not None
        and row.status != "applied"
        and not is_silent_waiver(row, silent_note)
    }


def _attention_notes(report: CoverageReport) -> set[str]:
    return attention_note_texts(report.waivers, _COVERAGE_SILENT)


def attention_block_lines(
    waivers: Sequence[WaiverRow], silent_note: str | tuple[str, ...]
) -> list[str]:
    """`STATUS  ID: why` for each waiver that needs attention (no indent, no dash)."""
    lines = []
    for row in waivers:
        if row.status == "applied" or is_silent_waiver(row, silent_note):
            continue
        text = row.note if row.note is not None else f"{row.status} waiver"
        lines.append(f"{row.status:<12} {row.id}: {text}")
    return lines


def _attention_lines(report: CoverageReport) -> list[str]:
    return attention_block_lines(report.waivers, _COVERAGE_SILENT)


SUMMARY_LIMIT = 20


def capped_category(
    title: str, items: Sequence[str], file_name: str = REPORT_FILE_NAME
) -> list[str]:
    """A summary category: `Title (n):` plus at most SUMMARY_LIMIT lines and an overflow line."""
    if not items:
        return []
    lines = [f"{title} ({len(items)}):", *items[:SUMMARY_LIMIT]]
    if len(items) > SUMMARY_LIMIT:
        lines.append(f"  ... and {len(items) - SUMMARY_LIMIT} more; see {file_name}")
    return lines


def _capped(title: str, items: Sequence[str]) -> list[str]:
    return capped_category(title, items)


def _group_errors(report: CoverageReport) -> list[str]:
    """Group errors that differ only in their leading id (a case, a rule, an escalation label).

    A dead IAM gives hundreds of `CASE-n: <same message>` lines; they become one line that
    lists up to three ids. Anything else stays one line per error, in first-seen order.
    """
    case_ids = {c.id for c in report.cases}
    known = case_ids | {r.id for r in report.rules}
    order: list[tuple[bool, str]] = []
    groups: dict[str, list[str]] = {}
    for error in report.errors:
        head, sep, rest = error.partition(": ")
        if sep and (head in known or head.startswith("escalation ")):
            if rest not in groups:
                order.append((True, rest))
            groups.setdefault(rest, []).append(head)
        else:
            order.append((False, error))
    lines = []
    for is_group, text in order:
        if not is_group:
            lines.append(f"  - {text}")
            continue
        ids = groups[text]
        if len(ids) == 1:
            lines.append(f"  - {ids[0]}: {text}")
            continue
        noun = "cases" if all(i in case_ids for i in ids) else "items"
        listed = ", ".join(ids[:3])
        more = f", +{len(ids) - 3} more" if len(ids) > 3 else ""
        lines.append(f"  - {text} ({len(ids)} {noun}: {listed}{more})")
    return lines


def _render_summary(report: CoverageReport) -> list[str]:
    """The --summary output: counts first, then what needs action."""
    metrics = report.metrics
    test_mode = report.mode == "test"
    counts = ", ".join(
        f"{status.value} {n}"
        for status in CaseStatus
        if (n := metrics.cases_by_status.get(status.value, 0))
    )
    cases = f"Cases: {metrics.specified_cases}" + (f" ({counts})" if counts else "")
    # The same labels as the full report (see _verdict): "Gate:" is the gate's verdict
    # (PASS or FAIL); "Result:" is for a run that could not give one (ERROR).
    if report.exit_code == 2:
        verdict = "Result: ERROR (exit 2)"
    else:
        verdict = f"Gate: {'FAIL' if report.exit_code == 1 else 'PASS'} (exit {report.exit_code})"
    lines = [
        f"lockwalk {'test' if test_mode else 'coverage'} - {report.scenario_suite}",
        cases,
        f"Tools: {metrics.registered_tools} registered, "
        f"{len(report.registered_tools_without_spec)} without a case, "
        f"{len(report.high_risk_tools_without_deny_case)} high-risk without a deny case",
        verdict,
    ]
    quiet = _quiet_lines(report)
    # Warnings about waivers already listed under "needing attention" are not repeated.
    shown = _attention_notes(report)
    warnings = [w for w in report.warnings if w not in shown]
    categories = [
        _capped("Errors", _group_errors(report)),
        _capped(
            "Blocking",
            ["  " + violation_line(v).removeprefix("  - ") for v in report.gate.violations],
        ),
        _capped("Waived", _waived_lines(report)) + quiet,
        _capped("Waivers needing attention", [f"  - {t}" for t in _attention_lines(report)]),
        _capped("Warnings", [f"  - {w}" for w in warnings]),
    ]
    for block in categories:
        if block:
            lines += ["", *block]
    return [to_ascii(line) for line in lines]
