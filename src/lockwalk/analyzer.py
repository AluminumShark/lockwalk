"""Turn the inventory and the planned cases into a coverage report.

Pure: no file, network, or clock access. Static mode never executes a case, so every
valid case is UNTESTED; that alone never fails the gate in static mode.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lockwalk.config import GateConfig
from lockwalk.graph.analysis import (
    evaluate_rules,
    graph_section,
    holderless_warnings,
    identity_summaries,
    index_graph,
    name_list,
    path_warnings,
    plural,
    role_reachability,
    startless_warnings,
)
from lockwalk.judge import PolicyOutcome, case_violations
from lockwalk.models import (
    AgentGraph,
    CaseRow,
    CaseStatus,
    CoverageReport,
    DoorResult,
    DoorStatus,
    EscalationResult,
    GateResult,
    GateViolation,
    GraphSection,
    Inventory,
    InventorySection,
    Metrics,
    PathVerdict,
    PlannedCase,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    SourceSummary,
    SpecState,
    ToolCoverage,
    ToolRow,
)
from lockwalk.spec_loader import SpecFile

if TYPE_CHECKING:
    from lockwalk.harness.verdicts import HarnessOutcome

# Tools at these risk levels are always listed when they lack a deny case, whatever the gate says.
DENY_CASE_WARNING_RISKS = frozenset({Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN})
# A reachable role x tool pair that no case or rule covers is at least a warning at these
# risk levels; the gate decides which of them are violations.
ROLE_GAP_WARNING_RISKS = frozenset({Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN})


def tool_spec_states(plan: Sequence[PlannedCase]) -> dict[str, SpecState]:
    """Map each tool to SpecState.YES (some case is valid) or SpecState.ERROR (all are ERROR).

    Tools with no cases are absent. This is the single definition of "has a spec".
    """
    states: dict[str, SpecState] = {}
    for planned in plan:
        tool = planned.scenario.tool
        if planned.status != CaseStatus.ERROR:
            states[tool] = SpecState.YES
        else:
            states.setdefault(tool, SpecState.ERROR)
    return states


@dataclass(frozen=True)
class GraphFindings:
    """What the agent graph adds to a report. NO_GRAPH_FINDINGS stands for "no graph"."""

    section: GraphSection
    rules: tuple[RuleRow, ...]
    reachability: tuple[ReachRow, ...] | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    violations: tuple[GateViolation, ...]
    untrusted: bool  # a rule is ERROR or the graph has errors: exit 2


NO_GRAPH_FINDINGS = GraphFindings(
    section=GraphSection(),
    rules=(),
    reachability=None,
    errors=(),
    warnings=(),
    violations=(),
    untrusted=False,
)


def role_gaps(
    rows: Sequence[ReachRow], gate: GateConfig
) -> tuple[tuple[GateViolation, ...], tuple[str, ...]]:
    """Violations and warnings for reachable role x tool pairs that nothing covers.

    Violations stay one per (role, tool), because the gate needs exact items. Pairs that
    only warn are summed up in one warning per role, in row order; the reachability rows
    keep every pair. Inconclusive pairs are not gaps: lockwalk does not know
    they are reachable.
    """
    violations: list[GateViolation] = []
    uncovered: dict[str, list[ReachRow]] = {}  # role -> its warning-only pairs, in row order
    for row in rows:
        if row.status is not ReachStatus.REACHABLE or row.covered_by:
            continue
        if row.risk in gate.fail_on_unspecified_role_risk:
            violations.append(
                GateViolation(
                    rule="fail_on_unspecified_role_risk",
                    role=row.role,
                    tool=row.tool,
                    risk=row.risk,
                )
            )
        elif row.risk in ROLE_GAP_WARNING_RISKS:
            uncovered.setdefault(row.role, []).append(row)
    warnings = tuple(
        f"role {role!r} can reach {len(gaps)} high-risk {plural('tool', len(gaps))} "
        "that no case or rule covers: "
        + name_list([f"{row.tool} (risk={row.risk.value})" for row in gaps])
        for role, gaps in uncovered.items()
    )
    return tuple(violations), warnings


def graph_findings(
    graph: AgentGraph,
    inventory: Inventory,
    spec: SpecFile,
    plan: Sequence[PlannedCase],
    gate: GateConfig,
) -> GraphFindings:
    """Evaluate the never_reaches rules and the role x tool table, and apply the gate.

    Warnings come in this order: the graph's own warnings, the roles that no entry agent
    lists (one warning, only with roles), the tools that no agent is known to use (one
    warning, only with rules or roles), identity warnings (one per caller agent), path
    warnings case by case, then uncovered role x tool pairs (one per role).
    Errors are the graph's errors, then one line per problem of each ERROR rule, in rule
    order. Violations are the never_reaches ones in rule order, then the
    fail_on_unspecified_role_risk ones in reachability row order (role, then tool).
    """
    rules = evaluate_rules(graph, spec.never_reaches, inventory)
    reachability = role_reachability(graph, inventory, plan, rules)
    rows = reachability or ()
    index = index_graph(graph)  # built once, shared by the identity and path checks
    path_lines = [line for planned in plan for line in path_warnings(graph, planned, index=index)]
    gap_violations, gap_warnings = role_gaps(rows, gate)

    errors = list(graph.errors)
    violations: list[GateViolation] = []
    for row in rules:
        if row.result is RuleResult.ERROR:
            errors.extend(f"{row.id}: {problem}" for problem in row.problems)
        elif row.result is RuleResult.FAIL or (
            row.result is RuleResult.INCONCLUSIVE and gate.fail_on_never_reaches_inconclusive
        ):
            violations.append(
                GateViolation(rule="never_reaches", rule_id=row.id, result=row.result)
            )
    violations.extend(gap_violations)
    return GraphFindings(
        section=graph_section(graph),
        rules=rules,
        reachability=reachability,
        errors=tuple(errors),
        warnings=(
            *graph.warnings,
            *startless_warnings(graph, index=index),
            *holderless_warnings(graph, inventory, has_rules=bool(spec.never_reaches), index=index),
            *identity_summaries(graph, rows, index=index),
            *path_lines,
            *gap_warnings,
        ),
        violations=tuple(violations),
        untrusted=bool(graph.errors) or any(row.result is RuleResult.ERROR for row in rules),
    )


def analyze(
    inventory: Inventory,
    spec: SpecFile,
    plan: Sequence[PlannedCase],
    gate: GateConfig,
    graph: AgentGraph | None = None,
) -> CoverageReport:
    """Compute tool coverage, metrics, gate violations, and the exit code.

    Without a graph, never_reaches rules and roles are not evaluated, and the report
    holds no graph findings. With one, graph findings are added after the
    other findings: errors, warnings, and violations alike. The plan must come from
    plan_cases(spec, inventory, graph) with this same graph object; a plan made without
    it marks discovered-only agents as unknown and skips the role check.
    """
    cases_by_tool: dict[str, list[PlannedCase]] = {}
    for planned in plan:
        cases_by_tool.setdefault(planned.scenario.tool, []).append(planned)

    tool_rows: list[ToolRow] = []
    without_spec: list[str] = []
    without_deny: list[str] = []
    violations: list[GateViolation] = []
    spec_states = tool_spec_states(plan)
    for tool in inventory.tools:
        cases = cases_by_tool.get(tool.id, [])
        has_deny = any(
            case.scenario.expect == "deny" and case.status != CaseStatus.ERROR for case in cases
        )
        # A tool is specified only if at least one of its cases is valid; a tool whose cases
        # are all errors is not covered (UNKNOWN is not PASS). case_ids still lists every case.
        specified = spec_states.get(tool.id) == SpecState.YES
        coverage = ToolCoverage.SPECIFIED if specified else ToolCoverage.UNSPECIFIED
        if coverage == ToolCoverage.UNSPECIFIED:
            without_spec.append(tool.id)
            if tool.risk in gate.fail_on_unspecified_risk:
                violations.append(
                    GateViolation(rule="fail_on_unspecified_risk", tool=tool.id, risk=tool.risk)
                )
        if not has_deny:
            if tool.risk in DENY_CASE_WARNING_RISKS:
                without_deny.append(tool.id)
            if tool.risk in gate.require_deny_case_for_risk:
                violations.append(
                    GateViolation(rule="require_deny_case_for_risk", tool=tool.id, risk=tool.risk)
                )
        tool_rows.append(
            ToolRow(
                id=tool.id,
                risk=tool.risk,
                action=tool.action,
                sources=tool.sources,
                supported_agents=tool.supported_agents,
                hints=tool.hints,
                coverage=coverage,
                case_ids=tuple(case.scenario.id for case in cases),
                has_deny_case=has_deny,
            )
        )

    by_status = {status.value: 0 for status in CaseStatus}
    for planned in plan:
        by_status[planned.status.value] += 1
    total = len(plan)
    executed = 0  # static mode never executes a case
    passed = by_status[CaseStatus.PASS.value]

    errors = list(inventory.errors)
    warnings = list(inventory.warnings)
    for planned in plan:
        if planned.status == CaseStatus.ERROR:
            errors.extend(f"{planned.scenario.id}: {problem}" for problem in planned.problems)
        elif not planned.action_verified:
            warnings.append(
                f"{planned.scenario.id}: action {planned.scenario.action!r} was not verified "
                f"because tool {planned.scenario.tool!r} has no registered action"
            )

    found = (
        NO_GRAPH_FINDINGS if graph is None else graph_findings(graph, inventory, spec, plan, gate)
    )
    errors.extend(found.errors)
    warnings.extend(found.warnings)
    violations.extend(found.violations)

    # Exit 2 comes from structured state, never from the text of the errors.
    untrusted = (
        bool(inventory.errors) or any(p.status == CaseStatus.ERROR for p in plan) or found.untrusted
    )
    exit_code = 2 if untrusted else 1 if violations else 0
    return CoverageReport(
        mode="static",
        scenario_suite=spec.scenario_suite,
        spec_schema_version=spec.schema_version,
        inventory=InventorySection(
            sources=tuple(
                SourceSummary(
                    source=source.source.label,
                    ok=source.ok,
                    tool_count=len(source.tools),
                    error=source.error,
                    optional=source.optional,
                    unavailable=source.unavailable,
                )
                for source in inventory.sources
            ),
            agents=inventory.agents,
            tools=tuple(tool_rows),
            drift=inventory.drift,
        ),
        cases=tuple(
            CaseRow(
                id=planned.scenario.id,
                agent=planned.scenario.route[-1],
                path=planned.scenario.route,
                tool=planned.scenario.tool,
                action=planned.scenario.action,
                expect=planned.scenario.expect,
                actor=planned.scenario.actor,
                role=planned.scenario.role,
                status=planned.status,
                action_verified=planned.action_verified,
                problems=planned.problems,
            )
            for planned in plan
        ),
        metrics=Metrics(
            registered_tools=len(inventory.tools),
            specified_cases=total,
            executed_cases=executed,
            execution_coverage=executed / total if total else None,
            verified_pass_rate=passed / total if total else None,
            cases_by_status=by_status,
            tools_without_spec=len(without_spec),
        ),
        registered_tools_without_spec=tuple(without_spec),
        high_risk_tools_without_deny_case=tuple(without_deny),
        agent_graph=found.section,
        reachability=found.reachability,
        rules=found.rules,
        gate=GateResult(passed=not violations, violations=tuple(violations)),
        errors=tuple(errors),
        warnings=tuple(warnings),
        exit_code=exit_code,
    )


UNEXPLAINED_ERROR = "internal error: an ERROR result has no error line"


def _guard_errors(errors: tuple[str, ...], *, has_error_result: bool) -> tuple[str, ...]:
    """Never let an ERROR result end in exit code 0 or 1: add a line so the exit code is 2."""
    if has_error_result and not errors:
        return (UNEXPLAINED_ERROR,)
    return errors


def with_test_outcome(
    report: CoverageReport,
    outcome: PolicyOutcome,
    *,
    policy_adapter: str,
    extra_warnings: Sequence[str] = (),
) -> CoverageReport:
    """Fold what the IAM said into the static report, and recompute the gate and exit code.

    Cases the outcome judged take its status, decision, and notes; static ERROR cases are
    not in the outcome and stay as they were. The outcome's errors, warnings, and
    violations follow the report's own. Warnings come in this order: the static report's,
    then the outcome's, then extra_warnings (for example fixture warnings from build_queries
    and the adapter's notes, such as a batch fallback).
    """
    cases: list[CaseRow] = []
    for row in report.cases:
        judged = outcome.cases.get(row.id)
        if judged is None:
            cases.append(row)
            continue
        cases.append(
            row.model_copy(
                update={
                    "status": judged.status,
                    "decision": judged.decision,
                    "notes": judged.notes,
                    "problems": judged.problems or row.problems,
                }
            )
        )
    by_status = {status.value: 0 for status in CaseStatus}
    for case in cases:
        by_status[case.status.value] += 1
    total = len(cases)
    # An ERROR answer is not an executed scenario: the IAM did not say anything usable.
    executed = sum(
        1
        for case in cases
        if case.decision is not None and case.decision.verdict is not PathVerdict.ERROR
    )
    metrics = report.metrics.model_copy(
        update={
            "cases_by_status": by_status,
            "executed_cases": executed,
            "execution_coverage": executed / total if total else None,
            "verified_pass_rate": by_status[CaseStatus.PASS.value] / total if total else None,
        }
    )
    errors = _guard_errors(
        (*report.errors, *outcome.errors),
        has_error_result=any(c.status is CaseStatus.ERROR for c in cases)
        or any(e.result is EscalationResult.ERROR for e in outcome.escalations),
    )
    violations = (*report.gate.violations, *outcome.violations)
    return report.model_copy(
        update={
            "mode": "test",
            "policy_adapter": policy_adapter,
            "cases": tuple(cases),
            "metrics": metrics,
            "escalations": outcome.escalations,
            "controls": outcome.controls,
            "errors": errors,
            "warnings": (*report.warnings, *outcome.warnings, *extra_warnings),
            "gate": GateResult(passed=not violations, violations=violations),
            "exit_code": 2 if errors else 1 if violations else 0,
        }
    )


_CASE_SEVERITY = {
    CaseStatus.UNTESTED: 0,
    CaseStatus.PASS: 1,
    CaseStatus.INCONCLUSIVE: 2,
    CaseStatus.ERROR: 3,
    CaseStatus.FAIL_POLICY: 4,
    CaseStatus.FAIL_EXECUTION: 5,
}
_DOOR_TO_CASE = {
    DoorStatus.INCONCLUSIVE: CaseStatus.INCONCLUSIVE,
    DoorStatus.ERROR: CaseStatus.ERROR,
    DoorStatus.FAIL_EXECUTION: CaseStatus.FAIL_EXECUTION,
}


def _with_door(row: CaseRow, door: DoorResult) -> CaseRow:
    """The case row with its door result: the more severe status, plus the door's lines."""
    status = row.status
    mapped = _DOOR_TO_CASE.get(door.status)
    if mapped is not None and _CASE_SEVERITY[mapped] > _CASE_SEVERITY[status]:
        status = mapped
    lines = [
        f"door ({run.mode}): {note}"
        for run in door.runs
        if run.status is not DoorStatus.OK
        for note in run.notes
    ]
    problems = row.problems
    if door.status is DoorStatus.ERROR:
        error_lines = [
            f"door ({run.mode}): {note}"
            for run in door.runs
            if run.status is DoorStatus.ERROR
            for note in run.notes
        ]
        extra = [*error_lines, *(f"door: {note}" for note in door.notes)]
        problems = (*problems, *dict.fromkeys(extra))
    return row.model_copy(
        update={
            "status": status,
            "door": door,
            "notes": (*row.notes, *lines),
            "problems": problems,
        }
    )


def with_harness_outcome(
    report: CoverageReport, harness: "HarnessOutcome", gate: GateConfig
) -> CoverageReport:
    """Fold the door test results into a test-mode report.

    A case takes the more severe of its IAM status and its door status (FAIL_EXECUTION >
    FAIL_POLICY > ERROR > INCONCLUSIVE > PASS). The case violations are rebuilt from the
    final statuses; the harness errors, warnings, and violations follow the report's own.
    """
    cases = tuple(
        _with_door(row, harness.doors[row.id]) if row.id in harness.doors else row
        for row in report.cases
    )
    by_status = {status.value: 0 for status in CaseStatus}
    for case in cases:
        by_status[case.status.value] += 1
    total = len(cases)
    metrics = report.metrics.model_copy(
        update={
            "cases_by_status": by_status,
            "verified_pass_rate": by_status[CaseStatus.PASS.value] / total if total else None,
        }
    )
    kept = [
        v for v in report.gate.violations if v.rule not in ("case", "fail_on_inconclusive_case")
    ]
    violations = (
        *kept,
        *case_violations([(case.id, case.status) for case in cases], gate),
        *harness.violations,
    )
    errors = _guard_errors(
        (*report.errors, *harness.errors),
        has_error_result=any(c.status is CaseStatus.ERROR for c in cases)
        or any(e.result is EscalationResult.ERROR for e in report.escalations)
        or any(d.status is DoorStatus.ERROR for d in harness.doors.values()),
    )
    return report.model_copy(
        update={
            "cases": cases,
            "metrics": metrics,
            "identity_checks": harness.identity_checks,
            "door_controls": harness.door_controls,
            "errors": errors,
            "warnings": (*report.warnings, *harness.warnings),
            "gate": GateResult(passed=not violations, violations=violations),
            "exit_code": 2 if errors else 1 if violations else 0,
        }
    )
