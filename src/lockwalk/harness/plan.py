"""Plan the door test runs from the question plan and the survey.

Pure: no file, network, or process access.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from lockwalk.fixtures import FixturesFile
from lockwalk.harness.protocol import (
    SCRIPTED_TEXT,
    DirectJob,
    Observed,
    ScriptedJob,
    Step,
    Survey,
    ToolInfo,
    reduce_subject,
)
from lockwalk.judge import PolicyOutcome
from lockwalk.models import AgentGraph, CaseStatus, EdgeKind, PlannedCase
from lockwalk.policy.base import Query
from lockwalk.queries import CaseAsk, QueryPlan
from lockwalk.registry import Registry


@dataclass(frozen=True)
class ScriptedPlan:
    jobs: dict[str, ScriptedJob] = field(default_factory=dict)  # case id -> job
    not_run: dict[str, str] = field(default_factory=dict)  # case id -> why not
    # case id -> the declared identity (reduced), or None when delegation_mode is undeclared
    expected: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DirectPlan:
    # case id -> one job per identity the tool hop asks the IAM with, in hop query order
    jobs: dict[str, tuple[DirectJob, ...]] = field(default_factory=dict)
    queries: dict[str, tuple[Query, ...]] = field(default_factory=dict)  # same order as jobs
    not_tested: dict[str, str] = field(default_factory=dict)  # case id -> why not
    errors: dict[str, str] = field(default_factory=dict)  # case id -> why ERROR before running
    warnings: tuple[str, ...] = ()


_NO_DOOR = "no DOOR in the hooks file, so lockwalk cannot see which identity the door received"


class _Edges:
    """The graph edges indexed once: (from, to) -> kinds."""

    def __init__(self, graph: AgentGraph, registry: Registry) -> None:
        self.delegations: dict[str, list[str]] = {}  # agent id -> its delegation tool ids
        for decl in registry.delegation_tools:
            self.delegations.setdefault(decl.agent, []).append(decl.id)
        self.kinds: dict[tuple[str, str], list[EdgeKind]] = {}
        for edge in graph.edges:
            kinds = self.kinds.setdefault((edge.from_id, edge.to_id), [])
            if edge.kind not in kinds:
                kinds.append(edge.kind)

    def holds(self, agent: str, tool: str) -> bool:
        return EdgeKind.USES_TOOL in self.kinds.get((agent, tool), ())


def _tool_args(fixtures: FixturesFile | None, name: str) -> dict[str, Any] | None:
    fixture = fixtures.resources.get(name) if fixtures is not None else None
    return fixture.tool_args if fixture is not None else None


def _one_string_argument(info: ToolInfo) -> dict[str, Any] | None:
    schema = info.input_schema
    properties = schema.get("properties") if isinstance(schema, Mapping) else None
    if not isinstance(properties, Mapping) or len(properties) != 1:
        return None
    ((name, prop),) = properties.items()
    required = schema.get("required") if isinstance(schema, Mapping) else None
    if isinstance(required, list | tuple) and any(item != name for item in required):
        return None
    if not isinstance(prop, Mapping) or prop.get("type") != "string":
        return None
    return {name: SCRIPTED_TEXT}


def _agent_tool_step(
    a: str, b: str, survey: Survey, registry: Registry, edges: _Edges
) -> Step | str:
    """The step where agent a calls agent b through a tool, or the reason it cannot be built."""
    info: ToolInfo | None = None
    agent = survey.agents.get(a)
    if agent is not None:
        info = agent.agent_tools.get(b)
    if info is None:
        found = [
            tool_id
            for tool_id in edges.delegations.get(b, ())
            if tool_id in survey.tools and edges.holds(a, tool_id)
        ]
        if not found:
            return f"lockwalk does not know which tool of {a!r} calls {b!r}"
        if len(found) > 1:
            names = ", ".join(repr(name) for name in found)
            return f"{a!r} has several tools that call {b!r} ({names}); lockwalk does not guess"
        info = survey.tools[found[0]]
    args = _one_string_argument(info)
    if args is None:
        return (
            f"lockwalk cannot build the arguments of tool {info.name!r}: "
            "it needs exactly one string parameter"
        )
    return Step(agent=a, kind="agent_tool", target=b, tool=info.name, args=args)


def _pair_step(
    a: str, b: str, framework: str, survey: Survey, registry: Registry, edges: _Edges
) -> Step | str:
    kinds = edges.kinds.get((a, b), [])
    if EdgeKind.HANDOFF in kinds and framework == "openai_agents":
        return Step(agent=a, kind="handoff", target=b)
    if framework == "langgraph" and (EdgeKind.HANDOFF in kinds or EdgeKind.TEAM in kinds):
        return Step(agent=a, kind="pass", target=b)
    if EdgeKind.AGENT_AS_TOOL in kinds:
        return _agent_tool_step(a, b, survey, registry, edges)
    others = [kind for kind in kinds if kind is not EdgeKind.CALLS]
    if not others:
        return (
            f"the call from {a!r} to {b!r} is declared with calls only, so lockwalk does not "
            "know which tool makes it; list that tool in the registry's delegation_tools, "
            "or provide run_path in the hooks file"
        )
    return f"scripted mode cannot drive the {others[0].value} edge from {a!r} to {b!r}"


def _build_steps(
    case: CaseAsk,
    tool_args: dict[str, Any],
    survey: Survey,
    registry: Registry,
    edges: _Edges,
) -> tuple[Step, ...] | str:
    """The steps of the route, or the reason they cannot be built."""
    route = case.route
    first = route[0]
    entry = survey.agents.get(first)
    if entry is None:
        return f"agent {first!r} is not in the [[inventory.python]] targets"
    if entry.framework == "other":
        return "scripted mode does not support this framework; provide run_path in the hooks file"
    if entry.framework == "langgraph" and any(not r.startswith(first + ":") for r in route[1:]):
        return f"the route leaves LangGraph graph {first!r}"
    steps: list[Step] = []
    for a, b in pairwise(route):
        known = survey.agents.get(a)
        framework = known.framework if known is not None else entry.framework
        step = _pair_step(a, b, framework, survey, registry, edges)
        if isinstance(step, str):
            return step
        steps.append(step)
    last = route[-1]
    if not edges.holds(last, case.tool):
        return f"agent {last!r} does not hold tool {case.tool!r} in the agent graph"
    steps.append(Step(agent=last, kind="tool", target=case.tool, tool=case.tool, args=tool_args))
    return tuple(steps)


def plan_scripted(
    planned: Sequence[PlannedCase],
    queries: QueryPlan,
    graph: AgentGraph,
    registry: Registry,
    fixtures: FixturesFile | None,
    survey: Survey,
    modes: Sequence[str],
) -> ScriptedPlan:
    if "scripted" not in modes or survey.problems:
        return ScriptedPlan()
    scenarios = {item.scenario.id: item.scenario for item in planned}
    edges = _Edges(graph, registry)
    jobs: dict[str, ScriptedJob] = {}
    not_run: dict[str, str] = {}
    expected: dict[str, dict[str, Any] | None] = {}
    for case in queries.cases:
        scenario = scenarios.get(case.case_id)
        if case.problems or not case.hops or scenario is None:
            continue
        hop = case.tool_hop
        expected[case.case_id] = (
            None
            if hop.mode == "undeclared"
            else reduce_subject(hop.queries[0].subject.model_dump(mode="json"))
        )
        visited: set[str] = set()
        repeated: str | None = None
        for agent in case.route:
            if agent in visited:
                repeated = agent
                break
            visited.add(agent)
        fixture_name = scenario.resource_fixture
        tool_args = _tool_args(fixtures, fixture_name)
        if not survey.door:
            not_run[case.case_id] = _NO_DOOR
            continue
        if repeated is not None:
            not_run[case.case_id] = (
                f"the route visits agent {repeated!r} more than once; "
                "scripted mode takes each agent's step once"
            )
            continue
        if case.tool not in survey.side_effects:
            not_run[case.case_id] = (
                f"tool {case.tool!r} is not in SIDE_EFFECTS, so lockwalk does not call it"
            )
            continue
        if tool_args is None:
            not_run[case.case_id] = f"resource fixture {fixture_name!r} has no tool_args"
            continue
        built = _build_steps(case, tool_args, survey, registry, edges)
        if isinstance(built, str) and not survey.run_path:
            not_run[case.case_id] = built
            continue
        user = (case.plain_user or hop.queries[0]).subject.model_dump(mode="json")
        jobs[case.case_id] = ScriptedJob(
            case_id=case.case_id,
            route=case.route,
            tool=case.tool,
            args=tool_args,
            subject=user,
            steps=() if isinstance(built, str) else built,
            use_run_path=isinstance(built, str),
        )
    warnings: tuple[str, ...] = ()
    if not survey.door and not_run:
        warnings = ("scripted mode needs DOOR in the hooks file; no route was run",)
    return ScriptedPlan(jobs=jobs, not_run=not_run, expected=expected, warnings=warnings)


def observed_subjects(
    plan: ScriptedPlan, observed: Mapping[str, Observed]
) -> dict[str, dict[str, Any]]:
    """case id -> the one identity (reduced) the door received for the tool."""
    found: dict[str, dict[str, Any]] = {}
    for case_id in plan.jobs:
        run = observed.get(case_id)
        if run is None or run.error is not None or run.not_run is not None:
            continue
        subjects = [call.subject for call in run.door_calls if call.error is None and call.subject]
        if subjects and all(subject == subjects[0] for subject in subjects):
            found[case_id] = subjects[0]
    return found


def plan_direct(
    planned: Sequence[PlannedCase],
    queries: QueryPlan,
    outcome: PolicyOutcome,
    fixtures: FixturesFile | None,
    survey: Survey,
    modes: Sequence[str],
) -> DirectPlan:
    if "direct" not in modes or survey.problems:
        return DirectPlan()
    scenarios = {item.scenario.id: item.scenario for item in planned}
    jobs: dict[str, tuple[DirectJob, ...]] = {}
    asked: dict[str, tuple[Query, ...]] = {}
    not_tested: dict[str, str] = {}
    errors: dict[str, str] = {}
    for case in queries.cases:
        scenario = scenarios.get(case.case_id)
        if case.problems or not case.hops or scenario is None:
            continue
        tool = case.tool
        decided = outcome.cases.get(case.case_id)
        if decided is not None and decided.status is CaseStatus.ERROR:
            not_tested[case.case_id] = (
                "the IAM part of this case is ERROR, so the door is not tested"
            )
            continue
        if tool not in survey.side_effects:
            not_tested[case.case_id] = f"tool {tool!r} is not in SIDE_EFFECTS"
            continue
        info = survey.tools.get(tool)
        if info is None:
            not_tested[case.case_id] = (
                f"tool {tool!r} is not a Python tool lockwalk found; MCP tools are not door tested"
            )
            continue
        if not info.callable:
            not_tested[case.case_id] = info.why_not or "the tool cannot be called"
            continue
        tool_args = _tool_args(fixtures, scenario.resource_fixture)
        if tool_args is None:
            not_tested[case.case_id] = (
                f"resource fixture {scenario.resource_fixture!r} has no tool_args"
            )
            continue
        problems = check_tool_args(info.input_schema, tool_args)
        if problems:
            errors[case.case_id] = (
                f"tool_args do not match the input schema of {tool!r}: {'; '.join(problems)}"
            )
            continue
        hop_queries = case.tool_hop.queries
        jobs[case.case_id] = tuple(
            DirectJob(
                case_id=case.case_id,
                tool=tool,
                args=tool_args,
                subject=query.subject.model_dump(mode="json"),
            )
            for query in hop_queries
        )
        asked[case.case_id] = hop_queries
    return DirectPlan(jobs=jobs, queries=asked, not_tested=not_tested, errors=errors)


def _is_type(value: object, name: str) -> bool:
    match name:
        case "string":
            return isinstance(value, str)
        case "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        case "number":
            return isinstance(value, int | float) and not isinstance(value, bool)
        case "boolean":
            return isinstance(value, bool)
        case "array":
            return isinstance(value, list)
        case "object":
            return isinstance(value, dict)
        case "null":
            return value is None
    return True  # a type name lockwalk does not know cannot be judged


def check_tool_args(schema: Mapping[str, Any] | None, args: Mapping[str, Any]) -> list[str]:
    """Problems with args against the top level of a JSON schema."""
    if not isinstance(schema, Mapping) or schema.get("type", "object") != "object":
        return []
    problems: list[str] = []
    required = schema.get("required")
    if isinstance(required, list | tuple):
        problems.extend(
            f"missing required argument {k!r}"
            for k in required
            if isinstance(k, str) and k not in args
        )
    raw = schema.get("properties")
    properties: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    closed = schema.get("additionalProperties") is False
    for key, value in args.items():
        if key not in properties:
            if closed:
                problems.append(f"unexpected argument {key!r}")
            continue
        prop = properties[key]
        declared = prop.get("type") if isinstance(prop, Mapping) else None
        if isinstance(declared, str):
            names = [declared]
        elif isinstance(declared, list) and all(isinstance(n, str) for n in declared):
            names = list(declared)
        else:
            continue
        if names and not any(_is_type(value, n) for n in names):
            problems.append(f"argument {key!r} must be {' or '.join(names)}")
    return problems
