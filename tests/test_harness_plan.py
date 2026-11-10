"""Tests for planning the door test runs."""

from typing import Any

import pytest
from test_queries import case, edge, make_graph, make_inventory, node, policy, tool, uses

from lockwalk.fixtures import FixturesFile
from lockwalk.harness.plan import (
    DirectPlan,
    ScriptedPlan,
    check_tool_args,
    observed_subjects,
    plan_direct,
    plan_scripted,
)
from lockwalk.harness.protocol import (
    SCRIPTED_TEXT,
    AgentInfo,
    Observed,
    ScriptedJob,
    Step,
    Survey,
    ToolInfo,
)
from lockwalk.judge import CaseOutcome, PolicyOutcome
from lockwalk.models import AgentGraph, CaseStatus, DoorCall, PlannedCase
from lockwalk.queries import QueryPlan, build_queries
from lockwalk.registry import Registry

ONE_STRING = {"type": "object", "properties": {"q": {"type": "string"}}}


def fixtures(tool_args: dict[str, Any] | None = {"amount": 5}) -> FixturesFile:  # noqa: B006
    resource: dict[str, Any] = {"type": "payment", "id": "p-1"}
    if tool_args is not None:
        resource["tool_args"] = tool_args
    return FixturesFile.model_validate(
        {
            "schema_version": "1",
            "subjects": {"alice": {"roles": ["analyst"]}},
            "agents": {},
            "resources": {"pay1": resource},
        }
    )


def registry(*delegation: dict[str, Any]) -> Registry:
    return Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [],
            "tools": [],
            "delegation_tools": list(delegation),
        }
    )


def survey(**kw: Any) -> Survey:
    data: dict[str, Any] = {
        "side_effects": {"pay": "m.pay"},
        "door": True,
        "run_path": False,
        "tools": {"pay": ToolInfo(name="pay", kind="function")},
        "agents": {"a": AgentInfo(id="a", framework="openai_agents")},
        "replaced": {"pay": 1},
    }
    data.update(kw)
    return Survey(**data)


def questions(
    planned: list[PlannedCase],
    graph: AgentGraph,
    fx: FixturesFile | None = None,
    observed: dict[str, dict[str, Any]] | None = None,
) -> QueryPlan:
    return build_queries(
        planned,
        graph,
        make_inventory(tool("pay")),
        fx or fixtures(),
        policy(),
        observed=observed,
    )


def simple(mode: Any = "user") -> AgentGraph:
    return make_graph([node("a", entry=True, mode=mode)], [uses("a", "pay")], entries=["a"])


def run_scripted(
    planned: list[PlannedCase],
    graph: AgentGraph | None = None,
    *,
    sv: Survey | None = None,
    reg: Registry | None = None,
    fx: FixturesFile | None = None,
    modes: tuple[str, ...] = ("scripted",),
) -> ScriptedPlan:
    graph = graph or simple()
    fx = fx or fixtures()
    return plan_scripted(
        planned, questions(planned, graph, fx), graph, reg or registry(), fx, sv or survey(), modes
    )


# ---- plan_scripted: the reasons ----


def test_modes_and_problems_give_an_empty_plan() -> None:
    assert run_scripted([case()], modes=("direct",)) == ScriptedPlan()
    assert run_scripted([case()], sv=survey(problems=("boom",))) == ScriptedPlan()


def test_simple_job() -> None:
    plan = run_scripted([case()])
    job = plan.jobs["C1"]
    assert job.route == ("a",) and job.tool == "pay" and job.args == {"amount": 5}
    assert job.steps == (
        Step(agent="a", kind="tool", target="pay", tool="pay", args={"amount": 5}),
    )
    assert not job.use_run_path
    assert plan.not_run == {} and plan.warnings == ()
    assert plan.expected == {"C1": {"type": "user", "id": "alice"}}


def test_no_door() -> None:
    plan = run_scripted([case("C1"), case("C2")], sv=survey(door=False))
    reason = "no DOOR in the hooks file, so lockwalk cannot see which identity the door received"
    assert plan.not_run == {"C1": reason, "C2": reason}
    assert plan.jobs == {}
    assert plan.warnings == ("scripted mode needs DOOR in the hooks file; no route was run",)


def test_repeated_agent() -> None:
    graph = make_graph(
        [node("a", entry=True), node("b")],
        [edge("a", "b"), edge("b", "a"), uses("a", "pay")],
        entries=["a"],
    )
    plan = run_scripted([case(path=("a", "b", "a"))], graph)
    assert plan.not_run == {
        "C1": "the route visits agent 'a' more than once; "
        "scripted mode takes each agent's step once"
    }


def test_tool_not_in_side_effects() -> None:
    plan = run_scripted([case()], sv=survey(side_effects={}))
    assert plan.not_run == {"C1": "tool 'pay' is not in SIDE_EFFECTS, so lockwalk does not call it"}


def test_no_tool_args() -> None:
    reason = "resource fixture 'pay1' has no tool_args"
    assert run_scripted([case()], fx=fixtures(None)).not_run == {"C1": reason}
    assert run_scripted([case(fixture="pay1")], fx=fixtures(None)).jobs == {}


def test_entry_agent_missing_and_other_framework() -> None:
    plan = run_scripted([case()], sv=survey(agents={}))
    assert plan.not_run == {"C1": "agent 'a' is not in the [[inventory.python]] targets"}
    other = survey(agents={"a": AgentInfo(id="a", framework="other")})
    plan = run_scripted([case()], sv=other)
    assert plan.not_run == {
        "C1": "scripted mode does not support this framework; provide run_path in the hooks file"
    }


def test_run_path_replaces_a_step_reason() -> None:
    other = survey(agents={"a": AgentInfo(id="a", framework="other")}, run_path=True)
    plan = run_scripted([case()], sv=other)
    job = plan.jobs["C1"]
    assert job.use_run_path and job.steps == () and plan.not_run == {}
    # run_path does not cover the earlier reasons
    plan = run_scripted([case()], sv=survey(run_path=True, side_effects={}))
    assert "C1" in plan.not_run and plan.jobs == {}


def test_last_agent_does_not_hold_tool() -> None:
    graph = make_graph([node("a", entry=True)], [], entries=["a"])
    plan = run_scripted([case()], graph)
    assert plan.not_run == {"C1": "agent 'a' does not hold tool 'pay' in the agent graph"}


# ---- plan_scripted: steps ----


def two_agent_graph(kind: str, *, mode: Any = None) -> AgentGraph:
    return make_graph(
        [node("a", entry=True, mode=mode), node("b", mode=mode)],
        [edge("a", "b", kind), uses("b", "pay")],
        entries=["a"],
    )


def test_openai_handoff() -> None:
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("handoff"))
    assert plan.jobs["C1"].steps == (
        Step(agent="a", kind="handoff", target="b"),
        Step(agent="b", kind="tool", target="pay", tool="pay", args={"amount": 5}),
    )


def test_langgraph_pass_and_prefix_rule() -> None:
    lg = survey(agents={"g": AgentInfo(id="g", framework="langgraph")})
    graph = make_graph(
        [node("g", entry=True), node("g:x")],
        [edge("g", "g:x", "team"), uses("g:x", "pay")],
        entries=["g"],
    )
    plan = run_scripted([case(path=("g", "g:x"))], graph, sv=lg)
    assert plan.jobs["C1"].steps[0] == Step(agent="g", kind="pass", target="g:x")
    graph = make_graph(
        [node("g", entry=True), node("h")],
        [edge("g", "h", "handoff"), uses("h", "pay")],
        entries=["g"],
    )
    plan = run_scripted([case(path=("g", "h"))], graph, sv=lg)
    assert plan.not_run == {"C1": "the route leaves LangGraph graph 'g'"}


def test_agent_as_tool_from_survey() -> None:
    info = ToolInfo(name="ask_b", kind="openai_agents", input_schema=ONE_STRING)
    sv = survey(
        agents={
            "a": AgentInfo(id="a", framework="openai_agents", agent_tools={"b": info}),
        }
    )
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("agent_as_tool"), sv=sv)
    assert plan.jobs["C1"].steps[0] == Step(
        agent="a", kind="agent_tool", target="b", tool="ask_b", args={"q": SCRIPTED_TEXT}
    )


def test_agent_as_tool_bad_schema() -> None:
    for schema in (None, {"properties": {}}, {"properties": {"q": {"type": "integer"}}}):
        info = ToolInfo(name="ask_b", kind="openai_agents", input_schema=schema)
        sv = survey(
            agents={"a": AgentInfo(id="a", framework="openai_agents", agent_tools={"b": info})}
        )
        plan = run_scripted([case(path=("a", "b"))], two_agent_graph("agent_as_tool"), sv=sv)
        assert plan.not_run == {
            "C1": "lockwalk cannot build the arguments of tool 'ask_b': "
            "it needs exactly one string parameter"
        }
    two = {"properties": {"q": {"type": "string"}, "r": {"type": "string"}}}
    info = ToolInfo(name="ask_b", kind="openai_agents", input_schema=two)
    sv = survey(agents={"a": AgentInfo(id="a", framework="openai_agents", agent_tools={"b": info})})
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("agent_as_tool"), sv=sv)
    assert "exactly one string parameter" in plan.not_run["C1"]


def test_agent_as_tool_extra_required_argument() -> None:
    schema = {**ONE_STRING, "required": ["q", "other"]}
    info = ToolInfo(name="ask_b", kind="openai_agents", input_schema=schema)
    sv = survey(agents={"a": AgentInfo(id="a", framework="openai_agents", agent_tools={"b": info})})
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("agent_as_tool"), sv=sv)
    assert "exactly one string parameter" in plan.not_run["C1"]
    ok = ToolInfo(
        name="ask_b", kind="openai_agents", input_schema={**ONE_STRING, "required": ["q"]}
    )
    sv = survey(agents={"a": AgentInfo(id="a", framework="openai_agents", agent_tools={"b": ok})})
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("agent_as_tool"), sv=sv)
    assert "C1" in plan.jobs


def delegation_graph(*tool_ids: str) -> AgentGraph:
    return make_graph(
        [node("a", entry=True), node("b")],
        [edge("a", "b", "agent_as_tool"), *(uses("a", t) for t in tool_ids), uses("b", "pay")],
        entries=["a"],
    )


def test_delegation_tool() -> None:
    reg = registry({"id": "dt", "agent": "b"})
    sv = survey(
        tools={
            "pay": ToolInfo(name="pay", kind="function"),
            "dt": ToolInfo(name="dt", kind="function", input_schema=ONE_STRING),
        }
    )
    plan = run_scripted([case(path=("a", "b"))], delegation_graph("dt"), sv=sv, reg=reg)
    assert plan.jobs["C1"].steps[0] == Step(
        agent="a", kind="agent_tool", target="b", tool="dt", args={"q": SCRIPTED_TEXT}
    )


def test_delegation_tool_none_and_several() -> None:
    plan = run_scripted([case(path=("a", "b"))], delegation_graph())
    assert plan.not_run == {"C1": "lockwalk does not know which tool of 'a' calls 'b'"}
    reg = registry({"id": "d1", "agent": "b"}, {"id": "d2", "agent": "b"})
    tools = {
        "pay": ToolInfo(name="pay", kind="function"),
        "d1": ToolInfo(name="d1", kind="function", input_schema=ONE_STRING),
        "d2": ToolInfo(name="d2", kind="function", input_schema=ONE_STRING),
    }
    plan = run_scripted(
        [case(path=("a", "b"))], delegation_graph("d1", "d2"), sv=survey(tools=tools), reg=reg
    )
    assert plan.not_run == {
        "C1": "'a' has several tools that call 'b' ('d1', 'd2'); lockwalk does not guess"
    }


def test_calls_only_reason_and_run_path() -> None:
    reason = (
        "the call from 'a' to 'b' is declared with calls only, so lockwalk does not know "
        "which tool makes it; list that tool in the registry's delegation_tools, "
        "or provide run_path in the hooks file"
    )
    graph = two_agent_graph("calls")
    assert run_scripted([case(path=("a", "b"))], graph).not_run == {"C1": reason}
    plan = run_scripted([case(path=("a", "b"))], graph, sv=survey(run_path=True))
    assert plan.jobs["C1"].use_run_path and plan.jobs["C1"].steps == ()
    # no edge at all gives the same reason
    nothing = make_graph([node("a", entry=True), node("b")], [uses("b", "pay")], entries=["a"])
    assert run_scripted([case(path=("a", "b"))], nothing).not_run == {"C1": reason}


def test_other_edge_kind() -> None:
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("remote"))
    assert plan.not_run == {"C1": "scripted mode cannot drive the remote edge from 'a' to 'b'"}
    # a handoff is only driven for the OpenAI Agents SDK
    sv = survey(agents={"a": AgentInfo(id="a", framework="pydantic_ai")})
    plan = run_scripted([case(path=("a", "b"))], two_agent_graph("handoff"), sv=sv)
    assert plan.not_run == {"C1": "scripted mode cannot drive the handoff edge from 'a' to 'b'"}


# ---- plan_scripted: expected and subject ----


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("user", {"type": "user", "id": "alice"}),
        ("agent", {"type": "agent", "id": "a"}),
        (
            "on_behalf_of",
            {"type": "user", "id": "alice", "act": {"type": "agent", "id": "a"}},
        ),
        (None, None),
    ],
)
def test_expected_and_user_subject(mode: Any, expected: Any) -> None:
    plan = run_scripted([case()], simple(mode))
    assert plan.expected == {"C1": expected}
    assert plan.jobs["C1"].subject["type"] == "user" and plan.jobs["C1"].subject["id"] == "alice"


# ---- observed_subjects ----


def job(case_id: str) -> ScriptedJob:
    return ScriptedJob(case_id=case_id, route=("a",), tool="pay", args={}, subject={})


def dc(who: str | None, kind: str = "agent") -> DoorCall:
    if who is None:
        return DoorCall(error="bad")
    return DoorCall(subject={"type": kind, "id": who}, decision=True)


def test_observed_subjects() -> None:
    plan = ScriptedPlan(jobs={c: job(c) for c in ("ok", "mixed", "none", "err", "skip", "gone")})
    seen = {
        "ok": Observed(door_calls=(dc("a"), dc("a"))),
        "mixed": Observed(door_calls=(dc("a"), dc("alice", "user"))),
        "none": Observed(),
        "err": Observed(door_calls=(dc("a"),), error="x"),
        "skip": Observed(door_calls=(dc(None), dc("b")), side_effect_calls=1),
        "other": Observed(door_calls=(dc("a"),)),
    }
    assert observed_subjects(plan, seen) == {
        "ok": {"type": "agent", "id": "a"},
        "skip": {"type": "agent", "id": "b"},
    }
    not_run = {"ok": Observed(door_calls=(dc("a"),), not_run="why")}
    assert observed_subjects(plan, not_run) == {}
    only_errors = {"ok": Observed(door_calls=(dc(None),))}
    assert observed_subjects(plan, only_errors) == {}


# ---- plan_direct ----


def outcome(**statuses: CaseStatus) -> PolicyOutcome:
    return PolicyOutcome(
        cases={k: CaseOutcome(status=v, decision=None) for k, v in statuses.items()},
        escalations=(),
        controls=(),
        errors=(),
        warnings=(),
        violations=(),
    )


def run_direct(
    planned: list[PlannedCase],
    graph: AgentGraph | None = None,
    *,
    sv: Survey | None = None,
    fx: FixturesFile | None = None,
    out: PolicyOutcome | None = None,
    modes: tuple[str, ...] = ("direct",),
) -> DirectPlan:
    graph = graph or simple()
    fx = fx or fixtures()
    return plan_direct(
        planned, questions(planned, graph, fx), out or outcome(), fx, sv or survey(), modes
    )


def test_direct_empty_plans() -> None:
    assert run_direct([case()], modes=("scripted",)) == DirectPlan()
    assert run_direct([case()], sv=survey(problems=("p",))) == DirectPlan()


def test_direct_job() -> None:
    plan = run_direct([case()])
    (one,) = plan.jobs["C1"]
    assert one.tool == "pay" and one.args == {"amount": 5}
    assert one.subject["type"] == "user" and one.subject["id"] == "alice"
    assert len(plan.queries["C1"]) == 1
    assert plan.not_tested == {} and plan.errors == {}


def test_direct_iam_error() -> None:
    plan = run_direct([case()], out=outcome(C1=CaseStatus.ERROR))
    assert plan.not_tested == {
        "C1": "the IAM part of this case is ERROR, so the door is not tested"
    }
    assert plan.jobs == {}


def test_direct_tool_rows() -> None:
    assert run_direct([case()], sv=survey(side_effects={})).not_tested == {
        "C1": "tool 'pay' is not in SIDE_EFFECTS"
    }
    assert run_direct([case()], sv=survey(tools={})).not_tested == {
        "C1": "tool 'pay' is not a Python tool lockwalk found; MCP tools are not door tested"
    }
    info = ToolInfo(name="pay", kind="agno", callable=False, why_not="agno needs a run")
    assert run_direct([case()], sv=survey(tools={"pay": info})).not_tested == {
        "C1": "agno needs a run"
    }
    assert run_direct([case()], fx=fixtures(None)).not_tested == {
        "C1": "resource fixture 'pay1' has no tool_args"
    }


def test_direct_args_error() -> None:
    info = ToolInfo(
        name="pay",
        kind="function",
        input_schema={"type": "object", "required": ["id"], "properties": {"id": {}}},
    )
    plan = run_direct([case()], sv=survey(tools={"pay": info}))
    assert plan.errors == {
        "C1": "tool_args do not match the input schema of 'pay': missing required argument 'id'"
    }
    assert plan.jobs == {}


def test_direct_undeclared_has_two_jobs_in_query_order() -> None:
    plan = run_direct([case()], simple(None))
    jobs = plan.jobs["C1"]
    assert [j.subject["type"] for j in jobs] == ["user", "agent"]
    assert [q.subject.type for q in plan.queries["C1"]] == ["user", "agent"]
    assert [j.subject["id"] for j in jobs] == [q.subject.id for q in plan.queries["C1"]]


def test_direct_skips_cases_with_problems() -> None:
    plan = run_direct([case(role="nobody")])
    assert plan.jobs == {} and plan.not_tested == {}


# ---- check_tool_args ----


def test_check_skipped() -> None:
    assert check_tool_args(None, {"x": 1}) == []
    assert check_tool_args({"type": "array", "required": ["x"]}, {}) == []
    assert check_tool_args({"required": ["x"]}, {}) == ["missing required argument 'x'"]


def test_check_missing_and_unexpected() -> None:
    schema = {"type": "object", "required": ["a", "b"], "properties": {"a": {}, "b": {}}}
    assert check_tool_args(schema, {"a": 1}) == ["missing required argument 'b'"]
    assert check_tool_args(schema, {"a": 1, "b": 2, "c": 3}) == []
    closed = {**schema, "additionalProperties": False}
    assert check_tool_args(closed, {"a": 1, "b": 2, "c": 3}) == ["unexpected argument 'c'"]


@pytest.mark.parametrize(
    ("kind", "good", "bad"),
    [
        ("string", "s", 1),
        ("integer", 1, True),
        ("integer", 1, 1.5),
        ("number", 1.5, True),
        ("number", 2, "2"),
        ("boolean", True, 1),
        ("array", [1], {}),
        ("object", {}, []),
        ("null", None, 0),
    ],
)
def test_check_types(kind: str, good: Any, bad: Any) -> None:
    schema = {"properties": {"x": {"type": kind}}}
    assert check_tool_args(schema, {"x": good}) == []
    assert check_tool_args(schema, {"x": bad}) == [f"argument 'x' must be {kind}"]


def test_check_unions_and_untyped() -> None:
    schema = {"properties": {"x": {"type": ["string", "null"]}, "y": {}, "z": {"type": 5}}}
    assert check_tool_args(schema, {"x": None, "y": object(), "z": 1}) == []
    assert check_tool_args(schema, {"x": 3}) == ["argument 'x' must be string or null"]
    assert check_tool_args({"properties": {"x": {"type": "integer"}}}, {"x": True}) != []
    assert check_tool_args({"properties": {"x": {"type": "number"}}}, {"x": 2}) == []
