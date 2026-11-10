"""judge_harness: door table, door controls, identity checks."""

from typing import Any

import pytest

from lockwalk.config import GateConfig
from lockwalk.harness.events import EventLog
from lockwalk.harness.plan import DirectPlan, ScriptedPlan
from lockwalk.harness.protocol import (
    AgentInfo,
    DirectJob,
    Observed,
    ScriptedJob,
    Survey,
    ToolInfo,
)
from lockwalk.harness.script import Script
from lockwalk.harness.verdicts import judge_harness, proves_door_control
from lockwalk.models import DoorCall, DoorStatus, IdentityResult, Risk
from lockwalk.policy.base import Decision, Entity, Query, QueryAction
from lockwalk.queries import CaseAsk, HopAsk, QueryPlan

ALICE = {"type": "user", "id": "alice"}
AGENT = {"type": "agent", "id": "finance-agent"}
ALLOW = Decision(verdict="allow")
DENY = Decision(verdict="deny")
ERR = Decision(verdict="error", error="boom")


def _query(subject_id: str = "alice", kind: str = "user", res: str = "r1") -> Query:
    return Query(
        subject=Entity(type=kind, id=subject_id),
        action=QueryAction(name="a:read"),
        resource=Entity(type="doc", id=res),
    )


def _case(
    cid: str = "C1",
    tool: str = "t",
    queries: tuple[Query, ...] | None = None,
    mode: Any = "user",
) -> CaseAsk:
    qs = queries or (_query(res=cid),)
    hop = HopAsk(
        caller="user", target=tool, kind="tool", mode=mode, queries=qs, control=("a:read", "doc")
    )
    return CaseAsk(
        case_id=cid,
        role="analyst",
        tool=tool,
        expect="allow",
        route=("finance-agent",),
        risk=Risk.LOW,
        hops=(hop,),
        plain_user=None,
    )


def _survey(**kw: Any) -> Survey:
    base: dict[str, Any] = {
        "side_effects": {"t": "m.f", "u": "m.g"},
        "door": True,
        "run_path": False,
        "tools": {
            "t": ToolInfo(name="t", kind="function"),
            "u": ToolInfo(name="u", kind="function"),
        },
        "agents": {"finance-agent": AgentInfo(id="finance-agent", framework="openai_agents")},
        "replaced": {"t": 1, "u": 1},
    }
    base.update(kw)
    return Survey(**base)


def _door(subject: dict[str, Any] | None = None, decision: bool = True) -> DoorCall:
    return DoorCall(subject=subject or ALICE, decision=decision)


def _sjob(cid: str = "C1", tool: str = "t") -> ScriptedJob:
    return ScriptedJob(case_id=cid, route=("finance-agent",), tool=tool, args={}, subject=ALICE)


def _djob(cid: str = "C1", tool: str = "t", subject: dict[str, Any] | None = None) -> DirectJob:
    return DirectJob(case_id=cid, tool=tool, args={}, subject=subject or ALICE)


def _run(
    cases: list[CaseAsk],
    answers: dict[str, Decision],
    *,
    survey: Survey | str | None = None,
    scripted_plan: ScriptedPlan | None = None,
    scripted: dict[str, Observed] | None = None,
    direct_plan: DirectPlan | None = None,
    direct: dict[str, tuple[Observed, ...]] | None = None,
    gate: GateConfig | None = None,
):
    return judge_harness(
        queries=QueryPlan(cases=tuple(cases), rows=(), warnings=()),
        answers=answers,
        survey=survey if survey is not None else _survey(),
        scripted_plan=scripted_plan or ScriptedPlan(),
        scripted=scripted or {},
        direct_plan=direct_plan or DirectPlan(),
        direct=direct or {},
        gate=gate or GateConfig(),
    )


def _direct_one(obs: Observed, iam: Decision, *, survey: Survey | None = None):
    case = _case()
    q = case.tool_hop.queries[0]
    return _run(
        [case],
        {q.key(): iam},
        survey=survey,
        direct_plan=DirectPlan(jobs={"C1": (_djob(),)}, queries={"C1": (q,)}),
        direct={"C1": (obs,)},
    )


def _scripted_one(obs: Observed, iam: Decision, *, expected: Any = ALICE, survey=None):
    case = _case()
    q = case.tool_hop.queries[0]
    return _run(
        [case],
        {q.key(): iam},
        survey=survey,
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": expected}),
        scripted={"C1": obs},
    )


def _status(out) -> DoorStatus:
    return out.doors["C1"].status


def _denied() -> Observed:
    return Observed(door_calls=(_door(decision=False),))


def _counted() -> Observed:
    return Observed(side_effect_calls=1, door_calls=(_door(),))


@pytest.mark.parametrize(
    ("obs", "iam", "status", "note"),
    [
        (Observed(error="the worker died"), ALLOW, DoorStatus.ERROR, "the worker died"),
        (
            Observed(door_calls=(DoorCall(error="bad door"),)),
            ALLOW,
            DoorStatus.ERROR,
            "the door recorder could not read a door call: bad door",
        ),
        (
            Observed(blocked_hosts=("a.example", "b.example")),
            DENY,
            DoorStatus.ERROR,
            "the code tried to connect to a.example, b.example; door tests block the network",
        ),
        (
            Observed(side_effect_calls=2),
            DENY,
            DoorStatus.FAIL_EXECUTION,
            "the IAM denied this, but the side effect of 't' ran 2 time(s)",
        ),
        (
            Observed(side_effect_calls=1, bypass=True),
            DENY,
            DoorStatus.FAIL_EXECUTION,
            "the IAM denied this, but the side effect of 't' ran 1 time(s) before the door "
            "asked the IAM",
        ),
        (
            Observed(side_effect_calls=1, bypass=True, door_calls=(_door(),)),
            ALLOW,
            DoorStatus.FAIL_EXECUTION,
            "the side effect of 't' ran before the door asked the IAM (the door was bypassed)",
        ),
        (_counted(), ALLOW, DoorStatus.OK, None),
        (
            Observed(door_calls=(_door(decision=False),)),
            ALLOW,
            DoorStatus.FAIL_EXECUTION,
            "the IAM allowed this, but the door denied it; the door may send the wrong identity",
        ),
        (
            Observed(door_calls=(_door(),)),
            ALLOW,
            DoorStatus.ERROR,
            "the IAM allowed this, but the side effect did not run and the door did not deny "
            "it; the tool failed for another reason",
        ),
    ],
)
def test_direct_run_table(obs, iam, status, note):
    out = _direct_one(obs, iam)
    result = out.doors["C1"]
    assert result.status is status
    run = result.runs[0]
    assert run.status is status and run.mode == "direct"
    if note is None:
        assert run.notes == ()
    else:
        assert run.notes[0] == note


def test_scripted_blocked_hosts_adds_the_fake_model_note():
    out = _scripted_one(Observed(blocked_hosts=("x.example",)), ALLOW)
    assert out.doors["C1"].runs[0].notes[0] == (
        "the code tried to connect to x.example; door tests block the network, "
        "so the fake model may not have taken effect"
    )
    assert out.errors == (
        "C1: door (scripted): the code tried to connect to x.example; door tests block the "
        "network, so the fake model may not have taken effect",
    )


def test_deny_with_zero_calls_is_ok_only_with_a_door_control():
    a, b = _case("A"), _case("B")
    qa, qb = a.tool_hop.queries[0], b.tool_hop.queries[0]
    out = _run(
        [a, b],
        {qa.key(): ALLOW, qb.key(): DENY},
        direct_plan=DirectPlan(
            jobs={"A": (_djob("A"),), "B": (_djob("B"),)}, queries={"A": (qa,), "B": (qb,)}
        ),
        direct={"A": (_counted(),), "B": (_denied(),)},
    )
    assert out.doors["B"].status is DoorStatus.OK
    assert [(c.tool, c.proven, c.proven_by) for c in out.door_controls] == [
        ("t", True, "A (direct)")
    ]


def test_deny_with_zero_calls_and_no_control_is_inconclusive():
    out = _direct_one(_denied(), DENY)
    assert _status(out) is DoorStatus.INCONCLUSIVE
    assert out.doors["C1"].runs[0].notes[0].startswith("no door control: the side effect of 't'")
    assert [(c.tool, c.proven, c.proven_by) for c in out.door_controls] == [("t", False, None)]
    assert out.errors == ()


def test_door_control_is_per_tool_sorted_and_scripted_comes_first():
    a, b = _case("A", tool="u"), _case("B", tool="t")
    qa, qb = a.tool_hop.queries[0], b.tool_hop.queries[0]
    out = _run(
        [a, b],
        {qa.key(): ALLOW, qb.key(): ALLOW},
        scripted_plan=ScriptedPlan(
            jobs={"A": _sjob("A", "u"), "B": _sjob("B", "t")}, expected={"A": None, "B": None}
        ),
        scripted={"A": _counted(), "B": _counted()},
        direct_plan=DirectPlan(jobs={"B": (_djob("B"),)}, queries={"B": (qb,)}),
        direct={"B": (_counted(),)},
    )
    assert [(c.tool, c.proven_by) for c in out.door_controls] == [
        ("t", "B (scripted)"),
        ("u", "A (scripted)"),
    ]


def test_allow_without_door_and_no_call_is_fail_execution():
    out = _direct_one(Observed(), ALLOW, survey=_survey(door=False))
    assert _status(out) is DoorStatus.FAIL_EXECUTION
    assert "without DOOR" in out.doors["C1"].runs[0].notes[0]


def test_allow_without_door_and_a_call_is_ok_and_bypass_is_ignored():
    out = _direct_one(Observed(side_effect_calls=1, bypass=True), ALLOW, survey=_survey(door=False))
    assert _status(out) is DoorStatus.OK


def test_iam_error_runs_are_not_recorded():
    out = _direct_one(Observed(side_effect_calls=1), ERR)
    assert "C1" not in out.doors
    assert out.errors == ()


def test_missing_answer_counts_as_error():
    case = _case()
    out = _run(
        [case],
        {},
        direct_plan=DirectPlan(
            jobs={"C1": (_djob(),)}, queries={"C1": (case.tool_hop.queries[0],)}
        ),
        direct={"C1": (Observed(),)},
    )
    assert "C1" not in out.doors


def test_exception_notes():
    out = _direct_one(
        Observed(side_effect_calls=1, exception="ValueError", exception_message="bad"), DENY
    )
    assert out.doors["C1"].runs[0].notes[1] == "the tool raised ValueError: bad"
    # OK rows get no exception note
    ok = _direct_one(Observed(side_effect_calls=1, exception="ValueError"), ALLOW)
    assert ok.doors["C1"].runs[0].notes == ()
    # frameworks that hide exceptions
    sv = _survey(tools={"t": ToolInfo(name="t", kind="agno")})
    hidden = _direct_one(Observed(side_effect_calls=1), DENY, survey=sv)
    assert hidden.doors["C1"].runs[0].notes[1] == (
        "agno hides tool exceptions, so the exception type is unknown"
    )
    sv2 = _survey(tools={"t": ToolInfo(name="t", kind="openai_agents")})
    hidden2 = _direct_one(Observed(side_effect_calls=1), DENY, survey=sv2)
    assert "openai_agents hides tool exceptions" in hidden2.doors["C1"].runs[0].notes[1]
    # a framework that does not hide them adds nothing
    plain = _direct_one(Observed(side_effect_calls=1), DENY)
    assert len(plain.doors["C1"].runs[0].notes) == 1


def _undeclared_case() -> CaseAsk:
    return _case(queries=(_query("alice"), _query("finance-agent", "agent")), mode="undeclared")


def test_undeclared_scripted_with_different_answers_is_not_judged():
    case = _undeclared_case()
    q1, q2 = case.tool_hop.queries
    out = _run(
        [case],
        {q1.key(): ALLOW, q2.key(): DENY},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": None}),
        scripted={"C1": _counted()},
    )
    result = out.doors["C1"]
    assert result.status is DoorStatus.NOT_TESTED and result.runs == ()
    assert result.notes == (
        "the IAM answers the user and the agent identity differently, so this run cannot be judged",
    )


def test_undeclared_scripted_with_the_same_answer_is_judged():
    case = _undeclared_case()
    q1, q2 = case.tool_hop.queries
    out = _run(
        [case],
        {q1.key(): ALLOW, q2.key(): ALLOW},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": None}),
        scripted={"C1": _counted()},
    )
    assert out.doors["C1"].status is DoorStatus.OK


def test_survey_failure_makes_every_case_error():
    for survey, text in (("boom", "boom"), (_survey(problems=("p1", "p2")), "p1; p2")):
        out = _run([_case("A"), _case("B")], {}, survey=survey)
        note = f"the door tests could not start: {text}"
        assert set(out.doors) == {"A", "B"}
        assert all(d.status is DoorStatus.ERROR and d.notes == (note,) for d in out.doors.values())
        assert out.errors == (f"A: door: {note}", f"B: door: {note}")
        assert out.identity_checks == () and out.door_controls == ()


def test_survey_failure_skips_cases_without_hops():
    bad = CaseAsk(
        case_id="X",
        role="r",
        tool="t",
        expect="allow",
        route=("a",),
        risk=Risk.LOW,
        hops=(),
        plain_user=None,
        problems=("bad",),
    )
    out = _run([bad], {}, survey="boom")
    assert out.doors == {}


def test_direct_plan_errors_and_not_tested():
    out = _run(
        [_case("A"), _case("B"), _case("C")],
        {},
        direct_plan=DirectPlan(
            errors={"A": "tool_args do not match"},
            not_tested={"B": "tool 't' is not in SIDE_EFFECTS"},
        ),
    )
    a, b = out.doors["A"], out.doors["B"]
    assert a.status is DoorStatus.ERROR and a.runs == () and a.notes == ("tool_args do not match",)
    assert b.status is DoorStatus.NOT_TESTED and b.runs == ()
    assert b.notes == ("direct: tool 't' is not in SIDE_EFFECTS",)
    assert "C" not in out.doors
    assert out.errors == ("A: door (direct): tool_args do not match",)


def test_scripted_not_run_notes_and_warning_grouping():
    out = _run(
        [_case("A"), _case("B"), _case("C")],
        {},
        scripted_plan=ScriptedPlan(
            not_run={"A": "r1", "B": "r2", "C": "r1"}, warnings=("plan warning",)
        ),
        survey=_survey(warnings=("survey warning",)),
    )
    assert out.doors["A"].notes == ("scripted: r1",)
    assert out.doors["A"].status is DoorStatus.NOT_TESTED
    assert out.warnings == (
        "survey warning",
        "plan warning",
        "scripted mode did not run 2 cases (A, C): r1",
        "scripted mode did not run 1 case (B): r2",
    )


def test_observed_not_run_is_a_note_and_a_warning():
    out = _scripted_one(Observed(not_run="no hook"), ALLOW)
    assert out.doors["C1"].notes == ("scripted: no hook",)
    assert out.doors["C1"].status is DoorStatus.NOT_TESTED
    assert out.warnings == ("scripted mode did not run 1 case (C1): no hook",)


def test_most_severe_run_wins_and_modes_combine():
    case = _case()
    q = case.tool_hop.queries[0]
    out = _run(
        [case],
        {q.key(): ALLOW},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": ALICE}),
        scripted={"C1": _counted()},
        direct_plan=DirectPlan(jobs={"C1": (_djob(),)}, queries={"C1": (q,)}),
        direct={"C1": (Observed(door_calls=(_door(decision=False),)),)},
    )
    result = out.doors["C1"]
    assert result.status is DoorStatus.FAIL_EXECUTION
    assert [r.mode for r in result.runs] == ["scripted", "direct"]


def test_plan_error_beats_ok_runs():
    case = _case()
    q = case.tool_hop.queries[0]
    out = _run(
        [case],
        {q.key(): ALLOW},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": ALICE}),
        scripted={"C1": _counted()},
        direct_plan=DirectPlan(errors={"C1": "bad args"}),
    )
    assert out.doors["C1"].status is DoorStatus.ERROR
    assert out.doors["C1"].notes == ("bad args",)


def test_missing_observed_is_an_error_run():
    out = _run(
        [_case()],
        {},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": None}),
    )
    assert out.doors["C1"].status is DoorStatus.ERROR


def test_undeclared_direct_has_two_jobs_in_order():
    case = _undeclared_case()
    q1, q2 = case.tool_hop.queries
    out = _run(
        [case],
        {q1.key(): ALLOW, q2.key(): DENY},
        direct_plan=DirectPlan(
            jobs={"C1": (_djob(), _djob(subject=AGENT))}, queries={"C1": (q1, q2)}
        ),
        direct={"C1": (_counted(), Observed(side_effect_calls=1))},
    )
    statuses = [r.status for r in out.doors["C1"].runs]
    assert statuses == [DoorStatus.OK, DoorStatus.FAIL_EXECUTION]


def test_identity_match_direct():
    out = _direct_one(_counted(), ALLOW)
    (row,) = out.identity_checks
    assert row.result is IdentityResult.MATCH
    assert row.case_id == "C1" and row.path == ("finance-agent",) and row.tool == "t"
    (obs,) = row.observations
    assert obs.mode == "direct" and obs.expected == ALICE and obs.observed == (ALICE,)
    assert out.violations == ()


def test_identity_mismatch_adds_violation_unless_gate_is_off():
    obs = Observed(side_effect_calls=1, door_calls=(_door(AGENT),))
    out = _direct_one(obs, ALLOW)
    assert out.identity_checks[0].result is IdentityResult.MISMATCH
    assert [(v.rule, v.case_id) for v in out.violations] == [("fail_on_identity_mismatch", "C1")]
    case = _case()
    q = case.tool_hop.queries[0]
    off = _run(
        [case],
        {q.key(): ALLOW},
        direct_plan=DirectPlan(jobs={"C1": (_djob(),)}, queries={"C1": (q,)}),
        direct={"C1": (obs,)},
        gate=GateConfig(fail_on_identity_mismatch=False),
    )
    assert off.identity_checks[0].result is IdentityResult.MISMATCH
    assert off.violations == ()


def test_identity_compares_only_type_id_and_act_chain():
    job_subject = {"type": "user", "id": "alice", "properties": {"roles": ["x"]}}
    case = _case()
    q = case.tool_hop.queries[0]
    out = _run(
        [case],
        {q.key(): ALLOW},
        direct_plan=DirectPlan(jobs={"C1": (_djob(subject=job_subject),)}, queries={"C1": (q,)}),
        direct={"C1": (_counted(),)},
    )
    assert out.identity_checks[0].result is IdentityResult.MATCH


def test_identity_scripted_observed_match_and_mismatch():
    obs = Observed(side_effect_calls=1, door_calls=(_door(AGENT),))
    (row,) = _scripted_one(obs, ALLOW, expected=None).identity_checks
    assert row.result is IdentityResult.OBSERVED
    assert row.observations[0].expected is None and row.observations[0].observed == (AGENT,)
    matched = _scripted_one(obs, ALLOW, expected=AGENT)
    assert matched.identity_checks[0].result is IdentityResult.MATCH
    mismatch = _scripted_one(obs, ALLOW, expected=ALICE)
    assert mismatch.identity_checks[0].result is IdentityResult.MISMATCH
    assert len(mismatch.violations) == 1


def test_identity_row_result_is_mismatch_over_match():
    case = _case()
    q = case.tool_hop.queries[0]
    out = _run(
        [case],
        {q.key(): ALLOW},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": ALICE}),
        scripted={"C1": _counted()},
        direct_plan=DirectPlan(jobs={"C1": (_djob(),)}, queries={"C1": (q,)}),
        direct={"C1": (Observed(side_effect_calls=1, door_calls=(_door(AGENT),)),)},
    )
    (row,) = out.identity_checks
    assert row.result is IdentityResult.MISMATCH
    assert [o.mode for o in row.observations] == ["direct", "scripted"]


def test_identity_not_run_without_door():
    out = _direct_one(Observed(side_effect_calls=1), ALLOW, survey=_survey(door=False))
    (row,) = out.identity_checks
    assert row.result is IdentityResult.NOT_RUN
    assert row.notes == (
        "no DOOR in the hooks file, so lockwalk cannot see which identity the door received",
    )
    assert out.violations == ()


def test_identity_door_not_called():
    d = _direct_one(Observed(side_effect_calls=1), ALLOW)
    assert d.identity_checks[0].result is IdentityResult.NOT_RUN
    assert d.identity_checks[0].notes == ("direct: the door was not called",)
    s = _scripted_one(Observed(side_effect_calls=1), ALLOW)
    assert s.identity_checks[0].notes == ("scripted: the door was not called for the tool",)


@pytest.mark.parametrize(
    "obs",
    [Observed(not_run="no hook"), Observed(error="boom"), None],
    ids=["not_run", "error", "none"],
)
def test_identity_scripted_without_usable_observation_is_noted(obs):
    case = _case()
    q = case.tool_hop.queries[0]
    out = _run(
        [case],
        {q.key(): ALLOW},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}, expected={"C1": ALICE}),
        scripted={"C1": obs} if obs is not None else {},
        direct_plan=DirectPlan(jobs={"C1": (_djob(),)}, queries={"C1": (q,)}),
        direct={"C1": (_counted(),)},
    )
    (row,) = out.identity_checks
    assert row.result is IdentityResult.MATCH
    assert "scripted: no usable observation" in row.notes


def test_tool_not_offered_scripted_run_cannot_be_ok():
    # no DOOR, IAM deny, a proven counter, and the tool was not offered
    a, b = _case("A"), _case("B")
    qa, qb = a.tool_hop.queries[0], b.tool_hop.queries[0]
    script = Script(
        ScriptedJob(case_id="B", route=("x",), tool="t", args={}, subject=ALICE), EventLog()
    )
    script.note("agent 'x' was not offered tool 't'")
    not_run = script.observation(door_configured=False).not_run
    assert not_run is not None
    observed = Observed(not_run=not_run)
    out = _run(
        [a, b],
        {qa.key(): ALLOW, qb.key(): DENY},
        survey=_survey(door=False),
        direct_plan=DirectPlan(jobs={"A": (_djob("A"),)}, queries={"A": (qa,)}),
        direct={"A": (_counted(),)},
        scripted_plan=ScriptedPlan(jobs={"B": _sjob("B")}, expected={"B": ALICE}),
        scripted={"B": observed},
    )
    assert out.doors["B"].status is not DoorStatus.OK
    assert out.doors["B"].runs == ()
    assert any("was not offered tool" in w for w in out.warnings)


def test_identity_row_for_not_run_and_not_tested_cases_only():
    out = _run(
        [_case("A"), _case("B"), _case("C")],
        {},
        scripted_plan=ScriptedPlan(not_run={"A": "r"}),
        direct_plan=DirectPlan(not_tested={"B": "why"}),
    )
    assert [(r.case_id, r.result) for r in out.identity_checks] == [
        ("A", IdentityResult.NOT_RUN),
        ("B", IdentityResult.NOT_RUN),
    ]


def test_no_modes_gives_nothing():
    out = _run([_case()], {})
    assert out.doors == {} and out.identity_checks == () and out.door_controls == ()


def test_door_controls_list_unproven_tools_too():
    a, b = _case("A", tool="u"), _case("B", tool="t")
    qa, qb = a.tool_hop.queries[0], b.tool_hop.queries[0]
    out = _run(
        [a, b],
        {qa.key(): DENY, qb.key(): ALLOW},
        direct_plan=DirectPlan(
            jobs={"A": (_djob("A", "u"),), "B": (_djob("B"),)}, queries={"A": (qa,), "B": (qb,)}
        ),
        direct={"A": (Observed(),), "B": (_counted(),)},
    )
    assert [(c.tool, c.proven, c.proven_by) for c in out.door_controls] == [
        ("t", True, "B (direct)"),
        ("u", False, None),
    ]


def test_deny_zero_calls_door_never_asked_is_error_p1():
    obs = Observed(exception="ValueError", exception_message="boom")
    out = _direct_one(obs, DENY)
    run = out.doors["C1"].runs[0]
    assert run.status is DoorStatus.ERROR
    assert run.notes[0] == (
        "the IAM denied this and the side effect did not run, but the door was never asked; "
        "the tool failed before reaching the door"
    )
    assert run.notes[1] == "the tool raised ValueError: boom"


def test_deny_zero_calls_door_allowed_is_fail_execution_p2():
    out = _direct_one(Observed(door_calls=(_door(decision=True),)), DENY)
    run = out.doors["C1"].runs[0]
    assert run.status is DoorStatus.FAIL_EXECUTION
    assert run.notes[0] == (
        "the IAM denied this, but the door allowed it; the side effect did not run only "
        "because the tool failed for another reason"
    )


def test_deny_zero_calls_door_denied_is_ok_when_proven_and_no_door_variants():
    a, b = _case("A"), _case("B")
    qa, qb = a.tool_hop.queries[0], b.tool_hop.queries[0]
    out = _run(
        [a, b],
        {qa.key(): ALLOW, qb.key(): DENY},
        direct_plan=DirectPlan(
            jobs={"A": (_djob("A"),), "B": (_djob("B"),)}, queries={"A": (qa,), "B": (qb,)}
        ),
        direct={"A": (_counted(),), "B": (_denied(),)},
        survey=_survey(door=False),
    )
    # without DOOR the zero-call deny is judged by the control alone
    assert out.doors["B"].status is DoorStatus.OK
    lone = _direct_one(Observed(), DENY, survey=_survey(door=False))
    assert lone.doors["C1"].status is DoorStatus.INCONCLUSIVE


def test_missing_expected_is_an_internal_error_and_not_run():
    case = _case()
    q = case.tool_hop.queries[0]
    out = _run(
        [case],
        {q.key(): ALLOW},
        scripted_plan=ScriptedPlan(jobs={"C1": _sjob()}),
        scripted={"C1": _counted()},
    )
    assert out.errors == (
        "C1: door: internal error: no expected identity was planned for the scripted run",
    )
    assert out.identity_checks[0].result is IdentityResult.NOT_RUN
    assert out.violations == ()


def test_a_run_with_blocked_hosts_or_door_errors_does_not_prove_the_tool():
    blocked = Observed(side_effect_calls=1, blocked_hosts=("x.example",))
    out = _direct_one(blocked, ALLOW)
    assert [(c.tool, c.proven, c.proven_by) for c in out.door_controls] == [("t", False, None)]
    bad_door = Observed(side_effect_calls=1, door_calls=(DoorCall(error="bad"),))
    out2 = _direct_one(bad_door, ALLOW)
    assert out2.door_controls[0].proven is False


def test_proves_door_control() -> None:
    ok_call = DoorCall(subject={"type": "user", "id": "a"}, decision=True)
    assert proves_door_control(Observed(side_effect_calls=1, door_calls=(ok_call,)))
    assert not proves_door_control(Observed(side_effect_calls=0))
    assert not proves_door_control(Observed(side_effect_calls=1, blocked_hosts=("x",)))
    assert not proves_door_control(
        Observed(side_effect_calls=1, door_calls=(DoorCall(error="bad"),))
    )
    assert not proves_door_control(Observed(side_effect_calls=1, error="boom"))
    assert not proves_door_control(Observed(side_effect_calls=1, not_run="x"))
