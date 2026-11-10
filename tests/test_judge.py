from lockwalk.config import GateConfig
from lockwalk.judge import PolicyOutcome, judge
from lockwalk.models import (
    CaseStatus,
    EscalationResult,
    Expectation,
    GateViolation,
    IdentityMode,
    PathVerdict,
    Risk,
    Verdict,
)
from lockwalk.policy.base import Decision, Entity, Query, QueryAction, error_decision
from lockwalk.queries import CaseAsk, ControlKey, HopAsk, QueryPlan, RowAsk

NO_CONTROL_NOTE = (
    "no positive control: no question about {action} on {rtype} got an allow in this run, "
    "so lockwalk cannot tell that the IAM understood it; add a case the IAM should allow"
)
HINT = "the IAM allows the user but denies the identity the route uses; normal use may fail"


def q(subject_id: str, action: str = "x:y", rtype: str = "r") -> Query:
    return Query(
        subject=Entity(type="user", id=subject_id),
        action=QueryAction(name=action),
        resource=Entity(type=rtype, id="res"),
    )


def answer(verdict: Verdict, error: str | None = None) -> Decision:
    if verdict is Verdict.ERROR:
        return error_decision(error or "boom")
    return Decision(verdict=verdict, reason="because", latency_ms=1.5)


ALLOW = Verdict.ALLOW
DENY = Verdict.DENY
ERR = Verdict.ERROR


def answers_for(pairs: list[tuple[Query, Decision]]) -> dict[str, Decision]:
    return {query.key(): decision for query, decision in pairs}


def tool_hop(
    queries: tuple[Query, ...],
    mode: IdentityMode = "user",
    control: ControlKey = ("x:y", "r"),
    caller: str = "user",
    target: str = "tool1",
) -> HopAsk:
    return HopAsk(
        caller=caller,
        target=target,
        kind="tool",
        mode=mode,
        queries=queries,
        control=control,
    )


def agent_hop(query: Query, caller: str = "user", target: str = "agent1") -> HopAsk:
    return HopAsk(
        caller=caller,
        target=target,
        kind="agent",
        mode="user",
        queries=(query,),
        control=("agent:invoke", "agent"),
    )


def case(
    case_id: str,
    expect: Expectation,
    hops: tuple[HopAsk, ...],
    plain_user: Query | None = None,
    route: tuple[str, ...] = ("agent1",),
    problems: tuple[str, ...] = (),
    role: str = "analyst",
    risk: Risk = Risk.HIGH,
) -> CaseAsk:
    return CaseAsk(
        case_id=case_id,
        role=role,
        tool="tool1",
        expect=expect,
        route=route,
        risk=risk,
        hops=hops,
        plain_user=plain_user,
        problems=problems,
    )


def simple_case(case_id: str, expect: Expectation, query: Query) -> CaseAsk:
    return case(case_id, expect, (tool_hop((query,)),))


def plan(cases: tuple[CaseAsk, ...] = (), rows: tuple[RowAsk, ...] = ()) -> QueryPlan:
    return QueryPlan(cases=cases, rows=rows, warnings=())


def row(
    role: str = "analyst",
    tool: str = "tool1",
    via: str = "agent1",
    risk: Risk = Risk.HIGH,
    mode: IdentityMode = "agent",
    path_query: Query | None = None,
    user_query: Query | None = None,
    control: ControlKey | None = ("x:y", "r"),
    unchecked: str | None = None,
) -> RowAsk:
    return RowAsk(
        role=role,
        tool=tool,
        via=via,
        risk=risk,
        mode=mode,
        path=(via,),
        path_query=path_query,
        user_query=user_query,
        control=control,
        unchecked=unchecked,
    )


def run(
    queries: QueryPlan,
    pairs: list[tuple[Query, Decision]],
    gate: GateConfig | None = None,
) -> PolicyOutcome:
    return judge(queries, answers_for(pairs), gate or GateConfig())


def test_allow_allow_passes() -> None:
    a = q("a")
    out = run(plan((simple_case("C1", "allow", a),)), [(a, answer(ALLOW))])
    outcome = out.cases["C1"]
    assert outcome.status is CaseStatus.PASS
    assert outcome.decision is not None
    assert outcome.decision.verdict is PathVerdict.ALLOW
    hop = outcome.decision.hops[0]
    assert hop.verdict is PathVerdict.ALLOW
    assert hop.answers[0].subject == {"type": "user", "id": "a", "properties": {}}
    assert hop.answers[0].reason == "because"
    assert hop.answers[0].latency_ms == 1.5
    assert out.violations == ()
    assert not out.untrusted


def test_deny_deny_with_control_from_another_case_passes() -> None:
    a, b = q("a"), q("b")
    cases = (simple_case("C1", "allow", a), simple_case("C2", "deny", b))
    out = run(plan(cases), [(a, answer(ALLOW)), (b, answer(DENY))])
    assert out.cases["C2"].status is CaseStatus.PASS
    assert out.violations == ()


def test_deny_deny_without_control_is_inconclusive() -> None:
    b = q("b")
    out = run(plan((simple_case("C2", "deny", b),)), [(b, answer(DENY))])
    outcome = out.cases["C2"]
    assert outcome.status is CaseStatus.INCONCLUSIVE
    assert outcome.notes == (NO_CONTROL_NOTE.format(action="x:y", rtype="r"),)
    assert out.violations == (
        GateViolation(
            rule="fail_on_inconclusive_case", case_id="C2", status=CaseStatus.INCONCLUSIVE
        ),
    )
    off = run(
        plan((simple_case("C2", "deny", b),)),
        [(b, answer(DENY))],
        GateConfig(fail_on_inconclusive_case=False),
    )
    assert off.cases["C2"].status is CaseStatus.INCONCLUSIVE
    assert off.violations == ()


def test_mismatches_are_fail_policy() -> None:
    a, b = q("a"), q("b")
    cases = (simple_case("C1", "deny", a), simple_case("C2", "allow", b))
    out = run(plan(cases), [(a, answer(ALLOW)), (b, answer(DENY))])
    assert out.cases["C1"].status is CaseStatus.FAIL_POLICY
    assert out.cases["C1"].notes == ("expected deny, but the IAM allowed it",)
    assert out.cases["C2"].status is CaseStatus.FAIL_POLICY
    assert out.cases["C2"].notes == ("expected allow, but the IAM denied user -> tool1",)
    assert out.violations == (
        GateViolation(rule="case", case_id="C1", status=CaseStatus.FAIL_POLICY),
        GateViolation(rule="case", case_id="C2", status=CaseStatus.FAIL_POLICY),
    )


def undeclared_case(expect: Expectation, user: Query, agent: Query) -> CaseAsk:
    hop = tool_hop((user, agent), mode="undeclared")
    return case("C1", expect, (hop,), plain_user=user)


def test_undeclared_differing_answers_are_inconclusive() -> None:
    user, agent = q("u"), q("ag")
    out = run(
        plan((undeclared_case("allow", user, agent),)),
        [(user, answer(DENY)), (agent, answer(ALLOW))],
    )
    outcome = out.cases["C1"]
    assert outcome.status is CaseStatus.INCONCLUSIVE
    assert outcome.notes == (
        "the delegation_mode of 'user' is not declared, and the IAM answers the user and the "
        "agent identity differently; declare delegation_mode in the registry",
    )
    assert outcome.decision is not None
    assert outcome.decision.verdict is PathVerdict.UNKNOWN
    assert outcome.decision.hops[0].verdict is PathVerdict.UNKNOWN
    assert len(outcome.decision.hops[0].answers) == 2


def test_undeclared_agreeing_answers_are_judged_normally() -> None:
    user, agent = q("u"), q("ag")
    out = run(
        plan((undeclared_case("allow", user, agent),)),
        [(user, answer(ALLOW)), (agent, answer(ALLOW))],
    )
    assert out.cases["C1"].status is CaseStatus.PASS
    out = run(
        plan((undeclared_case("allow", user, agent),)),
        [(user, answer(DENY)), (agent, answer(DENY))],
    )
    assert out.cases["C1"].status is CaseStatus.FAIL_POLICY


def test_denied_agent_hop_gives_deny_with_denied_hop_and_control() -> None:
    hop_q, tool_q, ok = q("h", "agent:invoke", "agent"), q("t"), q("ok", "agent:invoke", "agent")
    c1 = case(
        "C1",
        "deny",
        (agent_hop(hop_q, "user", "agent1"), tool_hop((tool_q,), caller="agent1")),
        route=("agent1",),
    )
    # No allow for (agent:invoke, agent) yet: the expected deny is inconclusive.
    out = run(plan((c1,)), [(hop_q, answer(DENY)), (tool_q, answer(ALLOW))])
    decision = out.cases["C1"].decision
    assert decision is not None
    assert decision.verdict is PathVerdict.DENY
    assert decision.denied_hop == "user -> agent1"
    assert out.cases["C1"].status is CaseStatus.INCONCLUSIVE
    assert out.cases["C1"].notes == (NO_CONTROL_NOTE.format(action="agent:invoke", rtype="agent"),)
    # An allow for the pair from another agent hop makes it PASS.
    c3 = case(
        "C3",
        "allow",
        (agent_hop(ok, "user", "agent2"), tool_hop((tool_q,), caller="agent2")),
    )
    out = run(
        plan((c1, c3)),
        [(hop_q, answer(DENY)), (tool_q, answer(ALLOW)), (ok, answer(ALLOW))],
    )
    assert out.cases["C1"].status is CaseStatus.PASS


def test_definite_deny_beats_unknown_hop() -> None:
    u, ag, d, t = q("u"), q("ag"), q("d"), q("t")
    unknown_hop = HopAsk(
        caller="user",
        target="agent1",
        kind="agent",
        mode="undeclared",
        queries=(u, ag),
        control=("agent:invoke", "agent"),
    )
    deny_hop = agent_hop(d, "agent1", "agent2")
    c = case("C1", "allow", (unknown_hop, deny_hop, tool_hop((t,), caller="agent2")))
    out = run(
        plan((c,)),
        [(u, answer(DENY)), (ag, answer(ALLOW)), (d, answer(DENY)), (t, answer(ALLOW))],
    )
    decision = out.cases["C1"].decision
    assert decision is not None
    assert decision.verdict is PathVerdict.DENY
    assert decision.denied_hop == "agent1 -> agent2"
    assert out.cases["C1"].status is CaseStatus.FAIL_POLICY
    assert out.cases["C1"].notes == ("expected allow, but the IAM denied agent1 -> agent2",)


def test_error_answer_makes_error_case_and_untrusted() -> None:
    a = q("a")
    out = run(plan((simple_case("C1", "allow", a),)), [(a, answer(ERR, "timed out"))])
    outcome = out.cases["C1"]
    assert outcome.status is CaseStatus.ERROR
    assert outcome.problems == ("user -> tool1: timed out",)
    assert outcome.decision is not None
    assert outcome.decision.verdict is PathVerdict.ERROR
    assert out.errors == ("C1: user -> tool1: timed out",)
    assert out.untrusted
    assert out.violations == ()


def test_missing_answer_is_an_error() -> None:
    a = q("a")
    out = run(plan((simple_case("C1", "allow", a),)), [])
    assert out.cases["C1"].status is CaseStatus.ERROR
    assert out.cases["C1"].problems == ("user -> tool1: no answer was recorded for this question",)
    assert out.untrusted


def test_case_with_problems_is_error_without_decision() -> None:
    c = case("C1", "allow", (), problems=("no resource type", "bad role"))
    out = run(plan((c,)), [])
    outcome = out.cases["C1"]
    assert outcome.status is CaseStatus.ERROR
    assert outcome.decision is None
    assert outcome.problems == ("no resource type", "bad role")
    assert out.errors == ("C1: no resource type", "C1: bad role")
    assert out.escalations == ()


def test_error_in_undeclared_hop_beats_differing_answers() -> None:
    user, agent = q("u"), q("ag")
    out = run(
        plan((undeclared_case("allow", user, agent),)),
        [(user, answer(ERR, "e1")), (agent, answer(ALLOW))],
    )
    assert out.cases["C1"].status is CaseStatus.ERROR
    assert out.cases["C1"].problems == ("user -> tool1: e1",)


def escalation_case(
    expect: Expectation = "allow", mode: IdentityMode = "agent"
) -> tuple[CaseAsk, Query, Query]:
    user, path = q("user1"), q("agent1")
    if mode == "undeclared":
        hop = tool_hop((user, path), mode=mode)
    else:
        hop = tool_hop((path,), mode=mode)
    return case("C1", expect, (hop,), plain_user=user, route=("agent1",)), user, path


def test_escalation_table_for_case_rows() -> None:
    cases = {
        (DENY, ALLOW): (
            EscalationResult.ESCALATION,
            "the IAM denies the user but allows the identity the route uses",
        ),
        (ALLOW, ALLOW): (EscalationResult.NONE, None),
        (ALLOW, DENY): (EscalationResult.NONE, HINT),
    }
    for (u_verdict, p_verdict), (result, note) in cases.items():
        c, user, path = escalation_case()
        out = run(plan((c,)), [(user, answer(u_verdict)), (path, answer(p_verdict))])
        (esc,) = out.escalations
        assert esc.result is result, (u_verdict, p_verdict)
        assert esc.notes == ((note,) if note else ())
        assert esc.case_id == "C1"
        assert esc.via == "agent1"
        assert esc.path == ("agent1",)
        assert esc.mode == "agent"
        assert esc.role == "analyst"
        assert esc.risk is Risk.HIGH
        assert esc.user_answer is not None and esc.user_answer.verdict is u_verdict
        assert esc.path_answer is not None and esc.path_answer.verdict is p_verdict


def test_escalation_deny_deny_needs_control() -> None:
    c, user, path = escalation_case(expect="deny")
    out = run(plan((c,)), [(user, answer(DENY)), (path, answer(DENY))])
    (esc,) = out.escalations
    assert esc.result is EscalationResult.INCONCLUSIVE
    assert esc.notes == (NO_CONTROL_NOTE.format(action="x:y", rtype="r"),)
    other = q("other")
    c2 = simple_case("C2", "allow", other)
    out = run(
        plan((c, c2)),
        [(user, answer(DENY)), (path, answer(DENY)), (other, answer(ALLOW))],
    )
    assert out.escalations[0].result is EscalationResult.NONE
    assert out.escalations[0].notes == ()


def test_escalation_undeclared_uses_agent_query_and_is_inconclusive() -> None:
    c, user, path = escalation_case(mode="undeclared")
    out = run(plan((c,)), [(user, answer(DENY)), (path, answer(ALLOW))])
    (esc,) = out.escalations
    assert esc.mode == "undeclared"
    assert esc.result is EscalationResult.INCONCLUSIVE
    assert esc.notes == (
        "if 'agent1' calls the tool with its own identity, this is an escalation; "
        "declare its delegation_mode",
    )
    assert esc.path_answer is not None
    assert esc.path_answer.subject["id"] == "agent1"
    assert esc.user_answer is not None
    assert esc.user_answer.subject["id"] == "user1"
    assert out.violations == (
        GateViolation(
            rule="fail_on_inconclusive_case", case_id="C1", status=CaseStatus.INCONCLUSIVE
        ),
        GateViolation(
            rule="fail_on_inconclusive_escalation",
            case_id="C1",
            role="analyst",
            tool="tool1",
            via="agent1",
        ),
    )


def test_escalation_error_either_side() -> None:
    c, user, path = escalation_case()
    out = run(plan((c,)), [(user, answer(ERR, "user broke")), (path, answer(ALLOW))])
    (esc,) = out.escalations
    assert esc.result is EscalationResult.ERROR
    assert esc.notes == ("user identity: user broke",)
    assert out.errors == ("escalation C1: user identity: user broke",)
    assert out.cases["C1"].status is CaseStatus.PASS
    out = run(plan((c,)), [(user, answer(ALLOW)), (path, answer(ERR, "path broke"))])
    assert out.escalations[0].notes == ("route identity: path broke",)
    assert out.cases["C1"].status is CaseStatus.ERROR
    # The case is already ERROR: no extra escalation line.
    assert out.errors == ("C1: user -> tool1: path broke",)


def test_row_escalations_and_unchecked() -> None:
    p, u = q("agent1"), q("user1")
    r = row(path_query=p, user_query=u)
    out = run(plan(rows=(r,)), [(p, answer(ALLOW)), (u, answer(DENY))])
    (esc,) = out.escalations
    assert esc.case_id is None
    assert esc.result is EscalationResult.ESCALATION
    assert out.violations == (
        GateViolation(rule="fail_on_escalation", role="analyst", tool="tool1", via="agent1"),
    )
    off = run(
        plan(rows=(r,)),
        [(p, answer(ALLOW)), (u, answer(DENY))],
        GateConfig(fail_on_escalation=False),
    )
    assert off.violations == ()
    un = row(
        path_query=None, user_query=None, control=None, unchecked="no resource", risk=Risk.CRITICAL
    )
    out = run(plan(rows=(un,)), [])
    (esc,) = out.escalations
    assert esc.result is EscalationResult.UNCHECKED
    assert esc.notes == ("no resource",)
    assert esc.user_answer is None and esc.path_answer is None
    assert out.violations == (
        GateViolation(
            rule="fail_on_unchecked_escalation",
            role="analyst",
            tool="tool1",
            via="agent1",
            risk=Risk.CRITICAL,
        ),
    )
    assert out.warnings == ()


def test_unchecked_rows_not_gated_warn_once_per_role() -> None:
    rows = (
        row(role="r1", tool="t1", via="a1", unchecked="x", control=None, risk=Risk.LOW),
        row(role="r2", tool="t1", via="a1", unchecked="x", control=None, risk=Risk.LOW),
        row(role="r1", tool="t2", via="a2", unchecked="x", control=None, risk=Risk.MEDIUM),
    )
    out = run(plan(rows=rows), [])
    assert out.violations == ()
    assert out.warnings == (
        "role 'r1': 2 escalation checks not run: t1 via a1, t2 via a2",
        "role 'r2': 1 escalation check not run: t1 via a1",
    )
    assert not out.untrusted


def test_hint_warning_for_cases_and_rows() -> None:
    c, user, path = escalation_case()
    p, u = q("agent9"), q("user9")
    r = row(role="ro", tool="to", via="ag", path_query=p, user_query=u)
    out = run(
        plan((c,), (r,)),
        [(user, answer(ALLOW)), (path, answer(DENY)), (p, answer(DENY)), (u, answer(ALLOW))],
    )
    assert out.warnings == (f"C1: {HINT}", f"ro/to via ag: {HINT}")
    assert all(e.result is EscalationResult.NONE for e in out.escalations)


def test_row_error_adds_error_line_with_label() -> None:
    p, u = q("agent1"), q("user1")
    r = row(path_query=p, user_query=u)
    out = run(plan(rows=(r,)), [(p, answer(ERR, "e1")), (u, answer(ERR, "e2"))])
    assert out.escalations[0].result is EscalationResult.ERROR
    assert out.errors == (
        "escalation analyst/tool1 via agent1: user identity: e2",
        "escalation analyst/tool1 via agent1: route identity: e1",
    )
    assert len(out.escalations[0].notes) == 2


def test_control_rows_sorted_with_allowed_by_forms() -> None:
    hq, tq, allow_q = q("h", "agent:invoke", "agent"), q("t", "z:z", "zz"), q("al", "a:a", "aa")
    c1 = case(
        "C1",
        "allow",
        (agent_hop(hq, "user", "agent1"), tool_hop((tq,), control=("z:z", "zz"), caller="agent1")),
    )
    c2 = case("C2", "allow", (tool_hop((allow_q,), control=("a:a", "aa")),))
    rp, ru = q("rp", "m:m", "mm"), q("ru", "m:m", "mm")
    r = row(role="ro", tool="to", via="ag", path_query=rp, user_query=ru, control=("m:m", "mm"))
    never = q("never", "n:n", "nn")
    c3 = case("C3", "deny", (tool_hop((never,), control=("n:n", "nn")),))
    un = row(unchecked="why", control=None)
    out = run(
        plan((c1, c2, c3), (r, un)),
        [
            (hq, answer(ALLOW)),
            (tq, answer(DENY)),
            (allow_q, answer(ALLOW)),
            (rp, answer(DENY)),
            (ru, answer(ALLOW)),
            (never, answer(DENY)),
        ],
    )
    got = [(c.action, c.resource_type, c.allowed, c.allowed_by) for c in out.controls]
    assert got == [
        ("a:a", "aa", True, "C2"),
        ("agent:invoke", "agent", True, "C1 (user -> agent1)"),
        ("m:m", "mm", True, "ro/to via ag"),
        ("n:n", "nn", False, None),
        ("z:z", "zz", False, None),
    ]


def test_control_allowed_by_plain_user_and_first_allow_order() -> None:
    # Case C1 denies its tool hop but its plain_user is allowed: that counts for the pair.
    path, user = q("p"), q("u")
    c1 = case("C1", "deny", (tool_hop((path,), mode="agent"),), plain_user=user)
    second = q("second")
    c2 = simple_case("C2", "allow", second)
    out = run(
        plan((c2, c1)),
        [(path, answer(DENY)), (user, answer(ALLOW)), (second, answer(ALLOW))],
    )
    assert [(c.allowed, c.allowed_by) for c in out.controls] == [(True, "C2")]
    out = run(plan((c1,)), [(path, answer(DENY)), (user, answer(ALLOW))])
    assert [(c.allowed, c.allowed_by) for c in out.controls] == [(True, "C1")]
    assert out.cases["C1"].status is CaseStatus.PASS


def test_control_error_answer_does_not_allow() -> None:
    a = q("a")
    out = run(plan((simple_case("C1", "allow", a),)), [(a, answer(ERR))])
    assert [(c.allowed, c.allowed_by) for c in out.controls] == [(False, None)]


def test_full_violation_order() -> None:
    fp, inc = q("fp"), q("inc")
    c_fail = simple_case("C1", "deny", fp)
    c_inc = case("C2", "deny", (tool_hop((inc,), control=("o:o", "oo")),))
    pa, ua = q("agentA"), q("userA")
    r_esc = row(role="r1", via="a1", path_query=pa, user_query=ua)
    pb, ub = q("agentB"), q("userB")
    r_inc = row(role="r2", via="a2", path_query=pb, user_query=ub, mode="undeclared")
    r_unc = row(role="r3", via="a3", unchecked="why", control=None, risk=Risk.UNKNOWN)
    out = run(
        plan((c_fail, c_inc), (r_esc, r_inc, r_unc)),
        [
            (fp, answer(ALLOW)),
            (inc, answer(DENY)),
            (pa, answer(ALLOW)),
            (ua, answer(DENY)),
            (pb, answer(ALLOW)),
            (ub, answer(DENY)),
        ],
    )
    assert [(v.rule, v.case_id, v.role) for v in out.violations] == [
        ("case", "C1", None),
        ("fail_on_inconclusive_case", "C2", None),
        ("fail_on_escalation", None, "r1"),
        ("fail_on_inconclusive_escalation", None, "r2"),
        ("fail_on_unchecked_escalation", None, "r3"),
    ]


def test_empty_plan_gives_an_empty_outcome() -> None:
    out = run(plan(), [])
    assert out.cases == {} and out.escalations == () and out.controls == ()
    assert out.errors == () and out.warnings == () and out.violations == ()
    assert not out.untrusted


def test_empty_hops_without_problems_is_error_not_pass() -> None:
    c = case("C1", "allow", ())
    out = run(plan((c,)), [])
    outcome = out.cases["C1"]
    assert outcome.status is CaseStatus.ERROR
    assert outcome.decision is None
    assert outcome.problems == ("no questions were built for this case",)
    assert out.errors == ("C1: no questions were built for this case",)
    assert out.escalations == ()
    assert out.untrusted


def test_unchecked_row_with_queries_present_is_unchecked() -> None:
    p, u = q("agent1"), q("user1")
    r = row(path_query=p, user_query=u, unchecked="no resource")
    out = run(plan(rows=(r,)), [(p, answer(ALLOW)), (u, answer(DENY))])
    (esc,) = out.escalations
    assert esc.result is EscalationResult.UNCHECKED
    assert esc.notes == ("no resource",)
    assert esc.user_answer is None and esc.path_answer is None


def test_row_with_missing_query_is_unchecked() -> None:
    p = q("agent1")
    r = row(path_query=p, user_query=None)
    out = run(plan(rows=(r,)), [(p, answer(ALLOW))])
    (esc,) = out.escalations
    assert esc.result is EscalationResult.UNCHECKED
    assert esc.notes == ("this route was not checked",)


def test_errors_order_case_errors_before_escalation_errors() -> None:
    bad = q("bad")
    c1 = simple_case("C1", "allow", bad)
    c2, user, path = escalation_case()
    c2 = case("C2", "allow", c2.hops, plain_user=user, route=c2.route)
    p, u = q("rp"), q("ru")
    r = row(path_query=p, user_query=u)
    out = run(
        plan((c2, c1), (r,)),
        [
            (bad, answer(ERR, "x")),
            (user, answer(ERR, "ue")),
            (path, answer(ALLOW)),
            (p, answer(ALLOW)),
            (u, answer(ERR, "re")),
        ],
    )
    assert out.errors == (
        "C1: user -> tool1: x",
        "escalation C2: user identity: ue",
        "escalation analyst/tool1 via agent1: user identity: re",
    )


def test_warnings_order_hints_before_unchecked() -> None:
    un = row(role="r0", tool="t0", via="a0", unchecked="x", control=None, risk=Risk.LOW)
    p, u = q("rp"), q("ru")
    hint_row = row(role="r1", tool="t1", via="a1", path_query=p, user_query=u)
    out = run(plan(rows=(un, hint_row)), [(p, answer(DENY)), (u, answer(ALLOW))])
    assert out.warnings == (
        f"r1/t1 via a1: {HINT}",
        "role 'r0': 1 escalation check not run: t0 via a0",
    )


def test_violations_order_cases_then_rows_mixed() -> None:
    fp = q("fp")
    c1 = simple_case("C1", "deny", fp)
    user, agent = q("u"), q("ag")
    c2 = undeclared_case("allow", user, agent)
    c2 = case("C2", "allow", c2.hops, plain_user=user)
    unc = row(role="ra", via="aa", unchecked="x", control=None, risk=Risk.CRITICAL)
    pb, ub = q("pb"), q("ub")
    esc = row(role="rb", via="ab", path_query=pb, user_query=ub)
    pc, uc = q("pc"), q("uc")
    inc = row(role="rc", via="ac", path_query=pc, user_query=uc, control=("o:o", "oo"))
    out = run(
        plan((c1, c2), (unc, esc, inc)),
        [
            (fp, answer(ALLOW)),
            (user, answer(DENY)),
            (agent, answer(ALLOW)),
            (pb, answer(ALLOW)),
            (ub, answer(DENY)),
            (pc, answer(DENY)),
            (uc, answer(DENY)),
        ],
    )
    assert [(v.rule, v.case_id, v.role) for v in out.violations] == [
        ("case", "C1", None),
        ("fail_on_inconclusive_case", "C2", None),
        ("fail_on_inconclusive_escalation", "C2", "analyst"),
        ("fail_on_unchecked_escalation", None, "ra"),
        ("fail_on_escalation", None, "rb"),
        ("fail_on_inconclusive_escalation", None, "rc"),
    ]
