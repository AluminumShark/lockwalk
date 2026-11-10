"""Guard rows and the gate's guard and identity keys."""

import time

import pytest
from observe_helpers import catalog

from lockwalk.config import GateConfig
from lockwalk.models import Risk
from lockwalk.observe.checks import guard_findings, observe_gate
from lockwalk.observe.door import DoorRecord, decision_only
from lockwalk.observe.links import RecordLink, TraceLinks
from lockwalk.observe.results import GuardRow, IdentityRow, ObserveViolation
from lockwalk.observe.spans import Span
from lockwalk.observe.tree import build_traces

T = "0" * 31 + "1"
CAT = catalog()


def door(decision="allow"):
    return DoorRecord(decision, "user", "u", (), "act", None, None)


def spans_for(*calls, trace=T, agent="trade-agent"):
    """calls: (span id, tool name). Each call sits under one agent span "a"."""
    out = [Span(trace, "a", None, "agent", name=agent)]
    out += [Span(trace, sid, "a", "tool", name=name) for sid, name in calls]
    return out


def _ambiguous(links):
    return frozenset(c for link in links if link.kind == "ambiguous" for c in link.candidates)


def make_links(trace, records=(), effects=()):
    """The one place that builds TraceLinks; the hand-built candidates give the ambiguous sets."""
    records, effects = tuple(records), tuple(effects)
    return TraceLinks(
        trace,
        records,
        effects,
        0,
        ambiguous_calls=_ambiguous(records),
        ambiguous_effect_calls=_ambiguous(effects),
    )


def rec(span_id, kind="ancestry", call=None, candidates=()):
    return RecordLink(span_id, kind, call, tuple(candidates), None, False, None, False)


def guard(spans, records=(), effects=(), cat=CAT, trace=T):
    views = build_traces(spans, cat)
    links = [make_links(trace, records, effects)]
    return guard_findings(views, links, cat)


def with_records(spans, *items):
    """Add a record span (decision) for every (record id, decision)."""
    return spans + [Span(T, rid, None, "other", door=door(dec)) for rid, dec in items]


def one(rows):
    assert len(rows) == 1
    return rows[0]


def test_guarded():
    spans = with_records(spans_for(("c", "execute_trade")), ("r", "allow"))
    row = one(guard(spans, [rec("r", call="c")]))
    assert (row.agent, row.tool, row.tool_known) == ("trade-agent", "execute_trade", True)
    assert dict(row.counts) == {"GUARDED": 1}
    assert row.traces == ()


def test_bypass_deny_with_effect_and_error_counts_like_deny():
    for decision in ("deny", "error"):
        spans = with_records(spans_for(("c", "execute_trade")), ("r", decision), ("e", "allow"))
        spans[-1] = Span(T, "e", "c", "other", effect=True)
        row = one(guard(spans, [rec("r", call="c")], [rec("e", call="c")]))
        assert dict(row.counts) == {"BYPASS": 1}
        assert row.traces == (T,)


def test_one_deny_among_allows_is_not_guarded():
    spans = with_records(spans_for(("c", "execute_trade")), ("r1", "allow"), ("r2", "deny"))
    row = one(guard(spans, [rec("r1", call="c"), rec("r2", call="c")]))
    assert dict(row.counts) == {"DENIED_UNVERIFIED": 1}


def test_denied_vs_unverified_depends_on_effect_anywhere_in_the_run():
    spans = spans_for(("c1", "execute_trade"), ("c2", "execute_trade"), ("c3", "execute_trade"))
    spans = with_records(spans, ("r1", "deny"), ("r3", "allow"), ("e3", "allow"))
    spans[-1] = Span(T, "e3", "c3", "other", effect=True)
    row = one(guard(spans, [rec("r1", call="c1"), rec("r3", call="c3")], [rec("e3", call="c3")]))
    assert dict(row.counts) == {"GUARDED": 1, "DENIED": 1, "UNGUARDED": 1}
    # no marker anywhere for this tool: unverified
    spans = with_records(spans_for(("c1", "execute_trade")), ("r1", "deny"))
    assert dict(one(guard(spans, [rec("r1", call="c1")])).counts) == {"DENIED_UNVERIFIED": 1}


def test_effect_of_another_tool_does_not_verify():
    spans = spans_for(("c1", "execute_trade"), ("c2", "get_stock_price"))
    cat = catalog(tools=("execute_trade", "get_stock_price"))
    spans = with_records(spans, ("r1", "deny"), ("e2", "allow"))
    spans[-1] = Span(T, "e2", "c2", "other", effect=True)
    rows = guard(spans, [rec("r1", call="c1")], [rec("e2", call="c2")], cat=cat)
    by_tool = {r.tool: r for r in rows}
    assert dict(by_tool["execute_trade"].counts) == {"DENIED_UNVERIFIED": 1}


def test_unguarded_and_effect_without_record():
    spans = spans_for(("c1", "execute_trade"), ("c2", "execute_trade"))
    spans += [Span(T, "e", "c2", "other", effect=True)]
    row = one(guard(spans, effects=[rec("e", call="c2")]))
    assert dict(row.counts) == {"UNGUARDED": 2}
    assert row.effect_without_record == 1
    assert row.traces == (T,)


def test_inconclusive_only_without_a_linked_record():
    spans = spans_for(("c1", "execute_trade"), ("c2", "execute_trade"), ("c3", "execute_trade"))
    spans = with_records(spans, ("r", "allow"), ("g", "allow"))
    ambiguous = rec("r", kind="ambiguous", candidates=("c1", "c2"))
    row = one(guard(spans, [ambiguous, rec("g", call="c2")]))
    assert dict(row.counts) == {"INCONCLUSIVE": 1, "GUARDED": 1, "UNGUARDED": 1}


def test_by_time_counts_calls_with_a_time_linked_record():
    spans = spans_for(("c1", "execute_trade"), ("c2", "execute_trade"))
    spans = with_records(spans, ("r1", "allow"), ("r2", "allow"), ("r3", "allow"))
    records = [
        rec("r1", kind="time", call="c1"),
        rec("r2", kind="time", call="c1"),
        rec("r3", kind="tool_call_id", call="c2"),
    ]
    row = one(guard(spans, records))
    assert (row.by_time, dict(row.counts)) == (1, {"GUARDED": 2})


def test_wrappers_and_unlinked_kinds_are_ignored():
    cat = catalog(tools=("execute_trade",), wrappers=("wrap_tool",))
    spans = spans_for(("w", "wrap_tool"))
    assert guard(spans, cat=cat) == ()
    # kind "none" and "covers_tools" never link
    spans = with_records(spans_for(("c", "execute_trade")), ("r", "allow"))
    row = one(guard(spans, [rec("r", kind="covers_tools", call="c")]))
    assert dict(row.counts) == {"UNGUARDED": 1}


def test_grouping_by_agent_and_tool_with_three_example_traces():
    cat = catalog()
    views, links = [], []
    for i in range(1, 6):
        trace = f"{i:032d}"
        views += build_traces(spans_for(("c", "execute_trade"), trace=trace), cat)
        links.append(make_links(trace))
    row = one(guard_findings(views, links, cat))
    assert dict(row.counts) == {"UNGUARDED": 5}
    assert len(row.traces) == 3
    other = build_traces(spans_for(("c", "execute_trade"), trace="9" * 32, agent="supervisor"), cat)
    rows = guard_findings(views + other, [*links, make_links("9" * 32)], cat)
    assert [r.agent for r in rows] == ["supervisor", "trade-agent"]


def test_unknown_tool_and_no_agent_row():
    spans = [
        Span(T, "c1", None, "tool", name="mystery https://u:pw@h/x"),
    ]
    row = one(guard(spans))
    assert row.agent is None and row.tool_known is False
    assert "pw" not in row.tool and row.tool.startswith("mystery")


def test_error_trace_has_no_rows():
    spans = [*spans_for(("c", "execute_trade")), Span(T, "a", None, "agent", name="x")]
    assert guard(spans) == ()


def test_linear_time():
    n = 100_000
    calls = [(f"c{i}", "execute_trade") for i in range(n)]
    spans = spans_for(*calls)
    spans += [Span(T, f"r{i}", None, "other", door=door()) for i in range(n)]
    records = [rec(f"r{i}", call=f"c{i}") for i in range(n)]
    start = time.perf_counter()
    row = one(guard(spans, records))
    assert time.perf_counter() - start < 10
    assert dict(row.counts) == {"GUARDED": n}


# ---- gate ----


def grow(counts, **kw):
    traces = () if set(counts) == {"GUARDED"} else (T,)
    kw.setdefault("agent", "trade-agent")
    kw.setdefault("tool", "execute_trade")
    kw.setdefault("tool_known", True)
    return GuardRow(counts=counts, by_time=0, effect_without_record=0, traces=traces, **kw)


def irow(result, tool="execute_trade"):
    return IdentityRow(
        path=("supervisor", "trade-agent"),
        tool=tool,
        mode="user",
        expected="the trace's user",
        observed="another user",
        result=result,
        count=1,
        traces=(T,),
    )


RISKS = {"execute_trade": Risk.HIGH, "get_stock_price": Risk.LOW}


def gate(guards=(), identities=(), cfg=None, risks=RISKS):
    return observe_gate(
        (), (), cfg or GateConfig(), identities=identities, guards=guards, risks=risks
    )


def test_bypass_always_blocks():
    cfg = GateConfig(
        fail_on_identity_mismatch=False,
        fail_on_inconclusive_observation=False,
        fail_on_unguarded_call=(),
    )
    result = gate([grow({"BYPASS": 1, "GUARDED": 2})], cfg=cfg)
    assert result.violations == (
        ObserveViolation(rule="bypass", agent="trade-agent", tool="execute_trade"),
    )
    assert not result.passed


def test_denied_and_guarded_do_not_block():
    rows = [grow({"DENIED": 1}), grow({"DENIED_UNVERIFIED": 1}, tool="x"), grow({"GUARDED": 1})]
    assert gate(rows).passed


def test_unguarded_by_risk_list():
    unguarded = grow({"UNGUARDED": 1})
    assert gate([unguarded]).violations == (
        ObserveViolation(rule="fail_on_unguarded_call", agent="trade-agent", tool="execute_trade"),
    )
    assert gate([unguarded], risks={"execute_trade": Risk.LOW}).passed
    assert gate([unguarded], cfg=GateConfig(fail_on_unguarded_call=())).passed
    only_low = GateConfig(fail_on_unguarded_call=(Risk.LOW,))
    assert gate([unguarded], cfg=only_low, risks={"execute_trade": Risk.LOW}).violations


def test_unknown_tool_counts_as_unknown_risk():
    unknown = grow({"UNGUARDED": 1}, tool="mystery", tool_known=False, agent=None)
    got = gate([unknown], risks={"mystery": Risk.LOW})
    assert got.violations == (ObserveViolation(rule="fail_on_unguarded_call", tool="mystery"),)
    assert gate([unknown], cfg=GateConfig(fail_on_unguarded_call=(Risk.HIGH,))).passed


def test_identity_mismatch_key():
    rows = [irow("MISMATCH"), irow("MATCH"), irow("OBSERVED")]
    got = gate(identities=rows)
    assert got.violations == (
        ObserveViolation(
            rule="fail_on_identity_mismatch",
            path=("supervisor", "trade-agent"),
            tool="execute_trade",
        ),
    )
    assert gate(identities=rows, cfg=GateConfig(fail_on_identity_mismatch=False)).passed


def test_inconclusive_key_covers_identity_and_guard():
    ident = irow("INCONCLUSIVE")
    guards = [grow({"INCONCLUSIVE": 1})]
    got = gate(guards=guards, identities=[ident])
    assert [(v.rule, v.subject) for v in got.violations] == [
        ("fail_on_inconclusive_observation", "identity"),
        ("fail_on_inconclusive_observation", "guard"),
    ]
    off = GateConfig(fail_on_inconclusive_observation=False)
    assert gate(guards=guards, identities=[ident], cfg=off).passed


def test_identity_row_without_tool_violation():
    got = gate(identities=[irow("MISMATCH", tool=None)])
    assert got.violations[0].tool is None


def test_violation_order_and_dedupe():
    guards = [grow({"UNGUARDED": 1}), grow({"BYPASS": 1}, tool="get_stock_price")]
    identities = [irow("INCONCLUSIVE"), irow("MISMATCH"), irow("MISMATCH")]
    routes = ()
    got = observe_gate(routes, (), GateConfig(), identities=identities, guards=guards, risks=RISKS)
    assert [v.rule for v in got.violations] == [
        "bypass",
        "fail_on_identity_mismatch",
        "fail_on_inconclusive_observation",
        "fail_on_unguarded_call",
    ]


@pytest.mark.parametrize("risks", [None, {}])
def test_missing_risks_mean_unknown(risks):
    got = gate([grow({"UNGUARDED": 1})], risks=risks)
    assert got.violations


def test_calls_past_the_listed_candidates_are_inconclusive():
    """links.ambiguous_calls holds every active call, not only the (capped) listed ones."""
    spans = spans_for(("c1", "execute_trade"), ("c2", "execute_trade"))
    spans = with_records(spans, ("r", "allow"))
    ambiguous = rec("r", kind="ambiguous", candidates=("c1",))
    links = TraceLinks(T, (ambiguous,), (), 0, ambiguous_calls=frozenset({"c1", "c2"}))
    row = one(guard_findings(build_traces(spans, CAT), [links], CAT))
    assert dict(row.counts) == {"INCONCLUSIVE": 2}


def test_denied_call_with_a_possible_effect_is_inconclusive():
    spans = with_records(
        spans_for(("c1", "execute_trade"), ("c2", "execute_trade")), ("r1", "deny")
    )
    spans += [Span(T, "r2", None, "other", door=door("deny"))]
    marker = rec("e", kind="ambiguous", candidates=("c1", "c2"))
    row = one(guard(spans, [rec("r1", call="c1"), rec("r2", call="c2")], [marker]))
    assert dict(row.counts) == {"INCONCLUSIVE": 2}


def test_possible_effect_does_not_hide_a_bypass_or_verify_denials():
    spans = with_records(
        spans_for(("c1", "execute_trade"), ("c2", "execute_trade")), ("r1", "deny")
    )
    spans += [
        Span(T, "r2", None, "other", door=door("deny")),
        Span(T, "e", "c1", "other", effect=True),
    ]
    marker = rec("m", kind="ambiguous", candidates=("c2",))
    row = one(
        guard(
            spans,
            [rec("r1", call="c1"), rec("r2", call="c2")],
            [rec("e", call="c1"), marker],
        )
    )
    assert dict(row.counts) == {"BYPASS": 1, "INCONCLUSIVE": 1}


def test_group_keys_separate_ids_from_names():
    cat = catalog(tools=("execute_trade",))
    spans = spans_for(("c1", "execute_trade"), ("c2", "mystery"))
    rows = guard(spans, cat=cat)
    assert {(r.tool, r.tool_known) for r in rows} == {("execute_trade", True), ("mystery", False)}


def only_records(spans, *items):
    """Add decision-only record spans for every (record id, decision)."""
    return spans + [
        Span(T, rid, None, "other", door=decision_only(dec, None)) for rid, dec in items
    ]


def test_decision_only_records_are_judged_like_any_record():
    spans = only_records(spans_for(("c", "execute_trade")), ("r", "allow"))
    assert dict(one(guard(spans, [rec("r", call="c")])).counts) == {"GUARDED": 1}
    for decision in ("deny", "error"):
        spans = only_records(spans_for(("c", "execute_trade")), ("r", decision))
        row = one(guard(spans, [rec("r", call="c")]))
        assert dict(row.counts) == {"DENIED_UNVERIFIED": 1}


def test_decision_only_deny_is_denied_when_the_tool_has_an_effect_elsewhere():
    spans = spans_for(("c1", "execute_trade"), ("c2", "execute_trade"))
    spans = [*only_records(spans, ("r1", "deny")), Span(T, "e2", "c2", "other", effect=True)]
    row = one(guard(spans, [rec("r1", call="c1")], [rec("e2", call="c2")]))
    assert dict(row.counts) == {"DENIED": 1, "UNGUARDED": 1}


def test_decision_only_deny_with_a_linked_effect_is_a_bypass():
    spans = only_records(spans_for(("c", "execute_trade")), ("r", "deny"))
    spans.append(Span(T, "e", "c", "other", effect=True))
    row = one(guard(spans, [rec("r", call="c")], [rec("e", call="c")]))
    assert dict(row.counts) == {"BYPASS": 1}


def test_door_in_a_sub_agent_guards_its_own_call_and_not_the_delegating_tool():
    from lockwalk.observe.links import link_trace

    # The door sits in the sub-agent next to execute_trade, inside its time range; the outer
    # delegate_trade runs around both. Only the call of the door's own agent can be linked.
    spans = [
        Span(T, "s", None, "agent", name="supervisor", start_ns=0, end_ns=100),
        Span(T, "dt", "s", "tool", name="delegate_trade", start_ns=1, end_ns=90),
        Span(T, "ta", "dt", "agent", name="trade-agent", start_ns=2, end_ns=80),
        Span(T, "d", "ta", "other", door=door(), start_ns=10, end_ns=11),
        Span(T, "et", "ta", "tool", name="execute_trade", start_ns=5, end_ns=20),
    ]
    views = build_traces(spans, CAT)
    rows = guard_findings(views, [link_trace(views[0])], CAT)
    rows_by_key = {(row.agent, row.tool): row for row in rows}
    delegate = rows_by_key[("supervisor", "delegate_trade")]
    execute = rows_by_key[("trade-agent", "execute_trade")]
    assert dict(delegate.counts) == {"UNGUARDED": 1}
    assert dict(execute.counts) == {"GUARDED": 1}
    assert execute.by_time == 1
