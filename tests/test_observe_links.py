import random
import time

from observe_helpers import catalog

from lockwalk.observe.door import DoorRecord
from lockwalk.observe.links import MAX_CANDIDATES, TraceLinks, link_trace
from lockwalk.observe.spans import Span
from lockwalk.observe.tree import build_traces

T = "t" * 32


def door(call_id: str | None = None) -> DoorRecord:
    return DoorRecord("allow", "user", "u1", (), "trade:execute", None, call_id)


def span(span_id: str, parent: str | None, kind="other", name=None, start=None, end=None, **kw):
    return Span(T, span_id, parent, kind, name, start_ns=start, end_ns=end, **kw)


def agent(span_id, parent, name="trade-agent", start=0, end=1000, **kw):
    return span(span_id, parent, "agent", name, start, end, **kw)


def tool(span_id, parent, name="execute_trade", start=None, end=None, **kw):
    return span(span_id, parent, "tool", name, start, end, **kw)


def link(spans, wrappers=()) -> TraceLinks:
    views = build_traces(spans, catalog(wrappers=wrappers))
    assert len(views) == 1
    return link_trace(views[0])


def test_ancestry_self_and_below() -> None:
    spans = [
        agent("a", None),
        tool("t1", "a", start=1, end=5, door=door()),
        span("d", "t1", start=2, end=3, door=door(), effect=True),
    ]
    links = link(spans)
    assert [(r.span_id, r.kind, r.call) for r in links.records] == [
        ("t1", "ancestry", "t1"),
        ("d", "ancestry", "t1"),
    ]
    assert [(e.span_id, e.kind, e.call) for e in links.effects] == [("d", "ancestry", "t1")]
    assert links.records[0].agent is not None
    assert links.records[0].agent.agent_id == "trade-agent"
    assert links.covers_tools == 0


def test_langchain_shape_time_link() -> None:
    spans = [
        span("app", None, start=0, end=100),
        agent("a", "app", start=1, end=90),
        tool("t1", "a", start=10, end=20),
        tool("t2", "a", start=30, end=40),
        span("d1", "app", start=12, end=13, door=door()),
        span("d2", "app", start=35, end=36, door=door()),
        span("e1", "app", start=15, end=16, effect=True),
        span("late", "app", start=50, end=51, door=door()),
    ]
    links = link(spans)
    got = {r.span_id: (r.kind, r.call) for r in links.records}
    assert got == {
        "d1": ("time", "t1"),
        "d2": ("time", "t2"),
        "late": ("none", None),
    }
    assert [(e.kind, e.call) for e in links.effects] == [("time", "t1")]
    d1 = next(r for r in links.records if r.span_id == "d1")
    assert d1.agent is not None and d1.agent.span_id == "a"
    late = next(r for r in links.records if r.span_id == "late")
    assert late.agent is None  # the app span is above the agent


def test_none_uses_nearest_agent() -> None:
    spans = [agent("a", None), span("d", "a", start=5, end=6, door=door())]
    (rec,) = link(spans).records
    assert rec.kind == "none"
    assert rec.agent is not None and rec.agent.span_id == "a"


def test_ambiguous_same_agent() -> None:
    spans = [
        span("app", None),
        agent("a", "app"),
        tool("t1", "a", start=10, end=30),
        tool("t2", "a", start=20, end=40),
        span("d", "app", start=25, end=26, door=door()),
    ]
    (rec,) = link(spans).records
    assert rec.kind == "ambiguous"
    assert rec.candidates == ("t1", "t2")
    assert rec.call is None
    assert rec.agent_ambiguous is False
    assert rec.agent is not None and rec.agent.span_id == "a"


def test_ambiguous_different_agents() -> None:
    spans = [
        span("app", None),
        agent("a", "app", name="supervisor"),
        agent("b", "app", name="trade-agent"),
        tool("t1", "a", name="delegate_trade", start=10, end=30),
        tool("t2", "b", start=20, end=40),
        span("d", "app", start=25, end=26, door=door()),
    ]
    (rec,) = link(spans).records
    assert rec.kind == "ambiguous"
    assert rec.agent is None
    assert rec.agent_ambiguous is True


def test_covers_tools() -> None:
    spans = [
        span("app", None, start=0, end=100, door=door()),
        agent("a", "app"),
        tool("t1", "a", start=10, end=20),
    ]
    links = link(spans)
    (rec,) = links.records
    assert rec.kind == "covers_tools"
    assert rec.call is None
    assert links.covers_tools == 1


def test_wrapper_below_counts_as_tool_below() -> None:
    spans = [
        span("app", None, start=0, end=100, door=door()),
        tool("w", "app", name="ask_trader", start=10, end=20),
        agent("a", "w", start=11, end=19),
    ]
    links = link(spans, wrappers=("ask_trader",))
    assert links.records[0].kind == "covers_tools"


def test_tool_call_id_match() -> None:
    spans = [
        span("app", None),
        agent("a", "app"),
        tool("t1", "a", start=10, end=30, tool_call_id="c1"),
        tool("t2", "a", start=10, end=30, tool_call_id="c2"),
        span("d", "app", start=12, end=13, door=door("c2")),
        span("dup", "app", start=12, end=13, door=door("zz")),
    ]
    got = {r.span_id: (r.kind, r.call) for r in link(spans).records}
    assert got["d"] == ("tool_call_id", "t2")
    assert got["dup"][0] == "ambiguous"  # unknown id: falls through to time


def test_duplicate_tool_call_id_is_not_a_match() -> None:
    spans = [
        span("app", None),
        tool("t1", "app", start=10, end=20, tool_call_id="c1"),
        tool("t2", "app", start=30, end=40, tool_call_id="c1"),
        span("d", "app", start=35, end=36, door=door("c1")),
    ]
    (rec,) = link(spans).records
    assert (rec.kind, rec.call) == ("time", "t2")


def test_record_in_wrapper_subtree_links_by_time_to_inner_tool() -> None:
    spans = [
        span("app", None),
        tool("w", "app", name="ask_trader", start=0, end=100),
        agent("a", "w", start=1, end=99),
        tool("t1", "a", start=10, end=50),
        span("d", "w", start=20, end=21, door=door()),
    ]
    (rec,) = link(spans, wrappers=("ask_trader",)).records
    assert (rec.kind, rec.call) == ("time", "t1")


def test_wrapper_itself_is_not_a_candidate() -> None:
    spans = [
        span("app", None),
        tool("w", "app", name="ask_trader", start=0, end=100),
        span("d", "app", start=20, end=21, door=door()),
    ]
    (rec,) = link(spans, wrappers=("ask_trader",)).records
    assert rec.kind == "none"


def test_record_without_start_is_none() -> None:
    spans = [
        span("app", None),
        tool("t1", "app", start=10, end=30),
        span("d", "app", start=None, end=None, door=door()),
    ]
    (rec,) = link(spans).records
    assert (rec.kind, rec.call) == ("none", None)


def test_start_only_call_is_a_candidate_next_to_a_normal_call() -> None:
    spans = [
        span("app", None),
        tool("t1", "app", start=5, end=30),
        tool("open", "app", start=10, end=None),
        span("d", "app", start=12, end=13, door=door()),
        span("late", "app", start=50, end=51, door=door()),
    ]
    links = link(spans)
    got = {r.span_id: r for r in links.records}
    assert got["d"].kind == "ambiguous"
    assert set(got["d"].candidates) == {"t1", "open"}
    assert (got["late"].kind, got["late"].call) == ("time", "open")  # only open is active
    assert "open" in links.ambiguous_calls and "t1" in links.ambiguous_calls


def test_call_without_times_makes_a_single_candidate_ambiguous() -> None:
    spans = [
        span("app", None),
        tool("t1", "app", start=10, end=30),
        tool("blank", "app", start=None, end=None),
        span("d", "app", start=15, end=16, door=door()),
    ]
    links = link(spans)
    (rec,) = links.records
    assert rec.kind == "ambiguous"
    assert set(rec.candidates) == {"t1", "blank"}
    assert links.ambiguous_calls == frozenset({"t1", "blank"})


def test_end_before_start_is_open_ended() -> None:
    spans = [
        span("app", None),
        tool("normal", "app", start=0, end=100),
        tool("inverted", "app", start=20, end=10),
        span("before", "app", start=15, end=16, door=door()),
        span("after", "app", start=50, end=51, door=door()),
    ]
    got = {r.span_id: (r.kind, r.call) for r in link(spans).records}
    assert got["before"] == ("time", "normal")  # the inverted call has not started yet
    assert got["after"][0] == "ambiguous"


def test_alone_open_ended_call_still_links() -> None:
    spans = [span("app", None), tool("blank", "app"), span("d", "app", start=5, door=door())]
    (rec,) = link(spans).records
    assert (rec.kind, rec.call) == ("time", "blank")


def test_time_bounds_inclusive() -> None:
    spans = [
        span("app", None),
        tool("t1", "app", start=10, end=20),
        span("a", "app", start=10, end=10, door=door()),
        span("b", "app", start=20, end=20, door=door()),
        span("c", "app", start=21, end=21, door=door()),
    ]
    got = {r.span_id: r.kind for r in link(spans).records}
    assert got == {"a": "time", "b": "time", "c": "none"}


def test_user_nearest_and_conflict() -> None:
    spans = [
        span("app", None, user_id="u1"),
        agent("a", "app", user_id="u1"),
        tool("t1", "a", start=1, end=5, user_id="u2"),
        span("d", "t1", door=door()),
        span("d2", "a", door=door()),
        span("d3", "app", door=door()),
    ]
    links = link(spans)
    got = {r.span_id: (r.user_id, r.user_conflict) for r in links.records}
    assert got["d"] == ("u2", True)
    assert got["d2"] == ("u1", False)
    assert got["d3"] == ("u1", False)
    assert "u2" not in repr(links.records[0])


def test_error_trace_has_no_links() -> None:
    spans = [span("a", None, door=door()), span("a", None, door=door())]
    links = link(spans)
    assert links.records == () and links.effects == () and links.covers_tools == 0


def test_deterministic_under_shuffle() -> None:
    spans = [
        span("app", None),
        agent("a", "app"),
        tool("t1", "a", start=10, end=30),
        tool("t2", "a", start=20, end=40),
        span("d", "app", start=25, end=26, door=door()),
        span("d2", "app", start=12, end=13, door=door(), effect=True),
    ]
    expected = link(spans)
    for seed in range(5):
        shuffled = spans[:]
        random.Random(seed).shuffle(shuffled)
        assert link(shuffled) == expected


def test_large_trace_is_fast() -> None:
    n = 50_000
    spans = [span("app", None), agent("a", "app", start=0, end=10 * n)]
    for i in range(n):
        spans.append(tool(f"t{i}", "a", start=10 * i, end=10 * i + 5))
        spans.append(span(f"d{i}", "app", start=10 * i + 2, end=10 * i + 3, door=door()))
    started = time.monotonic()
    links = link(spans)
    assert time.monotonic() - started < 20
    assert len(links.records) == n
    assert all(r.kind == "time" for r in links.records)


def test_adversarial_interleaved_is_bounded_and_fast() -> None:
    n = 50_000
    end = 10 * n
    spans = [span("app", None), agent("a", "app", start=0, end=end)]
    for i in range(n):
        spans.append(tool(f"t{i:06d}", "a", start=2 * i, end=end))
        spans.append(span(f"d{i:06d}", "app", start=2 * i + 1, end=2 * i + 1, door=door()))
    started = time.monotonic()
    links = link(spans)
    elapsed = time.monotonic() - started
    assert elapsed < 20
    assert all(len(r.candidates) <= MAX_CANDIDATES for r in links.records)
    by_span = {r.span_id: r for r in links.records}
    assert by_span["d000000"].kind == "time"  # one active call
    r = by_span["d000009"]  # calls 0..9 are active
    assert r.kind == "ambiguous"
    assert len(r.candidates) == MAX_CANDIDATES and r.more_candidates == 5
    assert by_span["d049999"].more_candidates == n - MAX_CANDIDATES
    assert len(links.ambiguous_calls) == n  # call j is active at record max(j, 1)


def test_ambiguous_calls_exact() -> None:
    spans = [
        span("app", None),
        agent("a", "app"),
        tool("t1", "a", start=10, end=30),
        tool("t2", "a", start=20, end=40),
        tool("t3", "a", start=100, end=200),
        tool("t4", "a", start=110, end=200),
        tool("t5", "a", start=300, end=400),
        span("d", "app", start=25, end=26, door=door()),  # ambiguous: t1, t2
        span("e", "app", start=150, end=151, effect=True),  # ambiguous effect only: t3, t4
        span("d5", "app", start=350, end=351, door=door()),  # single: t5
    ]
    links = link(spans)
    assert links.ambiguous_calls == frozenset({"t1", "t2"})


def test_ambiguous_calls_includes_call_past_the_cap() -> None:
    spans = [span("app", None), agent("a", "app")]
    spans += [tool(f"t{i}", "a", start=i, end=100) for i in range(8)]
    spans.append(span("d", "app", start=50, end=51, door=door()))
    links = link(spans)
    (rec,) = links.records
    assert rec.candidates == ("t0", "t1", "t2", "t3", "t4")
    assert rec.more_candidates == 3
    assert links.ambiguous_calls == frozenset(f"t{i}" for i in range(8))


def test_agent_ambiguous_when_only_sixth_candidate_differs() -> None:
    spans = [
        span("app", None),
        agent("a", "app", name="trade-agent"),
        agent("b", "app", name="supervisor"),
    ]
    spans += [tool(f"t{i}", "a", start=i, end=100) for i in range(5)]
    spans.append(tool("t5", "b", name="delegate_trade", start=5, end=100))
    spans.append(span("d", "app", start=50, end=51, door=door()))
    (rec,) = link(spans).records
    assert len(rec.candidates) == 5 and rec.more_candidates == 1
    assert rec.agent is None and rec.agent_ambiguous is True


def test_stale_heavy_lazy_deletion_is_fast() -> None:
    n = 20_000
    spans = [span("app", None), agent("a", "app", start=0, end=100 * n)]
    for i in range(n):  # many short calls that end early
        spans.append(tool(f"s{i:06d}", "a", start=10 * i, end=10 * i + 1))
    for j in range(3):  # a few long ones that start after the short ones
        spans.append(tool(f"zlong{j}", "a", start=10 * n + j, end=100 * n))
    for i in range(n):
        spans.append(span(f"d{i:06d}", "app", start=10 * n + 10 + i, door=door()))
    started = time.monotonic()
    links = link(spans)
    assert time.monotonic() - started < 20
    for rec in links.records:
        assert rec.kind == "ambiguous"
        assert rec.candidates == ("zlong0", "zlong1", "zlong2")
    assert links.ambiguous_calls == frozenset({"zlong0", "zlong1", "zlong2"})


def test_deep_chain_does_not_recurse() -> None:
    depth = 50_000
    spans = [span("n0", None)]
    for i in range(1, depth):
        if i == 10:
            spans.append(tool(f"n{i}", f"n{i - 1}", start=1, end=2))
        else:
            spans.append(span(f"n{i}", f"n{i - 1}"))
    spans.append(span("leaf", f"n{depth - 1}", door=door(), effect=True))
    links = link(spans)
    (rec,) = links.records
    assert (rec.kind, rec.call) == ("ancestry", "n10")
    assert [e.call for e in links.effects] == ["n10"]


def test_ambiguous_effect_calls_differ_from_ambiguous_calls() -> None:
    spans = [
        span("app", None),
        tool("d1", "app", start=10, end=30),
        tool("d2", "app", start=20, end=40),
        tool("e1", "app", start=100, end=200),
        tool("e2", "app", start=110, end=200),
        tool("open", "app", start=300, end=None),
        tool("solo", "app", start=500, end=600),
        span("door", "app", start=25, end=26, door=door()),  # ambiguous door: d1, d2
        span("marker", "app", start=150, end=151, effect=True),  # ambiguous effect: e1, e2
        span("marker2", "app", start=350, end=351, effect=True),  # only "open": single
        span("marker3", "app", start=550, end=551, effect=True),  # "open" and "solo"
    ]
    links = link(spans)
    # Door records only: d1, d2. Effect markers only: e1, e2, and the open-ended call, which
    # still overlaps "solo" at the last marker.
    assert links.ambiguous_calls == frozenset({"d1", "d2"})
    assert links.ambiguous_effect_calls == frozenset({"e1", "e2", "open", "solo"})
    assert not links.ambiguous_calls & links.ambiguous_effect_calls


def test_door_by_tool_call_id_and_effect_by_time_on_one_span() -> None:
    spans = [
        span("app", None),
        tool("t1", "app", start=10, end=20, tool_call_id="c1"),
        tool("t2", "app", start=30, end=40, tool_call_id="c2"),
        span("both", "app", start=35, end=36, door=door("c1"), effect=True),
    ]
    links = link(spans)
    assert [(r.kind, r.call) for r in links.records] == [("tool_call_id", "t1")]
    assert [(e.kind, e.call) for e in links.effects] == [("time", "t2")]


# ---- a record in a sub-agent is not credited to a call above that sub-agent ----


def delegation_spans(door_start=None, door_end=None, with_tool_times=False):
    """supervisor > delegate_trade (known, not a wrapper) > trade-agent, whose own call
    execute_trade is a sibling of the door span."""
    t0, t1 = (20, 30) if with_tool_times else (None, None)
    return [
        agent("s", None, name="supervisor", start=0, end=100),
        tool("dt", "s", name="delegate_trade", start=1, end=90),
        agent("ta", "dt", name="trade-agent", start=2, end=80),
        span("d", "ta", start=door_start, end=door_end, door=door(), effect=True),
        tool("et", "ta", name="execute_trade", start=t0, end=t1),
    ]


def test_record_in_a_sub_agent_is_not_credited_to_the_outer_call() -> None:
    links = link(delegation_spans())
    (rec,) = links.records
    assert rec.call != "dt"
    assert (rec.kind, rec.call) == ("none", None)
    assert rec.agent is not None and rec.agent.agent_id == "trade-agent"
    (effect,) = links.effects
    assert (effect.kind, effect.call) == ("none", None)


def test_record_in_a_sub_agent_is_not_pushed_to_the_outer_call_by_time() -> None:
    links = link(delegation_spans(door_start=10, door_end=11, with_tool_times=True))
    (rec,) = links.records
    assert rec.call != "dt"
    assert "dt" not in rec.candidates
    assert (rec.kind, rec.call, rec.candidates) == ("none", None, ())


def test_record_in_a_sub_agent_links_by_time_to_a_call_of_its_own_agent() -> None:
    # The door starts inside execute_trade (a call of the sub-agent) and inside delegate_trade
    # (the outer call). Only the call of the record's own agent visit is in reach.
    links = link(delegation_spans(door_start=25, door_end=26, with_tool_times=True))
    (rec,) = links.records
    assert (rec.kind, rec.call, rec.candidates) == ("time", "et", ())
    assert rec.agent is not None and rec.agent.agent_id == "trade-agent"
    (effect,) = links.effects
    assert (effect.kind, effect.call) == ("time", "et")


def test_ambiguity_inside_the_sub_agent_stays_ambiguous() -> None:
    spans = [
        agent("s", None, name="supervisor", start=0, end=100),
        tool("dt", "s", name="delegate_trade", start=1, end=90),
        agent("ta", "dt", name="trade-agent", start=2, end=80),
        span("d", "ta", start=25, end=26, door=door()),
        tool("e1", "ta", name="execute_trade", start=20, end=30),
        tool("e2", "ta", name="execute_trade", start=22, end=40),
    ]
    (rec,) = link(spans).records
    assert rec.kind == "ambiguous"
    assert set(rec.candidates) == {"e1", "e2"}  # never dt, and no one picked


def test_sub_agents_do_not_share_calls_by_time() -> None:
    # Two sub-agents run at the same time. Each door starts inside both agents' calls, but a
    # record only sees the calls of its own visit.
    spans = [
        agent("s", None, name="supervisor", start=0, end=100),
        tool("dt1", "s", name="delegate_trade", start=1, end=90),
        agent("a1", "dt1", name="trade-agent", start=2, end=80),
        tool("e1", "a1", name="execute_trade", start=10, end=50),
        span("d1", "a1", start=20, end=21, door=door()),
        tool("dt2", "s", name="delegate_trade", start=1, end=90),
        agent("a2", "dt2", name="trade-agent", start=2, end=80),
        tool("e2", "a2", name="execute_trade", start=10, end=50),
        span("d2", "a2", start=20, end=21, door=door()),
    ]
    by_span = {r.span_id: r for r in link(spans).records}
    assert (by_span["d1"].kind, by_span["d1"].call) == ("time", "e1")
    assert (by_span["d2"].kind, by_span["d2"].call) == ("time", "e2")


def test_many_sub_agents_are_linked_in_near_linear_time() -> None:
    # Every sub-agent is its own visit with a fenced record. Filtering the whole call list once
    # per visit would be quadratic (n visits x 2n calls); bucketing the calls by visit once
    # keeps it n log n.
    n = 20_000
    spans = [agent("s", None, name="supervisor", start=0, end=10 * n)]
    for i in range(n):
        base = 10 * i
        spans.append(tool(f"dt{i}", "s", name="delegate_trade", start=base, end=base + 9))
        spans.append(agent(f"a{i}", f"dt{i}", start=base, end=base + 9))
        spans.append(tool(f"et{i}", f"a{i}", start=base + 1, end=base + 8))
        spans.append(span(f"d{i}", f"a{i}", start=base + 4, end=base + 5, door=door()))
    started = time.monotonic()
    links = link(spans)
    assert time.monotonic() - started < 10
    assert len(links.records) == n
    assert all(r.kind == "time" and r.call == "et" + r.span_id[1:] for r in links.records)


def test_record_in_a_sub_agent_below_its_own_call_still_links_by_ancestry() -> None:
    spans = [
        agent("s", None, name="supervisor", start=0, end=100),
        tool("dt", "s", name="delegate_trade", start=1, end=90),
        agent("ta", "dt", name="trade-agent", start=2, end=80),
        tool("et", "ta", name="execute_trade", start=3, end=9),
        span("d", "et", start=4, end=5, door=door()),
    ]
    (rec,) = link(spans).records
    assert (rec.kind, rec.call) == ("ancestry", "et")
    assert rec.agent is not None and rec.agent.agent_id == "trade-agent"


def test_a_merged_agent_span_keeps_the_call_above_it() -> None:
    spans = [
        agent("a", None, start=0, end=100),
        tool("t1", "a", start=1, end=90),
        agent("a2", "t1", start=2, end=80),
        span("d", "a2", start=3, end=4, door=door()),
    ]
    (rec,) = link(spans).records
    assert (rec.kind, rec.call) == ("ancestry", "t1")
