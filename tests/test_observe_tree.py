"""Trees, paths and wrappers."""

import random
import time

from observe_helpers import catalog

from lockwalk.models import MAX_ROUTE_AGENTS
from lockwalk.observe.spans import Span
from lockwalk.observe.tree import build_traces

T = "a" * 32


def agent(sid, parent, name, start=None, **kw):
    return Span(T, sid, parent, "agent", name=name, start_ns=start, **kw)


def tool(sid, parent, name, start=None):
    return Span(T, sid, parent, "tool", name=name, start_ns=start)


def other(sid, parent, start=None):
    return Span(T, sid, parent, "other", start_ns=start)


def one(spans, cat=None):
    views = build_traces(spans, cat or catalog())
    assert len(views) == 1
    return views[0]


def test_nesting_and_paths():
    view = one(
        [
            agent("s1", None, "supervisor", 1),
            agent("s2", "s1", "trade-agent", 2),
            tool("s3", "s2", "execute_trade", 3),
        ]
    )
    assert view.complete and view.error is None
    assert view.order == ("s1", "s2", "s3")
    assert view.depth["s3"] == 2
    top, child = view.visits["s1"], view.visits["s2"]
    assert (top.caller, top.path) == ("user", ("supervisor",))
    assert (child.caller, child.path) == ("supervisor", ("supervisor", "trade-agent"))
    call = view.calls["s3"]
    assert call.agent == child and call.tool_id == "execute_trade" and not call.wrapper


def test_self_nesting_merges():
    view = one([agent("s1", None, "supervisor"), agent("s2", "s1", "supervisor")])
    assert view.merged == frozenset({"s2"})
    assert view.visits["s2"] is view.visits["s1"]


def test_unknown_names_self_nest_by_raw_name():
    view = one([agent("s1", None, "zzz"), agent("s2", "s1", "zzz"), agent("s3", "s1", "yyy")])
    assert view.merged == frozenset({"s2"})
    assert view.visits["s1"].path == ("?",)
    assert view.visits["s3"].path == ("?", "?")
    assert view.visits["s3"].caller is None


def test_explicit_caller_sibling_handoff():
    view = one(
        [
            agent("s1", None, "supervisor", 1),
            agent("s2", None, "trade-agent", 2, caller="supervisor"),
        ]
    )
    visit = view.visits["s2"]
    assert visit.caller == "supervisor" and visit.path == ("supervisor", "trade-agent")
    assert not visit.incomplete


def test_explicit_caller_blocks_self_nesting():
    view = one(
        [
            agent("s1", None, "supervisor", 1),
            agent("s2", "s1", "supervisor", 2, caller="trade-agent"),
        ]
    )
    assert view.merged == frozenset()
    assert view.visits["s2"].caller == "trade-agent"
    assert view.visits["s2"].incomplete


def _handoff(sid, parent, start):
    return Span(
        T,
        sid,
        parent,
        "handoff",
        handoff_from="supervisor",
        handoff_to="trade-agent",
        start_ns=start,
    )


def test_handoff_span_assigns_next_matching_agent():
    view = one(
        [
            agent("s1", None, "supervisor", 1),
            _handoff("h1", "s1", 2),
            agent("s2", None, "trade-agent", 3),
            agent("s3", None, "trade-agent", 4),
        ]
    )
    assert view.visits["s2"].caller == "supervisor"
    assert view.visits["s2"].path == ("supervisor", "trade-agent")
    assert view.visits["s3"].caller == "user"


def test_handoff_skips_agent_with_explicit_caller():
    view = one(
        [
            agent("s1", None, "supervisor", 1),
            _handoff("h1", "s1", 2),
            agent("s2", None, "trade-agent", 3, caller="supervisor"),
            agent("s3", None, "trade-agent", 4),
        ]
    )
    assert view.visits["s3"].caller == "supervisor"


def test_caller_visit_not_found_is_incomplete():
    view = one([agent("s1", None, "trade-agent", 1, caller="supervisor")])
    visit = view.visits["s1"]
    assert visit.incomplete and visit.caller == "supervisor"
    assert visit.path == ("trade-agent",)


def test_unknown_explicit_caller():
    view = one([agent("s1", None, "trade-agent", 1, caller="mystery")])
    visit = view.visits["s1"]
    assert visit.caller is None and visit.caller_name == "mystery" and visit.incomplete


def test_incomplete_trace_has_no_user_caller():
    view = one([agent("s1", "gone", "supervisor", 1), agent("s2", "s1", "trade-agent", 2)])
    assert not view.complete
    top = view.visits["s1"]
    assert top.caller is None and top.incomplete
    assert view.visits["s2"].path == ("supervisor", "trade-agent")


def test_duplicate_span_id():
    view = one([agent("s1", None, "supervisor"), tool("s1", None, "execute_trade")])
    assert view.error == "the trace repeats a span id"
    assert not view.visits and not view.calls


def test_parent_loop():
    view = one([agent("s1", "s2", "supervisor"), agent("s2", "s1", "trade-agent")])
    assert view.error == "the spans' parents form a loop"
    view = one([agent("s1", "s1", "supervisor")])
    assert view.error == "the spans' parents form a loop"


def test_path_too_long():
    spans = [agent("s0", None, "a0")]
    for i in range(1, MAX_ROUTE_AGENTS + 1):
        spans.append(agent(f"s{i}", f"s{i - 1}", f"a{i}"))
    assert one(spans).error is not None
    assert one(spans[:MAX_ROUTE_AGENTS]).error is None


def test_wrapper_by_registry_name():
    cat = catalog(wrappers=("ask_trade_agent",))
    view = one([agent("s1", None, "supervisor"), tool("s2", "s1", "ask_trade_agent")], cat)
    assert view.calls["s2"].wrapper


def test_wrapper_by_agent_below():
    view = one(
        [
            agent("s1", None, "supervisor"),
            tool("s2", "s1", "ask_trade_agent"),
            other("s3", "s2"),
            agent("s4", "s3", "trade-agent"),
            tool("s5", "s4", "execute_trade"),
        ]
    )
    assert view.calls["s2"].wrapper
    assert not view.calls["s5"].wrapper
    assert view.visits["s4"].path == ("supervisor", "trade-agent")


def test_agent_behind_another_tool_does_not_make_wrapper():
    view = one(
        [
            agent("s1", None, "supervisor"),
            tool("s2", "s1", "mystery_tool"),
            tool("s3", "s2", "other_tool"),
            agent("s4", "s3", "trade-agent"),
        ]
    )
    assert not view.calls["s2"].wrapper
    assert view.calls["s3"].wrapper


def test_known_tool_is_never_wrapper():
    view = one(
        [
            agent("s1", None, "supervisor"),
            tool("s2", "s1", "execute_trade"),
            agent("s3", "s2", "trade-agent"),
        ]
    )
    assert not view.calls["s2"].wrapper


def test_tool_without_agent():
    view = one([tool("s1", None, "execute_trade")])
    assert view.calls["s1"].agent is None


def test_alias_and_children_order():
    cat = catalog(agent_alias={"Sup": "supervisor"})
    view = one(
        [
            agent("s1", None, "Sup", 1),
            tool("b", "s1", "execute_trade", 5),
            tool("a", "s1", "execute_trade", 5),
            tool("c", "s1", "execute_trade", 2),
            tool("n", "s1", "execute_trade", None),
        ],
        cat,
    )
    assert view.visits["s1"].agent_id == "supervisor" and view.visits["s1"].name == "Sup"
    assert view.order == ("s1", "c", "a", "b", "n")


def test_traces_sorted():
    spans = [
        Span("b" * 32, "x", None, "agent", name="supervisor"),
        Span("a" * 32, "x", None, "agent", name="supervisor"),
    ]
    assert [v.trace_id for v in build_traces(spans, catalog())] == ["a" * 32, "b" * 32]


def test_deep_chain_is_iterative():
    n = 100_000
    spans = [agent("0", None, "supervisor")]
    spans += [other(str(i), str(i - 1)) for i in range(1, n)]
    spans.append(tool("t", str(n - 1), "execute_trade"))
    view = one(spans)
    assert view.error is None and len(view.order) == n + 1
    assert view.calls["t"].agent is view.visits["0"]


def test_linear_time_many_traces():
    spans = []
    for t in range(2000):
        tid = f"{t:032x}"
        parent = None
        for i in range(50):
            spans.append(Span(tid, f"{i * 2:016x}", parent, "agent", name="supervisor"))
            parent = f"{i * 2:016x}"
            spans.append(Span(tid, f"{i * 2 + 1:016x}", parent, "tool", name="execute_trade"))
    started = time.monotonic()
    views = build_traces(spans, catalog())
    assert len(views) == 2000
    assert time.monotonic() - started < 20


def test_a_b_a_on_one_path():
    view = one(
        [
            agent("s1", None, "supervisor"),
            agent("s2", "s1", "trade-agent"),
            agent("s3", "s2", "supervisor"),
        ]
    )
    assert view.visits["s3"].path == ("supervisor", "trade-agent", "supervisor")
    assert view.visits["s3"].caller == "trade-agent"
    assert view.merged == frozenset()


def test_handoff_to_unknown_agent():
    spans = [
        agent("s1", None, "supervisor", 1),
        Span(T, "h1", "s1", "handoff", handoff_from="supervisor", handoff_to="ghost", start_ns=2),
        agent("s2", None, "ghost", 3),
    ]
    visit = one(spans).visits["s2"]
    assert visit.agent_id is None
    assert visit.caller == "supervisor" and visit.path == ("supervisor", "?")


def test_merged_span_with_tool_children():
    view = one(
        [
            agent("s1", None, "supervisor"),
            agent("s2", "s1", "supervisor"),
            tool("s3", "s2", "execute_trade"),
        ]
    )
    assert view.calls["s3"].agent is view.visits["s1"]


def test_spans_without_start_times_are_ordered_by_id():
    view = one([tool("c", None, "execute_trade"), tool("a", None, "execute_trade")])
    assert view.order == ("a", "c")


def test_orphan_subtree_in_a_mostly_complete_trace():
    view = one(
        [
            agent("s1", None, "supervisor", 1),
            agent("o1", "gone", "trade-agent", 2),
            tool("o2", "o1", "execute_trade", 3),
            tool("t2", None, "execute_trade", 4),
        ]
    )
    assert not view.complete
    assert view.visits["s1"].caller == "user"
    assert view.visits["o1"].caller is None and view.visits["o1"].incomplete
    assert view.calls["o2"].agent is view.visits["o1"]
    assert view.calls["t2"].agent is None


def test_other_span_between_wrapper_and_agent_passes_through():
    view = one(
        [
            agent("s1", None, "supervisor"),
            tool("w", "s1", "ask_trade_agent"),
            other("o", "w"),
            agent("s2", "o", "trade-agent"),
        ]
    )
    assert view.calls["w"].wrapper


def test_known_agent_inside_unknown_agent_has_no_caller():
    # The edge A -> ? -> B is not judged: observe cannot tell what the unknown agent is.
    view = one([agent("s1", None, "ghost"), agent("s2", "s1", "trade-agent")])
    assert view.visits["s2"].caller is None
    assert view.visits["s2"].path == ("?", "trade-agent")


def test_path_error_names_the_span():
    spans = [agent("s0", None, "a0")]
    for i in range(1, MAX_ROUTE_AGENTS + 1):
        spans.append(agent(f"s{i}", f"s{i - 1}", f"a{i}"))
    assert one(spans).error == (
        f"a call path is longer than {MAX_ROUTE_AGENTS} agents (at span s{MAX_ROUTE_AGENTS})"
    )


def test_duplicate_span_id_is_not_complete():
    assert not one([agent("s1", None, "supervisor"), agent("s1", None, "supervisor")]).complete


def test_shuffled_input_gives_identical_views():
    spans = [
        agent("s1", None, "supervisor", 1),
        Span(T, "h1", "s1", "handoff", handoff_from="supervisor", handoff_to="trade-agent"),
        agent("s2", None, "trade-agent", 5),
        agent("s3", "s1", "trade-agent", 3),
        tool("s4", "s3", "execute_trade"),
        tool("s5", "s3", "execute_trade"),
        agent("s6", "gone", "ghost"),
        other("s7", "s1"),
    ]
    expected = build_traces(spans, catalog())
    for seed in range(5):
        shuffled = list(spans)
        random.Random(seed).shuffle(shuffled)
        assert build_traces(shuffled, catalog()) == expected
