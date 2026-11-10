"""The route check."""

import random
import re
from datetime import UTC, datetime

from observe_helpers import catalog

from lockwalk.config import GateConfig
from lockwalk.observe.checks import observe_gate, observe_totals, observe_window, route_findings
from lockwalk.observe.spans import ReadResult, Span
from lockwalk.observe.tree import build_traces


def a(t, sid, parent, name, start=None, **kw):
    return Span(t, sid, parent, "agent", name=name, start_ns=start, **kw)


def tl(t, sid, parent, name, start=None):
    return Span(t, sid, parent, "tool", name=name, start_ns=start)


def findings(spans, cat=None):
    cat = cat or catalog()
    return route_findings(build_traces(spans, cat), cat)


T1, T2, T3, T4 = ("0" * 31 + str(i) for i in (1, 2, 3, 4))


def test_status_of_each_edge_kind():
    spans = [
        a(T1, "1", None, "supervisor"),
        a(T1, "2", "1", "trade-agent"),
        tl(T1, "3", "2", "execute_trade"),
        tl(T1, "4", "1", "execute_trade"),
        a(T1, "5", None, "trade-agent"),
    ]
    routes, unknown = findings(spans)
    assert unknown == ()
    got = {(r.from_id, r.to_id, r.to_kind): r for r in routes}
    assert got[("user", "supervisor", "agent")].status == "ON_MAP"
    assert got[("supervisor", "trade-agent", "agent")].status == "ON_MAP"
    assert got[("trade-agent", "execute_trade", "tool")].status == "ON_MAP"
    assert got[("supervisor", "execute_trade", "tool")].status == "OFF_MAP"
    assert got[("user", "trade-agent", "agent")].status == "OFF_MAP"
    assert [r.status for r in routes] == ["OFF_MAP", "OFF_MAP", "ON_MAP", "ON_MAP", "ON_MAP"]


def test_suggestions_exact():
    cat = catalog(agent_edges=())
    spans = [
        a(T1, "1", None, "trade-agent"),
        a(T1, "2", "1", "supervisor"),
        tl(T1, "3", "2", "execute_trade"),
    ]
    routes, _ = findings(spans, cat)
    sug = {(r.from_id, r.to_id): r.suggestion for r in routes if r.status == "OFF_MAP"}
    assert sug[("user", "trade-agent")] == (
        "mark agent trade-agent as an entry agent: set 'entry: true' on trade-agent "
        "in registry.yaml"
    )
    assert sug[("trade-agent", "supervisor")] == (
        "declare the call: add supervisor to 'calls' of agent trade-agent in registry.yaml"
    )
    assert sug[("supervisor", "execute_trade")] == (
        "declare the tool use: add supervisor to 'supported_agents' of tool execute_trade "
        "in registry.yaml"
    )


def test_row_order():
    spans = [
        a(T1, "1", None, "trade-agent"),
        a(T1, "2", None, "supervisor"),
        a(T1, "3", "2", "trade-agent"),
        tl(T1, "4", "2", "execute_trade"),
    ]
    routes, _ = findings(spans)
    keys = [(r.status, r.from_id, r.to_kind, r.to_id) for r in routes]
    assert keys == [
        ("OFF_MAP", "supervisor", "tool", "execute_trade"),
        ("OFF_MAP", "user", "agent", "trade-agent"),
        ("ON_MAP", "supervisor", "agent", "trade-agent"),
        ("ON_MAP", "user", "agent", "supervisor"),
    ]


def test_grouping_counts_and_examples():
    spans = []
    for t in (T1, T2, T3, T4):
        spans.append(a(t, "1", None, "supervisor"))
        spans.append(a(t, "2", None, "supervisor"))
    spans.append(a(T1, "9", None, "supervisor"))
    routes, _ = findings(spans)
    (row,) = routes
    assert row.count == 9
    assert row.traces == (T1, T2, T3)


def test_merged_visit_counts_once():
    routes, _ = findings([a(T1, "1", None, "supervisor"), a(T1, "2", "1", "supervisor")])
    assert routes[0].count == 1


def test_unknown_agent_tool_and_caller():
    spans = [
        a(T1, "1", None, "supervisor"),
        a(T1, "2", "1", "ghost"),
        tl(T1, "3", "1", "mystery"),
        tl(T1, "4", None, "execute_trade"),
        tl(T1, "5", None, "nameless"),
        a(T1, "6", None, "trade-agent", caller="phantom"),
    ]
    _, unknown = findings(spans)
    got = {(u.kind, u.name): u.count for u in unknown}
    assert got == {
        ("agent", "ghost"): 1,
        ("agent", "phantom"): 1,
        ("tool", "mystery"): 1,
        ("tool", "nameless"): 1,
        ("caller", "execute_trade"): 1,
        ("caller", "nameless"): 1,
    }
    assert [(u.kind, u.name) for u in unknown] == sorted(got)


def test_incomplete_trace_makes_no_user_edge_and_no_caller_row():
    spans = [a(T1, "1", "gone", "supervisor"), tl(T1, "2", "gone", "execute_trade")]
    routes, unknown = findings(spans)
    assert routes == () and unknown == ()


def test_wrapper_is_not_a_tool_call():
    cat = catalog(wrappers=("ask_trade_agent",))
    spans = [a(T1, "1", None, "supervisor"), tl(T1, "2", "1", "ask_trade_agent")]
    routes, unknown = findings(spans, cat)
    assert unknown == () and len(routes) == 1


def other(t, sid, parent, start=None):
    return Span(t, sid, parent, "other", name="step", start_ns=start)


def tool_rows(unknown):
    return {(u.kind, u.name): u.count for u in unknown if u.kind == "tool"}


def test_unregistered_tool_with_an_agent_below_is_unknown():
    spans = [
        a(T1, "1", None, "supervisor"),
        tl(T1, "2", "1", "rogue_exec"),
        a(T1, "3", "2", "trade-agent"),
        tl(T1, "4", "3", "execute_trade"),
    ]
    routes, unknown = findings(spans)
    assert tool_rows(unknown) == {("tool", "rogue_exec"): 1}
    # What happens below the wrapper does not change.
    assert {(r.from_id, r.to_id, r.to_kind) for r in routes} >= {
        ("supervisor", "trade-agent", "agent"),
        ("trade-agent", "execute_trade", "tool"),
    }


def test_unregistered_tool_with_a_tool_or_nothing_below_stays_one_unknown_row():
    spans = [
        a(T1, "1", None, "supervisor"),
        tl(T1, "2", "1", "plain_tool"),
        tl(T1, "3", "1", "other_tool"),
        tl(T1, "4", "3", "inner_tool"),
    ]
    _, unknown = findings(spans)
    assert tool_rows(unknown) == {
        ("tool", "plain_tool"): 1,
        ("tool", "other_tool"): 1,
        ("tool", "inner_tool"): 1,
    }


def test_known_delegation_tool_with_an_agent_below_is_not_unknown():
    cat = catalog(wrappers=("ask_trade_agent",))
    spans = [
        a(T1, "1", None, "supervisor"),
        tl(T1, "2", "1", "ask_trade_agent"),
        a(T1, "3", "2", "trade-agent"),
    ]
    _, unknown = findings(spans, cat)
    assert unknown == ()


def test_an_unregistered_wrapper_inside_another_is_unknown_twice():
    spans = [
        a(T1, "1", None, "supervisor"),
        tl(T1, "2", "1", "outer_rogue"),
        a(T1, "3", "2", "trade-agent"),
        tl(T1, "4", "3", "inner_rogue"),
        a(T1, "5", "4", "trade-agent"),
    ]
    _, unknown = findings(spans)
    assert tool_rows(unknown) == {("tool", "outer_rogue"): 1, ("tool", "inner_rogue"): 1}


def test_an_unregistered_wrapper_behind_another_span_is_unknown():
    spans = [
        a(T1, "1", None, "supervisor"),
        tl(T1, "2", "1", "rogue_exec"),
        other(T1, "3", "2"),
        a(T1, "4", "3", "trade-agent"),
    ]
    _, unknown = findings(spans)
    assert tool_rows(unknown) == {("tool", "rogue_exec"): 1}


def test_error_traces_skipped():
    spans = [a(T1, "1", None, "ghost"), a(T1, "1", None, "ghost")]
    assert findings(spans) == ((), ())


def test_unknown_names_masked_and_cut():
    spans = [
        a(T1, "1", None, "https://u:p@x.example/" + "z" * 400),
        tl(T1, "2", None, "https://u:p@x.example"),
    ]
    _, unknown = findings(spans)
    assert unknown
    for row in unknown:
        assert "u:p@" not in row.name
        assert len(row.name) <= 200


def test_totals_and_window():
    spans = [
        a(T1, "1", None, "supervisor", 1_700_000_000_000_000_000),
        a(T1, "2", "1", "supervisor", 1_700_000_100_000_000_000),
        tl(T1, "3", "1", "execute_trade"),
        Span(T1, "4", "1", "other", unnamed_marker=True),
        Span(T2, "5", None, "other"),
        a(T3, "6", "gone", "supervisor"),
        a(T4, "7", None, "supervisor"),
        a(T4, "7", None, "supervisor"),
    ]
    views = build_traces(spans, catalog())
    read = ReadResult(sources=("a.json", "b.json"))
    totals = observe_totals(read, views, spans)
    assert totals.files == 2 and totals.traces == 4 and totals.spans == 8
    assert totals.agent_spans == 2  # s1 and s6; s2 merged, T4 errored
    assert totals.tool_calls == 1
    # T3 has an orphan parent; T4 repeats a span id (completeness unknown).
    assert totals.incomplete_traces == 2 and totals.error_traces == 1
    assert totals.unnamed_markers == 1
    window = observe_window(spans)
    first = datetime.fromtimestamp(1_700_000_000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    last = datetime.fromtimestamp(1_700_000_100, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert (window.first, window.last) == (first, last)
    assert observe_window([a(T1, "1", None, "x")]).first is None


def test_gate_keys():
    spans = [a(T1, "1", None, "trade-agent"), a(T1, "2", "1", "ghost")]
    routes, unknown = findings(spans)
    on = observe_gate(routes, unknown, GateConfig())
    assert not on.passed
    assert {v.rule for v in on.violations} == {"fail_on_off_map_route", "fail_on_unknown_component"}
    only_route = observe_gate(routes, unknown, GateConfig(fail_on_unknown_component=False))
    assert [v.rule for v in only_route.violations] == ["fail_on_off_map_route"]
    assert only_route.violations[0].from_id == "user"
    only_unknown = observe_gate(routes, unknown, GateConfig(fail_on_off_map_route=False))
    assert only_unknown.violations[0].name == "ghost" and only_unknown.violations[0].kind == "agent"
    off = observe_gate(
        routes, unknown, GateConfig(fail_on_off_map_route=False, fail_on_unknown_component=False)
    )
    assert off.passed and off.violations == ()


def test_findings_do_not_depend_on_input_order():
    spans = [
        a(T1, "1", None, "supervisor", 1),
        a(T1, "2", "1", "trade-agent", 2),
        tl(T1, "3", "2", "execute_trade", 3),
        tl(T1, "4", "1", "execute_trade", 4),
        a(T2, "5", None, "ghost"),
        tl(T2, "6", None, "mystery"),
    ]
    expected = findings(spans)
    for seed in range(5):
        shuffled = list(spans)
        random.Random(seed).shuffle(shuffled)
        assert findings(shuffled) == expected


def test_window_ignores_a_time_outside_four_digit_years():
    assert observe_window([a(T1, "1", None, "x", 1_000_000_000)]).first is not None
    stamp = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
    # Year 1: older Pythons and Windows give no window; Python 3.14 writes "0001", which fits.
    year_one = -62_135_596_800 * 1_000_000_000  # 0001-01-01
    window = observe_window([a(T1, "1", None, "x", year_one)])
    if (window.first, window.last) != (None, None):
        assert window.first is not None and window.last is not None
        assert stamp.fullmatch(window.first) and window.first.startswith("0001-")
        assert stamp.fullmatch(window.last) and window.last.startswith("0001-")
    # A year past 9999 never fits four digits, on every Python.
    year_10000 = 253_402_300_800 * 1_000_000_000  # 10000-01-01
    window = observe_window([a(T1, "1", None, "x", year_10000)])
    assert (window.first, window.last) == (None, None)


def test_an_empty_name_is_shown_as_empty():
    from lockwalk.observe.checks import shown_name

    assert shown_name("") == "(empty)"
    assert shown_name("abc") == "abc"


def test_a_blank_name_is_shown_as_empty():
    from lockwalk.observe.checks import shown_name

    assert shown_name("   ") == "(empty)"
