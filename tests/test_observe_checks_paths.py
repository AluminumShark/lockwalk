"""Path rows and the gate's untested-path key."""

import time

from observe_helpers import catalog

from lockwalk.config import GateConfig
from lockwalk.models import Risk
from lockwalk.observe.checks import observe_gate, path_findings
from lockwalk.observe.results import ObserveViolation, PathRow
from lockwalk.observe.spans import Span
from lockwalk.observe.tree import build_traces

T = "0" * 31 + "1"
ROUTE = ("supervisor", "trade-agent")


def deep(trace=T, tool="execute_trade"):
    return [
        Span(trace, "1", None, "agent", name="supervisor"),
        Span(trace, "2", "1", "agent", name="trade-agent"),
        Span(trace, "3", "2", "tool", name=tool),
    ]


def paths(spans, **kw):
    cat = catalog(**kw)
    return path_findings(build_traces(spans, cat), cat)


def one(rows):
    assert len(rows) == 1
    return rows[0]


def test_tested_when_the_route_and_tool_match():
    row = one(paths(deep(), case_routes=((ROUTE, "execute_trade"),)))
    assert (row.path, row.tool, row.incomplete, row.status) == (
        ROUTE,
        "execute_trade",
        False,
        "TESTED",
    )


def test_tested_other_path_and_untested():
    row = one(
        paths(
            deep(),
            case_routes=((("trade-agent",), "execute_trade"),),
            case_agents=(("trade-agent", "execute_trade"),),
        )
    )
    assert row.status == "TESTED_OTHER_PATH"
    assert one(paths(deep())).status == "UNTESTED"
    other_tool = paths(deep(), case_agents=(("trade-agent", "delegate_trade"),))
    assert one(other_tool).status == "UNTESTED"


def test_incomplete_path_never_tested_but_may_be_other_path():
    spans = [
        Span(T, "2", "9", "agent", name="trade-agent"),
        Span(T, "3", "2", "tool", name="execute_trade"),
    ]
    # a case with exactly this one-agent route does not make an incomplete path TESTED
    row = one(
        paths(
            spans,
            case_routes=((("trade-agent",), "execute_trade"),),
            case_agents=(("trade-agent", "execute_trade"),),
        )
    )
    assert (row.incomplete, row.status, row.path) == (True, "TESTED_OTHER_PATH", ("trade-agent",))
    assert one(paths(spans)).status == "UNTESTED"


def test_only_known_agents_tools_and_non_wrappers():
    spans = [
        Span(T, "1", None, "agent", name="mystery"),
        Span(T, "2", "1", "tool", name="execute_trade"),
        Span(T, "3", None, "tool", name="execute_trade"),  # no calling agent
        Span(T, "4", None, "agent", name="supervisor"),
        Span(T, "5", "4", "tool", name="unknown_tool"),
        Span(T, "6", "4", "tool", name="delegate_trade"),
    ]
    rows = paths(spans, tools=("execute_trade",), wrappers=("delegate_trade",))
    assert rows == ()
    rows = paths(spans)
    assert [(r.path, r.tool) for r in rows] == [(("supervisor",), "delegate_trade")]


def test_grouping_and_examples():
    spans = []
    for i in range(1, 6):
        spans += deep(trace=f"{i:032d}")
        spans += [Span(f"{i:032d}", "4", "2", "tool", name="execute_trade")]
    row = one(paths(spans))
    assert row.count == 10
    assert row.traces == tuple(f"{i:032d}" for i in range(1, 4))


def test_untested_sorts_first():
    spans = [*deep(), Span(T, "4", "2", "tool", name="delegate_trade")]
    rows = paths(spans, case_routes=((ROUTE, "delegate_trade"),))
    assert [r.status for r in rows] == ["UNTESTED", "TESTED"]


def test_error_trace_gives_no_rows():
    assert paths([*deep(), Span(T, "3", "2", "tool", name="x")]) == ()


def test_linear_time():
    spans = deep()[:2]
    spans += [Span(T, f"t{i}", "2", "tool", name="execute_trade") for i in range(100_000)]
    start = time.perf_counter()
    rows = paths(spans)
    assert time.perf_counter() - start < 10
    assert one(rows).count == 100_000


# ---- gate ----


def prow(status="UNTESTED", tool="execute_trade"):
    return PathRow(path=ROUTE, tool=tool, incomplete=False, status=status, count=1, traces=(T,))


RISKS = {"execute_trade": Risk.CRITICAL, "get_stock_price": Risk.LOW}


def test_untested_path_by_risk_list():
    got = observe_gate((), (), GateConfig(), paths=[prow()], risks=RISKS)
    assert got.violations == (
        ObserveViolation(rule="fail_on_untested_path", path=ROUTE, tool="execute_trade"),
    )
    low = observe_gate((), (), GateConfig(), paths=[prow(tool="get_stock_price")], risks=RISKS)
    assert low.passed
    cfg = GateConfig(fail_on_untested_path=(Risk.LOW,))
    assert observe_gate((), (), cfg, paths=[prow(tool="get_stock_price")], risks=RISKS).violations
    assert observe_gate((), (), GateConfig(fail_on_untested_path=()), paths=[prow()]).passed


def test_other_statuses_never_block_and_missing_risk_is_unknown():
    rows = [prow("TESTED"), prow("TESTED_OTHER_PATH")]
    assert observe_gate((), (), GateConfig(), paths=rows, risks=RISKS).passed
    assert observe_gate((), (), GateConfig(), paths=[prow()]).violations


def test_stage_two_call_still_works():
    assert observe_gate((), (), GateConfig()).passed
