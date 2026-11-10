"""inspect --case real traffic and inspect --trace door lines."""

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from observe_helpers import catalog

from lockwalk import inspection
from lockwalk.inspection import inspect_case, inspect_trace
from lockwalk.observe.door import DoorRecord, decision_only
from lockwalk.observe.links import RecordLink, TraceLinks
from lockwalk.observe.output import write_observe
from lockwalk.observe.results import (
    GuardRow,
    IdentityRow,
    ObserveGate,
    ObserveReport,
    ObserveTotals,
    ObserveWindow,
    PathRow,
)
from lockwalk.observe.spans import Span
from lockwalk.observe.tree import build_traces
from lockwalk.report import write_report

NOW = datetime(2026, 11, 8, 10, 0, tzinfo=UTC)
TRACE = "a" * 32
USER_ID = "alice-secret-id"


def observe_report(**changes: Any) -> ObserveReport:
    base = dict(
        scenario_suite="demo",
        sources=("a.jsonl",),
        totals=ObserveTotals(
            files=1,
            traces=1,
            spans=3,
            agent_spans=1,
            tool_calls=1,
            incomplete_traces=0,
            error_traces=0,
            unnamed_markers=0,
        ),
        window=ObserveWindow(first="2026-11-07T00:00:00Z", last="2026-11-08T00:00:00Z"),
        gate=ObserveGate(passed=True),
        exit_code=0,
    )
    return ObserveReport.model_validate({**base, **changes})


def matching_rows() -> dict[str, Any]:
    return dict(
        identities=(
            IdentityRow(
                path=("finance-agent",),
                tool="read_portfolio",
                mode="user",
                expected="the trace's user",
                observed="the trace's user",
                result="MATCH",
                count=120,
                traces=(TRACE,),
            ),
            IdentityRow(  # another tool: not shown
                path=("finance-agent",),
                tool="get_stock_price",
                mode="user",
                expected="x",
                observed="y",
                result="MISMATCH",
                count=5,
                traces=(TRACE,),
            ),
        ),
        guards=(
            GuardRow(
                agent="finance-agent",
                tool="read_portfolio",
                tool_known=True,
                counts={"GUARDED": 118, "UNGUARDED": 2},
                by_time=0,
                effect_without_record=0,
                traces=(TRACE,),
            ),
        ),
        paths=(
            PathRow(
                path=("finance-agent",),
                tool="read_portfolio",
                incomplete=False,
                status="TESTED",
                count=120,
                traces=(TRACE,),
            ),
        ),
    )


def prepare(tmp_path: Path, make_report, observe: ObserveReport | str | None) -> Path:
    write_report(make_report(), tmp_path, generated_at=NOW, version="x")
    if isinstance(observe, ObserveReport):
        write_observe(observe, tmp_path, generated_at=NOW, version="x")
    elif observe is not None:
        (tmp_path / "observe.json").write_text(observe, encoding="utf-8")
    return tmp_path


def test_real_traffic_lines(tmp_path: Path, make_report) -> None:
    folder = prepare(tmp_path, make_report, observe_report(**matching_rows()))
    lines = inspect_case(folder, "CASE-003")
    head = next(line for line in lines if line.startswith("  real traffic (observe, "))
    assert head.endswith("):")
    gaps = lines.index("  gaps:")
    traffic = lines[lines.index(head) + 1 : gaps]
    assert traffic == [
        "    identity (user): MATCH 120, expected the trace's user, saw the trace's user",
        "    door: GUARDED 118, UNGUARDED 2",
        "    path: TESTED 120",
    ]
    assert "MISMATCH" not in "\n".join(lines)  # a row of another tool
    assert USER_ID not in "\n".join(lines)


def test_real_traffic_did_not_take_this_path(tmp_path: Path, make_report) -> None:
    folder = prepare(tmp_path, make_report, observe_report(**matching_rows()))
    lines = inspect_case(folder, "CASE-004")  # research-agent -> execute_trade
    start = next(i for i, line in enumerate(lines) if line.startswith("  real traffic"))
    assert lines[start + 1] == "    real traffic did not take this path"


def test_a_run_with_errors_does_not_claim_the_path_was_not_taken(
    tmp_path: Path, make_report
) -> None:
    report = observe_report(**matching_rows(), errors=("a.jsonl: bad line",), exit_code=2)
    folder = prepare(tmp_path, make_report, report)
    lines = inspect_case(folder, "CASE-004")
    start = next(i for i, line in enumerate(lines) if line.startswith("  real traffic"))
    assert lines[start + 1] == "    the last observe run had errors; real traffic may be incomplete"
    assert "real traffic did not take this path" not in "\n".join(lines)


def test_a_route_case_matches_the_whole_path(tmp_path: Path, make_report) -> None:
    case = dict(
        id="CASE-010",
        actor="alice",
        role="analyst",
        tool="read_portfolio",
        action="portfolio:read",
        resource_fixture="alice-portfolio",
        expect="allow",
        path=["research-agent", "finance-agent"],
    )
    write_report(make_report(extra_cases=[case]), tmp_path, generated_at=NOW, version="x")
    write_observe(observe_report(**matching_rows()), tmp_path, generated_at=NOW, version="x")
    lines = inspect_case(tmp_path, "CASE-010")
    # identity and path rows are for the one-agent path only; guard rows have no path, so the
    # calling agent (last agent of the route) and the tool decide
    text = "\n".join(lines)
    assert "identity (" not in text and "    path: " not in text
    assert "    door: GUARDED 118, UNGUARDED 2" in lines


def test_no_observe_json_shows_nothing(tmp_path: Path, make_report) -> None:
    lines = inspect_case(prepare(tmp_path, make_report, None), "CASE-003")
    text = "\n".join(lines)
    assert "real traffic" not in text and "observe.json" not in text


@pytest.mark.parametrize(
    "junk", ["not json", "[1]", '{"schema_version": "0"}', '{"schema_version": "1"}']
)
def test_a_broken_observe_json_is_a_gap(tmp_path: Path, make_report, junk: str) -> None:
    folder = prepare(tmp_path, make_report, junk)
    lines = inspect_case(folder, "CASE-003")
    gap = next(line for line in lines if "observe.json cannot be used:" in line)
    assert gap.startswith("    - observe.json cannot be used: ")
    assert lines.index(gap) > lines.index("  gaps:")
    assert not any(line.startswith("  real traffic") for line in lines)


def test_observe_json_that_is_a_directory_is_a_gap(tmp_path: Path, make_report) -> None:
    folder = prepare(tmp_path, make_report, None)
    (folder / "observe.json").mkdir()
    lines = inspect_case(folder, "CASE-003")
    assert any("observe.json cannot be used:" in line for line in lines)


def test_many_matching_rows_are_capped(tmp_path: Path, make_report) -> None:
    rows = tuple(
        IdentityRow(
            path=("finance-agent",),
            tool="read_portfolio",
            mode="user",
            expected="the trace's user",
            observed=f"agent:a{i}",
            result="OBSERVED",
            count=1,
            traces=(TRACE,),
        )
        for i in range(30)
    )
    folder = prepare(tmp_path, make_report, observe_report(identities=rows))
    lines = inspect_case(folder, "CASE-003")
    assert "    ... and 10 more; see observe.json" in lines


def test_traffic_lines_are_ascii(tmp_path: Path, make_report) -> None:
    rows = matching_rows()
    rows["identities"] = (rows["identities"][0].model_copy(),)
    evil = IdentityRow(
        path=("finance-agent",),
        tool="read_portfolio",
        mode="user",
        expected="\x1b[31m",
        observed="\u522a",
        result="MISMATCH",
        count=1,
        traces=(TRACE,),
    )
    folder = prepare(tmp_path, make_report, observe_report(identities=(evil,)))
    for line in inspect_case(folder, "CASE-003"):
        assert line.isascii() and "\x1b" not in line


# ---- inspect --trace door lines ----


def door(decision: str = "allow", kind: str = "agent", ident: str = "trade-agent", act=()):
    return DoorRecord(
        decision=decision,  # ty: ignore[invalid-argument-type]
        subject_type=kind,
        subject_id=ident,
        act=tuple(act),
        action="trade:execute",
        resource_type=None,
        tool_call_id=None,
    )


def view_with_doors(*, door_on_tool: bool = True):
    spans = [
        Span(TRACE, "s1", None, "agent", name="supervisor", start_ns=1),
        Span(TRACE, "s2", "s1", "agent", name="trade-agent", start_ns=2),
        Span(TRACE, "s3", "s2", "tool", name="execute_trade", start_ns=3),
        Span(TRACE, "d1", "s3", "other", start_ns=4, door=door("deny", "user", USER_ID)),
        Span(TRACE, "e1", "s3", "other", start_ns=5, effect=True),
        Span(
            TRACE,
            "d2",
            "s2",
            "other",
            start_ns=6,
            door=door("allow", "agent", "ghost-agent", act=[("agent", "trade-agent")]),
        ),
        Span(TRACE, "e2", "s2", "other", start_ns=7, effect=True),
    ]
    (view,) = build_traces(spans, catalog())
    return view


def link(span_id: str, kind: str, view, *, call=None, user_id=USER_ID, **kw) -> RecordLink:
    agent = view.visits["s2"]
    return RecordLink(
        span_id=span_id,
        kind=kind,  # ty: ignore[invalid-argument-type]
        call=call,
        candidates=kw.get("candidates", ()),
        agent=agent,
        agent_ambiguous=False,
        user_id=user_id,
        user_conflict=False,
    )


def hand_links(view) -> TraceLinks:
    return TraceLinks(
        trace_id=TRACE,
        records=(
            link("d1", "time", view, call="s3"),
            link("d2", "none", view),
        ),
        effects=(
            link("e1", "ancestry", view, call="s3"),
            link("e2", "none", view),
        ),
        covers_tools=0,
    )


def test_door_lines_sit_below_the_tool_line() -> None:
    view = view_with_doors()
    lines = inspection._trace_lines(view, catalog(), hand_links(view))
    tool = next(i for i, line in enumerate(lines) if "tool execute_trade" in line)
    assert lines[tool + 1].strip() == "door: deny for the trace's user (linked by time)"
    assert lines[tool + 2].strip() == "effect marker (linked by ancestry)"
    # deeper than the tool line
    assert len(lines[tool + 1]) - len(lines[tool + 1].lstrip()) > len(lines[tool]) - len(
        lines[tool].lstrip()
    )


def test_records_without_a_call_sit_under_their_agent() -> None:
    view = view_with_doors()
    lines = inspection._trace_lines(view, catalog(), hand_links(view))
    agent = next(i for i, line in enumerate(lines) if line.strip().startswith("agent trade-agent"))
    assert lines[agent + 1].strip() == (
        "door record not linked to a tool call: allow for agent:hidden, acting through trade-agent "
        "(no tool call found)"
    )
    assert lines[agent + 2].strip() == "effect marker not linked to a tool call"


def test_other_user_and_cannot_compare() -> None:
    view = view_with_doors()
    other = TraceLinks(
        trace_id=TRACE,
        records=(link("d1", "tool_call_id", view, call="s3", user_id="someone-else"),),
        effects=(),
        covers_tools=0,
    )
    text = "\n".join(inspection._trace_lines(view, catalog(), other))
    assert "door: deny for another user (linked by tool call id)" in text
    unknown = TraceLinks(
        trace_id=TRACE,
        records=(link("d1", "ancestry", view, call="s3", user_id=None),),
        effects=(),
        covers_tools=0,
    )
    text = "\n".join(inspection._trace_lines(view, catalog(), unknown))
    assert "door: deny for a user (cannot compare) (linked by ancestry)" in text


def test_ambiguous_and_covering_records() -> None:
    view = view_with_doors()
    links = TraceLinks(
        trace_id=TRACE,
        records=(
            link("d1", "ambiguous", view, candidates=("s3", "s9")),
            link("d2", "covers_tools", view),
        ),
        effects=(),
        covers_tools=1,
    )
    text = "\n".join(inspection._trace_lines(view, catalog(), links))
    assert "(several tool calls match by time; not linked)" in text
    assert "candidate" not in text
    assert "(its span contains tool calls)" in text


def test_no_user_id_anywhere_and_ascii() -> None:
    view = view_with_doors()
    lines = inspection._trace_lines(view, catalog(), hand_links(view))
    for line in lines:
        assert USER_ID not in line and line.isascii()


def test_without_links_nothing_changes() -> None:
    view = view_with_doors()
    assert inspection._trace_lines(view, catalog()) == inspection._trace_lines(
        view, catalog(), None
    )
    assert "door" not in "\n".join(inspection._trace_lines(view, catalog()))


def test_inspect_trace_uses_the_links_of_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    view = view_with_doors()
    run = SimpleNamespace(
        views=[view],
        links=[hand_links(view)],
        catalog=catalog(),
        report=SimpleNamespace(errors=()),
    )
    monkeypatch.setattr(inspection, "wanted_trace_id", lambda settings, trace_id: trace_id)
    monkeypatch.setattr(inspection, "run_observe", lambda settings, only_trace: run)
    lines = inspect_trace(SimpleNamespace(), TRACE)  # ty: ignore[invalid-argument-type]
    assert any("door: deny for the trace's user" in line for line in lines)
    run.links = []  # a run without links shows no door lines
    plain = inspect_trace(SimpleNamespace(), TRACE)  # ty: ignore[invalid-argument-type]
    assert not any("door:" in line for line in plain)


def test_inspect_uses_the_same_shown_form_as_the_identity_rows() -> None:
    from lockwalk.observe.checks import observed_form

    cat = catalog(agent_alias={"trade_bot": "trade-agent"})
    view = view_with_doors()
    record = view.spans["d2"].door
    assert record is not None
    links = hand_links(view)
    expected = observed_form(record.subject_type, record.subject_id, record.act, USER_ID, cat)
    text = "\n".join(inspection._trace_lines(view, cat, links))
    assert f"allow for {expected}" in text


def test_a_span_name_alias_is_not_a_known_agent_and_hidden_links_are_marked() -> None:
    from lockwalk.observe.checks import observed_form

    cat = catalog(agent_alias={"trade_bot": "trade-agent"})
    assert observed_form("agent", "trade_bot", (), None, cat) == "agent:hidden"
    assert (
        observed_form("agent", "trade-agent", (("user", "x"), ("agent", "trade_bot")), None, cat)
        == "agent:trade-agent, acting through ? < ?"
    )


@pytest.mark.parametrize(("with_user", "shown"), [(True, "present"), (False, "missing")])
def test_trace_header_says_whether_the_trace_has_a_user(
    monkeypatch: pytest.MonkeyPatch, with_user: bool, shown: str
) -> None:
    spans = [
        Span(TRACE, "s1", None, "agent", name="supervisor", start_ns=1),
        Span(TRACE, "s2", "s1", "other", start_ns=2, user_id=USER_ID if with_user else None),
    ]
    (view,) = build_traces(spans, catalog())
    run = SimpleNamespace(
        views=[view], links=[], catalog=catalog(), report=SimpleNamespace(errors=())
    )
    monkeypatch.setattr(inspection, "wanted_trace_id", lambda settings, trace_id: trace_id)
    monkeypatch.setattr(inspection, "run_observe", lambda settings, only_trace: run)
    lines = inspect_trace(SimpleNamespace(), TRACE)  # ty: ignore[invalid-argument-type]
    assert lines[0].endswith(f"  user: {shown}")
    assert USER_ID not in "\n".join(lines)


def test_decision_only_record_lines() -> None:
    spans = [
        Span(TRACE, "s2", None, "agent", name="trade-agent", start_ns=2),
        Span(TRACE, "s3", "s2", "tool", name="execute_trade", start_ns=3),
        Span(TRACE, "d1", "s3", "other", start_ns=4, door=decision_only("deny", "c1")),
        Span(TRACE, "d2", "s2", "other", start_ns=5, door=decision_only("deny", None)),
    ]
    (view,) = build_traces(spans, catalog())
    agent = view.visits["s2"]

    def make(span_id, kind, call):
        return RecordLink(span_id, kind, call, (), agent, False, USER_ID, False)

    links = TraceLinks(TRACE, (make("d1", "tool_call_id", "s3"), make("d2", "none", None)), (), 0)
    lines = inspection._trace_lines(view, catalog(), links)
    text = " | ".join(line.strip() for line in lines)
    assert "door: deny (decision only, no subject) (linked by tool call id)" in text
    unlinked = "door record not linked to a tool call: deny (decision only, no subject)"
    assert f"{unlinked} (no tool call found)" in text
