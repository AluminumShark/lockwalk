"""Identity rows and the test-report side by side."""

import itertools
import time
from datetime import UTC, datetime
from pathlib import Path

from observe_helpers import catalog

from lockwalk.models import IdentityCheckRow, IdentityObservation, IdentityResult
from lockwalk.observe.checks import (
    STATIC_REPORT_WARNING,
    TEST_DIFFERS_NOTE,
    count_links,
    identity_findings,
    load_test_report,
    records_without_known_agent,
)
from lockwalk.observe.door import DoorRecord, decision_only
from lockwalk.observe.links import RecordLink, TraceLinks
from lockwalk.observe.spans import Span
from lockwalk.observe.tree import build_traces
from lockwalk.report import write_report

T = "0" * 31 + "1"
USER = "user-secret-4711"
OTHER = "user-secret-9999"


def door(stype="user", sid=USER, act=(), decision="allow"):
    return DoorRecord(
        decision=decision,
        subject_type=stype,
        subject_id=sid,
        act=tuple(act),
        action="trade",
        resource_type=None,
        tool_call_id=None,
    )


def base_spans(rec, tool="execute_trade"):
    """supervisor > trade-agent > tool, with the record on its own span below the tool."""
    return [
        Span(T, "1", None, "agent", name="supervisor"),
        Span(T, "2", "1", "agent", name="trade-agent"),
        Span(T, "3", "2", "tool", name=tool),
        Span(T, "4", "3", "other", door=rec),
    ]


def run(
    spans,
    *,
    mode="user",
    user=USER,
    cat=None,
    report=None,
    agent_ambiguous=False,
    conflict=False,
    kind="ancestry",
    call="3",
    record="4",
    candidates=(),
    link_agent="auto",
):
    cat = cat or catalog(modes={"trade-agent": mode, "supervisor": mode})
    views = build_traces(spans, cat)
    view = views[0]
    agent = view.calls[call].agent if link_agent == "auto" and call in view.calls else None
    if link_agent != "auto":
        agent = link_agent
    link = RecordLink(
        span_id=record,
        kind=kind,
        call=call if kind != "ambiguous" else None,
        candidates=tuple(candidates),
        agent=agent,
        agent_ambiguous=agent_ambiguous,
        user_id=user,
        user_conflict=conflict,
    )
    links = [TraceLinks(T, (link,), (), 0)]
    return identity_findings(views, links, cat, report)


def one(rows):
    assert len(rows) == 1
    return rows[0]


def test_user_mode_match_and_shown_form():
    row = one(run(base_spans(door())))
    assert (row.result, row.observed, row.expected) == (
        "MATCH",
        "the trace's user",
        "the trace's user",
    )
    assert (row.path, row.tool, row.mode) == (
        ("supervisor", "trade-agent"),
        "execute_trade",
        "user",
    )


def test_user_mode_other_user_mismatch():
    row = one(run(base_spans(door(sid=OTHER))))
    assert (row.result, row.observed) == ("MISMATCH", "another user")


def test_user_mode_agent_subject_mismatch_even_without_user():
    row = one(run(base_spans(door("agent", "trade-agent")), user=None))
    assert (row.result, row.observed) == ("MISMATCH", "agent:trade-agent")


def test_user_mode_missing_user_inconclusive():
    row = one(run(base_spans(door()), user=None))
    assert (row.result, row.observed) == ("INCONCLUSIVE", "a user (cannot compare)")
    assert row.notes == ("the trace has no user id to compare with",)


def test_user_conflict_uses_the_nearest_user_with_a_note():
    note = "the trace holds two different user ids; the nearest one is used"
    row = one(run(base_spans(door()), conflict=True))
    assert (row.result, row.observed, row.notes) == ("MATCH", "the trace's user", (note,))
    row = one(run(base_spans(door(sid=OTHER)), conflict=True))
    assert (row.result, row.observed, row.notes) == ("MISMATCH", "another user", (note,))


def test_ambiguous_takes_the_first_candidate_with_a_known_agent():
    spans = [
        Span(T, "1", None, "agent", name="mystery"),
        Span(T, "2", "1", "tool", name="execute_trade"),
        Span(T, "3", None, "agent", name="trade-agent"),
        Span(T, "5", "3", "tool", name="execute_trade"),
        Span(T, "4", None, "other", door=door()),
    ]
    row = one(
        run(
            spans,
            kind="ambiguous",
            agent_ambiguous=True,
            candidates=("2", "5"),
            link_agent=None,
            call="5",
        )
    )
    assert (row.result, row.path) == ("INCONCLUSIVE", ("trade-agent",))
    none_known = run(
        spans[:2] + spans[4:],
        kind="ambiguous",
        agent_ambiguous=True,
        candidates=("2",),
        link_agent=None,
        call="2",
    )
    assert none_known == ()


def test_user_mode_with_act_is_mismatch():
    row = one(run(base_spans(door(act=[("agent", "trade-agent")]))))
    assert row.result == "MISMATCH"
    assert row.observed == "the trace's user, acting through trade-agent"


def test_agent_mode():
    cat = catalog(modes={"trade-agent": "agent"})
    assert one(run(base_spans(door("agent", "trade-agent")), cat=cat)).result == "MATCH"
    wrong = one(run(base_spans(door("agent", "supervisor")), cat=cat))
    assert (wrong.result, wrong.observed) == ("MISMATCH", "agent:supervisor")
    with_act = one(run(base_spans(door("agent", "trade-agent", [("agent", "x")])), cat=cat))
    assert with_act.result == "MISMATCH"
    assert one(run(base_spans(door()), cat=cat)).result == "MISMATCH"


def test_unknown_agent_id_and_other_types_are_hidden():
    cat = catalog(modes={"trade-agent": "agent"})
    row = one(run(base_spans(door("agent", "ghost-1")), cat=cat))
    assert row.observed == "agent:hidden"
    row = one(run(base_spans(door("service", "svc-secret")), cat=cat))
    assert row.observed == "service:hidden"
    assert "svc-secret" not in row.model_dump_json()


def obo_door(*chain, sid=USER):
    return door(sid=sid, act=[("agent", a) for a in chain])


def test_on_behalf_of_match_and_chain_order():
    row = one(run(base_spans(obo_door("trade-agent", "supervisor")), mode="on_behalf_of"))
    assert row.result == "MATCH"
    assert row.expected == "the trace's user, acting through trade-agent < supervisor"
    assert row.observed == "the trace's user, acting through trade-agent < supervisor"


def test_on_behalf_of_wrong_chain_mismatch():
    reversed_ = obo_door("supervisor", "trade-agent")
    assert one(run(base_spans(reversed_), mode="on_behalf_of")).result == "MISMATCH"
    short = obo_door("trade-agent")
    assert one(run(base_spans(short), mode="on_behalf_of")).result == "MISMATCH"
    none = door()
    assert one(run(base_spans(none), mode="on_behalf_of")).result == "MISMATCH"
    link_type = door(act=[("agent", "trade-agent"), ("user", "supervisor")])
    assert one(run(base_spans(link_type), mode="on_behalf_of")).result == "MISMATCH"


def test_on_behalf_of_wrong_user_and_missing_user():
    ok_chain = ("trade-agent", "supervisor")
    assert one(run(base_spans(obo_door(*ok_chain, sid=OTHER)), mode="on_behalf_of")).result == (
        "MISMATCH"
    )
    row = one(run(base_spans(obo_door(*ok_chain)), mode="on_behalf_of", user=None))
    assert row.result == "INCONCLUSIVE"


def test_on_behalf_of_incomplete_path_inconclusive():
    spans = [
        Span(T, "2", "9", "agent", name="trade-agent"),  # parent "9" is not in the data
        Span(T, "3", "2", "tool", name="execute_trade"),
        Span(T, "4", "3", "other", door=obo_door("trade-agent", "supervisor")),
    ]
    row = one(run(spans, mode="on_behalf_of"))
    assert row.result == "INCONCLUSIVE"
    assert "incomplete" in row.notes[0]
    # an outermost link that is not the calling agent is wrong even when the path is incomplete
    bad = [spans[0], spans[1], Span(T, "4", "3", "other", door=obo_door("supervisor"))]
    assert one(run(bad, mode="on_behalf_of")).result == "MISMATCH"


def test_undeclared_is_observed():
    cat = catalog(modes={})
    row = one(run(base_spans(door(sid=OTHER)), cat=cat))
    assert (row.result, row.mode, row.observed) == ("OBSERVED", "undeclared", "another user")


def test_ambiguous_agent_inconclusive_without_tool():
    spans = [*base_spans(door()), Span(T, "5", "2", "tool", name="execute_trade")]
    row = one(
        run(
            spans,
            kind="ambiguous",
            agent_ambiguous=True,
            candidates=("3", "5"),
            link_agent=None,
            call="3",
        )
    )
    assert (row.result, row.tool) == ("INCONCLUSIVE", None)
    assert row.notes == (
        "the record cannot be tied to one tool call; it is shown under the first candidate's path",
    )
    assert row.expected == "cannot be tied to one tool call"
    assert row.observed == "the trace's user"
    assert records_without_known_agent(*views_links(spans)) == 0


def test_unknown_or_absent_agent_is_not_a_row():
    spans = base_spans(door())
    assert run(spans, link_agent=None) == ()
    unknown = [
        Span(T, "2", None, "agent", name="mystery"),
        Span(T, "3", "2", "tool", name="execute_trade"),
        Span(T, "4", "3", "other", door=door()),
    ]
    assert run(unknown) == ()


def test_tool_none_when_the_record_is_not_under_a_call():
    spans = [
        Span(T, "1", None, "agent", name="supervisor"),
        Span(T, "4", "1", "other", door=door()),
    ]
    views = build_traces(spans, catalog(modes={"supervisor": "user"}))
    agent = views[0].visits["1"]
    link = RecordLink("4", "none", None, (), agent, False, USER, False)
    rows = identity_findings(
        views, [TraceLinks(T, (link,), (), 0)], catalog(modes={"supervisor": "user"}), None
    )
    assert one(rows).tool is None and one(rows).path == ("supervisor",)


def test_unknown_tool_has_no_tool():
    row = one(run(base_spans(door(), tool="mystery_tool")))
    assert row.tool is None


def test_grouping_counts_and_examples():
    traces = [f"{i:032d}" for i in range(1, 6)]
    views, links = [], []
    cat = catalog(modes={"trade-agent": "user"})
    for trace in traces:
        spans = [
            Span(trace, "1", None, "agent", name="supervisor"),
            Span(trace, "2", "1", "agent", name="trade-agent"),
            Span(trace, "3", "2", "tool", name="execute_trade"),
            Span(trace, "4", "3", "other", door=door()),
        ]
        view = build_traces(spans, cat)[0]
        views.append(view)
        agent = view.calls["3"].agent
        link = RecordLink("4", "ancestry", "3", (), agent, False, USER, False)
        links.append(TraceLinks(trace, (link, link), (), 0))
    row = one(identity_findings(views, links, cat, None))
    assert row.count == 10
    assert row.traces == tuple(traces[:3])


def test_no_user_id_in_any_row():
    rows = run(base_spans(door(sid=OTHER)))
    rows += run(base_spans(door(sid=USER)))
    blob = "".join(row.model_dump_json() for row in rows)
    assert USER not in blob and OTHER not in blob and "user-secret" not in blob


def test_long_subject_type_is_cut_and_masked():
    cat = catalog(modes={"trade-agent": "agent"})
    row = one(run(base_spans(door("t" * 500 + " https://u:pw@h/x", "id")), cat=cat))
    assert len(row.observed) <= 200
    assert "pw" not in row.observed


# ---- side by side ----


def build_test_report(
    make_report, *, result=IdentityResult.MATCH, tool="execute_trade", mode="test"
):
    report = make_report()
    check = IdentityCheckRow(
        case_id="CASE-003",
        path=("supervisor", "trade-agent"),
        tool=tool,
        result=result,
        observations=(
            IdentityObservation(
                mode="direct",
                expected={"type": "user"},
                observed=({"type": "user"},),
                result=result,
            ),
            IdentityObservation(
                mode="scripted", expected={"type": "user"}, observed=(), result=result
            ),
        ),
    )
    return report.model_copy(update={"mode": mode, "identity_checks": (check,)})


def test_side_by_side_match_beside_mismatch_adds_note(make_report):
    report = build_test_report(make_report)
    row = one(run(base_spans(door(sid=OTHER)), report=report))
    assert row.test_results == ("CASE-003 direct: MATCH", "CASE-003 scripted: MATCH")
    assert row.notes == (TEST_DIFFERS_NOTE,)


def test_side_by_side_no_note_when_observed_matches(make_report):
    report = build_test_report(make_report)
    row = one(run(base_spans(door()), report=report))
    assert row.test_results and row.notes == ()


def test_side_by_side_other_tool_or_path_or_static(make_report):
    other_tool = build_test_report(make_report, tool="read_portfolio")
    assert one(run(base_spans(door()), report=other_tool)).test_results == ()
    static = build_test_report(make_report, mode="static")
    assert one(run(base_spans(door()), report=static)).test_results == ()


def test_side_by_side_mismatching_test_result_has_no_note(make_report):
    report = build_test_report(make_report, result=IdentityResult.MISMATCH)
    row = one(run(base_spans(door(sid=OTHER)), report=report))
    assert row.test_results[0] == "CASE-003 direct: MISMATCH"
    assert row.notes == ()


# ---- load_test_report ----


def test_load_none_and_missing(tmp_path):
    assert load_test_report(None) == (None, None)
    assert load_test_report(tmp_path / "coverage.json") == (None, None)


def test_load_unreadable_and_invalid(tmp_path: Path):
    bad = tmp_path / "coverage.json"
    bad.write_text("{not json", encoding="utf-8")
    report, warning = load_test_report(bad)
    assert report is None and warning is not None and "cannot be used" in warning
    bad.write_text('{"schema_version": "999"}', encoding="utf-8")
    report, warning = load_test_report(bad)
    assert report is None and warning is not None
    report, warning = load_test_report(tmp_path)  # a directory
    assert report is None and warning is not None


def test_load_valid_test_and_static(tmp_path: Path, make_report):
    path = tmp_path / "coverage.json"
    stamp = {"generated_at": datetime(2026, 1, 1, tzinfo=UTC), "version": "0.1.0"}
    write_report(build_test_report(make_report), tmp_path, **stamp)
    report, warning = load_test_report(path)
    assert warning is None and report is not None and report.mode == "test"
    write_report(build_test_report(make_report, mode="static"), tmp_path, **stamp)
    assert load_test_report(path) == (None, STATIC_REPORT_WARNING)


def test_linear_time():
    cat = catalog(modes={"trade-agent": "user"})
    spans = [
        Span(T, "a", None, "agent", name="supervisor"),
        Span(T, "b", "a", "agent", name="trade-agent"),
        Span(T, "c", "b", "tool", name="execute_trade"),
    ]
    n = 100_000
    spans += [Span(T, f"r{i}", "c", "other", door=door()) for i in range(n)]
    views = build_traces(spans, cat)
    agent = views[0].calls["c"].agent
    records = tuple(
        RecordLink(f"r{i}", "ancestry", "c", (), agent, False, USER, False) for i in range(n)
    )
    start = time.perf_counter()
    rows = identity_findings(views, [TraceLinks(T, records, (), 0)], cat, None)
    assert time.perf_counter() - start < 5
    assert one(rows).count == n


def views_links(spans, call="3", record="4"):
    cat = catalog(modes={"trade-agent": "user"})
    views = build_traces(spans, cat)
    agent = views[0].calls[call].agent if call in views[0].calls else None
    link = RecordLink(record, "ancestry", call, (), agent, False, USER, False)
    return views, [TraceLinks(T, (link,), (), 0)]


def test_records_without_known_agent_are_counted():
    unknown = [
        Span(T, "2", None, "agent", name="mystery"),
        Span(T, "3", "2", "tool", name="execute_trade"),
        Span(T, "4", "3", "other", door=door()),
    ]
    assert records_without_known_agent(*views_links(unknown)) == 1
    assert records_without_known_agent(*views_links(base_spans(door()))) == 0


def test_on_behalf_of_incomplete_path_compares_known_positions():
    # path ("trade-agent",) is the known tail: act[0] must be trade-agent
    def incomplete(act):
        spans = [
            Span(T, "2", "9", "agent", name="trade-agent"),
            Span(T, "3", "2", "tool", name="execute_trade"),
            Span(T, "4", "3", "other", door=door(act=act)),
        ]
        return one(run(spans, mode="on_behalf_of")).result

    assert incomplete([("agent", "trade-agent")]) == "INCONCLUSIVE"
    assert incomplete([("agent", "trade-agent"), ("agent", "supervisor")]) == "INCONCLUSIVE"
    assert incomplete([("agent", "supervisor")]) == "MISMATCH"
    assert incomplete([]) == "MISMATCH"


def test_on_behalf_of_incomplete_two_step_path():
    spans = [
        Span(T, "1", "9", "agent", name="supervisor"),
        Span(T, "2", "1", "agent", name="trade-agent"),
        Span(T, "3", "2", "tool", name="execute_trade"),
        Span(T, "4", "3", "other", door=obo_door("trade-agent")),
    ]
    assert one(run(spans, mode="on_behalf_of")).result == "MISMATCH"  # shorter than known path
    spans[-1] = Span(T, "4", "3", "other", door=obo_door("trade-agent", "other"))
    assert one(run(spans, mode="on_behalf_of")).result == "MISMATCH"
    spans[-1] = Span(T, "4", "3", "other", door=obo_door("trade-agent", "supervisor"))
    assert one(run(spans, mode="on_behalf_of")).result == "INCONCLUSIVE"


def test_complete_path_longer_chain_is_mismatch():
    chain = obo_door("trade-agent", "supervisor", "extra")
    assert one(run(base_spans(chain), mode="on_behalf_of")).result == "MISMATCH"


def test_test_results_are_capped_and_note_needs_every_check_to_match(make_report):
    report = build_test_report(make_report)
    base = report.identity_checks[0]
    many = tuple(base.model_copy(update={"case_id": f"CASE-{i:03d}"}) for i in range(8))
    capped = report.model_copy(update={"identity_checks": many})
    row = one(run(base_spans(door(sid=OTHER)), report=capped))
    assert len(row.test_results) == 11
    assert row.test_results[-1] == "... and 6 more"
    assert TEST_DIFFERS_NOTE in row.notes
    worse = base.model_copy(update={"case_id": "CASE-900", "result": IdentityResult.MISMATCH})
    mixed = report.model_copy(update={"identity_checks": (base, worse)})
    row = one(run(base_spans(door(sid=OTHER)), report=mixed))
    assert TEST_DIFFERS_NOTE not in row.notes


def test_decision_only_record_is_not_an_identity_row():
    spans = base_spans(decision_only("deny", None))
    assert run(spans) == ()
    counts = count_links(*views_links(spans))
    assert counts.no_subject == 1
    assert counts.no_known_agent == 0
    assert records_without_known_agent(*views_links(spans)) == 0


def test_decision_only_record_next_to_a_normal_one_gives_the_normal_row():
    spans = [*base_spans(door()), Span(T, "5", "3", "other", door=decision_only("allow", None))]
    cat = catalog(modes={"trade-agent": "user", "supervisor": "user"})
    views = build_traces(spans, cat)
    agent = views[0].calls["3"].agent

    def link(span_id):
        return RecordLink(span_id, "ancestry", "3", (), agent, False, USER, False)

    links = [TraceLinks(T, (link("4"), link("5")), (), 0)]
    rows = identity_findings(views, links, cat, None)
    assert [(row.result, row.count) for row in rows] == [("MATCH", 1)]
    assert count_links(views, links).no_subject == 1


# ---- expected text stays inside its own cap ----


def chain_case(names, mode, rec):
    """A catalog and spans for the agents in `names`, each calling the next, then a tool."""
    spans = [Span(T, "1", None, "agent", name=names[0])]
    for index, name in enumerate(names[1:], start=2):
        spans.append(Span(T, str(index), str(index - 1), "agent", name=name))
    last = len(names)
    spans.append(Span(T, str(last + 1), str(last), "tool", name="execute_trade"))
    spans.append(Span(T, str(last + 2), str(last + 1), "other", door=rec))
    cat = catalog(
        agents=tuple(names),
        entry=(names[0],),
        agent_edges=tuple(itertools.pairwise(names)),
        tool_edges=((names[-1], "execute_trade"),),
        modes={name: mode for name in names},
    )
    return cat, spans, str(last + 1), str(last + 2)


def test_expected_is_capped_for_a_long_agent_id_in_agent_mode():
    name = "a" * 195
    cat, spans, call, record = chain_case([name], "agent", door("agent", name))
    row = one(run(spans, cat=cat, call=call, record=record))
    assert len(row.expected) <= 200
    assert row.expected.endswith("...")


def test_expected_is_capped_as_a_whole_for_a_long_path_on_behalf_of():
    names = ["a" * 150, "b" * 150, "c" * 150]
    rec = door("user", USER, [("agent", names[1])])
    cat, spans, call, record = chain_case(names, "on_behalf_of", rec)
    row = one(run(spans, cat=cat, call=call, record=record))
    assert len(row.expected) <= 200
    assert row.expected.startswith("the trace's user, acting through ")


def test_expected_masks_a_url_shaped_agent_id():
    name = "agent-https://u:pw@h/x"
    cat, spans, call, record = chain_case([name], "agent", door("agent", name))
    row = one(run(spans, cat=cat, call=call, record=record))
    assert "pw" not in row.expected
