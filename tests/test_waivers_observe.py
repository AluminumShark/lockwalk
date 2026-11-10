from datetime import date, timedelta

import pytest

import lockwalk.waivers as waivers_module
from lockwalk.observe.results import (
    GuardRow,
    IdentityRow,
    ObserveGate,
    ObserveReport,
    ObserveTotals,
    ObserveViolation,
    ObserveWindow,
    PathRow,
    RouteRow,
    UnknownRow,
)
from lockwalk.waivers import (
    Waiver,
    WaiverMatch,
    WaiversFile,
    apply_observe_waivers,
)

TODAY = date(2026, 6, 1)


def _day(offset: int) -> date:
    return TODAY + timedelta(days=offset)


def _w(wid, match, *, expires=None) -> Waiver:
    return Waiver(
        id=wid,
        match=WaiverMatch.model_validate(match),
        reason="accepted",
        owner="alice@example.com",
        expires=expires if expires is not None else _day(10),
    )


def _file(*items: Waiver) -> WaiversFile:
    return WaiversFile(schema_version="1", waivers=tuple(items))


V_ROUTE = ObserveViolation(rule="fail_on_off_map_route", from_id="a", to_id="b")
V_UNKNOWN = ObserveViolation(rule="fail_on_unknown_component", kind="tool", name="x")
V_BYPASS = ObserveViolation(rule="bypass", agent="a", tool="t")
V_BYPASS_NONE = ObserveViolation(rule="bypass", tool="t")
V_UNGUARDED = ObserveViolation(rule="fail_on_unguarded_call", agent="a", tool="t")
V_GUARD_INC = ObserveViolation(
    rule="fail_on_inconclusive_observation", subject="guard", agent="a", tool="t"
)
V_MISMATCH = ObserveViolation(rule="fail_on_identity_mismatch", path=("user", "a"), tool="t")
V_MISMATCH_NOTOOL = ObserveViolation(rule="fail_on_identity_mismatch", path=("user", "a"))
V_ID_INC = ObserveViolation(
    rule="fail_on_inconclusive_observation", subject="identity", path=("user", "a"), tool="t"
)
V_UNTESTED = ObserveViolation(rule="fail_on_untested_path", path=("user", "a"), tool="t")


def _report(violations=(), *, errors=(), **rows) -> ObserveReport:
    return ObserveReport(
        scenario_suite="s",
        sources=("x",),
        totals=ObserveTotals(
            files=1,
            traces=1,
            spans=1,
            agent_spans=1,
            tool_calls=1,
            incomplete_traces=0,
            error_traces=0,
            unnamed_markers=0,
        ),
        window=ObserveWindow(),
        gate=ObserveGate(passed=not violations, violations=tuple(violations)),
        errors=tuple(errors),
        warnings=("old warning",),
        exit_code=2 if errors else (1 if violations else 0),
        **rows,
    )


def _apply(report, *items):
    return apply_observe_waivers(report, _file(*items), TODAY)


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(waivers_module, "today", lambda: TODAY)


@pytest.mark.parametrize(
    ("match", "violation"),
    [
        ({"route": {"from": "a", "to": "b"}}, V_ROUTE),
        ({"unknown": {"kind": "tool", "name": "x"}}, V_UNKNOWN),
        ({"unguarded": {"agent": "a", "tool": "t"}}, V_BYPASS),
        ({"unguarded": {"agent": "(none)", "tool": "t"}}, V_BYPASS_NONE),
        ({"unguarded": {"agent": "a", "tool": "t"}}, V_UNGUARDED),
        ({"unguarded": {"agent": "a", "tool": "t"}}, V_GUARD_INC),
        ({"observed_identity": {"path": ["user", "a"], "tool": "t"}}, V_MISMATCH),
        ({"observed_identity": {"path": ["user", "a"], "tool": None}}, V_MISMATCH_NOTOOL),
        ({"observed_identity": {"path": ["user", "a"]}}, V_MISMATCH_NOTOOL),
        ({"observed_identity": {"path": ["user", "a"], "tool": "t"}}, V_ID_INC),
        ({"untested_path": {"path": ["user", "a"], "tool": "t"}}, V_UNTESTED),
    ],
)
def test_each_kind_applies(match, violation):
    out = _apply(_report((violation,)), _w("W1", match))
    assert out.gate.passed and out.gate.violations == ()
    assert [(x.violation, x.waiver_id) for x in out.gate.waived] == [(violation, "W1")]
    assert out.waivers[0].status == "applied"
    assert out.exit_code == 0


_KINDS = [
    (
        {"route": {"from": "a", "to": "b"}},
        {"route": {"from": "a", "to": "c"}},
        V_ROUTE,
        "a -> b",
    ),
    (
        {"unknown": {"kind": "tool", "name": "x"}},
        {"unknown": {"kind": "tool", "name": "y"}},
        V_UNKNOWN,
        "tool x",
    ),
    (
        {"unguarded": {"agent": "a", "tool": "t"}},
        {"unguarded": {"agent": "b", "tool": "t"}},
        V_BYPASS,
        "a/t",
    ),
    (
        {"observed_identity": {"path": ["user", "a"], "tool": "t"}},
        {"observed_identity": {"path": ["user", "b"], "tool": "t"}},
        V_MISMATCH,
        "user > a (t)",
    ),
    (
        {"untested_path": {"path": ["user", "a"], "tool": "t"}},
        {"untested_path": {"path": ["user", "a"], "tool": "u"}},
        V_UNTESTED,
        "user > a (t)",
    ),
]
_KIND_ARGS = pytest.mark.parametrize(("match", "other", "violation", "label"), _KINDS)


@_KIND_ARGS
def test_other_values_do_not_match(match, other, violation, label):
    out = _apply(_report((violation,)), _w("W1", other))
    assert out.exit_code == 1
    assert out.waivers[0].status == "unmatched"
    assert "matches nothing in this run" in str(out.waivers[0].note)
    assert any("W1" in w for w in out.warnings)


def test_path_must_match_exactly():
    out = _apply(
        _report((V_MISMATCH,)),
        _w("W1", {"observed_identity": {"path": ["user"], "tool": "t"}}),
        _w("W2", {"observed_identity": {"path": ["user", "*"], "tool": "t"}}),
    )
    assert [w.status for w in out.waivers] == ["unmatched", "unmatched"]
    assert out.exit_code == 1


def test_question_mark_path_step_is_literal():
    v = ObserveViolation(rule="fail_on_untested_path", path=("user", "?"), tool="t")
    out = _apply(_report((v,)), _w("W1", {"untested_path": {"path": ["user", "?"], "tool": "t"}}))
    assert out.exit_code == 0


@_KIND_ARGS
def test_expired_keeps_violation_blocking(match, other, violation, label):
    out = _apply(_report((violation,)), _w("W1", match, expires=_day(-1)))
    assert out.exit_code == 1 and out.gate.violations == (violation,)
    row = out.waivers[0]
    assert row.status == "expired" and row.matched == (label,)
    assert "blocks the gate again" in str(row.note)
    assert row.note in out.warnings


@_KIND_ARGS
def test_expired_covered_by_a_later_waiver(match, other, violation, label):
    out = _apply(_report((violation,)), _w("OLD", match, expires=_day(-1)), _w("NEW", match))
    assert out.exit_code == 0
    assert str(out.waivers[0].note).endswith("its findings are covered by NEW")


@_KIND_ARGS
def test_adds_nothing(match, other, violation, label):
    out = _apply(_report((violation,)), _w("W1", match), _w("W2", match))
    assert [w.status for w in out.waivers] == ["applied", "unmatched"]
    assert "adds nothing" in str(out.waivers[1].note)
    assert "already waived by W1" in str(out.waivers[1].note)


def test_one_waiver_covers_every_violation_with_its_key():
    out = _apply(
        _report((V_BYPASS, V_UNGUARDED, V_GUARD_INC)),
        _w("W1", {"unguarded": {"agent": "a", "tool": "t"}}),
    )
    assert len(out.gate.waived) == 3 and out.exit_code == 0


def test_partial_waiver_leaves_the_rest_blocking():
    out = _apply(_report((V_ROUTE, V_UNKNOWN)), _w("W1", {"route": {"from": "a", "to": "b"}}))
    assert out.gate.violations == (V_UNKNOWN,)
    assert not out.gate.passed and out.exit_code == 1


def test_bypass_is_waivable():
    out = _apply(_report((V_BYPASS,)), _w("W1", {"unguarded": {"agent": "a", "tool": "t"}}))
    assert out.exit_code == 0 and out.gate.waived[0].violation.rule == "bypass"


def test_exit_code_stays_two_with_errors():
    out = _apply(
        _report((V_ROUTE,), errors=("boom",)), _w("W1", {"route": {"from": "a", "to": "b"}})
    )
    assert out.exit_code == 2 and out.gate.passed


def test_existing_waived_entries_are_kept():
    first = _apply(_report((V_ROUTE, V_UNKNOWN)), _w("W1", {"route": {"from": "a", "to": "b"}}))
    second = apply_observe_waivers(
        first, _file(_w("W2", {"unknown": {"kind": "tool", "name": "x"}})), TODAY
    )
    assert [x.waiver_id for x in second.gate.waived] == ["W1", "W2"]


def test_waived_by_on_every_row_type():
    report = _report(
        (V_ROUTE, V_UNKNOWN, V_BYPASS, V_MISMATCH, V_UNTESTED),
        routes=(
            RouteRow(
                from_id="a",
                to_id="b",
                to_kind="agent",
                status="OFF_MAP",
                count=1,
                traces=("t1",),
                suggestion="add it",
            ),
            RouteRow(
                from_id="a", to_id="c", to_kind="agent", status="ON_MAP", count=1, traces=("t1",)
            ),
        ),
        unknown=(UnknownRow(kind="tool", name="x", count=1, traces=("t1",)),),
        identities=(
            IdentityRow(
                path=("user", "a"),
                tool="t",
                mode="user",
                expected="the trace's user",
                observed="agent:a",
                result="MISMATCH",
                count=1,
                traces=("t1",),
            ),
        ),
        guards=(
            GuardRow(
                agent="a",
                tool="t",
                tool_known=True,
                counts={"BYPASS": 1},
                by_time=0,
                effect_without_record=0,
                traces=("t1",),
            ),
        ),
        paths=(
            PathRow(
                path=("user", "a"),
                tool="t",
                incomplete=False,
                status="UNTESTED",
                count=1,
                traces=("t1",),
            ),
        ),
    )
    out = _apply(
        report,
        _w("R", {"route": {"from": "a", "to": "b"}}),
        _w("U", {"unknown": {"kind": "tool", "name": "x"}}),
        _w("G", {"unguarded": {"agent": "a", "tool": "t"}}),
        _w("I", {"observed_identity": {"path": ["user", "a"], "tool": "t"}}),
        _w("P", {"untested_path": {"path": ["user", "a"], "tool": "t"}}),
    )
    assert [r.waived_by for r in out.routes] == ["R", None]
    assert out.unknown[0].waived_by == "U"
    assert out.guards[0].waived_by == "G"
    assert out.identities[0].waived_by == "I"
    assert out.paths[0].waived_by == "P"
    assert out.exit_code == 0
    assert report.routes[0].waived_by is None  # input untouched


def test_no_agent_guard_row_is_marked_by_none_marker():
    report = _report(
        (V_BYPASS_NONE,),
        guards=(
            GuardRow(
                agent=None,
                tool="t",
                tool_known=True,
                counts={"BYPASS": 1},
                by_time=0,
                effect_without_record=0,
                traces=("t1",),
            ),
        ),
    )
    out = _apply(report, _w("G", {"unguarded": {"agent": "(none)", "tool": "t"}}))
    assert out.guards[0].waived_by == "G"


@pytest.mark.parametrize(
    "match",
    [
        {"case": "CASE-1"},
        {"rule": "RULE-1"},
        {"escalation": {"case": "CASE-1"}},
        {"identity": "CASE-1"},
        {"role_gap": {"role": "r", "tool": "t"}},
        {"tool_gap": "t"},
    ],
)
def test_coverage_and_test_kinds_are_silent_in_observe(match):
    before = _report()
    out = _apply(before, _w("W1", match))
    row = out.waivers[0]
    assert row.status == "unmatched" and row.matched == ()
    assert row.note == "checked only by lockwalk coverage or lockwalk test"
    assert out.warnings == before.warnings
    assert out.exit_code == 0


def test_silent_even_when_a_violation_has_the_same_text():
    out = _apply(_report((V_UNKNOWN,)), _w("W1", {"tool_gap": "x"}))
    assert out.exit_code == 1 and out.gate.violations == (V_UNKNOWN,)


def test_warnings_append_to_old_ones():
    out = _apply(_report((V_ROUTE,)), _w("W1", {"route": {"from": "q", "to": "z"}}))
    assert out.warnings[0] == "old warning" and len(out.warnings) == 2


def test_result_is_a_validated_report():
    out = _apply(_report((V_ROUTE,)), _w("W1", {"route": {"from": "a", "to": "b"}}))
    assert ObserveReport.model_validate(out.model_dump()) == out


def _identity(result, *, tool="t"):
    return IdentityRow(
        path=("user", "a"),
        tool=tool,
        mode="user",
        expected="the trace's user",
        observed="agent:a" if result == "MISMATCH" else "the trace's user",
        result=result,
        count=1,
        traces=("t1",),
    )


def test_identity_waiver_marks_only_the_blocking_row():
    report = _report(
        (V_MISMATCH,),
        identities=(_identity("MATCH"), _identity("MISMATCH")),
    )
    out = _apply(report, _w("I", {"observed_identity": {"path": ["user", "a"], "tool": "t"}}))
    assert [r.waived_by for r in out.identities] == [None, "I"]
    assert out.exit_code == 0


def test_path_waiver_marks_only_the_untested_row():
    def row(status):
        return PathRow(
            path=("user", "a"),
            tool="t",
            incomplete=status == "UNTESTED",
            status=status,
            count=1,
            traces=("t1",),
        )

    report = _report((V_UNTESTED,), paths=(row("TESTED"), row("UNTESTED")))
    out = _apply(report, _w("P", {"untested_path": {"path": ["user", "a"], "tool": "t"}}))
    assert [r.waived_by for r in out.paths] == [None, "P"]


def test_guard_waiver_marks_only_rows_with_blocking_counts():
    def row(agent, counts):
        return GuardRow(
            agent=agent,
            tool="t",
            tool_known=True,
            counts=counts,
            by_time=0,
            effect_without_record=0,
            traces=("t1",),
        )

    report = _report(
        (V_BYPASS,), guards=(row("a", {"GUARDED": 2}), row("a", {"GUARDED": 1, "BYPASS": 1}))
    )
    out = _apply(report, _w("G", {"unguarded": {"agent": "a", "tool": "t"}}))
    assert [r.waived_by for r in out.guards] == [None, "G"]


def test_inconclusive_row_is_not_marked_when_its_rule_is_off():
    # Only the MISMATCH violation exists (fail_on_inconclusive_observation is off).
    report = _report((V_MISMATCH,), identities=(_identity("MISMATCH"), _identity("INCONCLUSIVE")))
    out = _apply(report, _w("I", {"observed_identity": {"path": ["user", "a"], "tool": "t"}}))
    assert [r.waived_by for r in out.identities] == ["I", None]


def test_inconclusive_guard_count_is_not_marked_when_only_bypass_was_waived():
    def row(counts):
        return GuardRow(
            agent="a",
            tool="t",
            tool_known=True,
            counts=counts,
            by_time=0,
            effect_without_record=0,
            traces=("t1",),
        )

    report = _report(
        (V_BYPASS,), guards=(row({"BYPASS": 1}), row({"GUARDED": 1, "INCONCLUSIVE": 1}))
    )
    out = _apply(report, _w("G", {"unguarded": {"agent": "a", "tool": "t"}}))
    assert [r.waived_by for r in out.guards] == ["G", None]


def test_coverage_and_observe_kinds_partition_the_match_fields():
    fields = frozenset(WaiverMatch.model_fields)
    assert fields == waivers_module.COVERAGE_KINDS | waivers_module.OBSERVE_KINDS
    assert not waivers_module.COVERAGE_KINDS & waivers_module.OBSERVE_KINDS
