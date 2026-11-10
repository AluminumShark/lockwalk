import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from lockwalk.models import WaiverRow
from lockwalk.observe.output import (
    ObserveFileError,
    observe_to_dict,
    read_observe,
    render_observe,
    write_observe,
)
from lockwalk.observe.results import (
    GuardRow,
    IdentityRow,
    ObserveGate,
    ObserveReport,
    ObserveTotals,
    ObserveViolation,
    ObserveWaived,
    ObserveWindow,
    PathRow,
    RouteRow,
    UnknownRow,
)

NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)
TRACE = "a" * 32


def totals(**changes: int) -> ObserveTotals:
    base = dict(
        files=1,
        traces=3,
        spans=20,
        agent_spans=5,
        tool_calls=4,
        incomplete_traces=0,
        error_traces=0,
        unnamed_markers=0,
    )
    return ObserveTotals.model_validate({**base, **changes})


def clean(**changes: Any) -> ObserveReport:
    base = dict(
        scenario_suite="demo",
        sources=("a.jsonl",),
        totals=totals(),
        window=ObserveWindow(),
        gate=ObserveGate(passed=True),
        exit_code=0,
    )
    return ObserveReport.model_validate({**base, **changes})


def failing() -> ObserveReport:
    return clean(
        routes=(
            RouteRow(
                from_id="user",
                to_id="supervisor",
                to_kind="agent",
                status="ON_MAP",
                count=3,
                traces=(TRACE,),
            ),
            RouteRow(
                from_id="supervisor",
                to_id="trade-agent",
                to_kind="agent",
                status="OFF_MAP",
                count=2,
                traces=(TRACE, "b" * 32),
                suggestion="add a call from supervisor",
            ),
        ),
        unknown=(UnknownRow(kind="agent", name="ghost", count=1, traces=("c" * 32,)),),
        gate=ObserveGate(
            passed=False,
            violations=(
                ObserveViolation(
                    rule="fail_on_off_map_route", from_id="supervisor", to_id="trade-agent"
                ),
                ObserveViolation(rule="fail_on_unknown_component", kind="agent", name="ghost"),
            ),
        ),
        warnings=("something odd",),
        exit_code=1,
    )


def test_round_trip(tmp_path: Path) -> None:
    report = failing()
    path = write_observe(report, tmp_path / "out", generated_at=NOW, version="1.2.3")
    assert path == tmp_path / "out" / "observe.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["generated_at"] == "2026-11-08T12:00:00Z"
    assert document["lockwalk_version"] == "1.2.3"
    assert document["schema_version"] == "2"
    assert read_observe(path) == report
    assert observe_to_dict(report, generated_at=NOW, version="1.2.3") == document


def test_naive_time_is_refused() -> None:
    with pytest.raises(ValueError):
        observe_to_dict(clean(), generated_at=datetime(2026, 1, 1), version="1")


def write_file(tmp_path: Path, text: str | bytes) -> Path:
    path = tmp_path / "observe.json"
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ObserveFileError, match="lockwalk observe"):
        read_observe(tmp_path / "observe.json")


@pytest.mark.parametrize("text", ["not json SECRET", b"\xff\xfe SECRET", "[1]", '{"a": 1, "a": 2}'])
def test_junk_is_refused_without_quoting(tmp_path: Path, text: str | bytes) -> None:
    with pytest.raises(ObserveFileError) as info:
        read_observe(write_file(tmp_path, text))
    assert "SECRET" not in str(info.value)


def test_schema_mismatch(tmp_path: Path) -> None:
    document = observe_to_dict(clean(), generated_at=NOW, version="1")
    document["schema_version"] = "1"
    with pytest.raises(ObserveFileError, match="run lockwalk observe again"):
        read_observe(write_file(tmp_path, json.dumps(document)))


def test_invalid_body_does_not_quote_input(tmp_path: Path) -> None:
    document = observe_to_dict(clean(), generated_at=NOW, version="1")
    document["scenario_suite"] = ["SECRET"]
    with pytest.raises(ObserveFileError) as info:
        read_observe(write_file(tmp_path, json.dumps(document)))
    assert "SECRET" not in str(info.value)


def test_directory_is_a_read_error(tmp_path: Path) -> None:
    with pytest.raises(ObserveFileError, match=r"cannot be read \(\w+\)"):
        read_observe(tmp_path)


def test_file_of_exactly_the_cap_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_observe(clean(), tmp_path, generated_at=NOW, version="1")
    size = path.stat().st_size
    monkeypatch.setattr("lockwalk.observe.output.MAX_OBSERVE_BYTES", size)
    assert read_observe(path) == clean()
    monkeypatch.setattr("lockwalk.observe.output.MAX_OBSERVE_BYTES", size - 1)
    with pytest.raises(ObserveFileError, match="larger"):
        read_observe(path)


def test_render_uses_singular_counts() -> None:
    one = totals(traces=1, spans=1, agent_spans=1, tool_calls=1, incomplete_traces=1)
    lines = render_observe(clean(totals=one))
    assert lines[2] == "Read:         1 trace, 1 span (1 agent span, 1 tool call)"
    assert "Incomplete:   1 trace" in lines


def test_render_clean_report() -> None:
    lines = render_observe(clean())
    assert lines[0] == "lockwalk observe - demo"
    assert lines[1] == "Sources:      a.jsonl"
    assert lines[2] == "Read:         3 traces, 20 spans (5 agent spans, 4 tool calls)"
    assert lines[-1] == "Gate: PASS (exit 0)"
    text = "\n".join(lines)
    for absent in ("Incomplete", "Window", "OFF_MAP", "UNKNOWN", "Notes", "Warnings", "Errors"):
        assert absent not in text
    assert "Routes on the map (ON_MAP): 0" in text


def test_render_failing_report() -> None:
    lines = render_observe(failing(), notes=("a note",))
    assert "Routes not on the map (OFF_MAP):" in lines
    assert f"  supervisor -> trade-agent (agent)  2 time(s), e.g. trace {TRACE}" in lines
    assert "    fix: add a call from supervisor" in lines
    assert "Not on the map (UNKNOWN):" in lines
    assert f"  agent ghost  1 time(s), e.g. trace {'c' * 32}" in lines
    assert "Routes on the map (ON_MAP): 1" in lines
    assert lines[lines.index("Notes:") + 1] == "  - a note"
    assert lines[lines.index("Warnings:") + 1] == "  - something odd"
    assert lines[-1] == "Gate: FAIL (exit 1) - 2 violation(s)"
    assert lines.count("-" * 40) == 2
    assert not any(line.startswith("Result:") for line in lines)


def test_render_incomplete_window_errors() -> None:
    report = clean(
        totals=totals(incomplete_traces=2),
        window=ObserveWindow(first="2026-01-01T00:00:00Z", last="2026-01-02T00:00:00Z"),
        errors=("boom",),
        exit_code=2,
    )
    lines = render_observe(report)
    assert "Incomplete:   2 traces" in lines
    assert "Window:       2026-01-01T00:00:00Z .. 2026-01-02T00:00:00Z" in lines
    assert lines[lines.index("Errors:") + 1] == "  - boom"
    expected = "Result: ERROR (exit 2) - the report is incomplete; fix the errors above"
    assert lines[-1] == expected
    assert not any(line.startswith("Gate:") for line in lines)


def test_sources_are_cut_and_joined() -> None:
    lines = render_observe(clean(sources=("x" * 200, "b.jsonl")))
    assert lines[1] == "Sources:      " + "x" * 77 + "..., b.jsonl"


def test_many_sources_are_capped() -> None:
    sources = tuple(f"s{i}.jsonl" for i in range(50))
    lines = render_observe(clean(sources=sources))
    shown = ", ".join(f"s{i}.jsonl" for i in range(5))
    assert lines[1] == f"Sources:      {shown}, ... (+45 more)"


def test_no_sources() -> None:
    assert render_observe(clean(sources=()))[1] == "Sources:      (none)"


def test_half_known_window() -> None:
    first = render_observe(clean(window=ObserveWindow(first="2026-11-08T10:00:00Z")))
    assert "Window:       2026-11-08T10:00:00Z .. ?" in first
    last = render_observe(clean(window=ObserveWindow(last="2026-11-08T10:00:00Z")))
    assert "Window:       ? .. 2026-11-08T10:00:00Z" in last


def test_caller_rows() -> None:
    row = UnknownRow(kind="caller", name="execute_trade", count=2, traces=(TRACE,))
    lines = render_observe(clean(unknown=(row,)))
    assert f"  tool execute_trade (no calling agent)  2 time(s), e.g. trace {TRACE}" in lines


def test_lists_are_capped() -> None:
    lines = render_observe(clean(warnings=tuple(f"w{i}" for i in range(30))))
    start = lines.index("Warnings:")
    assert lines[start + 1] == "  - w0"
    assert lines[start + 20] == "  - w19"
    assert lines[start + 21] == "  - ... (+10 more; see observe.json)"
    assert lines[start + 22] == "-" * 40


def test_exactly_the_cap_is_not_marked() -> None:
    lines = render_observe(clean(), notes=tuple(f"n{i}" for i in range(20)))
    assert not any("more" in line for line in lines)


def test_large_report_is_one_line_per_row() -> None:
    routes = tuple(
        RouteRow(
            from_id=f"a{i}",
            to_id=f"b{i}",
            to_kind="agent",
            status="OFF_MAP",
            count=1,
            traces=(TRACE,),
            suggestion="fix it",
        )
        for i in range(5000)
    )
    violations = tuple(
        ObserveViolation(rule="fail_on_off_map_route", from_id=r.from_id, to_id=r.to_id)
        for r in routes
    )
    gate = ObserveGate(passed=False, violations=violations)
    lines = render_observe(clean(routes=routes, gate=gate, exit_code=1))
    assert sum(1 for line in lines if " -> " in line) == 5000
    assert sum(1 for line in lines if line == "    fix: fix it") == 5000
    assert len(lines) < 10100


def test_escaping() -> None:
    name = "\x1b[31mevil\u522a"
    report = clean(
        scenario_suite=name,
        sources=(name,),
        unknown=(UnknownRow(kind="tool", name=name, count=1, traces=(TRACE,)),),
        warnings=(name,),
        routes=(
            RouteRow(
                from_id="a",
                to_id="b",
                to_kind="agent",
                status="OFF_MAP",
                count=1,
                traces=(TRACE,),
                suggestion=name,
            ),
        ),
        gate=ObserveGate(
            passed=False,
            violations=(
                ObserveViolation(rule="fail_on_unknown_component", kind="tool", name=name),
            ),
        ),
        exit_code=1,
    )
    lines = render_observe(report, notes=(name,))
    for line in lines:
        assert line.isascii()
        assert "\x1b" not in line
    assert any(r"\x1b[31mevil\u522a" in line for line in lines)


# ---- guard, identity and path rows, waivers and summary ----

SILENT = "checked only by lockwalk coverage or lockwalk test"


def identity(**changes: Any) -> IdentityRow:
    base = dict(
        path=("supervisor", "trade-agent"),
        tool="execute_trade",
        mode="user",
        expected="the trace's user",
        observed="agent:trade-agent",
        result="MISMATCH",
        count=2,
        traces=(TRACE,),
        notes=("the door got the agent",),
        test_results=("CASE-003 direct: MATCH",),
    )
    return IdentityRow.model_validate({**base, **changes})


def guard(**changes: Any) -> GuardRow:
    base = dict(
        agent="trade-agent",
        tool="execute_trade",
        tool_known=True,
        counts={"BYPASS": 2, "GUARDED": 3},
        by_time=1,
        effect_without_record=0,
        traces=(TRACE,),
    )
    return GuardRow.model_validate({**base, **changes})


def path_row(**changes: Any) -> PathRow:
    base = dict(
        path=("supervisor", "trade-agent"),
        tool="execute_trade",
        incomplete=False,
        status="UNTESTED",
        count=4,
        traces=(TRACE,),
    )
    return PathRow.model_validate({**base, **changes})


def violation(rule: str, **fields: Any) -> ObserveViolation:
    return ObserveViolation.model_validate({"rule": rule, **fields})


def waiver_row(**changes: Any) -> WaiverRow:
    base = dict(
        id="W-1",
        owner="alice",
        expires="2027-01-01",
        reason="accepted",
        match={"unguarded": {"agent": "a", "tool": "t"}},
        status="applied",
        matched=("x",),
    )
    return WaiverRow.model_validate({**base, **changes})


def four_findings() -> ObserveReport:
    """One MISMATCH, one BYPASS, one UNTESTED (waived) and one UNGUARDED (waived)."""
    route = ("supervisor", "trade-agent")
    mismatch = violation("fail_on_identity_mismatch", path=route, tool="execute_trade")
    bypass = violation("bypass", agent="trade-agent", tool="execute_trade")
    untested = violation("fail_on_untested_path", path=route, tool="execute_trade")
    unguarded = violation("fail_on_unguarded_call", agent="supervisor", tool="read_report")
    return clean(
        identities=(
            identity(),
            identity(
                result="MATCH", observed="the trace's user", count=120, notes=(), test_results=()
            ),
            identity(result="OBSERVED", mode="undeclared", count=7, notes=(), test_results=()),
        ),
        guards=(
            guard(),
            guard(
                agent="supervisor",
                tool="read_report",
                counts={"UNGUARDED": 1, "DENIED_UNVERIFIED": 2},
                by_time=0,
                effect_without_record=1,
                waived_by="W-2",
            ),
            guard(agent=None, tool="ping", counts={"GUARDED": 9, "DENIED": 1}, by_time=0),
        ),
        paths=(
            path_row(waived_by="W-1"),
            path_row(path=("supervisor",), tool="ping", status="TESTED", count=10),
            path_row(path=("supervisor",), tool="x", status="TESTED_OTHER_PATH", count=3),
        ),
        waivers=(
            waiver_row(),
            waiver_row(id="W-2", status="expired", note="W-2 expired on 2026-01-01"),
            waiver_row(id="W-3", status="unmatched", note="W-3 matches nothing"),
            waiver_row(id="W-4", status="unmatched", note=SILENT),
        ),
        gate=ObserveGate(
            passed=False,
            violations=(mismatch, bypass),
            waived=(
                ObserveWaived(violation=untested, waiver_id="W-1"),
                ObserveWaived(violation=unguarded, waiver_id="W-2"),
            ),
        ),
        warnings=("W-2 expired on 2026-01-01", "plain warning"),
        exit_code=1,
    )


def test_identity_section() -> None:
    lines = render_observe(four_findings())
    start = lines.index("Identity sent to the IAM (MISMATCH / INCONCLUSIVE):")
    assert lines[start + 1] == (
        "  MISMATCH  supervisor -> trade-agent, tool execute_trade, mode user: 2 time(s), "
        f"e.g. trace {TRACE}"
    )
    assert lines[start + 2 : start + 6] == [
        "    expected: the trace's user",
        "    observed: agent:trade-agent",
        "    test: CASE-003 direct: MATCH",
        "    note: the door got the agent",
    ]
    text = "\n".join(lines)
    assert "OBSERVED  " not in text and "  MATCH  " not in text  # OK rows only as counts
    assert "Identity: 120 MATCH, 7 OBSERVED" in lines


def test_identity_without_tool_and_inconclusive() -> None:
    row = identity(tool=None, result="INCONCLUSIVE", notes=(), test_results=(), mode="undeclared")
    lines = render_observe(clean(identities=(row,)))
    prefix = "  INCONCLUSIVE  supervisor -> trade-agent, tool (no tool)"
    assert any(line.startswith(prefix) for line in lines)


def test_guard_section() -> None:
    lines = render_observe(four_findings())
    start = lines.index("Tool calls without a working door (BYPASS / UNGUARDED / INCONCLUSIVE):")
    assert lines[start + 1] == "  trade-agent / execute_trade: GUARDED 3, BYPASS 2"
    assert lines[start + 2] == f"    linked by time 1, e.g. trace {TRACE}"
    assert lines[start + 3] == (
        "  supervisor / read_report: DENIED_UNVERIFIED 2, UNGUARDED 1 [waived: W-2]"
    )
    assert lines[start + 4].startswith("    effect without record 1")
    assert "ping" not in "\n".join(lines[start : start + 6])
    assert "Guarded calls: 12 GUARDED, 1 DENIED" in lines


def test_denied_unverified_is_a_note() -> None:
    lines = render_observe(four_findings())
    assert (
        "2 denied call(s) of read_report are DENIED_UNVERIFIED" in lines[lines.index("Notes:") + 1]
    )


def test_untested_section_and_tested_counts() -> None:
    lines = render_observe(four_findings())
    start = lines.index("Real paths no case tests (UNTESTED):")
    assert lines[start + 1] == (
        f"  supervisor -> trade-agent / execute_trade: 4 time(s), e.g. trace {TRACE} [waived: W-1]"
    )
    assert "Tested paths: 10 TESTED, 3 TESTED_OTHER_PATH" in lines
    incomplete = render_observe(clean(paths=(path_row(incomplete=True),)))
    assert any("(start of the path not in the data)" in line for line in incomplete)


def test_new_sections_are_omitted_when_empty() -> None:
    text = "\n".join(render_observe(clean()))
    for absent in ("Identity", "Tool calls without", "Real paths", "Guarded", "Tested", "Waived"):
        assert absent not in text


def test_waived_route_and_unknown_rows_are_marked() -> None:
    route = RouteRow(
        from_id="a",
        to_id="b",
        to_kind="agent",
        status="OFF_MAP",
        count=1,
        traces=(TRACE,),
        suggestion="s",
        waived_by="W-9",
    )
    unknown = UnknownRow(kind="tool", name="t", count=1, traces=(TRACE,), waived_by="W-8")
    lines = render_observe(clean(routes=(route,), unknown=(unknown,)))
    assert any(line.endswith(" [waived: W-9]") for line in lines)
    assert any(line.endswith(" [waived: W-8]") for line in lines)


def test_waived_and_attention_blocks() -> None:
    lines = render_observe(four_findings())
    start = lines.index("Waived:")
    assert lines[start + 1] == (
        "  - UNTESTED path: supervisor -> trade-agent / execute_trade "
        "(W-1, owner alice, until 2027-01-01)"
    )
    assert lines[start + 2].startswith("  - UNGUARDED: supervisor / read_report (W-2")
    start = lines.index("Waivers needing attention:")
    assert lines[start + 1] == "  expired      W-2: W-2 expired on 2026-01-01"
    assert lines[start + 2] == "  unmatched    W-3: W-3 matches nothing"
    assert "W-4" not in "\n".join(lines)  # a silent row is not listed
    assert "  1 waiver(s) are checked only by lockwalk coverage or lockwalk test" in lines
    # a warning that is a waiver note shown above is not repeated under Warnings
    warnings = lines[lines.index("Warnings:") :]
    assert "  - plain warning" in warnings
    assert "  - W-2 expired on 2026-01-01" not in warnings


def test_summary_categories() -> None:
    lines = render_observe(four_findings(), summary=True)
    assert lines[0] == "lockwalk observe - demo"
    assert lines[1] == "Read: 3 traces, 20 spans (5 agent spans, 4 tool calls)"
    assert "Identity: 120 MATCH, 7 OBSERVED, 2 MISMATCH" in lines
    assert (
        "Guarded calls: 12 GUARDED, 1 DENIED, 2 DENIED_UNVERIFIED, 2 BYPASS, 1 UNGUARDED" in lines
    )
    assert "Tested paths: 10 TESTED, 3 TESTED_OTHER_PATH, 4 UNTESTED" in lines
    assert "Gate: FAIL (exit 1) - 2 violation(s)" in lines
    assert "Blocking (2):" in lines
    assert "  - identity MISMATCH: supervisor -> trade-agent / execute_trade" in lines
    assert "  - BYPASS: trade-agent / execute_trade" in lines
    assert "Waived (2):" in lines
    assert "Waivers needing attention (2):" in lines
    assert "Warnings (2):" in lines  # the plain warning and the DENIED_UNVERIFIED note
    text = "\n".join(lines)
    assert "Errors" not in text
    assert "Identity sent to the IAM" not in text  # no full sections
    assert len(lines) < 40


def test_summary_caps_each_category_at_twenty() -> None:
    violations = tuple(violation("bypass", agent="a", tool=f"t{i}") for i in range(45))
    report = clean(
        gate=ObserveGate(passed=False, violations=violations),
        errors=tuple(f"e{i}" for i in range(21)),
        exit_code=2,
    )
    lines = render_observe(report, summary=True)
    start = lines.index("Blocking (45):")
    assert lines[start + 20] == "  - BYPASS: a / t19"
    assert lines[start + 21] == "  ... and 25 more; see observe.json"
    start = lines.index("Errors (21):")
    assert lines[start + 21] == "  ... and 1 more; see observe.json"
    assert any(line.startswith("Result: ERROR") for line in lines)


def test_summary_of_a_clean_report() -> None:
    lines = render_observe(clean(), summary=True)
    assert lines[-1] == "Gate: PASS (exit 0)"
    assert "Blocking" not in "\n".join(lines)


def test_identity_row_waived_marker() -> None:
    report = clean(identities=(identity(waived_by="W-7"),))
    lines = render_observe(report)
    first = next(line for line in lines if line.startswith("  MISMATCH"))
    assert first.endswith(f"e.g. trace {TRACE} [waived: W-7]")


def test_violation_text_never_prints_none() -> None:
    from lockwalk.observe.output import _violation_text

    cases = [
        violation("bypass", tool="t"),
        violation("fail_on_identity_mismatch", path=("a",)),
        violation("fail_on_untested_path", path=("a",), tool="t"),
        violation("fail_on_inconclusive_observation", subject="guard", tool="t"),
        violation("fail_on_inconclusive_observation", subject="identity", path=("a",)),
    ]
    for item in cases:
        assert "None" not in _violation_text(item)
    assert _violation_text(cases[1]) == "identity MISMATCH: a / (no tool)"
    assert _violation_text(cases[2]) == "UNTESTED path: a / t"


def test_guard_detail_line_is_skipped_when_empty() -> None:
    row = guard(counts={"UNGUARDED": 1}, by_time=0, traces=(TRACE,))
    lines = render_observe(clean(guards=(row,)))
    start = lines.index("  trade-agent / execute_trade: UNGUARDED 1")
    assert lines[start + 1] == f"    e.g. trace {TRACE}"
    # a row with nothing to say (no time links, no effect, no example trace) has no detail line
    from lockwalk.observe.output import _guard_lines

    nothing = guard(counts={"GUARDED": 1}, by_time=0, traces=())
    assert _guard_lines([nothing]) == ["  trade-agent / execute_trade: GUARDED 1"]


def test_silent_waiver_notes_decide_which_warnings_are_dropped() -> None:
    # A silent waiver's note is not printed, so an equal warning stays.
    silent = waiver_row(id="W-4", status="unmatched", note=SILENT)
    report = clean(waivers=(silent,), warnings=(SILENT,))
    lines = render_observe(report)
    assert "  - " + SILENT in lines
    shown = waiver_row(id="W-3", status="expired", note="W-3 expired")
    lines = render_observe(clean(waivers=(shown,), warnings=("W-3 expired",)))
    assert "  - W-3 expired" not in lines


def test_new_text_is_ascii() -> None:
    evil = "\x1b[31mevil\u522a"
    report = clean(
        identities=(identity(expected=evil, observed=evil, notes=(evil,), test_results=(evil,)),),
        guards=(guard(tool=evil, agent=evil),),
        paths=(path_row(tool=evil, path=(evil,)),),
    )
    for summary in (False, True):
        for line in render_observe(report, notes=(evil,), summary=summary):
            assert line.isascii() and "\x1b" not in line


def test_door_records_line_in_both_forms() -> None:
    with_doors = totals(
        door_records=5, calls_with_record=3, records_without_call=2, records_by_time=1
    )
    line = "Door records: 5 (3 tool call(s) have one; 2 not tied to a tool call, 1 linked by time)"
    full = render_observe(clean(totals=with_doors))
    assert full[3] == line
    summary = render_observe(clean(totals=with_doors), summary=True)
    assert summary[2] == line
    assert line.isascii()


def test_no_door_records_line_without_records() -> None:
    for summary in (False, True):
        assert not any("Door records" in x for x in render_observe(clean(), summary=summary))


def test_totals_without_calls_with_record_still_validate() -> None:
    document = totals().model_dump()
    del document["calls_with_record"]
    assert ObserveTotals.model_validate(document).calls_with_record == 0
