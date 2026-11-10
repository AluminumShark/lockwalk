"""The --summary terminal output."""

from typing import Any

import pytest

from lockwalk.models import (
    CaseRow,
    CaseStatus,
    GateResult,
    GateViolation,
    RuleResult,
    WaivedViolation,
    WaiverRow,
)
from lockwalk.report import render_coverage


def case(case_id: str, status: CaseStatus) -> CaseRow:
    return CaseRow(
        id=case_id,
        agent="finance-agent",
        path=("finance-agent",),
        tool="read_portfolio",
        action="portfolio:read",
        expect="allow",
        status=status,
        action_verified=True,
        problems=(),
    )


def build(make_report: Any, **update: Any) -> Any:
    base = make_report()
    counts = {s.value: 0 for s in CaseStatus}
    counts.update(update.pop("counts", {}))
    metrics = base.metrics.model_copy(update={"cases_by_status": counts})
    fields = {"mode": "test", "policy_adapter": "authzen", "metrics": metrics}
    return base.model_copy(update={**fields, **update})


def violations(n: int) -> tuple[GateViolation, ...]:
    return tuple(
        GateViolation(rule="case", case_id=f"CASE-{i:03d}", status=CaseStatus.FAIL_POLICY)
        for i in range(n)
    )


def waiver(wid: str, status: str = "applied", **extra: Any) -> WaiverRow:
    fields: dict[str, Any] = {
        "id": wid,
        "owner": "alice",
        "expires": "2026-12-31",
        "reason": "accepted",
        "match": {"case": "CASE-000"},
        "status": status,
    }
    return WaiverRow.model_validate({**fields, **extra})


def test_static_summary_of_a_clean_report(make_report):
    assert render_coverage(make_report(), summary=True) == [
        "lockwalk coverage - finance-demo-v1",
        "Cases: 4 (UNTESTED 4)",
        "Tools: 3 registered, 0 without a case, 0 high-risk without a deny case",
        "Gate: PASS (exit 0)",
    ]


def test_test_mode_summary_with_blocking_and_warnings(make_report):
    report = build(
        make_report,
        counts={"PASS": 3, "FAIL_POLICY": 1},
        gate=GateResult(passed=False, violations=violations(1)),
        warnings=("something odd",),
        exit_code=1,
    )
    assert render_coverage(report, summary=True) == [
        "lockwalk test - finance-demo-v1",
        "Cases: 4 (PASS 3, FAIL_POLICY 1)",
        "Tools: 3 registered, 0 without a case, 0 high-risk without a deny case",
        "Gate: FAIL (exit 1)",
        "",
        "Blocking (1):",
        "  case: CASE-000 (FAIL_POLICY)",
        "",
        "Warnings (1):",
        "  - something odd",
    ]


def test_summary_has_no_tree_table_or_door_lines(make_report):
    report = build(make_report, cases=(case("CASE-001", CaseStatus.PASS),))
    text = "\n".join(render_coverage(report, summary=True))
    for absent in ("Agent graph", "Role reachability", "Cases:\n", "door", "Inventory"):
        assert absent not in text


def test_large_report_stays_short(make_report):
    cases = tuple(case(f"CASE-{i:03d}", CaseStatus.ERROR) for i in range(300))
    report = build(
        make_report,
        counts={"ERROR": 300},
        cases=cases,
        errors=tuple(f"CASE-{i:03d}: IAM unreachable" for i in range(300)),
        gate=GateResult(passed=False, violations=violations(500)),
        exit_code=2,
    )
    lines = render_coverage(report, summary=True)
    assert len(lines) < 40
    assert "Result: ERROR (exit 2)" in lines
    assert "Cases: 4 (ERROR 300)" in lines
    start = lines.index("Errors (1):")
    assert (
        lines[start + 1]
        == "  - IAM unreachable (300 cases: CASE-000, CASE-001, CASE-002, +297 more)"
    )
    assert "Blocking (500):" in lines
    assert lines[lines.index("Blocking (500):") + 21] == "  ... and 480 more; see coverage.json"


def test_error_grouping_keeps_different_messages_apart(make_report):
    cases = tuple(case(f"CASE-{i:03d}", CaseStatus.ERROR) for i in range(4))
    report = build(
        make_report,
        cases=cases,
        errors=(
            "CASE-000: bad action",
            "CASE-001: IAM down",
            "CASE-002: bad action",
            "inventory exploded",
            "escalation analyst/execute_trade via a: IAM down",
            "CASE-003: bad action",
            "CASE-004: IAM down",
        ),
        exit_code=2,
    )
    lines = render_coverage(report, summary=True)
    start = lines.index("Errors (4):")
    assert lines[start + 1 : start + 5] == [
        "  - bad action (3 cases: CASE-000, CASE-002, CASE-003)",
        "  - IAM down (2 items: CASE-001, escalation analyst/execute_trade via a)",
        "  - inventory exploded",
        "  - CASE-004: IAM down",
    ]


def test_group_ids_can_be_rules(make_report):
    rules = []
    for rid in ("RULE-001", "RULE-002"):
        rules.append(
            {
                "id": rid,
                "agent": None,
                "role": "analyst",
                "tool": "t",
                "target_agent": None,
                "result": RuleResult.ERROR,
                "problems": ("p",),
            }
        )
    from lockwalk.models import RuleRow

    report = build(
        make_report,
        rules=tuple(RuleRow.model_validate(r) for r in rules),
        errors=("RULE-001: unknown tool 't'", "RULE-002: unknown tool 't'"),
        exit_code=2,
    )
    lines = render_coverage(report, summary=True)
    assert "  - unknown tool 't' (2 items: RULE-001, RULE-002)" in lines


def test_twenty_line_cap_on_every_category(make_report):
    waived = tuple(WaivedViolation(violation=v, waiver_id="W-1") for v in violations(25))
    report = build(
        make_report,
        gate=GateResult(passed=True, violations=(), waived=waived),
        waivers=(waiver("W-1"), *(waiver(f"W-X{i}", "unmatched", note="stale") for i in range(22))),
        warnings=tuple(f"warning {i}" for i in range(21)),
        exit_code=0,
    )
    lines = render_coverage(report, summary=True)
    overflow = "  ... and {} more; see coverage.json"
    for title, total in (("Waived", 25), ("Waivers needing attention", 22), ("Warnings", 21)):
        start = lines.index(f"{title} ({total}):")
        assert lines[start + 21] == overflow.format(total - 20)
        assert lines[start + 20].startswith("  ") and "..." not in lines[start + 20]
    waived_line = lines[lines.index("Waived (25):") + 1]
    assert waived_line == "  - case: CASE-000 (FAIL_POLICY) (W-1, owner alice, until 2026-12-31)"
    assert (
        lines[lines.index("Waivers needing attention (22):") + 1] == "  - unmatched    W-X0: stale"
    )


def test_exactly_twenty_lines_have_no_overflow_line(make_report):
    report = build(make_report, warnings=tuple(f"w{i}" for i in range(20)))
    lines = render_coverage(report, summary=True)
    assert not any("more; see coverage.json" in line for line in lines)


def test_empty_categories_are_left_out(make_report):
    lines = render_coverage(make_report(), summary=True)
    for title in ("Errors", "Blocking", "Waived", "Waivers needing", "Warnings"):
        assert not any(line.startswith(title) for line in lines)


def test_summary_escapes_text_from_outside(make_report):
    esc, bell = chr(27), chr(7)
    report = build(
        make_report,
        errors=(f"boom {esc}[31m",),
        warnings=(f"caf\u00e9 {bell}",),
        waivers=(waiver("W-1", "expired", owner=f"al{esc}ice"),),
        gate=GateResult(
            passed=True,
            violations=(),
            waived=(WaivedViolation(violation=violations(1)[0], waiver_id="W-1"),),
        ),
        exit_code=2,
    )
    lines = render_coverage(report, summary=True)
    text = "\n".join(lines)
    assert esc not in text and bell not in text
    assert "boom \\x1b[31m" in text
    assert "caf\\xe9 \\x07" in text
    assert "owner al\\x1bice" in text


def test_summary_does_not_change_the_report(make_report):
    report = build(make_report, warnings=("w",))
    render_coverage(report, summary=True)
    assert render_coverage(report) == render_coverage(report, summary=False)


def test_summary_test_only_waivers_are_quiet(make_report):
    note = "checked only by lockwalk test"
    report = build(
        make_report,
        waivers=(
            waiver("W-A", "unmatched", note=note),
            waiver("W-B", "unmatched", note=note),
        ),
    )
    lines = render_coverage(report, summary=True)
    assert not any(line.startswith("Waivers needing") for line in lines)
    assert lines[-1] == "  2 waiver(s) are checked only by lockwalk test"


def test_summary_quiet_line_sits_in_the_waived_category(make_report):
    note = "checked only by lockwalk test"
    report = build(
        make_report,
        gate=GateResult(
            passed=True,
            violations=(),
            waived=(WaivedViolation(violation=violations(1)[0], waiver_id="W-1"),),
        ),
        waivers=(waiver("W-1"), waiver("W-A", "unmatched", note=note)),
    )
    lines = render_coverage(report, summary=True)
    start = lines.index("Waived (1):")
    assert lines[start + 2] == "  1 waiver(s) are checked only by lockwalk test"


def test_summary_does_not_repeat_attention_waivers_in_warnings(make_report):
    report = build(
        make_report,
        waivers=(
            waiver("W-OLD", "expired", note="waiver W-OLD expired on 2026-01-01 (owner alice)"),
            waiver("W-STALE", "unmatched", note="waiver W-STALE matches nothing"),
        ),
        warnings=(
            "waiver W-OLD expired on 2026-01-01 (owner alice)",
            "waiver W-STALE matches nothing",
            "something else",
            "waiver W-OTHER is unrelated",
        ),
    )
    lines = render_coverage(report, summary=True)
    assert "Waivers needing attention (2):" in lines
    assert "Warnings (2):" in lines
    assert "  - something else" in lines
    assert "  - waiver W-OTHER is unrelated" in lines
    assert sum("waiver W-OLD expired" in line for line in lines) == 1
    full = render_coverage(report)
    assert sum("waiver W-OLD expired" in line for line in full) == 1
    assert "  - something else" in full


def test_summary_of_a_huge_report_stays_capped_and_fast(make_report):
    import time

    count = 5000
    waivers = tuple(
        waiver(f"W {i}", "expired", note=f"waiver W {i} expired on 2026-01-01 (owner alice)")
        for i in range(count)
    )
    report = build(
        make_report,
        errors=tuple(f"distinct error {i}" for i in range(100_000)),
        waivers=waivers,
        warnings=(*(w.note for w in waivers if w.note), "other"),
        exit_code=2,
    )
    started = time.monotonic()
    lines = render_coverage(report, summary=True)
    assert time.monotonic() - started < 10  # loose: only a quadratic version would miss it
    assert len(lines) < 100
    assert "Errors (100000):" in lines
    assert f"Waivers needing attention ({count}):" in lines
    assert "Warnings (1):" in lines  # the waiver warnings are not repeated


def test_owner_with_rich_markup_prints_literally(make_report):
    report = build(
        make_report,
        waivers=(waiver("W-1", "expired", owner="[bold]x[/]", note="n"),),
        gate=GateResult(
            passed=True,
            violations=(),
            waived=(WaivedViolation(violation=violations(1)[0], waiver_id="W-1"),),
        ),
    )
    lines = render_coverage(report, summary=True)
    assert any("owner [bold]x[/]," in line for line in lines)


def test_error_with_a_colon_in_its_head_stays_one_line(make_report):
    report = build(
        make_report,
        cases=(case("CASE-001", CaseStatus.ERROR),),
        errors=("A: B: c", "A: B: c", "CASE-001: B: c"),
        exit_code=2,
    )
    lines = render_coverage(report, summary=True)
    start = lines.index("Errors (3):")
    assert lines[start + 1 : start + 4] == ["  - A: B: c", "  - A: B: c", "  - CASE-001: B: c"]


def verdict_line(lines: list[str]) -> str:
    return next(line for line in lines if line.startswith(("Gate: ", "Result: ")))


@pytest.mark.parametrize(
    ("exit_code", "expected"),
    [(0, "Gate: PASS (exit 0)"), (1, "Gate: FAIL (exit 1)"), (2, "Result: ERROR (exit 2)")],
)
def test_summary_and_full_report_share_one_verdict_prefix(make_report, exit_code, expected):
    report = build(
        make_report,
        gate=GateResult(passed=exit_code == 0, violations=violations(1 if exit_code else 0)),
        exit_code=exit_code,
    )
    full = verdict_line(render_coverage(report))
    short = verdict_line(render_coverage(report, summary=True))
    assert short.startswith(expected)
    assert full.startswith(expected)
