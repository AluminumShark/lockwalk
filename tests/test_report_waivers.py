"""Waived markers in the full terminal output."""

from typing import Any

from lockwalk.models import (
    CaseRow,
    CaseStatus,
    EscalationResult,
    EscalationRow,
    GateResult,
    GateViolation,
    IdentityCheckRow,
    IdentityResult,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    WaivedViolation,
    WaiverRow,
)
from lockwalk.report import render_coverage


def case(case_id: str, status: CaseStatus, **extra: Any) -> CaseRow:
    fields: dict[str, Any] = {
        "id": case_id,
        "agent": "finance-agent",
        "path": ("finance-agent",),
        "tool": "read_portfolio",
        "action": "portfolio:read",
        "expect": "allow",
        "status": status,
        "action_verified": True,
        "problems": (),
    }
    return CaseRow.model_validate({**fields, **extra})


def escalation(result: EscalationResult, **extra: Any) -> EscalationRow:
    fields: dict[str, Any] = {
        "case_id": None,
        "role": "analyst",
        "tool": "execute_trade",
        "via": "finance-agent",
        "risk": Risk.CRITICAL,
        "mode": "agent",
        "path": ("finance-agent",),
        "result": result,
    }
    return EscalationRow.model_validate({**fields, **extra})


def rule(rule_id: str, result: RuleResult, **extra: Any) -> RuleRow:
    fields: dict[str, Any] = {
        "id": rule_id,
        "agent": None,
        "role": "analyst",
        "tool": "execute_trade",
        "target_agent": None,
        "result": result,
    }
    return RuleRow.model_validate({**fields, **extra})


def identity(case_id: str, **extra: Any) -> IdentityCheckRow:
    fields: dict[str, Any] = {
        "case_id": case_id,
        "path": ("finance-agent",),
        "tool": "read_portfolio",
        "result": IdentityResult.MISMATCH,
    }
    return IdentityCheckRow.model_validate({**fields, **extra})


def reach(**extra: Any) -> ReachRow:
    fields: dict[str, Any] = {
        "role": "trader",
        "tool": "read_portfolio",
        "risk": Risk.HIGH,
        "status": ReachStatus.REACHABLE,
    }
    return ReachRow.model_validate({**fields, **extra})


def build_report(make_report: Any, **update: Any) -> Any:
    base = make_report()
    counts = {s.value: 0 for s in CaseStatus}
    counts.update(update.pop("counts", {}))
    metrics = base.metrics.model_copy(update={"cases_by_status": counts})
    fields = {"mode": "test", "policy_adapter": "authzen", "metrics": metrics}
    return base.model_copy(update={**fields, **update})


def waiver_row(wid: str, status: str = "applied", **extra: Any) -> WaiverRow:
    fields: dict[str, Any] = {
        "id": wid,
        "owner": "alice",
        "expires": "2026-12-31",
        "reason": "accepted risk",
        "match": {"case": "CASE-002"},
        "status": status,
    }
    return WaiverRow.model_validate({**fields, **extra})


def waived(violation: GateViolation, wid: str) -> WaivedViolation:
    return WaivedViolation(violation=violation, waiver_id=wid)


CASE_VIOLATION = GateViolation(rule="case", case_id="CASE-002", status=CaseStatus.FAIL_POLICY)


def pin_report(make_report: Any) -> Any:
    return build_report(
        make_report,
        counts={"PASS": 1, "FAIL_POLICY": 1},
        cases=(
            case("CASE-001", CaseStatus.PASS),
            case("CASE-002", CaseStatus.FAIL_POLICY, notes=("expected deny",)),
        ),
        escalations=(escalation(EscalationResult.ESCALATION),),
        identity_checks=(identity("CASE-002"),),
        rules=(rule("RULE-001", RuleResult.PASS),),
        reachability=(reach(),),
        gate=GateResult(passed=False, violations=(CASE_VIOLATION,)),
        exit_code=1,
    )


def test_pinned_test_mode_rendering_without_waivers(make_report):
    """Byte-for-byte pin of the full output as it was before waivers existed."""
    assert render_coverage(pin_report(make_report)) == PINNED_TEST


def test_pinned_static_rendering_without_waivers(make_report):
    assert render_coverage(make_report()) == PINNED_STATIC


PINNED_TEST = [
    "lockwalk test - finance-demo-v1",
    "Mode: test (asked the IAM through authzen)",
    "Inventory sources: registry:registry.yaml, mcp:finance-tools",
    "----------------------------------------",
    "Registered tools:                   3",
    "Specified scenarios:                4",
    "Executed scenarios:                 0/4",
    "Passed:                             1",
    "Failed (policy):                    1",
    "Inconclusive:                       0",
    "Tools without spec:                 0",
    "High-risk tools without deny case:  0",
    "Inventory drift:                    none",
    "",
    "Role reachability:",
    "  trader  read_portfolio  high  REACHABLE  delegation_mode=unknown  covered_by=NONE",
    "Never-reaches rules:",
    "  RULE-001  PASS          role:analyst -> tool:execute_trade",
    "",
    "Cases:",
    "  CASE-001  PASS            finance-agent -> read_portfolio  (expect allow, IAM -)",
    "  CASE-002  FAIL_POLICY     finance-agent -> read_portfolio  (expect allow, IAM -)",
    "    expected deny",
    "",
    "Escalation checks: 1 ESCALATION",
    "  ESCALATION    analyst -> execute_trade via finance-agent (agent)",
    "",
    "Identity checks: 1 MISMATCH",
    "  MISMATCH  CASE-002: finance-agent -> read_portfolio",
    "",
    "Gate: FAIL (exit 1)",
    "  - case: CASE-002 (FAIL_POLICY)",
]

PINNED_STATIC = [
    "lockwalk coverage - finance-demo-v1",
    "Mode: static (no tests executed)",
    "Inventory sources: registry:registry.yaml, mcp:finance-tools",
    "----------------------------------------",
    "Registered tools:                   3",
    "Specified scenarios:                4",
    "Executed scenarios:                 0/4 (not run)",
    "Untested:                           4",
    "Tools without spec:                 0",
    "High-risk tools without deny case:  0",
    "Inventory drift:                    none",
    "",
    "Gate: PASS (exit 0)",
]


def waived_report(make_report: Any) -> Any:
    """The pin report with every row waived by a different waiver."""
    return build_report(
        make_report,
        counts={"PASS": 1, "FAIL_POLICY": 1},
        cases=(
            case("CASE-001", CaseStatus.PASS),
            case("CASE-002", CaseStatus.FAIL_POLICY, waived_by="W-CASE"),
        ),
        escalations=(escalation(EscalationResult.ESCALATION, waived_by="W-ESC"),),
        identity_checks=(identity("CASE-002", waived_by="W-ID"),),
        rules=(rule("RULE-001", RuleResult.FAIL, waived_by="W-RULE"),),
        reachability=(reach(waived_by="W-GAP"),),
        waivers=(
            waiver_row("W-CASE"),
            waiver_row("W-ESC", match={"escalation": {"case": "X"}}),
            waiver_row("W-ID", owner="bob"),
            waiver_row("W-RULE"),
            waiver_row("W-GAP"),
        ),
        gate=GateResult(
            passed=True,
            violations=(),
            waived=(
                waived(CASE_VIOLATION, "W-CASE"),
                waived(GateViolation(rule="fail_on_identity_mismatch", case_id="CASE-002"), "W-ID"),
            ),
        ),
        exit_code=0,
    )


def test_each_waived_marker(make_report):
    lines = render_coverage(waived_report(make_report))
    assert (
        "  CASE-002  FAIL_POLICY     finance-agent -> read_portfolio"
        "  (expect allow, IAM -) [waived: W-CASE]" in lines
    )
    assert (
        "  CASE-001  PASS            finance-agent -> read_portfolio  (expect allow, IAM -)"
        in lines
    )
    assert (
        "  ESCALATION    analyst -> execute_trade via finance-agent (agent) [waived: W-ESC]"
        in lines
    )
    assert "  MISMATCH  CASE-002: finance-agent -> read_portfolio [waived: W-ID]" in lines
    assert any(
        line.startswith("  RULE-001  FAIL") and line.endswith(" [waived: W-RULE]") for line in lines
    )
    assert any(
        line.startswith("  trader  read_portfolio") and line.endswith(" [waived: W-GAP]")
        for line in lines
    )


def test_waived_block_follows_the_gate(make_report):
    lines = render_coverage(waived_report(make_report))
    start = lines.index("Gate: PASS (exit 0)")
    assert lines[start + 1 :] == [
        "Waived:",
        "  - case: CASE-002 (FAIL_POLICY) (W-CASE, owner alice, until 2026-12-31)",
        "  - fail_on_identity_mismatch: CASE-002 (W-ID, owner bob, until 2026-12-31)",
    ]


def test_waived_block_after_remaining_violations(make_report):
    other = GateViolation(rule="case", case_id="CASE-009", status=CaseStatus.FAIL_EXECUTION)
    report = waived_report(make_report)
    gate = GateResult(passed=False, violations=(other,), waived=report.gate.waived)
    lines = render_coverage(report.model_copy(update={"gate": gate, "exit_code": 1}))
    start = lines.index("Gate: FAIL (exit 1)")
    assert lines[start + 1] == "  - case: CASE-009 (FAIL_EXECUTION)"
    assert lines[start + 2] == "Waived:"


OLD_TEXT = "waiver W-OLD expired on 2026-01-01 (owner alice)"
STALE_TEXT = "waiver W-STALE matches nothing in this run; it may be stale (owner alice)"
ERR_TEXT = (
    "waiver W-ERR matches CASE-004, which is ERROR; an ERROR means the test itself "
    "is broken and cannot be waived"
)


def test_waivers_needing_attention_block(make_report):
    report = waived_report(make_report).model_copy(
        update={
            "waivers": (
                waiver_row("W-CASE"),
                waiver_row("W-OLD", status="expired", note=OLD_TEXT),
                waiver_row("W-NEW", status="unmatched", note="checked only by lockwalk test"),
                waiver_row("W-STALE", status="unmatched", note=STALE_TEXT),
                waiver_row("W-ERR", status="not_allowed", note=ERR_TEXT),
            ),
            "warnings": (STALE_TEXT, OLD_TEXT, ERR_TEXT),
        }
    )
    lines = render_coverage(report)
    start = lines.index("Waivers needing attention:")
    assert lines[start + 1 : start + 4] == [
        "  expired      W-OLD: waiver W-OLD expired on 2026-01-01 (owner alice)",
        "  unmatched    W-STALE: waiver W-STALE matches nothing in this run; "
        "it may be stale (owner alice)",
        "  not_allowed  W-ERR: waiver W-ERR matches CASE-004, which is ERROR; an ERROR means "
        "the test itself is broken and cannot be waived",
    ]
    assert lines[-1] == "  1 waiver(s) are checked only by lockwalk test"
    assert not any("W-NEW" in line for line in lines)


def test_test_only_waivers_alone_give_one_quiet_line(make_report):
    note = "checked only by lockwalk test"
    report = make_report().model_copy(
        update={
            "waivers": (
                waiver_row("W-A", status="unmatched", note=note),
                waiver_row("W-B", status="unmatched", note=note),
            )
        }
    )
    lines = render_coverage(report)
    assert "Waivers needing attention:" not in lines
    assert lines[-2:] == [
        "Gate: PASS (exit 0)",
        "  2 waiver(s) are checked only by lockwalk test",
    ]


def test_no_attention_block_when_all_applied(make_report):
    lines = render_coverage(waived_report(make_report))
    assert "Waivers needing attention:" not in lines


def test_owner_with_control_character_is_escaped(make_report):
    owner = "al" + chr(27) + "[31mice" + chr(7)
    report = waived_report(make_report).model_copy(
        update={"waivers": (waiver_row("W-CASE", owner=owner),)}
    )
    lines = render_coverage(report)
    assert all(chr(27) not in line and chr(7) not in line for line in lines)
    expected = "(W-CASE, owner al\\x1b[31mice\\x07, until 2026-12-31)"
    assert any(expected in line for line in lines)


def test_static_gate_line_with_waived_only(make_report):
    report = make_report().model_copy(
        update={
            "gate": GateResult(passed=True, violations=(), waived=(waived(CASE_VIOLATION, "W-1"),)),
            "waivers": (waiver_row("W-1"),),
        }
    )
    lines = render_coverage(report)
    assert lines[-2:] == [
        "Waived:",
        "  - case: CASE-002 (FAIL_POLICY) (W-1, owner alice, until 2026-12-31)",
    ]


def test_attention_line_without_a_note_uses_a_fixed_text(make_report):
    report = make_report().model_copy(update={"waivers": (waiver_row("W-A B", status="expired"),)})
    lines = render_coverage(report)
    assert "  expired      W-A B: expired waiver" in lines


def test_owner_with_rich_markup_prints_literally(make_report):
    report = waived_report(make_report).model_copy(
        update={"waivers": (waiver_row("W-CASE", owner="[bold]x[/]"),)}
    )
    assert any("owner [bold]x[/]," in line for line in render_coverage(report))


def test_full_output_shows_each_waiver_note_once(make_report):
    report = waived_report(make_report).model_copy(
        update={
            "waivers": (
                waiver_row("W-OLD", status="expired", note=OLD_TEXT),
                waiver_row("W-STALE", status="unmatched", note=STALE_TEXT),
                waiver_row("W-ERR", status="not_allowed", note=ERR_TEXT),
            ),
            "warnings": (STALE_TEXT, OLD_TEXT, ERR_TEXT, "unrelated warning"),
        }
    )
    lines = render_coverage(report)
    for text in (STALE_TEXT, OLD_TEXT, ERR_TEXT):
        assert sum(text in line for line in lines) == 1
    start = lines.index("Warnings:")
    assert "unrelated warning" in lines[start + 1]
    assert lines.index("Waivers needing attention:") > start


def test_observe_only_waivers_are_quiet_in_coverage(make_report):
    note = "checked only by lockwalk observe"
    report = make_report().model_copy(
        update={
            "waivers": (
                waiver_row("W-A", status="unmatched", note=note),
                waiver_row("W-B", status="unmatched", note=note),
                waiver_row("W-C", status="unmatched", note="checked only by lockwalk test"),
            ),
        }
    )
    lines = render_coverage(report)
    assert "Waivers needing attention:" not in lines
    assert lines[-2:] == [
        "  1 waiver(s) are checked only by lockwalk test",
        "  2 waiver(s) are checked only by lockwalk observe",
    ]
    summary = render_coverage(report, summary=True)
    assert not any(line.startswith("Waivers needing") for line in summary)
    assert summary[-2:] == lines[-2:]
