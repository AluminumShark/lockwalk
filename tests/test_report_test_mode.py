from typing import Any

import pytest

from lockwalk.models import (
    Answer,
    CaseDecision,
    CaseRow,
    CaseStatus,
    ControlRow,
    EscalationResult,
    EscalationRow,
    GateResult,
    GateViolation,
    HopResult,
    PathVerdict,
    Risk,
    Verdict,
)
from lockwalk.report import render_coverage, violation_line

# Captured from the output for make_report() before the test-mode rows existed.
STATIC_LITERAL = [
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


def _decision(verdict: PathVerdict = PathVerdict.ALLOW) -> CaseDecision:
    answer_verdict = Verdict.DENY if verdict == PathVerdict.DENY else Verdict.ALLOW
    hop = HopResult(
        caller="finance-agent",
        target="read_portfolio",
        kind="tool",
        mode="agent",
        verdict=verdict,
        answers=(Answer(subject={"type": "agent", "id": "finance-agent"}, verdict=answer_verdict),),
    )
    return CaseDecision(verdict=verdict, hops=(hop,))


def _case(case_id: str, status: CaseStatus, **extra) -> CaseRow:
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


def _escalation(result: EscalationResult, **extra) -> EscalationRow:
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


def _test_report(make_report, **update):
    base = make_report()
    counts = {s.value: 0 for s in CaseStatus}
    counts.update(update.pop("counts", {}))
    executed = sum(n for key, n in counts.items() if key not in ("UNTESTED", "ERROR"))
    metrics = base.metrics.model_copy(
        update={"cases_by_status": counts, "executed_cases": executed}
    )
    fields = {"mode": "test", "policy_adapter": "authzen", "metrics": metrics}
    return base.model_copy(update={**fields, **update})


def test_header_and_base_metrics_rows(make_report):
    report = _test_report(make_report, counts={"PASS": 3, "FAIL_POLICY": 1})
    lines = render_coverage(report)
    assert lines[0] == "lockwalk test - finance-demo-v1"
    assert lines[1] == "Mode: test (asked the IAM through authzen)"
    start = lines.index("Executed scenarios:                 4/4")
    assert lines[start : start + 5] == [
        "Executed scenarios:                 4/4",
        "Passed:                             3",
        "Failed (policy):                    1",
        "Inconclusive:                       0",
        "Tools without spec:                 0",
    ]
    assert not any(line.startswith("Untested") for line in lines)
    assert not any(line.startswith("Failed (execution)") for line in lines)
    assert not any(line.startswith("Case errors") for line in lines)


def test_conditional_metrics_rows_appear_when_above_zero(make_report):
    report = _test_report(
        make_report, counts={"FAIL_EXECUTION": 1, "UNTESTED": 2, "ERROR": 1, "PASS": 1}
    )
    lines = render_coverage(report)
    start = lines.index("Inconclusive:                       0")
    assert lines[start + 1 : start + 4] == [
        "Failed (execution):                 1",
        "Untested:                           2",
        "Case errors:                        1",
    ]


def test_case_lines_with_notes_and_problems(make_report):
    cases = (
        _case("CASE-001", CaseStatus.PASS, decision=_decision()),
        _case(
            "CASE-002",
            CaseStatus.FAIL_POLICY,
            expect="deny",
            path=("research-agent", "finance-agent"),
            decision=_decision(),
            notes=("expected deny, IAM said allow",),
        ),
        _case("CASE-003", CaseStatus.UNTESTED),
        _case("CASE-004", CaseStatus.ERROR, problems=("unknown fixture", "bad action")),
    )
    lines = render_coverage(_test_report(make_report, cases=cases))
    start = lines.index("Cases:")
    assert lines[start - 1] == ""
    assert lines[start + 1 : start + 9] == [
        "  CASE-001  PASS            finance-agent -> read_portfolio  (expect allow, IAM allow)",
        "  CASE-002  FAIL_POLICY     research-agent -> finance-agent -> read_portfolio"
        "  (expect deny, IAM allow)",
        "    expected deny, IAM said allow",
        "  CASE-003  UNTESTED        finance-agent -> read_portfolio  (expect allow, IAM -)",
        "  CASE-004  ERROR           finance-agent -> read_portfolio  (expect allow, IAM -)",
        "    unknown fixture",
        "    bad action",
        "",
    ]


def test_cases_block_sits_before_errors(make_report):
    report = _test_report(
        make_report,
        cases=(_case("CASE-001", CaseStatus.PASS, decision=_decision()),),
        errors=("boom",),
        exit_code=2,
    )
    lines = render_coverage(report)
    assert lines.index("Cases:") < lines.index("Errors:")


def test_escalation_header_rows_and_case_prefix(make_report):
    escalations = (
        _escalation(EscalationResult.ESCALATION, notes=("user denied, agent allowed",)),
        _escalation(EscalationResult.NONE),
        _escalation(EscalationResult.NONE, tool="read_portfolio"),
        _escalation(EscalationResult.UNCHECKED, case_id="CASE-009", mode="on_behalf_of"),
        _escalation(EscalationResult.INCONCLUSIVE, role="auditor"),
        _escalation(EscalationResult.ERROR, notes=("IAM unreachable",)),
    )
    lines = render_coverage(_test_report(make_report, escalations=escalations))
    header = "Escalation checks: 1 ESCALATION, 1 INCONCLUSIVE, 1 UNCHECKED, 1 ERROR, 2 NONE"
    start = lines.index(header)
    assert lines[start + 1 : start + 8] == [
        "  ESCALATION    analyst -> execute_trade via finance-agent (agent)",
        "    user denied, agent allowed",
        "  UNCHECKED     CASE-009: analyst -> execute_trade via finance-agent (on_behalf_of)",
        "  INCONCLUSIVE  auditor -> execute_trade via finance-agent (agent)",
        "  ERROR         analyst -> execute_trade via finance-agent (agent)",
        "    IAM unreachable",
        "",
    ]
    assert not any(line.lstrip().startswith("NONE") for line in lines)


def test_escalation_header_leaves_out_zero_counts(make_report):
    lines = render_coverage(
        _test_report(make_report, escalations=(_escalation(EscalationResult.NONE),))
    )
    assert "Escalation checks: 1 NONE" in lines


def test_no_escalation_block_without_rows(make_report):
    lines = render_coverage(_test_report(make_report))
    assert not any(line.startswith("Escalation checks") for line in lines)


def test_missing_controls_block(make_report):
    controls = (
        ControlRow(action="trade:execute", resource_type="order", allowed=False),
        ControlRow(
            action="market:read", resource_type="stock", allowed=True, allowed_by="CASE-001"
        ),
    )
    lines = render_coverage(_test_report(make_report, controls=controls))
    start = lines.index("Positive controls missing:")
    assert lines[start + 1] == "  trade:execute on order"
    assert lines[start + 2] == ""
    assert "market:read on stock" not in "\n".join(lines)


def test_no_missing_controls_block_when_all_allowed(make_report):
    controls = (
        ControlRow(
            action="market:read", resource_type="stock", allowed=True, allowed_by="CASE-001"
        ),
    )
    lines = render_coverage(_test_report(make_report, controls=controls))
    assert not any(line.startswith("Positive controls") for line in lines)


def test_every_new_violation_line(make_report):
    violations = (
        GateViolation(rule="case", case_id="CASE-002", status=CaseStatus.FAIL_POLICY),
        GateViolation(
            rule="fail_on_inconclusive_case", case_id="CASE-003", status=CaseStatus.INCONCLUSIVE
        ),
        GateViolation(rule="fail_on_escalation", role="analyst", tool="t", via="a"),
        GateViolation(
            rule="fail_on_escalation", role="analyst", tool="t", via="a", case_id="CASE-009"
        ),
        GateViolation(rule="fail_on_inconclusive_escalation", role="r", tool="t", via="a"),
        GateViolation(
            rule="fail_on_inconclusive_escalation", role="r", tool="t", via="a", case_id="C-1"
        ),
        GateViolation(
            rule="fail_on_unchecked_escalation", role="r", tool="t", via="a", risk=Risk.HIGH
        ),
    )
    report = _test_report(
        make_report, gate=GateResult(passed=False, violations=violations), exit_code=1
    )
    lines = render_coverage(report)
    start = lines.index("Gate: FAIL (exit 1)")
    assert lines[start + 1 :] == [
        "  - case: CASE-002 (FAIL_POLICY)",
        "  - fail_on_inconclusive_case: CASE-003",
        "  - fail_on_escalation: analyst -> t via a",
        "  - fail_on_escalation: analyst -> t via a (CASE-009)",
        "  - fail_on_inconclusive_escalation: r -> t via a",
        "  - fail_on_inconclusive_escalation: r -> t via a (C-1)",
        "  - fail_on_unchecked_escalation: r -> t via a (risk=high)",
    ]


def test_non_ascii_note_is_escaped(make_report):
    case = _case(
        "CASE-001",
        CaseStatus.FAIL_POLICY,
        decision=_decision(),
        notes=("IAM reason: " + chr(0x522A) + chr(0x9664),),
    )
    lines = render_coverage(_test_report(make_report, cases=(case,)))
    bs = chr(92)
    assert f"    IAM reason: {bs}u522a{bs}u9664" in lines
    assert all(line.isascii() for line in lines)


def test_static_report_renders_exactly_as_before(make_report):
    assert render_coverage(make_report()) == STATIC_LITERAL


def test_case_violation_without_status_prints_placeholder():
    violation = GateViolation.model_construct(rule="case", case_id="C", status=None)
    report_lines = violation_line(violation)
    assert report_lines == "  - case: C (?)"


def test_empty_test_report_has_no_extra_blocks(make_report):
    lines = render_coverage(_test_report(make_report, cases=()))
    assert not any(line.startswith("  CASE-") for line in lines)
    for title in ("Escalation checks", "Positive controls missing"):
        assert not any(line.startswith(title) for line in lines)


def test_missing_adapter_name_falls_back_to_unknown(make_report):
    lines = render_coverage(_test_report(make_report, policy_adapter=None))
    assert lines[1] == "Mode: test (asked the IAM through unknown)"


def test_empty_path_leaves_no_stray_arrow(make_report):
    case = _case("CASE-001", CaseStatus.UNTESTED, path=())
    lines = render_coverage(_test_report(make_report, cases=(case,)))
    assert "  CASE-001  UNTESTED        read_portfolio  (expect allow, IAM -)" in lines


ESC = chr(27)


def _esc_report(make_report, where: str):
    bad = f"x{ESC}[31my"
    update: dict[str, Any] = {}
    if where == "adapter":
        update["policy_adapter"] = bad
    elif where == "case_note":
        update["cases"] = (_case("CASE-001", CaseStatus.FAIL_POLICY, notes=(bad,)),)
    elif where == "escalation_note":
        update["escalations"] = (_escalation(EscalationResult.ESCALATION, notes=(bad,)),)
    elif where == "violation_case_id":
        violation = GateViolation.model_construct(
            rule="fail_on_inconclusive_case", case_id=bad, status=CaseStatus.INCONCLUSIVE
        )
        update["gate"] = GateResult(passed=False, violations=(violation,))
        update["exit_code"] = 1
    else:
        update["controls"] = (ControlRow(action=bad, resource_type="order", allowed=False),)
    return _test_report(make_report, **update)


@pytest.mark.parametrize(
    "where", ["adapter", "case_note", "escalation_note", "violation_case_id", "control_action"]
)
def test_escape_character_is_escaped_everywhere(make_report, where):
    text = " ".join(render_coverage(_esc_report(make_report, where)))
    assert ESC not in text
    assert f"x{chr(92)}x1b[31my" in text
