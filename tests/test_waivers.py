from datetime import date, timedelta
from pathlib import Path

import pytest

import lockwalk.waivers as waivers_module
from lockwalk.config import GateConfig
from lockwalk.errors import StructuralError
from lockwalk.models import (
    CaseRow,
    CaseStatus,
    CoverageReport,
    EscalationResult,
    EscalationRow,
    GateResult,
    GateViolation,
    IdentityCheckRow,
    IdentityResult,
    InventorySection,
    Metrics,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    WaiverRow,
)
from lockwalk.waivers import (
    Waiver,
    WaiverMatch,
    WaiversFile,
    apply_waivers,
    load_waivers,
)
from lockwalk.waivers import today as real_today

TODAY = date(2026, 6, 15)


def today() -> date:
    return waivers_module.today()


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(waivers_module, "today", lambda: TODAY)


def _day(offset: int) -> date:
    return today() + timedelta(days=offset)


def _report(violations=(), *, mode="test", errors=(), **rows) -> CoverageReport:
    return CoverageReport(
        mode=mode,
        scenario_suite="s",
        spec_schema_version="1",
        inventory=InventorySection(sources=(), agents=(), tools=(), drift=None),
        cases=rows.pop("cases", ()),
        metrics=Metrics(
            registered_tools=0,
            specified_cases=0,
            executed_cases=0,
            execution_coverage=None,
            verified_pass_rate=None,
            cases_by_status={},
            tools_without_spec=0,
        ),
        registered_tools_without_spec=(),
        high_risk_tools_without_deny_case=(),
        gate=GateResult(passed=not violations, violations=tuple(violations)),
        errors=tuple(errors),
        warnings=("old warning",),
        exit_code=2 if errors else (1 if violations else 0),
        **rows,
    )


def _case(case_id, status=CaseStatus.FAIL_POLICY) -> CaseRow:
    return CaseRow(
        id=case_id,
        agent="a",
        tool="t",
        action="x",
        expect="deny",
        status=status,
        action_verified=True,
        problems=("broken",) if status == CaseStatus.ERROR else (),
    )


def _rule(rule_id, result=RuleResult.FAIL) -> RuleRow:
    return RuleRow(
        id=rule_id,
        agent=None,
        role=None,
        tool=None,
        target_agent=None,
        result=result,
        problems=("broken",) if result == RuleResult.ERROR else (),
    )


def _esc(case_id=None, result=EscalationResult.ESCALATION, role="analyst") -> EscalationRow:
    return EscalationRow(
        case_id=case_id,
        role=role,
        tool="execute_trade",
        via="trade-agent",
        risk=Risk.HIGH,
        mode="agent",
        path=("a", "trade-agent"),
        result=result,
    )


def _ident(case_id) -> IdentityCheckRow:
    return IdentityCheckRow(case_id=case_id, path=("a",), tool="t", result=IdentityResult.MISMATCH)


def _reach(role="trader", tool="read_portfolio") -> ReachRow:
    return ReachRow(role=role, tool=tool, risk=Risk.CRITICAL, status=ReachStatus.REACHABLE)


V_CASE = GateViolation(rule="case", case_id="CASE-006", status=CaseStatus.FAIL_POLICY)
V_INCONCLUSIVE = GateViolation(
    rule="fail_on_inconclusive_case", case_id="CASE-007", status=CaseStatus.INCONCLUSIVE
)
V_RULE = GateViolation(rule="never_reaches", rule_id="RULE-002", result=RuleResult.FAIL)
V_ESC_CASE = GateViolation(
    rule="fail_on_escalation", case_id="CASE-006", role="analyst", tool="execute_trade", via="v"
)
V_ESC_ROW = GateViolation(
    rule="fail_on_unchecked_escalation",
    role="analyst",
    tool="execute_trade",
    via="trade-agent",
    risk=Risk.HIGH,
)
V_IDENT = GateViolation(rule="fail_on_identity_mismatch", case_id="CASE-006")
V_ROLE_GAP = GateViolation(
    rule="fail_on_unspecified_role_risk", role="trader", tool="read_portfolio", risk=Risk.CRITICAL
)
V_TOOL_GAP = GateViolation(rule="fail_on_unspecified_risk", tool="execute_trade", risk=Risk.HIGH)
V_DENY_GAP = GateViolation(rule="require_deny_case_for_risk", tool="wire_money", risk=Risk.CRITICAL)


def _w(wid, match, *, expires=None, owner="alice@example.com") -> Waiver:
    return Waiver(
        id=wid,
        match=WaiverMatch.model_validate(match),
        reason="accepted",
        owner=owner,
        expires=expires if expires is not None else _day(10),
    )


def _file(*items: Waiver) -> WaiversFile:
    return WaiversFile(schema_version="1", waivers=tuple(items))


APPLIED_CASES = [
    ({"case": "CASE-006"}, V_CASE),
    ({"case": "CASE-007"}, V_INCONCLUSIVE),
    ({"rule": "RULE-002"}, V_RULE),
    ({"escalation": {"case": "CASE-006"}}, V_ESC_CASE),
    ({"escalation": {"role": "analyst", "tool": "execute_trade", "via": "trade-agent"}}, V_ESC_ROW),
    ({"identity": "CASE-006"}, V_IDENT),
    ({"role_gap": {"role": "trader", "tool": "read_portfolio"}}, V_ROLE_GAP),
    ({"tool_gap": "execute_trade"}, V_TOOL_GAP),
    ({"tool_gap": "wire_money"}, V_DENY_GAP),
]


@pytest.mark.parametrize(("match", "violation"), APPLIED_CASES)
def test_every_match_kind_applies(match, violation):
    other = GateViolation(rule="never_reaches", rule_id="RULE-099", result=RuleResult.FAIL)
    report = _report((violation, other))
    out = apply_waivers(report, _file(_w("W1", match)), today())
    assert out.gate.violations == (other,)
    assert [(v.violation, v.waiver_id) for v in out.gate.waived] == [(violation, "W1")]
    assert out.gate.passed is False
    assert out.exit_code == 1
    assert out.waivers[0].status == "applied"
    assert out.waivers[0].expires == _day(10).isoformat()
    assert out.waivers[0].match == match
    assert out.waivers[0].matched
    assert out.warnings == ("old warning",)


def test_exit_code_goes_to_zero_when_everything_is_waived():
    report = _report((V_CASE,), cases=(_case("CASE-006"),))
    out = apply_waivers(report, _file(_w("W1", {"case": "CASE-006"})), today())
    assert out.gate.passed is True
    assert out.exit_code == 0
    assert out.cases[0].status == CaseStatus.FAIL_POLICY  # the finding is unchanged
    assert out.cases[0].waived_by == "W1"


def test_exit_code_stays_two_with_errors():
    report = _report((V_CASE,), errors=("boom",))
    out = apply_waivers(report, _file(_w("W1", {"case": "CASE-006"})), today())
    assert out.gate.violations == ()
    assert out.errors == ("boom",)
    assert out.exit_code == 2


def test_waived_by_on_every_row_type():
    report = _report(
        (V_CASE, V_RULE, V_ESC_CASE, V_ESC_ROW, V_IDENT, V_ROLE_GAP),
        cases=(_case("CASE-006"), _case("CASE-008")),
        rules=(_rule("RULE-002"), _rule("RULE-003")),
        escalations=(_esc("CASE-006"), _esc(None), _esc(None, role="other")),
        identity_checks=(_ident("CASE-006"), _ident("CASE-008")),
        reachability=(_reach(), _reach(tool="other")),
    )
    items = _file(
        _w("W1", {"case": "CASE-006"}),
        _w("W2", {"rule": "RULE-002"}),
        _w("W3", {"escalation": {"case": "CASE-006"}}),
        _w(
            "W4", {"escalation": {"role": "analyst", "tool": "execute_trade", "via": "trade-agent"}}
        ),
        _w("W5", {"identity": "CASE-006"}),
        _w("W6", {"role_gap": {"role": "trader", "tool": "read_portfolio"}}),
    )
    out = apply_waivers(report, items, today())
    assert [c.waived_by for c in out.cases] == ["W1", None]
    assert [r.waived_by for r in out.rules] == ["W2", None]
    assert [e.waived_by for e in out.escalations] == ["W3", "W4", None]
    assert [i.waived_by for i in out.identity_checks] == ["W5", None]
    assert out.reachability is not None
    assert [r.waived_by for r in out.reachability] == ["W6", None]
    assert out.gate.violations == ()


def test_tool_gap_marks_no_row():
    report = _report((V_TOOL_GAP,), cases=(_case("CASE-006"),))
    out = apply_waivers(report, _file(_w("W1", {"tool_gap": "execute_trade"})), today())
    assert out.cases[0].waived_by is None
    assert out.gate.waived[0].waiver_id == "W1"


def test_expiry_day_is_still_valid():
    report = _report((V_CASE,))
    out = apply_waivers(report, _file(_w("W1", {"case": "CASE-006"}, expires=today())), today())
    assert out.waivers[0].status == "applied"


def test_expired_with_a_match_keeps_the_violation():
    expires = _day(-1)
    report = _report((V_CASE,), cases=(_case("CASE-006"),))
    out = apply_waivers(report, _file(_w("W1", {"case": "CASE-006"}, expires=expires)), today())
    assert out.gate.violations == (V_CASE,)
    assert out.gate.waived == ()
    assert out.exit_code == 1
    assert out.cases[0].waived_by is None
    row = out.waivers[0]
    assert row.status == "expired"
    assert row.matched == ("CASE-006",)
    text = (
        f"waiver W1 expired on {expires.isoformat()} (owner alice@example.com); "
        "CASE-006 blocks the gate again"
    )
    assert out.warnings == ("old warning", text)
    assert row.note == text


def test_expired_without_a_match():
    expires = _day(-30)
    out = apply_waivers(_report(), _file(_w("W1", {"case": "CASE-006"}, expires=expires)), today())
    row = out.waivers[0]
    assert row.status == "expired"
    assert row.matched == ()
    assert (
        out.warnings[-1] == f"waiver W1 expired on {expires.isoformat()} (owner alice@example.com)"
    )


NOT_ALLOWED = [
    ({"case": "CASE-006"}, {"cases": (_case("CASE-006", CaseStatus.ERROR),)}, "case CASE-006"),
    ({"identity": "CASE-006"}, {"cases": (_case("CASE-006", CaseStatus.ERROR),)}, "case CASE-006"),
    ({"rule": "RULE-002"}, {"rules": (_rule("RULE-002", RuleResult.ERROR),)}, "rule RULE-002"),
    (
        {"escalation": {"case": "CASE-006"}},
        {"escalations": (_esc("CASE-006", EscalationResult.ERROR),)},
        "escalation CASE-006",
    ),
    (
        {"escalation": {"role": "analyst", "tool": "execute_trade", "via": "trade-agent"}},
        {"escalations": (_esc(None, EscalationResult.ERROR),)},
        "escalation analyst/execute_trade via trade-agent",
    ),
]


@pytest.mark.parametrize(("match", "rows", "target"), NOT_ALLOWED)
def test_not_allowed_for_error_targets(match, rows, target):
    out = apply_waivers(_report(**rows), _file(_w("W1", match)), today())
    assert out.waivers[0].status == "not_allowed"
    expected = (
        f"waiver W1 matches {target}, which is ERROR; "
        "an ERROR means the test itself is broken and cannot be waived"
    )
    assert out.warnings == ("old warning", expected)
    assert out.waivers[0].note == expected


def test_unmatched_in_test_mode_warns():
    out = apply_waivers(_report(), _file(_w("W1", {"case": "CASE-404"})), today())
    row = out.waivers[0]
    assert row.status == "unmatched"
    assert row.matched == ()
    assert out.warnings[-1] == (
        "waiver W1 matches nothing in this run; it may be stale (owner alice@example.com)"
    )


@pytest.mark.parametrize(
    "match",
    [
        {"case": "CASE-404"},
        {"escalation": {"case": "CASE-404"}},
        {"escalation": {"role": "a", "tool": "b", "via": "c"}},
        {"identity": "CASE-404"},
    ],
)
def test_static_mode_is_silent_for_test_only_kinds(match):
    out = apply_waivers(_report(mode="static"), _file(_w("W1", match)), today())
    assert out.waivers[0].status == "unmatched"
    assert out.waivers[0].note == "checked only by lockwalk test"
    assert out.warnings == ("old warning",)


@pytest.mark.parametrize(
    "match",
    [
        {"rule": "RULE-404"},
        {"role_gap": {"role": "a", "tool": "b"}},
        {"tool_gap": "nothing"},
    ],
)
def test_static_mode_still_warns_for_other_kinds(match):
    out = apply_waivers(_report(mode="static"), _file(_w("W1", match)), today())
    assert out.waivers[0].status == "unmatched"
    assert out.warnings[-1].startswith("waiver W1 matches nothing in this run")


def test_two_waivers_on_one_violation_first_wins():
    report = _report((V_CASE,), cases=(_case("CASE-006"),))
    items = _file(
        _w("W1", {"case": "CASE-006"}),
        _w("W2", {"case": "CASE-006"}, owner="bob@example.com"),
    )
    out = apply_waivers(report, items, today())
    assert [w.status for w in out.waivers] == ["applied", "unmatched"]
    assert [v.waiver_id for v in out.gate.waived] == ["W1"]
    assert out.cases[0].waived_by == "W1"
    assert len(out.warnings) == 2
    text = "waiver W2 adds nothing: its findings are already waived by W1 (owner bob@example.com)"
    assert out.warnings[-1] == text
    assert out.waivers[1].note == text


def test_expired_waiver_does_not_take_a_violation_from_a_later_one():
    report = _report((V_CASE,))
    items = _file(
        _w("OLD", {"case": "CASE-006"}, expires=_day(-1)),
        _w("NEW", {"case": "CASE-006"}),
    )
    out = apply_waivers(report, items, today())
    assert [w.status for w in out.waivers] == ["expired", "applied"]
    assert out.gate.violations == ()


@pytest.mark.parametrize("expired_first", [True, False])
def test_expired_note_says_covered_when_another_waiver_takes_the_finding(expired_first):
    expires = _day(-1)
    old = _w("OLD", {"case": "CASE-006"}, expires=expires)
    new = _w("NEW", {"case": "CASE-006"})
    items = _file(old, new) if expired_first else _file(new, old)
    out = apply_waivers(_report((V_CASE,), cases=(_case("CASE-006"),)), items, today())
    assert out.gate.violations == ()
    text = (
        f"waiver OLD expired on {expires.isoformat()} (owner alice@example.com); "
        "its findings are covered by NEW"
    )
    row = next(r for r in out.waivers if r.id == "OLD")
    assert row.status == "expired"
    assert row.note == text
    assert text in out.warnings
    assert not any("blocks the gate again" in w for w in out.warnings)


def test_expired_note_keeps_blocking_text_when_only_some_hits_are_covered():
    # Two expired waivers on one finding: neither is covered, both keep the old wording.
    items = _file(
        _w("OLD1", {"case": "CASE-006"}, expires=_day(-1)),
        _w("OLD2", {"case": "CASE-006"}, expires=_day(-2)),
    )
    out = apply_waivers(_report((V_CASE,), cases=(_case("CASE-006"),)), items, today())
    assert [str(w.note).endswith("CASE-006 blocks the gate again") for w in out.waivers] == [
        True,
        True,
    ]


def test_waivers_keep_file_order_and_input_is_not_mutated():
    report = _report((V_CASE, V_RULE))
    items = _file(_w("B", {"rule": "RULE-002"}), _w("A", {"case": "CASE-006"}))
    out = apply_waivers(report, items, today())
    assert [w.id for w in out.waivers] == ["B", "A"]
    assert [v.waiver_id for v in out.gate.waived] == ["B", "A"]
    assert report.gate.violations == (V_CASE, V_RULE)
    assert report.waivers == ()


def test_linear_on_five_thousand_violations_and_waivers(monkeypatch):
    count = 5000
    violations = tuple(
        GateViolation(rule="never_reaches", rule_id=f"RULE-{i}", result=RuleResult.FAIL)
        for i in range(count)
    )
    items = _file(*(_w(f"W{i}", {"rule": f"RULE-{i}"}) for i in range(count)))
    report = _report(violations, rules=tuple(_rule(f"RULE-{i}") for i in range(count)))

    calls = []
    original = waivers_module._violation_key

    def counting(violation):
        calls.append(1)
        return original(violation)

    monkeypatch.setattr(waivers_module, "_violation_key", counting)
    out = apply_waivers(report, items, today())
    assert len(calls) == count  # each violation is keyed once, not once per waiver
    assert out.gate.violations == ()
    assert len(out.gate.waived) == count
    assert all(row.waived_by is not None for row in out.rules)


def test_many_violations_on_one_key_stay_cheap():
    violations = tuple(
        GateViolation(rule="case", case_id="CASE-1", status=CaseStatus.FAIL_POLICY)
        for _ in range(2000)
    )
    out = apply_waivers(_report(violations), _file(_w("W1", {"case": "CASE-1"})), today())
    assert len(out.gate.waived) == 2000


# ---------------------------------------------------------------------------
# load_waivers


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "waivers.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _entry(wid="W1", match="{case: CASE-1}", expires=None) -> str:
    expires = expires if expires is not None else _day(30).isoformat()
    return (
        f"  - id: {wid}\n    match: {match}\n    reason: ok\n"
        f"    owner: alice@example.com\n    expires: {expires}\n"
    )


def _load(tmp_path, body: str, gate=None):
    path = _write(tmp_path, "schema_version: '1'\nwaivers:\n" + body)
    return load_waivers(path, gate or GateConfig(), today())


def _problems(tmp_path, text: str, gate=None) -> tuple[str, ...]:
    path = _write(tmp_path, text)
    with pytest.raises(StructuralError) as info:
        load_waivers(path, gate or GateConfig(), today())
    return info.value.problems


def test_load_valid_file(tmp_path):
    loaded = _load(tmp_path, _entry() + _entry("W2", "{tool_gap: execute_trade}"))
    assert [w.id for w in loaded.waivers] == ["W1", "W2"]
    assert loaded.waivers[0].expires == _day(30)
    assert loaded.waivers[0].match.case == "CASE-1"


def test_load_empty_waivers_list(tmp_path):
    path = _write(tmp_path, "schema_version: '1'\nwaivers: []\n")
    assert load_waivers(path, GateConfig(), today()).waivers == ()


def test_today_returns_a_date():
    assert isinstance(real_today(), date)


def test_load_empty_and_non_mapping_files(tmp_path):
    assert _problems(tmp_path, "") == ("the file is empty",)
    assert "mapping" in _problems(tmp_path, "- a\n")[0]


def test_load_duplicate_ids(tmp_path):
    problems = _problems(
        tmp_path, "schema_version: '1'\nwaivers:\n" + _entry() + _entry(match="{case: CASE-2}")
    )
    assert problems == ("waivers[1] W1: duplicate id (first used by waivers[0])",)


def test_load_max_days_rule(tmp_path):
    late = _day(91).isoformat()
    problems = _problems(tmp_path, "schema_version: '1'\nwaivers:\n" + _entry(expires=late))
    assert problems == (
        f"waivers[0] W1: expires {late} is more than [gate] max_waiver_days = 90 days "
        f"after today ({today().isoformat()})",
    )


def test_load_max_days_boundary_and_custom_limit(tmp_path):
    _load(tmp_path, _entry(expires=_day(90).isoformat()))
    gate = GateConfig(max_waiver_days=5)
    with pytest.raises(StructuralError):
        _load(tmp_path, _entry(expires=_day(6).isoformat()), gate)
    _load(tmp_path, _entry(expires=_day(5).isoformat()), gate)


def test_load_past_dates_are_fine(tmp_path):
    assert _load(tmp_path, _entry(expires=_day(-400).isoformat())).waivers[0].expires < today()


def test_load_rejects_a_datetime(tmp_path):
    problems = _problems(
        tmp_path,
        "schema_version: '1'\nwaivers:\n" + _entry(expires=f"{_day(5).isoformat()} 10:00:00"),
    )
    assert "waivers[0].expires" in problems[0]
    assert "not a date and time" in problems[0]


def test_load_rejects_two_match_kinds_and_none(tmp_path):
    body = "schema_version: '1'\nwaivers:\n"
    both = _problems(tmp_path, body + _entry(match="{case: A, rule: B}"))
    assert "exactly one" in both[0]
    none = _problems(tmp_path, body + _entry(match="{}"))
    assert "exactly one" in none[0]


def test_load_rejects_bad_escalation_and_role_gap_shapes(tmp_path):
    body = "schema_version: '1'\nwaivers:\n"
    assert _problems(tmp_path, body + _entry(match="{escalation: {role: a}}"))
    assert _problems(tmp_path, body + _entry(match="{escalation: {case: A, role: a}}"))
    assert _problems(tmp_path, body + _entry(match="{escalation: {}}"))
    assert _problems(tmp_path, body + _entry(match="{role_gap: {role: a}}"))


def test_wildcard_looking_values_are_literals(tmp_path):
    loaded = _load(tmp_path, _entry(match="{tool_gap: '*'}") + _entry("W2", "{case: 'CASE-*'}"))
    assert loaded.waivers[0].match.tool_gap == "*"
    assert loaded.waivers[1].match.case == "CASE-*"
    out = apply_waivers(_report((V_CASE,)), loaded, today())
    assert out.gate.violations == (V_CASE,)  # a pattern waives nothing


def test_load_rejects_unknown_keys_and_empty_values(tmp_path):
    body = "schema_version: '1'\nwaivers:\n"
    extra = _problems(tmp_path, body + _entry() + "    note: hi\n")
    assert "note" in extra[0]
    assert _problems(tmp_path, body + _entry(match="{case: ''}"))
    assert _problems(tmp_path, "schema_version: '1'\nwaivers: []\nextra: 1\n")
    assert _problems(tmp_path, "schema_version: '2'\nwaivers: []\n")
    assert _problems(tmp_path, "waivers: []\n")


def test_load_missing_required_field(tmp_path):
    text = "schema_version: '1'\nwaivers:\n  - id: W1\n    match: {case: A}\n    reason: r\n"
    assert any("owner" in p for p in _problems(tmp_path, text))


def test_load_reports_every_problem_at_once(tmp_path):
    late = _day(500).isoformat()
    problems = _problems(
        tmp_path,
        "schema_version: '1'\nwaivers:\n"
        + _entry(expires=late)
        + _entry("W2", expires=late)
        + _entry("W2"),
    )
    assert len(problems) == 3


# ---------------------------------------------------------------------------
# WaiverRow validators (models.py)


def _row(expires: str, match: dict) -> WaiverRow:
    return WaiverRow(id="W", owner="o", reason="r", match=match, status="applied", expires=expires)


def test_waiver_row_rejects_a_bad_date_and_deep_match():
    _row("2026-12-31", {"case": "A"})
    with pytest.raises(ValueError, match="Invalid isoformat"):
        _row("31/12/2026", {"case": "A"})
    deep: dict = {}
    node = deep
    for _ in range(80):
        node["x"] = {}
        node = node["x"]
    with pytest.raises(ValueError, match="nested"):
        _row("2026-12-31", deep)


def test_load_calendar_invalid_date_is_a_config_error(tmp_path):
    body = "schema_version: '1'\nwaivers:\n" + _entry(expires="2026-02-30")
    problems = _problems(tmp_path, body)
    assert problems[0].startswith("invalid YAML value: ")


def test_case_waiver_does_not_take_other_rules_with_the_same_case_id():
    report = _report((V_CASE, V_ESC_CASE, V_IDENT))
    out = apply_waivers(report, _file(_w("W1", {"case": "CASE-006"})), today())
    assert out.gate.violations == (V_ESC_CASE, V_IDENT)
    assert [v.violation for v in out.gate.waived] == [V_CASE]


def test_tool_gap_waiver_does_not_take_another_tool():
    report = _report((V_TOOL_GAP,))
    out = apply_waivers(report, _file(_w("W1", {"tool_gap": "other_tool"})), today())
    assert out.gate.violations == (V_TOOL_GAP,)
    assert out.waivers[0].status == "unmatched"


def test_role_gap_waiver_does_not_take_another_tool():
    other = GateViolation(
        rule="fail_on_unspecified_role_risk", role="trader", tool="B", risk=Risk.CRITICAL
    )
    mine = GateViolation(
        rule="fail_on_unspecified_role_risk", role="trader", tool="A", risk=Risk.CRITICAL
    )
    items = _file(_w("W1", {"role_gap": {"role": "trader", "tool": "A"}}))
    out = apply_waivers(_report((mine, other)), items, today())
    assert out.gate.violations == (other,)


def test_row_form_escalation_waiver_does_not_take_a_case_form_violation():
    match = {"escalation": {"role": "analyst", "tool": "execute_trade", "via": "v"}}
    out = apply_waivers(_report((V_ESC_CASE,)), _file(_w("W1", match)), today())
    assert out.gate.violations == (V_ESC_CASE,)
    assert out.waivers[0].status == "unmatched"


def test_not_allowed_leaves_the_error_row_and_the_gate_alone():
    report = _report(
        (V_RULE,), cases=(_case("CASE-006", CaseStatus.ERROR),), errors=("CASE-006: broken",)
    )
    out = apply_waivers(report, _file(_w("W1", {"case": "CASE-006"})), today())
    assert out.waivers[0].status == "not_allowed"
    assert out.cases[0].waived_by is None
    assert out.gate.violations == (V_RULE,)
    assert out.gate.waived == ()
    assert out.exit_code == 2


def test_applied_report_round_trips():
    report = _report((V_CASE, V_RULE), cases=(_case("CASE-006"),), rules=(_rule("RULE-002"),))
    items = _file(_w("W1", {"case": "CASE-006"}), _w("W2", {"case": "NOPE"}))
    out = apply_waivers(report, items, today())
    assert CoverageReport.model_validate(out.model_dump()) == out
    assert CoverageReport.model_validate_json(out.model_dump_json()) == out


@pytest.mark.parametrize("mode", ["test", "static"])
@pytest.mark.parametrize(
    "match",
    [
        {"route": {"from": "user", "to": "a"}},
        {"unknown": {"kind": "tool", "name": "x"}},
        {"unguarded": {"agent": "(none)", "tool": "t"}},
        {"observed_identity": {"path": ["a"], "tool": None}},
        {"untested_path": {"path": ["a", "?"], "tool": "t"}},
    ],
)
def test_observe_kinds_are_silent_unmatched_in_coverage_and_test(match, mode):
    before = _report(mode=mode)
    out = apply_waivers(before, _file(_w("W1", match)), today())
    row = out.waivers[0]
    assert row.status == "unmatched" and row.matched == ()
    assert row.note == "checked only by lockwalk observe"
    assert out.warnings == before.warnings  # no warning
    assert out.exit_code == 0
    if "route" in match:
        assert row.match == {"route": {"from": "user", "to": "a"}}
