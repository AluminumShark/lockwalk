"""lockwalk diff must not say anything false about waivers, rules or what a case checks."""

import json
from datetime import UTC, datetime

import pytest

from lockwalk.diff import (
    DIFF_SCHEMA_VERSION,
    HEAD_INCOMPLETE,
    ReportDiff,
    diff_reports,
    has_changes,
)
from lockwalk.diff_markdown import MAX_BODY, MAX_VALUE, code, render_diff_markdown
from lockwalk.diff_output import diff_to_json, render_diff_text
from lockwalk.models import (
    GateResult,
    GateViolation,
    Risk,
    RuleRow,
    WaivedViolation,
    WaiverRow,
)

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
V1 = GateViolation(rule="fail_on_unspecified_risk", tool="x", risk=Risk.CRITICAL)
V2 = GateViolation(rule="fail_on_unspecified_risk", tool="y", risk=Risk.HIGH)


def gate(report, violations=(), waived=()):
    result = GateResult(passed=not violations, violations=tuple(violations), waived=tuple(waived))
    return report.model_copy(update={"gate": result})


def waived(violation, waiver_id="W-1"):
    return WaivedViolation(violation=violation, waiver_id=waiver_id)


def waiver(waiver_id="W-1", **changes):
    fields = {
        "id": waiver_id,
        "owner": "alice@example.com",
        "expires": "2027-01-31",
        "reason": "tracked in a ticket",
        "match": {"rule": "RULE-001"},
        "status": "applied",
    }
    fields.update(changes)
    return WaiverRow.model_validate(fields)


def with_waivers(report, *rows):
    return report.model_copy(update={"waivers": tuple(rows)})


def rule(rule_id="RULE-001", **changes):
    fields = {
        "id": rule_id,
        "agent": None,
        "role": "analyst",
        "tool": "execute_trade",
        "target_agent": None,
        "result": "PASS",
    }
    fields.update(changes)
    return RuleRow.model_validate(fields)


def with_rules(report, *rows):
    return report.model_copy(update={"rules": tuple(rows)})


def edit_case(report, case_id, **changes):
    cases = tuple(
        case.model_copy(update=changes) if case.id == case_id else case for case in report.cases
    )
    return report.model_copy(update={"cases": cases})


def build(**changes) -> ReportDiff:
    fields = {
        "head_status": "PASS",
        "head_violations": 0,
        "waived": 0,
        "base_given": True,
        "incomplete": False,
        "warnings": (),
    }
    for name in ReportDiff.model_fields:
        fields.setdefault(name, ())
    fields.update(changes)
    return ReportDiff.model_validate(fields)


def all_outputs(diff):
    return {
        "text": "\n".join(render_diff_text(diff)),
        "json": diff_to_json(diff, generated_at=NOW, version="1"),
        "markdown": render_diff_markdown(diff),
    }


def test_schema_version_is_2():
    assert DIFF_SCHEMA_VERSION == "2"


def test_a_newly_waived_violation_is_not_no_longer_reported(make_report):
    base = gate(make_report(), [V1, V2])
    head = gate(make_report(), [], [waived(V1), waived(V2, "W-2")])
    result = diff_reports(head, base)
    assert result.no_longer_reported == ()
    assert result.new_violations == ()
    assert [(w.violation, w.waiver_id) for w in result.newly_waived] == [(V1, "W-1"), (V2, "W-2")]
    assert result.waived == 2


def test_a_new_problem_hidden_by_a_waiver_is_newly_waived(make_report):
    result = diff_reports(gate(make_report(), [], [waived(V1)]), make_report())
    assert [w.violation for w in result.newly_waived] == [V1]
    assert result.new_violations == ()


def test_a_violation_waived_on_both_sides_is_not_newly_waived(make_report):
    report = gate(make_report(), [], [waived(V1)])
    result = diff_reports(report, report)
    assert result.newly_waived == ()
    assert result.no_longer_reported == ()


def test_a_removed_waiver_makes_the_violation_new(make_report):
    base = gate(make_report(), [], [waived(V1)])
    head = gate(make_report(), [V1])
    result = diff_reports(head, base)
    assert result.new_violations == (V1,)
    assert result.newly_waived == ()
    assert result.no_longer_reported == ()


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ("active", "active", None),
        ("active", "waived", "newly_waived"),
        ("active", "absent", "no_longer_reported"),
        ("waived", "active", "new_violations"),
        ("waived", "waived", None),
        ("waived", "absent", "no_longer_reported"),
        ("absent", "active", "new_violations"),
        ("absent", "waived", "newly_waived"),
        ("absent", "absent", None),
    ],
)
def test_every_transition_lands_in_exactly_one_list(make_report, before, after, expected):
    def side(state):
        if state == "active":
            return gate(make_report(), [V1])
        if state == "waived":
            return gate(make_report(), [], [waived(V1)])
        return make_report()

    result = diff_reports(side(after), side(before))
    lists = {
        "new_violations": [V1] if V1 in result.new_violations else [],
        "newly_waived": [w for w in result.newly_waived if w.violation == V1],
        "no_longer_reported": [V1] if V1 in result.no_longer_reported else [],
    }
    found = [name for name, rows in lists.items() if rows]
    assert found == ([expected] if expected else [])
    assert has_changes(result) is (expected is not None)
    if expected is None:
        assert render_diff_text(result)[-1].startswith("No changes in")


def test_a_problem_waived_in_the_base_and_gone_is_no_longer_reported(make_report):
    base = gate(make_report(), [], [waived(V1), waived(V2, "W-2")])
    result = diff_reports(make_report(), base)
    assert result.no_longer_reported == (V1, V2)
    assert result.newly_waived == ()
    assert "No changes" not in "\n".join(render_diff_text(result))
    assert "No longer reported (2)" in render_diff_markdown(result)


def test_a_waived_problem_gone_from_an_errored_head_is_not_listed(make_report):
    base = gate(make_report(), [], [waived(V1)])
    head = make_report().model_copy(update={"errors": ("boom",), "exit_code": 2})
    assert diff_reports(head, base).no_longer_reported == ()


def test_a_real_fix_is_no_longer_reported_and_not_waived(make_report):
    result = diff_reports(make_report(), gate(make_report(), [V1]))
    assert result.no_longer_reported == (V1,)
    assert result.newly_waived == ()


def test_no_base_has_no_newly_waived_but_counts_waived(make_report):
    head = gate(make_report(), [V2], [waived(V1)])
    result = diff_reports(head, None)
    assert result.newly_waived == ()
    assert result.waived == 1
    assert "1 waived" in render_diff_text(result)[0]
    assert "1 waived" in render_diff_markdown(result)


def test_errored_head_lists_newly_waived_but_nothing_gone(make_report):
    base = gate(make_report(), [V1, V2])
    head = gate(make_report(), [], [waived(V1)]).model_copy(
        update={"errors": ("boom",), "exit_code": 2}
    )
    result = diff_reports(head, base)
    assert result.no_longer_reported == ()
    assert [w.violation for w in result.newly_waived] == [V1]
    assert HEAD_INCOMPLETE in result.warnings
    assert "problems that went away are not listed" in HEAD_INCOMPLETE
    assert "fixed" not in HEAD_INCOMPLETE


def test_no_output_says_fixed(make_report):
    base = gate(make_report(), [V1])
    for head in (make_report(), gate(make_report(), [], [waived(V1)])):
        for name, out in all_outputs(diff_reports(head, base)).items():
            assert "ixed" not in out.replace("fixed_", ""), name


def test_newly_waived_section_follows_new_problems(make_report):
    base = gate(make_report(), [V2])
    head = gate(make_report(), [V1], [waived(V2, "W-9")])
    text = render_diff_text(diff_reports(head, base))
    assert "Newly waived (1):" in text
    assert text.index("New problems (1):") + 3 == text.index("Newly waived (1):")
    assert "  - fail_on_unspecified_risk: y (risk=high) [waiver W-9]" in text
    markdown = render_diff_markdown(diff_reports(head, base))
    assert "### Newly waived (1)" in markdown
    assert "- `fail_on_unspecified_risk: y (risk=high)` waived by `W-9`" in markdown


def test_waiver_added_removed_changed(make_report):
    base = with_waivers(
        make_report(), waiver("W-GONE"), waiver("W-KEPT"), waiver("W-MOVED"), waiver("W-EDIT")
    )
    head = with_waivers(
        make_report(),
        waiver("W-NEW", expires="2027-02-01"),
        waiver("W-KEPT"),
        waiver("W-MOVED", expires="2027-03-01"),
        waiver("W-EDIT", owner="bob@example.com", reason="other"),
    )
    result = diff_reports(head, base)
    assert [(w.id, w.expires) for w in result.waivers_added] == [("W-NEW", "2027-02-01")]
    assert [(w.id, w.expires) for w in result.waivers_removed] == [("W-GONE", "2027-01-31")]
    moved, edit = sorted(result.waivers_changed, key=lambda c: c.id)[1], result.waivers_changed[0]
    assert edit.id == "W-EDIT"
    assert edit.fields == ("owner", "reason")
    assert edit.base_expires is None
    assert moved.id == "W-MOVED"
    assert moved.fields == ("expires",)
    assert (moved.base_expires, moved.head_expires) == ("2027-01-31", "2027-03-01")


def test_waiver_status_matched_and_note_are_not_compared(make_report):
    base = with_waivers(make_report(), waiver(status="applied", matched=("RULE-001",)))
    head = with_waivers(make_report(), waiver(status="expired", matched=(), note="expired"))
    result = diff_reports(head, base)
    assert result.waivers_changed == ()
    assert not has_changes(result)


def test_a_changed_match_is_a_waiver_change(make_report):
    base = with_waivers(make_report(), waiver())
    head = with_waivers(make_report(), waiver(match={"rule": "RULE-002"}))
    result = diff_reports(head, base)
    assert result.waivers_changed[0].fields == ("match",)


def test_owner_and_reason_never_appear(make_report):
    base = with_waivers(make_report(), waiver("W-EDIT", owner="carol-secret", reason="why-secret"))
    head = with_waivers(
        make_report(),
        waiver("W-EDIT", owner="dave-secret", reason="because-secret", expires="2027-02-02"),
        waiver("W-NEW", owner="erin-secret", reason="new-secret"),
    )
    for name, out in all_outputs(diff_reports(head, base)).items():
        assert "secret" not in out, name
        assert "W-EDIT" in out
        assert "2027-01-31" in out
        assert "2027-02-02" in out
    text = "\n".join(render_diff_text(diff_reports(head, base)))
    assert "Waiver changes (2):" in text


def test_rules_added_removed_changed(make_report):
    base = with_rules(
        make_report(), rule("R-GONE"), rule("R-KEPT"), rule("R-RES"), rule("R-TOOL", tool="a")
    )
    head = with_rules(
        make_report(),
        rule("R-NEW", result="FAIL"),
        rule("R-KEPT"),
        rule("R-RES", result="FAIL"),
        rule("R-TOOL", tool="b", agent="ag"),
    )
    result = diff_reports(head, base)
    assert [(r.id, r.result) for r in result.rules_added] == [("R-NEW", "FAIL")]
    assert [r.id for r in result.rules_removed] == ["R-GONE"]
    changed = {c.id: c for c in result.rules_changed}
    assert set(changed) == {"R-RES", "R-TOOL"}
    assert [(f.field, f.base, f.head) for f in changed["R-RES"].changes] == [
        ("result", "PASS", "FAIL")
    ]
    assert [(f.field, f.base, f.head) for f in changed["R-TOOL"].changes] == [
        ("agent", None, "ag"),
        ("tool", "a", "b"),
    ]


def test_rule_reason_and_witness_are_not_compared(make_report):
    base = with_rules(make_report(), rule(reason="one"))
    head = with_rules(make_report(), rule(reason="two", problems=("p",)))
    assert diff_reports(head, base).rules_changed == ()


@pytest.mark.parametrize(
    ("field", "value", "shown"),
    [
        ("expect", "deny", "allow -> deny"),
        ("agent", "other-agent", "-> other-agent"),
        ("path", ("a", "b"), "a > b"),
        ("role", "trader", "analyst -> trader"),
        ("action", "x:y", "-> x:y"),
        ("tool", "other_tool", "-> other_tool"),
    ],
)
def test_changed_case_fields_show_both_values(make_report, field, value, shown):
    base = make_report()
    case = base.cases[1]
    head = edit_case(base, case.id, **{field: value})
    result = diff_reports(head, base)
    assert [c.id for c in result.cases_changed] == [case.id]
    assert [f.field for f in result.cases_changed[0].changes] == [field]
    for name in ("text", "markdown"):
        out = all_outputs(result)[name].replace("`", "")
        assert shown in out, name
        assert "Changes to what a case checks (1)" in out, name
        assert "No changes" not in out, name


def test_a_changed_expect_is_loud_and_not_no_changes(make_report):
    base = make_report()
    head = edit_case(base, "CASE-002", expect="deny")
    result = diff_reports(head, base)
    assert has_changes(result)
    text = render_diff_text(result)
    row = next(line for line in text if "CASE-002" in line)
    assert "EXPECT" in row
    assert "allow -> deny" in row
    assert "No changes" not in "\n".join(text)
    markdown = render_diff_markdown(result)
    assert "**expect**" in markdown or "**EXPECT**" in markdown


def test_changed_actor_shows_the_name_only(make_report):
    base = edit_case(make_report(), "CASE-002", actor="secret-person-a")
    head = edit_case(make_report(), "CASE-002", actor="secret-person-b")
    result = diff_reports(head, base)
    assert [f.field for f in result.cases_changed[0].changes] == ["actor"]
    for name, out in all_outputs(result).items():
        assert "secret-person" not in out, name
        assert "actor" in out, name


def test_cases_are_compared_even_when_modes_differ(make_report):
    base = make_report()
    head = edit_case(base, "CASE-002", expect="deny").model_copy(
        update={"mode": "test" if base.mode == "static" else "static"}
    )
    assert [c.id for c in diff_reports(head, base).cases_changed] == ["CASE-002"]


def test_case_status_change_alone_is_not_a_spec_change(make_report):
    base = make_report()
    head = edit_case(base, "CASE-002", status="FAIL_POLICY", notes=("x",))
    assert diff_reports(head, base).cases_changed == ()


def test_unset_role_is_shown_as_not_set(make_report):
    base = edit_case(make_report(), "CASE-002", role=None)
    head = make_report()
    result = diff_reports(head, base)
    change = result.cases_changed[0].changes[0]
    assert (change.field, change.base, change.head) == ("role", None, "analyst")
    assert "(not set) -> `analyst`" in render_diff_markdown(result)
    assert "(not set) -> analyst" in "\n".join(render_diff_text(result))


def test_no_base_fills_none_of_the_new_lists(make_report):
    head = gate(with_waivers(with_rules(make_report(), rule()), waiver()), [], [waived(V1)])
    result = diff_reports(head, None)
    for name in (
        "newly_waived",
        "waivers_added",
        "waivers_removed",
        "waivers_changed",
        "cases_changed",
        "rules_added",
        "rules_removed",
        "rules_changed",
    ):
        assert getattr(result, name) == (), name


def test_has_changes_picks_up_every_new_list(make_report):
    empty = diff_reports(make_report(), make_report())
    for name in (
        "newly_waived",
        "waivers_added",
        "waivers_removed",
        "waivers_changed",
        "cases_changed",
        "rules_added",
        "rules_removed",
        "rules_changed",
    ):
        assert name in type(empty).model_fields
        assert has_changes(empty.model_copy(update={name: ("row",)})), name


def test_the_plain_line_names_what_was_compared(make_report):
    result = diff_reports(make_report(), make_report())
    line = "No changes in gate problems, waivers, tools, rules or cases."
    assert render_diff_text(result)[-1] == line
    assert f"\n{line}\n" in render_diff_markdown(result)


def test_section_order_in_text_and_markdown(make_report):
    base = with_waivers(with_rules(make_report(), rule("R-OLD")), waiver("W-OLD"))
    base = gate(base, [V2])
    head = with_waivers(with_rules(make_report(), rule("R-NEW")), waiver("W-NEW"))
    head = edit_case(gate(head, [V1], [waived(V2)]), "CASE-002", expect="deny")
    result = diff_reports(head, base)
    titles = [
        "New problems (1)",
        "Newly waived (1)",
        "Waiver changes (2)",
        "Rule changes (2)",
        "Changes to what a case checks (1)",
    ]
    text = "\n".join(render_diff_text(result))
    markdown = render_diff_markdown(result)
    for out, prefix in ((text, ""), (markdown, "### ")):
        positions = [out.index(prefix + title) for title in titles]
        assert positions == sorted(positions)


def test_json_is_sorted_deterministic_and_ascii(make_report):
    base = with_waivers(with_rules(make_report(), rule("R-B"), rule("R-A")), waiver("W-B"))
    head = with_waivers(
        with_rules(make_report(), rule("R-D"), rule("R-C")),
        waiver("W-D"),
        waiver("W-C", owner="\u522a"),
    )
    head = edit_case(edit_case(head, "CASE-003", expect="allow"), "CASE-002", expect="deny")
    head = gate(head, [], [waived(V2, "W-\u522a"), waived(V1)])
    first = diff_to_json(diff_reports(head, base), generated_at=NOW, version="1")
    second = diff_to_json(
        diff_reports(head.model_copy(update={"cases": head.cases[::-1]}), base),
        generated_at=NOW,
        version="1",
    )
    assert first == second
    assert first.isascii()
    document = json.loads(first)
    assert [r["id"] for r in document["rules_added"]] == ["R-C", "R-D"]
    assert [r["id"] for r in document["rules_removed"]] == ["R-A", "R-B"]
    assert [c["id"] for c in document["cases_changed"]] == ["CASE-002", "CASE-003"]
    assert [w["id"] for w in document["waivers_added"]] == ["W-C", "W-D"]
    assert document["schema_version"] == "2"
    assert "owner" not in first


# ---- Markdown values ----

HOSTILE = [
    "a`b`` c",
    "@someone",
    "</details>",
    "line\nbreak",
    "\u202e",
    "\u00a0" * 3,
    "\u3000",
    "e" + "\u0301" * 150,
    "n" * 10000,
    "x" * 190 + "\U000e0001" * 10,
]


def outside_code_only_fixed(markdown, hostile_words=("@someone", "</details>", "\u202e")):
    # Removes code spans the CommonMark way; what is left must hold none of the hostile text.
    import re

    out = []
    pos = 0
    while pos < len(markdown):
        if markdown[pos] != "`":
            out.append(markdown[pos])
            pos += 1
            continue
        end = pos
        while end < len(markdown) and markdown[end] == "`":
            end += 1
        run = markdown[pos:end]
        match = re.search(rf"(?<!`){re.escape(run)}(?!`)", markdown[end:])
        if match is None:
            out.append(run)
            pos = end
        else:
            pos = end + match.end()
    rest = "".join(out)
    for word in hostile_words:
        assert word not in rest
    return rest


def test_a_lookalike_letter_is_not_a_lookalike():
    shown = code("get_st\u043ack_price")
    assert shown == "`get_st\\u043ack_price`"
    assert shown != code("get_stack_price")


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        ("\u5220\u9664", "\\u5220\\u9664"),
        ("a\u00a0b", "a\\u00a0b"),
        ("e\u0301", "e\\u0301"),
        ("x\U0001f600y", "x\\U0001f600y"),
        ("tab\there", "tab\\u0009here"),
        ("del\x7f", "del\\u007f"),
        ("plain~ok", "plain~ok"),
    ],
)
def test_code_spells_every_non_ascii_character(value, shown):
    assert code(value) == f"`{shown}`"
    assert code(value).isascii()


def test_code_hides_nbsp_ideographic_space_and_combining_marks():
    assert code("\u00a0\u00a0") == "`\\u00a0\\u00a0`"
    assert code("\u3000") == "`\\u3000`"
    assert code("a b") == "`a b`"
    shown = code("e" + "\u0301" * 150)
    assert "\u0301" not in shown
    assert len(shown) <= MAX_VALUE + 2


@pytest.mark.parametrize("value", HOSTILE)
def test_code_stays_within_max_value(value):
    shown = code(value)
    inner = shown.strip("`")
    assert len(inner.strip()) <= MAX_VALUE or "``" in shown
    assert "\n" not in shown
    # The text between the fences, without padding, is within the limit.
    fence = len(shown) - len(shown.lstrip("`"))
    body = shown[fence:-fence]
    assert len(body.strip(" ")) <= MAX_VALUE


@pytest.mark.parametrize("length", range(180, 205))
def test_truncation_never_cuts_an_escape(length):
    for char in ("\n", "\U000e0001", "\u202e"):
        value = "a" * (length - 3) + char * 3
        shown = code(value)
        body = shown.strip("`").strip(" ")
        assert len(body) <= MAX_VALUE
        if body.endswith("..."):
            body = body[:-3]
        assert body.count("\\") * 1 >= 0
        # Every backslash in the body starts a complete escape.
        import re

        for match in re.finditer(r"\\", body):
            assert re.match(r"\\(u[0-9a-f]{4}|U[0-9a-f]{8})", body[match.start() :]), body[-12:]


def test_a_value_that_fits_exactly_is_not_cut():
    assert code("a" * MAX_VALUE) == "`" + "a" * MAX_VALUE + "`"
    assert code("a" * (MAX_VALUE + 1)).endswith("...`")


def test_hostile_values_in_every_new_row(make_report):
    from lockwalk.diff import (
        CaseSpecChange,
        FieldChange,
        RuleChange,
        RuleRef,
        WaivedRef,
        WaiverChange,
        WaiverRef,
    )

    diff = build(
        newly_waived=tuple(
            WaivedRef(
                violation=GateViolation(rule="fail_on_unspecified_risk", tool=h, risk=Risk.HIGH),
                waiver_id=h,
            )
            for h in HOSTILE
        ),
        waivers_added=tuple(WaiverRef(id=h, expires="2027-01-01") for h in HOSTILE),
        waivers_removed=tuple(WaiverRef(id=h, expires="2027-01-01") for h in HOSTILE),
        waivers_changed=tuple(
            WaiverChange(
                id=h, fields=("expires",), base_expires="2027-01-01", head_expires="2027-02-02"
            )
            for h in HOSTILE
        ),
        rules_added=tuple(RuleRef(id=h, result="FAIL") for h in HOSTILE),
        rules_removed=tuple(RuleRef(id=h, result="FAIL") for h in HOSTILE),
        rules_changed=tuple(
            RuleChange(id=h, changes=(FieldChange(field="tool", base=h, head=h + "!"),))
            for h in HOSTILE
        ),
        cases_changed=tuple(
            CaseSpecChange(
                id=h,
                tool=h,
                changes=(
                    FieldChange(field="expect", base="allow", head="deny"),
                    FieldChange(field="agent", base=h, head=h),
                    FieldChange(field="path", base=h, head=h),
                    FieldChange(field="role", base=h, head=None),
                ),
            )
            for h in HOSTILE
        ),
    )
    text = render_diff_markdown(diff)
    assert len(text) <= MAX_BODY
    outside_code_only_fixed(text)
    # Every line is fixed layout, so a hostile value can never start a line of its own.
    known = ("<!-- lockwalk-diff -->", "**lockwalk:", "### ", "- ", "The full report")
    for line in text.splitlines():
        assert not line or line.startswith(known), line[:40]
    assert text.count("\n- ") > 0
    assert render_diff_text(diff)
    assert all(line.isascii() for line in render_diff_text(diff))
    assert diff_to_json(diff, generated_at=NOW, version="1").isascii()


def test_worst_case_body_fits_with_every_new_list(make_report):
    from lockwalk.diff import CaseSpecChange, FieldChange, RuleChange

    name = "n" * 300
    changes = tuple(FieldChange(field=f, base=name, head=name) for f in ("agent", "path", "role"))
    diff = build(
        cases_changed=tuple(
            CaseSpecChange(id=f"C{i:05d}".ljust(300, "n"), tool=name, changes=changes)
            for i in range(1500)
        ),
        rules_changed=tuple(
            RuleChange(id=f"R{i:05d}".ljust(300, "n"), changes=changes) for i in range(1500)
        ),
    )
    text = render_diff_markdown(diff)
    assert len(text) <= MAX_BODY
    assert "### Changes to what a case checks (1500)" in text
