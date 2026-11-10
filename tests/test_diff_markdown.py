import re

import pytest

from lockwalk.diff import (
    NOT_RELIABLE,
    CaseChange,
    CaseRef,
    ReportDiff,
    RiskChange,
    ToolRef,
)
from lockwalk.diff_markdown import FOOTER, MARKER, MAX_BODY, code, render_diff_markdown
from lockwalk.diff_output import render_diff_text
from lockwalk.models import CaseStatus, GateViolation, Risk

HOSTILE = [
    "@octocat",
    "#1",
    "<script>alert(1)</script>",
    "[x](http://evil)",
    "a`b",
    "line\nbreak",
]


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


def violation(tool: str) -> GateViolation:
    return GateViolation(rule="fail_on_unspecified_risk", tool=tool, risk=Risk.CRITICAL)


def tool_ref(name: str) -> ToolRef:
    return ToolRef(id=name, risk=Risk.HIGH)


def change(name: str, tool: str = "t") -> CaseChange:
    return CaseChange(id=name, tool=tool, base=CaseStatus.PASS, head=CaseStatus.FAIL_POLICY)


def outside_code(markdown: str) -> str:
    """Remove code spans the CommonMark way: a run of backticks closes at the next equal run."""
    out: list[str] = []
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
    return "".join(out)


def test_code_plain_and_backticks():
    assert code("x") == "`x`"
    assert code("a`b") == "``a`b``"
    assert code("`a") == "`` `a ``"
    assert code("a`") == "`` a` ``"
    assert code("a``b") == "```a``b```"


@pytest.mark.parametrize("value", ["@octocat", "#123", "<img src=x>", "[a](http://x)"])
def test_code_keeps_markup_inside(value):
    assert code(value) == f"`{value}`"


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        ("a\nb", "a\\u000ab"),
        ("a\tb", "a\\u0009b"),
        ("a\x1bb", "a\\u001bb"),
        ("a\u202eb", "a\\u202eb"),
        ("a\u2028b", "a\\u2028b"),
    ],
)
def test_code_escapes_hidden_characters(value, shown):
    assert code(value) == f"`{shown}`"
    assert code(value).isascii()


def test_code_escapes_astral_characters_unambiguously():
    assert code("a\U000e0001b") == "`a\\U000e0001b`"


def test_code_truncates_and_marks_empty():
    long = code("a" * 500)
    assert long == "`" + "a" * 197 + "..." + "`"
    assert code("") == "`(empty)`"


def test_layout_and_heading():
    diff = build(head_status="FAIL", head_violations=2, new_violations=(violation("x"),))
    lines = render_diff_markdown(diff).splitlines()
    assert lines[0] == MARKER == "<!-- lockwalk-diff -->"
    assert lines[2] == "**lockwalk: gate FAIL** (2 violations)"
    assert "### New problems (1)" in lines
    assert lines[-1] == "The full report is in the CI artifact."


def test_heading_variants():
    assert "**lockwalk: gate PASS** (0 violations)" in render_diff_markdown(build())
    assert "**lockwalk: gate FAIL** (1 violation)" in render_diff_markdown(
        build(head_status="FAIL", head_violations=1)
    )
    assert "(0 violations, 3 waived)" in render_diff_markdown(build(waived=3))
    error = render_diff_markdown(build(head_status="ERROR", incomplete=True))
    assert "**lockwalk: gate ERROR** - incomplete, see warnings" in error


def test_incomplete_heading_never_reads_all_clear():
    text = render_diff_markdown(build(incomplete=True, warnings=("w",)))
    assert "incomplete, see warnings" in text.splitlines()[2]
    assert NOT_RELIABLE in text


def test_no_changes_sentences():
    plain = "No changes in gate problems, waivers, tools, rules or cases."
    assert f"\n{plain}\n" in render_diff_markdown(build())
    assert f"\n{NOT_RELIABLE}\n" in render_diff_markdown(build(incomplete=True))
    assert "No changes" not in render_diff_markdown(build(cases_worse=(change("c"),)))


def test_section_order_and_warnings_first():
    diff = build(
        warnings=("first warning", "second warning"),
        new_violations=(violation("a"),),
        no_longer_reported=(violation("b"),),
        tools_added_without_spec=(tool_ref("c"),),
        tools_removed=(tool_ref("d"),),
        cases_worse=(change("e"),),
        cases_better=(change("f"),),
        cases_added=(CaseRef(id="g", tool="t", status=CaseStatus.PASS),),
    )
    text = render_diff_markdown(diff)
    titles = [
        "> first warning\n> second warning",
        "### New problems (1)",
        "### No longer reported (1)",
        "### New tools without spec (1)",
        "### Other tool changes (1)",
        "### Cases that got worse (1)",
        "### Cases that got better (1)",
        "### Other case changes (1)",
    ]
    positions = [text.index(title) for title in titles]
    assert positions == sorted(positions)
    assert text.splitlines()[4] == "> first warning"


def test_row_formats():
    diff = build(
        new_violations=(violation("pay"),),
        tools_added_without_spec=(tool_ref("t1"),),
        tools_gained_spec=(tool_ref("t2"),),
        risk_changes=(RiskChange(id="t3", base=Risk.LOW, head=Risk.HIGH),),
        cases_worse=(change("c1", "pay"),),
    )
    lines = render_diff_markdown(diff).splitlines()
    assert "- `fail_on_unspecified_risk: pay (risk=critical)`" in lines
    assert "- `t1` (risk: `high`)" in lines
    assert "- got a spec: `t2` (risk: `high`)" in lines
    assert "- risk of `t3`: `low` -> `high`" in lines
    assert "- `c1` on `pay`: `PASS` -> `FAIL_POLICY`" in lines


def test_hostile_values_stay_in_code():
    diff = build(
        head_violations=len(HOSTILE),
        new_violations=tuple(violation(h) for h in HOSTILE),
        no_longer_reported=tuple(violation(h + "!") for h in HOSTILE),
        tools_added_without_spec=tuple(tool_ref(h) for h in HOSTILE),
        tools_added=tuple(tool_ref(h + "?") for h in HOSTILE),
        tools_removed=tuple(tool_ref(h + "-") for h in HOSTILE),
        risk_changes=tuple(RiskChange(id=h, base=Risk.LOW, head=Risk.HIGH) for h in HOSTILE),
        cases_worse=tuple(change(h, h) for h in HOSTILE),
        cases_better=tuple(change(h, h) for h in HOSTILE),
        cases_added=tuple(CaseRef(id=h, tool=h, status=CaseStatus.PASS) for h in HOSTILE),
    )
    text = render_diff_markdown(diff)
    rest = outside_code(text)
    for bad in ("@octocat", "<script", "](http", "#1", "evil"):
        assert bad not in rest
    assert "\\u000a" in text
    for line in text.splitlines():
        for hostile in HOSTILE:
            assert not line.startswith(hostile)
            assert not line.startswith("- " + hostile)


def test_non_ascii_is_spelled_out_in_code():
    text = render_diff_markdown(build(tools_added_without_spec=(tool_ref("\u522a\u9664"),)))
    assert "- `\\u522a\\u9664` (risk: `high`)" in text
    assert render_diff_markdown(build(tools_added_without_spec=(tool_ref("x"),))).isascii()


def test_row_limit():
    for count, shown, more in ((49, 49, 0), (50, 50, 0), (51, 50, 1)):
        diff = build(tools_added_without_spec=tuple(tool_ref(f"t{i}") for i in range(count)))
        text = render_diff_markdown(diff)
        assert f"### New tools without spec ({count})" in text
        assert text.count("- `t") == shown
        assert (f"- ...and {more} more" in text) is (more > 0)


def test_worst_case_fits_and_counts_are_right():
    name = "n" * 200
    n = 1500

    def names(prefix: str) -> list[str]:
        return [f"{prefix}{i:05d}".ljust(200, "n") for i in range(n)]

    diff = build(
        head_status="FAIL",
        head_violations=n,
        new_violations=tuple(violation(x) for x in names("v")),
        no_longer_reported=tuple(violation(x) for x in names("w")),
        tools_added_without_spec=tuple(tool_ref(x) for x in names("a")),
        tools_added=tuple(tool_ref(x) for x in names("b")),
        cases_worse=tuple(change(x, name) for x in names("c")),
        cases_better=tuple(change(x, name) for x in names("d")),
        cases_other=tuple(change(x, name) for x in names("e")),
        cases_added=tuple(CaseRef(id=x, tool=name, status=CaseStatus.PASS) for x in names("f")),
    )
    text = render_diff_markdown(diff)
    assert len(text) < MAX_BODY
    assert text.startswith(MARKER)
    assert "**lockwalk: gate FAIL** (1500 violations)" in text
    assert text.endswith("The full report is in the CI artifact.\n")
    totals = [int(x) for x in re.findall(r"^### .*\((\d+)\)$", text, flags=re.M)]
    more = [int(x) for x in re.findall(r"^- \.\.\.and (\d+) more$", text, flags=re.M)]
    assert totals == [n, n, n, n, n, n, 2 * n]
    per_list = text.count("\n- `fail_on_unspecified_risk") // 2
    assert 0 < per_list < 50
    assert text.count("\n- `c") == per_list
    assert more == [total - per_list for total in totals]


def test_deterministic_and_single_trailing_newline():
    diff = build(cases_worse=(change("c"),), new_violations=(violation("x"),))
    assert render_diff_markdown(diff) == render_diff_markdown(diff)
    text = render_diff_markdown(diff)
    assert text.endswith("\n")
    assert not text.endswith("\n\n")


def full_diff() -> ReportDiff:
    return build(
        warnings=("w",),
        new_violations=(violation("a"),),
        no_longer_reported=(violation("b"),),
        tools_added_without_spec=(tool_ref("c"),),
        tools_removed=(tool_ref("d"),),
        cases_worse=(change("e"),),
        cases_better=(change("f"),),
        cases_added=(CaseRef(id="g", tool="t", status=CaseStatus.PASS),),
    )


def test_section_titles_match_the_text_output():
    diff = full_diff()
    text_titles = [
        match.group(1)
        for line in render_diff_text(diff)
        if (match := re.fullmatch(r"(.+) \(\d+\):", line))
    ]
    markdown_titles = [
        match.group(1)
        for line in render_diff_markdown(diff).splitlines()
        if (match := re.fullmatch(r"### (.+) \(\d+\)", line))
    ]
    assert len(markdown_titles) == 7
    assert text_titles == markdown_titles


@pytest.mark.parametrize(
    "diff",
    [
        build(),
        build(incomplete=True, warnings=("w",)),
        build(head_status="ERROR", incomplete=True),
        build(head_status="PASS", cases_better=(change("c"),)),
    ],
    ids=["no-changes", "incomplete", "error", "pass-with-changes"],
)
def test_marker_first_and_footer_last(diff):
    lines = render_diff_markdown(diff).splitlines()
    assert lines[0] == MARKER
    assert lines[-1] == FOOTER


@pytest.mark.parametrize(
    ("status", "shown"), [("PASS", True), ("FAIL", True), ("ERROR", False)], ids=str
)
def test_violation_count_is_hidden_only_for_an_error_head(status, shown):
    diff = build(head_status=status, head_violations=7, incomplete=status == "ERROR")
    text_first = render_diff_text(diff)[0]
    markdown_heading = render_diff_markdown(diff).splitlines()[2]
    assert ("7 violation" in markdown_heading) is shown
    assert ("7 violation(s)" in text_first) is shown


def test_the_shrinking_loop_stops_at_limit_one_when_nothing_fits(monkeypatch):
    import lockwalk.diff_markdown as module

    diff = build(tools_added_without_spec=tuple(tool_ref(f"t{i}") for i in range(200)))
    limits = []
    real = module._render

    def spy(value, limit):
        limits.append(limit)
        assert len(limits) < 20, "the loop did not stop"
        return real(value, limit)

    monkeypatch.setattr(module, "MAX_BODY", 10)
    monkeypatch.setattr(module, "_render", spy)
    text = render_diff_markdown(diff)
    assert limits == [50, 25, 12, 6, 3, 1]
    assert text == real(diff, 1)
    assert text.count("\n- `t") == 1
    assert "- ...and 199 more" in text
