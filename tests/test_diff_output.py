import json
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

import lockwalk.cli
from lockwalk.cli import app
from lockwalk.diff import NO_CHANGES, NOT_RELIABLE, ReportDiff, ToolRef, diff_reports
from lockwalk.diff_output import diff_to_json, render_diff_text
from lockwalk.models import CaseStatus, GateResult, GateViolation, Risk
from lockwalk.report import ReportFileError, read_report, report_to_dict, write_report

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
UNSPECIFIED = GateViolation(rule="fail_on_unspecified_risk", tool="x", risk=Risk.CRITICAL)


def failing(report):
    return report.model_copy(update={"gate": GateResult(passed=False, violations=(UNSPECIFIED,))})


def changed_case(report):
    case = report.cases[0]
    cases = (case.model_copy(update={"status": CaseStatus.FAIL_POLICY}), *report.cases[1:])
    return report.model_copy(update={"cases": cases}), case


def test_text_sections_and_counts(make_report):
    base = make_report()
    head, case = changed_case(failing(make_report(extra_tools=["delete_portfolio"])))
    lines = render_diff_text(diff_reports(head, base))
    assert lines[0] == "lockwalk diff - head gate: FAIL (1 violation(s))"
    assert "New problems (1):" in lines
    assert "New tools without spec (1):" in lines
    assert "  - delete_portfolio (risk=unknown)" in lines
    assert "Cases that got worse (1):" in lines
    assert f"  - {case.id} ({case.tool}): {case.status.value} -> FAIL_POLICY" in lines
    assert NO_CHANGES not in lines


def test_text_waived_in_head_line(make_report):
    result = diff_reports(make_report(), make_report())
    assert render_diff_text(result)[0] == "lockwalk diff - head gate: PASS (0 violation(s))"
    waived = result.model_copy(update={"waived": 2})
    assert "0 violation(s), 2 waived)" in render_diff_text(waived)[0]


def test_text_no_changes(make_report):
    lines = render_diff_text(diff_reports(make_report(), make_report()))
    assert lines[-1] == NO_CHANGES


def test_text_incomplete_is_not_no_changes(make_report):
    head = make_report().model_copy(update={"errors": ("boom",), "exit_code": 2})
    lines = render_diff_text(diff_reports(head, make_report()))
    assert NO_CHANGES not in lines
    assert lines[-1] == NOT_RELIABLE
    assert "Warnings:" in lines
    assert not any("boom" in line for line in lines)


def test_text_other_tool_changes(make_report):
    result = diff_reports(make_report(extra_tools=["t"]), make_report())
    result = result.model_copy(
        update={
            "tools_added_without_spec": (),
            "tools_added": result.tools_added_without_spec,
            "tools_removed": result.tools_added_without_spec,
        }
    )
    lines = render_diff_text(result)
    assert "Other tool changes (2):" in lines
    assert "  - added: t (risk=unknown)" in lines
    assert "  - removed: t (risk=unknown)" in lines


def test_text_is_ascii_and_one_line_per_row(make_report):
    result = diff_reports(make_report(extra_tools=["del\u522a"]), make_report())
    (tool,) = result.tools_added_without_spec
    hostile = ToolRef(id="del\u522a\nline", risk=tool.risk)
    result = result.model_copy(update={"tools_added_without_spec": (hostile,)})
    lines = render_diff_text(result)
    assert all(line.isascii() and "\n" not in line for line in lines)
    assert any("del\\u522a\\x0aline" in line for line in lines)


def test_json_document(make_report):
    result = diff_reports(failing(make_report()), make_report())
    text = diff_to_json(result, generated_at=NOW, version="1.2.3")
    assert text.isascii()
    document = json.loads(text)
    assert document["schema_version"] == "2"
    assert document["lockwalk_version"] == "1.2.3"
    assert document["generated_at"].startswith("2026-11-09")
    assert document["head_status"] == "FAIL"
    assert document["new_violations"][0]["tool"] == "x"
    assert text == diff_to_json(result, generated_at=NOW, version="1.2.3")


def test_json_escapes_non_ascii(make_report):
    result = diff_reports(make_report(extra_tools=["\u522a"]), make_report())
    text = diff_to_json(result, generated_at=NOW, version="1")
    assert text.isascii()
    assert json.loads(text)["tools_added_without_spec"][0]["id"] == "\u522a"


@pytest.fixture
def reports(tmp_path, make_report):
    def _write(name, report):
        folder = tmp_path / name
        folder.mkdir()
        return write_report(report, folder, generated_at=NOW, version="1")

    return _write


def test_cli_text(reports, make_report):
    base = reports("b", make_report())
    head = reports("h", failing(make_report(extra_tools=["delete_portfolio"])))
    result = CliRunner().invoke(app, ["diff", "--head", str(head), "--base", str(base)])
    assert result.exit_code == 0
    assert "lockwalk diff - head gate: FAIL" in result.output
    assert "delete_portfolio (risk=unknown)" in result.output


def test_cli_json(reports, make_report):
    base = reports("b", make_report())
    head = reports("h", make_report())
    result = CliRunner().invoke(
        app, ["diff", "--head", str(head), "--base", str(base), "--format", "json"]
    )
    assert result.exit_code == 0
    assert json.loads(result.output)["head_status"] == "PASS"


def test_cli_without_base(reports, make_report):
    head = reports("h", make_report())
    result = CliRunner().invoke(app, ["diff", "--head", str(head)])
    assert result.exit_code == 0
    assert "no base report was given" in result.output


def test_cli_missing_file(tmp_path, reports, make_report):
    head = reports("h", make_report())
    result = CliRunner().invoke(
        app, ["diff", "--head", str(head), "--base", str(tmp_path / "none.json")]
    )
    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "run lockwalk coverage or lockwalk test" in result.output
    assert "Result: ERROR (exit 2)" in result.output


def test_cli_other_schema_version(tmp_path, reports, make_report):
    head = reports("h", make_report())
    document = report_to_dict(make_report(), generated_at=NOW, version="1")
    document["schema_version"] = "0"
    old = tmp_path / "old.json"
    old.write_text(json.dumps(document), encoding="utf-8")
    result = CliRunner().invoke(app, ["diff", "--head", str(head), "--base", str(old)])
    assert result.exit_code == 2
    assert "schema_version" in result.output


def test_cli_requires_head():
    assert CliRunner().invoke(app, ["diff"]).exit_code == 2


def test_cli_markdown_is_utf8_bytes(monkeypatch, reports, make_report):
    head = reports("h", make_report())
    monkeypatch.setattr(lockwalk.cli, "render_diff_markdown", lambda diff: "x \u522a")
    result = CliRunner().invoke(app, ["diff", "--head", str(head), "--format", "markdown"])
    assert result.exit_code == 0
    assert "\u522a".encode() in result.stdout_bytes


def test_read_report_default_hint(tmp_path):
    with pytest.raises(ReportFileError, match="run lockwalk test first"):
        read_report(tmp_path / "missing.json")
    with pytest.raises(ReportFileError, match="run lockwalk coverage first"):
        read_report(tmp_path / "missing.json", hint="run lockwalk coverage")


def test_first_line_says_see_warnings_when_incomplete(make_report):
    base = make_report().model_copy(update={"errors": ("boom",), "exit_code": 2})
    line = render_diff_text(diff_reports(make_report(), base))[0]
    assert line == "lockwalk diff - head gate: PASS (0 violation(s)) - see warnings"


def test_text_remaining_rows(make_report):
    base = make_report()
    ref = diff_reports(make_report(extra_tools=["t"]), base).tools_added_without_spec[0]
    case = base.cases[0]
    from lockwalk.diff import CaseChange, CaseRef, RiskChange

    result = diff_reports(base, base).model_copy(
        update={
            "no_longer_reported": (UNSPECIFIED,),
            "tools_lost_spec": (ref,),
            "tools_gained_spec": (ref,),
            "risk_changes": (RiskChange(id="t", base=Risk.LOW, head=Risk.HIGH),),
            "cases_better": (
                CaseChange(id="C-1", tool="t", base=CaseStatus.FAIL_POLICY, head=CaseStatus.PASS),
            ),
            "cases_other": (
                CaseChange(id="C-2", tool="t", base=CaseStatus.UNTESTED, head=CaseStatus.ERROR),
            ),
            "cases_added": (CaseRef(id="C-3", tool="t", status=CaseStatus.UNTESTED),),
            "cases_removed": (CaseRef(id=case.id, tool="t", status=CaseStatus.PASS),),
        }
    )
    lines = render_diff_text(result)
    assert "No longer reported (1):" in lines
    assert "Other tool changes (3):" in lines
    assert "  - lost its spec: t (risk=unknown)" in lines
    assert "  - got a spec: t (risk=unknown)" in lines
    assert "  - risk: t low -> high" in lines
    assert "Cases that got better (1):" in lines
    assert "  - C-1 (t): FAIL_POLICY -> PASS" in lines
    assert "Other case changes (3):" in lines
    assert "  - C-2 (t): UNTESTED -> ERROR" in lines
    assert "  - added: C-3 (t): UNTESTED" in lines
    assert f"  - removed: {case.id} (t): PASS" in lines


def test_json_keys_match_the_model(make_report):
    result = diff_reports(make_report(), make_report())
    document = json.loads(diff_to_json(result, generated_at=NOW, version="1"))
    assert set(document) == {
        "schema_version",
        "lockwalk_version",
        "generated_at",
        *ReportDiff.model_fields,
    }


@pytest.mark.parametrize("target", ["render_diff_text", "diff_to_json", "render_diff_markdown"])
def test_cli_render_crash_is_exit_2(monkeypatch, reports, make_report, target):
    head = reports("h", make_report())

    def boom(*args, **kwargs):
        raise RuntimeError("render broke")

    monkeypatch.setattr(lockwalk.cli, target, boom)
    fmt = {"render_diff_text": "text", "diff_to_json": "json"}.get(target, "markdown")
    result = CliRunner().invoke(app, ["diff", "--head", str(head), "--format", fmt])
    assert result.exit_code == 2
    assert "Result: ERROR (exit 2)" in result.output


def test_cli_compare_crash_is_exit_2(monkeypatch, reports, make_report):
    head = reports("h", make_report())

    def boom(*args, **kwargs):
        raise RuntimeError("compare broke")

    monkeypatch.setattr(lockwalk.cli, "diff_reports", boom)
    result = CliRunner().invoke(app, ["diff", "--head", str(head)])
    assert result.exit_code == 2
    assert "Result: ERROR (exit 2)" in result.output
