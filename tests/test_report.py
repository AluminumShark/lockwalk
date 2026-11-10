import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from lockwalk.errors import StructuralError
from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import SourceRef, SourceResult, ToolDescriptor
from lockwalk.report import (
    render_coverage,
    render_discover,
    render_structural_error,
    report_to_dict,
    to_ascii,
    write_report,
)

NOW = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)


def test_json_document_has_the_documented_top_level_keys(make_report):
    document = report_to_dict(make_report(), generated_at=NOW, version="0.1.0.dev0")
    assert list(document) == [
        "schema_version",
        "lockwalk_version",
        "generated_at",
        "mode",
        "scenario_suite",
        "spec_schema_version",
        "policy_adapter",
        "run_id",
        "inventory",
        "cases",
        "metrics",
        "registered_tools_without_spec",
        "high_risk_tools_without_deny_case",
        "agent_graph",
        "reachability",
        "rules",
        "escalations",
        "controls",
        "identity_checks",
        "door_controls",
        "waivers",
        "gate",
        "errors",
        "warnings",
        "exit_code",
    ]
    assert document["schema_version"] == "5"
    assert document["generated_at"] == "2026-11-06T12:00:00Z"
    assert document["policy_adapter"] is None
    assert "security_score" not in json.dumps(document)


def test_write_report_creates_the_directory_and_file(make_report, tmp_path):
    path = write_report(make_report(), tmp_path / "out", generated_at=NOW, version="x")
    assert path == tmp_path / "out" / "coverage.json"
    assert json.loads(path.read_text(encoding="utf-8"))["exit_code"] == 0


def test_render_coverage_for_a_tool_without_spec(make_report):
    lines = render_coverage(make_report(extra_tools=["delete_portfolio"]))
    assert lines == [
        "lockwalk coverage - finance-demo-v1",
        "Mode: static (no tests executed)",
        "Inventory sources: registry:registry.yaml, mcp:finance-tools",
        "----------------------------------------",
        "Registered tools:                   4",
        "Specified scenarios:                4",
        "Executed scenarios:                 0/4 (not run)",
        "Untested:                           4",
        "Tools without spec:                 1   "
        "(delete_portfolio, risk=unknown, source=mcp:finance-tools)",
        "High-risk tools without deny case:  1   (delete_portfolio)",
        "Inventory drift:                    discovered only: delete_portfolio",
        "",
        "Warnings:",
        "  - tool 'delete_portfolio' was reported by a discovery source but is not declared "
        "in the registry, so its risk is unknown",
        "",
        "Gate: FAIL (exit 1)",
        "  - fail_on_unspecified_risk: delete_portfolio (risk=unknown)",
        "  - require_deny_case_for_risk: delete_portfolio (risk=unknown)",
    ]


def test_render_coverage_pass_and_notes(make_report):
    lines = render_coverage(make_report(), notes=["something to know"])
    assert "Note: something to know" in lines
    assert "Tools without spec:                 0" in lines
    assert lines[-1] == "Gate: PASS (exit 0)"


def test_render_coverage_with_no_cases(make_report):
    lines = render_coverage(make_report(cases=[]))
    assert "Executed scenarios:                 N/A (no specified scenarios)" in lines


def test_render_coverage_with_errors(make_report):
    lines = render_coverage(
        make_report(extra_tools=["delete_portfolio"], failed_source="json:missing.json")
    )
    assert (
        "Inventory sources: registry:registry.yaml, mcp:finance-tools, json:missing.json (FAILED)"
        in lines
    )
    assert any(line.endswith("(incomplete: json:missing.json failed)") for line in lines)
    assert "  - json:missing.json: file not found: missing.json" in lines
    assert "Result: ERROR (exit 2) - the report is incomplete; fix the errors above" in lines
    assert "Gate violations:" in lines


def test_to_ascii_escapes_non_ascii():
    assert to_ascii("delete \u522a\u9664") == "delete \\u522a\\u9664"


def test_render_discover_lists_tools_and_spec_status():
    mcp = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:finance-tools"),
        ok=True,
        tools=(
            ToolDescriptor(name="get_stock_price"),
            ToolDescriptor(name="delete_portfolio", hints={"destructiveHint": True}),
        ),
    )
    lines = render_discover(merge_inventory([mcp]), {"get_stock_price": "yes"})
    assert "Agents (0): (none declared)" in lines
    assert "Tools (2):" in lines
    assert "  get_stock_price   risk=unknown  sources=mcp:finance-tools  spec=yes" in lines
    assert (
        "  delete_portfolio  risk=unknown  sources=mcp:finance-tools  spec=NO"
        "  hints=destructiveHint=true"
    ) in lines
    assert lines[-1] == "Result: OK (exit 0)"


def test_render_discover_shows_error_when_all_cases_are_errors():
    mcp = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:x"), ok=True, tools=(ToolDescriptor(name="a"),)
    )
    lines = render_discover(merge_inventory([mcp]), {"a": "ERROR"})
    assert "  a  risk=unknown  sources=mcp:x  spec=ERROR" in lines


def test_render_discover_without_spec_has_no_spec_column():
    mcp = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:x"), ok=True, tools=(ToolDescriptor(name="a"),)
    )
    assert "  a  risk=unknown  sources=mcp:x" in render_discover(merge_inventory([mcp]), None)


def test_render_structural_error():
    error = StructuralError("registry.yaml", ["tools[2].risks: Extra inputs are not permitted"])
    assert render_structural_error(error) == [
        "Configuration error in registry.yaml:",
        "  - tools[2].risks: Extra inputs are not permitted",
        "",
        "Result: ERROR (exit 2)",
    ]


def test_to_ascii_escapes_control_characters():
    assert to_ascii("a\x1b[2Jb\rc\nd\x07e\x7f") == "a\\x1b[2Jb\\x0dc\\x0ad\\x07e\\x7f"
    assert to_ascii("tab\there") == "tab\\x09here"


def test_forged_verdict_and_escape_codes_cannot_reach_the_terminal(make_report):
    report = make_report(extra_tools=["delete_portfolio"], failed_source="json:missing.json")
    hostile = report.model_copy(
        update={"errors": (*report.errors, "boom\nGate: PASS (exit 0)\x1b[2J")}
    )
    lines = render_coverage(hostile)
    assert "Gate: PASS (exit 0)" not in lines
    assert all(line.isascii() for line in lines)
    assert not any("\x1b" in line for line in lines)
    assert any("boom\\x0aGate: PASS (exit 0)\\x1b[2J" in line for line in lines)


def test_report_to_dict_rejects_naive_datetime(make_report):
    with pytest.raises(ValueError, match="timezone-aware"):
        report_to_dict(make_report(), generated_at=datetime(2026, 11, 6, 12, 0), version="x")


def test_report_to_dict_converts_to_utc(make_report):
    local = datetime(2026, 11, 6, 20, 0, tzinfo=timezone(timedelta(hours=8)))
    document = report_to_dict(make_report(), generated_at=local, version="x")
    assert document["generated_at"] == "2026-11-06T12:00:00Z"


def test_write_report_keeps_non_ascii_as_utf8(make_report, tmp_path):
    report = make_report()
    report = report.model_copy(update={"warnings": ("tool \u522a", *report.warnings)})
    path = write_report(report, tmp_path, generated_at=NOW, version="x")
    raw = path.read_text(encoding="utf-8")
    assert "\u522a" in raw
    assert "\\u522a" not in raw
    assert "tool \u522a" in json.loads(raw)["warnings"]


def test_render_discover_with_a_failed_source_ends_with_error():
    failed = SourceResult(
        source=SourceRef(kind="json", label="json:missing.json"),
        ok=False,
        error="file not found: missing.json",
    )
    lines = render_discover(merge_inventory([failed]), None)
    assert lines[-1] == "Result: ERROR (exit 2)"


def test_write_report_leaves_no_temp_files(make_report, tmp_path):
    write_report(make_report(), tmp_path / "out", generated_at=datetime.now(UTC), version="0")
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["coverage.json"]


def test_write_report_survives_a_lone_surrogate_in_error_text(make_report, tmp_path):
    # User exception messages can carry a lone surrogate; writing must not crash.
    report = make_report().model_copy(update={"warnings": ("bad \ud800 value",)})
    path = write_report(report, tmp_path, generated_at=NOW, version="x")
    assert "bad \\ud800 value" in path.read_text(encoding="utf-8")


def test_v2_graph_fields_default_to_empty(make_report):
    document = report_to_dict(make_report(), generated_at=NOW, version="x")
    assert document["agent_graph"]["nodes"] == []
    assert document["reachability"] is None
    assert document["rules"] == []
    assert document["cases"][0]["path"] == ["finance-agent"]


def test_failed_optional_source_is_rendered_as_unavailable(make_report):
    from lockwalk.models import SourceSummary

    report = make_report()
    section = report.inventory.model_copy(
        update={
            "sources": (
                *report.inventory.sources,
                SourceSummary(
                    source="mcp:partner",
                    ok=False,
                    tool_count=0,
                    error="down",
                    optional=True,
                    unavailable=True,
                ),
            )
        }
    )
    text = " ".join(render_coverage(report.model_copy(update={"inventory": section})))
    assert "mcp:partner (unavailable, optional)" in text
    assert "FAILED" not in text
    result = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:partner"), ok=False, error="down", optional=True
    )
    assert "mcp:partner (unavailable, optional)" in " ".join(
        render_discover(merge_inventory([result]), None)
    )


def test_optional_source_with_an_item_error_is_failed_not_unavailable(make_report):
    from lockwalk.models import SourceSummary

    result = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:partner"),
        ok=False,
        error="bad item",
        optional=True,
        tools=(ToolDescriptor(name="a"),),
    )
    assert "mcp:partner (FAILED)" in " ".join(render_discover(merge_inventory([result]), None))
    report = make_report()
    summary = SourceSummary(
        source="mcp:partner",
        ok=False,
        tool_count=1,
        error="bad item",
        optional=True,
        unavailable=result.unavailable,
    )
    section = report.inventory.model_copy(update={"sources": (summary,)})
    text = " ".join(render_coverage(report.model_copy(update={"inventory": section})))
    assert "mcp:partner (FAILED)" in text
