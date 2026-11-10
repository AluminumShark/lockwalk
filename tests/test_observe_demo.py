"""The demo trace files in examples/multi_agent/traces run through the real CLI.

Discovery imports examples/multi_agent/app.py in a worker subprocess (real OpenAI Agents SDK
and Pydantic AI objects). Nothing calls a model or the network. The guide shows the output of
off_map.jsonl, and a test checks that it is still what lockwalk prints.
"""

import json
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lockwalk import waivers
from lockwalk.cli import app
from lockwalk.observe import pipeline as observe_pipeline

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "multi_agent"
GUIDE = REPO_ROOT / "docs" / "lockwalk-observe.md"

runner = CliRunner()
TODAY = date(2026, 11, 8)  # waivers-observe.yaml expires on 2027-01-31


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(waivers, "today", lambda: TODAY)


@pytest.fixture(autouse=True)
def no_local_test_report(monkeypatch: pytest.MonkeyPatch) -> None:
    """The example folder may hold a .lockwalk/coverage.json from a manual run (it is ignored by
    git). The demo output must not depend on it, so the test report reads as absent here; the
    side by side is tested in test_observe_e2e_doors.py."""
    monkeypatch.setattr(observe_pipeline, "load_test_report", lambda _path: (None, None))


OFF_MAP_ROW = "  supervisor -> trade-agent (agent)  1 time(s), e.g. trace " + "c3" * 16
UNKNOWN_ROW = "  agent refund-agent  1 time(s), e.g. trace " + "d4" * 16


def observe(
    name: str, output_dir: Path, monkeypatch: pytest.MonkeyPatch, *extra: str
) -> tuple[int, list[str], dict]:
    monkeypatch.chdir(EXAMPLE)  # the example is run from its own folder
    result = runner.invoke(
        app,
        ["observe", "--traces", f"traces/{name}.jsonl", "--output-dir", str(output_dir), *extra],
    )
    lines = result.output.splitlines()
    report = json.loads((output_dir / "observe.json").read_text(encoding="utf-8"))
    return result.exit_code, lines, report


def test_ok_every_route_is_on_the_map(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, lines, report = observe("ok", tmp_path, monkeypatch)
    assert code == 0
    assert sum(1 for row in report["routes"] if row["status"] == "ON_MAP") == 9
    assert [row["result"] for row in report["identities"]] == ["MATCH"] * 3
    assert [row["counts"] for row in report["guards"] if "GUARDED" in row["counts"]] == [
        {"GUARDED": 1}
    ] * 3
    assert "Gate: PASS (exit 0)" in lines
    assert not any(row["status"] == "OFF_MAP" for row in report["routes"])
    assert report["unknown"] == []
    assert report["errors"] == []


def test_off_map_has_one_off_map_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, lines, report = observe("off_map", tmp_path, monkeypatch)
    assert code == 1
    assert OFF_MAP_ROW in lines
    off_map = [row for row in report["routes"] if row["status"] == "OFF_MAP"]
    assert [(row["from_id"], row["to_id"]) for row in off_map] == [("supervisor", "trade-agent")]
    assert report["unknown"] == []
    assert report["gate"]["violations"][0]["rule"] == "fail_on_off_map_route"


def test_unknown_has_one_unknown_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, lines, report = observe("unknown", tmp_path, monkeypatch)
    assert code == 1
    assert UNKNOWN_ROW in lines
    assert [(row["kind"], row["name"]) for row in report["unknown"]] == [("agent", "refund-agent")]
    assert not any(row["status"] == "OFF_MAP" for row in report["routes"])
    assert report["gate"]["violations"][0]["rule"] == "fail_on_unknown_component"


def test_guide_shows_the_real_off_map_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, lines, _ = observe("off_map", tmp_path, monkeypatch)
    shown = lines[: lines.index("") if "" in lines else len(lines)]  # up to the report path
    text = GUIDE.read_text(encoding="utf-8")
    block = text.split("```text\n", 1)[1].split("```", 1)[0].splitlines()
    assert block == shown


def violations(report: dict) -> list[tuple[str, str | None]]:
    return [(v["rule"], v.get("tool")) for v in report["gate"]["violations"]]


def test_mismatch_sends_the_user_where_the_agent_belongs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, lines, report = observe("mismatch", tmp_path, monkeypatch)
    assert code == 1
    assert violations(report) == [("fail_on_identity_mismatch", "execute_trade")]
    (row,) = report["identities"]
    assert (row["result"], row["mode"], row["tool"]) == ("MISMATCH", "agent", "execute_trade")
    assert (row["expected"], row["observed"]) == ("agent:trade-agent", "the trace's user")
    assert not any("bob" in line for line in lines)  # a user id is never printed


def test_unguarded_ran_with_no_door_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, report = observe("unguarded", tmp_path, monkeypatch)
    assert code == 1
    assert violations(report) == [("fail_on_unguarded_call", "read_portfolio")]
    (row,) = report["guards"]
    assert (row["agent"], row["tool"], row["counts"]) == (
        "finance-agent",
        "read_portfolio",
        {"UNGUARDED": 1},
    )
    assert row["effect_without_record"] == 1


def test_bypass_was_denied_and_still_ran(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, report = observe("bypass", tmp_path, monkeypatch)
    assert code == 1
    assert violations(report) == [("bypass", "execute_trade")]
    (row,) = report["guards"]
    assert row["counts"] == {"BYPASS": 1}


def test_untested_path_has_no_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, report = observe("untested", tmp_path, monkeypatch)
    assert code == 1
    assert violations(report) == [("fail_on_untested_path", "confirm_price")]
    (row,) = report["paths"]
    assert (row["path"], row["status"]) == (["trade-desk", "trade-agent"], "UNTESTED")


@pytest.mark.parametrize("name", ["mismatch", "unguarded", "untested"])
def test_the_observe_waivers_make_exit_zero(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, lines, report = observe(name, tmp_path, monkeypatch, "--waivers", "waivers-observe.yaml")
    assert code == 0, lines
    assert report["gate"]["violations"] == []
    assert len(report["gate"]["waived"]) == 1
    assert "Gate: PASS (exit 0)" in lines


def test_the_observe_waivers_do_not_accept_a_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, _, report = observe("bypass", tmp_path, monkeypatch, "--waivers", "waivers-observe.yaml")
    assert code == 1
    assert violations(report) == [("bypass", "execute_trade")]


def test_summary_of_the_bypass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, lines, _ = observe("bypass", tmp_path, monkeypatch, "--summary")
    assert code == 1
    assert "Blocking (1):" in lines
    assert "  - BYPASS: trade-agent / execute_trade" in lines


def test_expired_observe_waivers_stop_working(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(waivers, "today", lambda: date(2027, 2, 1))
    code, lines, report = observe(
        "untested", tmp_path, monkeypatch, "--waivers", "waivers-observe.yaml"
    )
    assert code == 1, lines
    assert violations(report) == [("fail_on_untested_path", "confirm_price")]
    assert any(row["status"] == "expired" for row in report["waivers"])


@pytest.mark.parametrize("extra", [[], ["--summary"]])
def test_coverage_with_the_observe_waivers_is_quiet(
    extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(EXAMPLE)
    result = runner.invoke(
        app,
        ["coverage", "--waivers", "waivers-observe.yaml", "--output-dir", str(tmp_path), *extra],
    )
    assert result.exit_code in (0, 1), result.output
    lines = result.output.splitlines()
    assert "Waivers needing attention:" not in lines
    assert not any(line.startswith("Waivers needing attention (") for line in lines)
    assert "  3 waiver(s) are checked only by lockwalk observe" in lines
    assert not any("matches nothing" in line for line in lines)
