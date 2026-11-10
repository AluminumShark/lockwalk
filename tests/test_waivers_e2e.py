"""Waivers and --summary through the real CLI and the Python API.

Waivers files are written to tmp_path and dated from a patched lockwalk.waivers.today. Only
test_the_shipped_demo_files_load reads the files in examples/multi_agent. reuse_discovery
shares the Python discovery result between the runs of this module. Nothing calls a model
or the network.
"""

import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pytest
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from typer.testing import CliRunner

from lockwalk import cli, waivers
from lockwalk.config import GateConfig
from lockwalk.testing import run_test
from lockwalk.waivers import load_waivers

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI = REPO_ROOT / "examples" / "multi_agent"
CEDAR = REPO_ROOT / "examples" / "iam_cedar"

runner = CliRunner()
TODAY = date(2026, 11, 8)


@dataclass(frozen=True)
class Run:
    code: int
    stdout: str
    report: dict | None
    lines: list[str]


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(waivers, "today", lambda: TODAY)


def waivers_file(tmp_path: Path, entries: list[tuple[str, str, str]], name: str = "w.yaml") -> Path:
    """Write a waivers file from (id, match flow mapping, expires) entries."""
    body = "".join(
        f"  - id: {wid}\n    match: {match}\n    reason: accepted for the test\n"
        f"    owner: alice@example.com\n    expires: {expires}\n"
        for wid, match, expires in entries
    )
    path = tmp_path / name
    path.write_text("schema_version: '1'\nwaivers:\n" + body, encoding="utf-8")
    return path


def invoke(command: str, config: Path, output: Path, *args: str | Path) -> Run:
    result = runner.invoke(
        cli.app, [command, "--config", str(config), "--output-dir", str(output), *map(str, args)]
    )
    path = output / "coverage.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return Run(result.exit_code, result.stdout, report, result.stdout.splitlines())


def coverage(output: Path, *args: str | Path) -> Run:
    return invoke("coverage", MULTI / ".lockwalk.toml", output, *args)


def policy_test(output: Path, *args: str | Path) -> Run:
    return invoke("test", CEDAR / ".lockwalk.toml", output, "--no-harness", *args)


BOTH = [("W-1", "{rule: RULE-001}", "2027-01-31"), ("W-2", "{rule: RULE-002}", "2027-01-31")]


def test_coverage_without_waivers_fails(tmp_path):
    run = coverage(tmp_path / "out")
    assert run.code == 1, run.stdout
    assert run.report is not None
    assert [v["rule_id"] for v in run.report["gate"]["violations"]] == ["RULE-001", "RULE-002"]
    assert run.report["gate"]["waived"] == []


def test_coverage_with_both_rules_waived_passes(tmp_path):
    run = coverage(tmp_path / "out", "--waivers", waivers_file(tmp_path, BOTH))
    assert run.code == 0, run.stdout
    assert "Gate: PASS (exit 0)" in run.lines
    assert sum("[waived: " in line for line in run.lines) == 2
    assert run.report is not None
    assert run.report["gate"]["violations"] == []
    assert sorted(w["waiver_id"] for w in run.report["gate"]["waived"]) == ["W-1", "W-2"]
    marks = {r["id"]: r.get("waived_by") for r in run.report["rules"]}
    assert marks["RULE-001"] == "W-1"
    assert marks["RULE-002"] == "W-2"
    assert [w["status"] for w in run.report["waivers"]] == ["applied", "applied"]


def test_the_same_file_after_its_date_is_expired(tmp_path, monkeypatch):
    path = waivers_file(tmp_path, BOTH)
    monkeypatch.setattr(waivers, "today", lambda: date(2027, 2, 1))
    run = coverage(tmp_path / "out", "--waivers", path)
    assert run.code == 1, run.stdout
    assert run.report is not None
    assert [w["status"] for w in run.report["waivers"]] == ["expired", "expired"]
    assert run.report["gate"]["waived"] == []
    expired = [w for w in run.report["warnings"] if "expired on 2027-01-31" in w]
    assert len(expired) == 2
    assert not any("[waived: " in line for line in run.lines)
    assert "Waivers needing attention:" in run.lines


def assert_structural_error(run: Run, output: Path, path: Path) -> None:
    assert run.code == 2, run.stdout
    assert not (output / "coverage.json").exists()  # the old report was removed
    assert str(path) in run.stdout
    assert "Configuration error" in run.stdout


def write_old_report(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "coverage.json").write_text('{"old": true}', encoding="utf-8")


def test_a_waiver_over_max_waiver_days_is_a_structural_error(tmp_path):
    path = waivers_file(tmp_path, [("W-FAR", "{rule: RULE-001}", "2027-06-01")])
    output = tmp_path / "out"
    write_old_report(output)
    run = coverage(output, "--waivers", path)
    assert_structural_error(run, output, path)
    assert "W-FAR" in run.stdout
    assert "max_waiver_days" in run.stdout


def test_a_bad_waivers_file_fails_before_any_source_is_read(tmp_path, monkeypatch):
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("a source was read")

    monkeypatch.setattr("lockwalk.pipeline.build_inventory", boom)
    path = tmp_path / "w.yaml"
    path.write_text("schema_version: '1'\nwaivers: nope\n", encoding="utf-8")
    output = tmp_path / "out"
    write_old_report(output)
    run = coverage(output, "--waivers", path)
    assert_structural_error(run, output, path)
    assert "AssertionError" not in run.stdout


@pytest.mark.parametrize("content", [None, ""], ids=["missing", "empty"])
def test_a_missing_or_empty_waivers_file_is_a_structural_error(tmp_path, content):
    path = tmp_path / "w.yaml"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    output = tmp_path / "out"
    write_old_report(output)
    run = coverage(output, "--waivers", path)
    assert_structural_error(run, output, path)


def test_the_flag_wins_over_the_waivers_in_the_config_file(tmp_path):
    valid = waivers_file(tmp_path, BOTH, name="valid.yaml")
    expired = waivers_file(tmp_path, [(w, m, "2026-06-30") for w, m, _ in BOTH], "expired.yaml")

    def rel(name: str) -> str:
        return os.path.relpath(MULTI / name, tmp_path).replace(os.sep, "/")

    config = tmp_path / ".lockwalk.toml"
    config.write_text(
        "[lockwalk]\n"
        f'registry = "{rel("registry.yaml")}"\n'
        f'spec = "{rel("security-spec.yaml")}"\n'
        f'waivers = "{expired.name}"\n'
        "[[inventory.python]]\n"
        f'target = "{rel("app.py")}:OPENAI_ENTRY_AGENTS"\n'
        "[[inventory.python]]\n"
        f'target = "{rel("app.py")}:pricing_agent"\n',
        encoding="utf-8",
    )
    by_config = invoke("coverage", config, tmp_path / "a")
    assert by_config.code == 1, by_config.stdout
    assert by_config.report is not None
    assert [w["status"] for w in by_config.report["waivers"]] == ["expired", "expired"]
    by_flag = invoke("coverage", config, tmp_path / "b", "--waivers", valid)
    assert by_flag.code == 0, by_flag.stdout


def test_test_mode_waives_case_005(tmp_path):
    plain = policy_test(tmp_path / "plain")
    assert plain.code == 1, plain.stdout
    path = waivers_file(tmp_path, [("W-C5", "{case: CASE-005}", "2027-01-31")])
    run = policy_test(tmp_path / "waived", "--waivers", path)
    assert run.report is not None
    case = next(c for c in run.report["cases"] if c["id"] == "CASE-005")
    assert case["status"] == "FAIL_POLICY"
    assert case["waived_by"] == "W-C5"
    waived = run.report["gate"]["waived"]
    assert [
        (w["waiver_id"], w["violation"]["rule"], w["violation"]["case_id"]) for w in waived
    ] == [("W-C5", "case", "CASE-005")]
    assert not any(v["rule"] == "case" for v in run.report["gate"]["violations"])


def test_a_waiver_on_an_error_case_is_not_allowed(tmp_path):
    bridge = tmp_path / "bad_bridge.py"
    bridge.write_text(
        "def decide(subject, action, resource, context):\n    raise RuntimeError('broken')\n",
        encoding="utf-8",
    )
    path = waivers_file(tmp_path, [("W-ERR", "{case: CASE-005}", "2027-01-31")])
    run = policy_test(tmp_path / "out", "--policy", f"python:{bridge}:decide", "--waivers", path)
    assert run.code == 2, run.stdout
    assert run.report is not None
    case = next(c for c in run.report["cases"] if c["id"] == "CASE-005")
    assert case["status"] == "ERROR"
    assert not case.get("waived_by")
    assert run.report["waivers"][0]["status"] == "not_allowed"
    assert any("W-ERR" in w and "ERROR" in w for w in run.report["warnings"])


def test_summary_is_short_and_leaves_coverage_json_unchanged(tmp_path):
    full = coverage(tmp_path / "full")
    short = coverage(tmp_path / "short", "--summary")
    assert short.code == full.code == 1
    assert len(short.lines) < len(full.lines) / 2
    assert "Blocking (2):" in short.lines
    assert "Agent graph (entry agents: supervisor, trade-desk):" not in short.lines
    assert full.report is not None and short.report is not None
    # The timestamp differs between runs; everything else must be identical.
    for report in (full.report, short.report):
        report.pop("generated_at", None)
    assert full.report == short.report


def test_summary_shows_a_shadowed_waiver_once(tmp_path):
    path = waivers_file(tmp_path, [BOTH[0], ("W-DUP", "{rule: RULE-001}", "2027-01-31"), BOTH[1]])
    run = coverage(tmp_path / "out", "--waivers", path, "--summary")
    assert run.code == 0, run.stdout
    assert sum("W-DUP" in line for line in run.lines) == 1
    assert any("W-DUP adds nothing: its findings are already waived by W-1" in x for x in run.lines)


def test_python_api_returns_the_waived_report(tmp_path):
    path = waivers_file(tmp_path, [("W-C5", "{case: CASE-005}", "2027-01-31")])
    config = CEDAR / ".lockwalk.toml"
    plain = run_test(config, no_harness=True)
    waived = run_test(config, waivers=str(path), no_harness=True)
    assert plain.gate.waived == ()
    assert [w.waiver_id for w in waived.gate.waived] == ["W-C5"]
    assert waived.exit_code == 1
    assert len(waived.gate.violations) == len(plain.gate.violations) - 1
    assert next(c for c in waived.cases if c.id == "CASE-005").waived_by == "W-C5"


def test_the_shipped_demo_files_load(monkeypatch):
    monkeypatch.setattr(waivers, "today", lambda: date(2026, 12, 1))
    for name in ("waivers.yaml", "waivers-expired.yaml"):
        loaded = load_waivers(MULTI / name, GateConfig(), waivers.today())
        assert sorted(str(w.match.rule) for w in loaded.waivers) == ["RULE-001", "RULE-002"]
