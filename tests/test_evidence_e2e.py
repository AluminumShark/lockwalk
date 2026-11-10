"""lockwalk test writes evidence.jsonl, and lockwalk inspect reads it.

Real runs of the CLI on tests/harness_apps/desk (fake models, counters, no network).
"""

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner, Result

from lockwalk.cli import app
from lockwalk.evidence import read_evidence

APPS = Path(__file__).resolve().parent / "harness_apps"

pytestmark = pytest.mark.filterwarnings("ignore")


def _desk_spec(directory: Path) -> Path:
    """A spec with only CASE-1 and CASE-2, written into the directory."""
    spec = yaml.safe_load((APPS / "desk" / "security-spec.yaml").read_text(encoding="utf-8"))
    spec["cases"] = [case for case in spec["cases"] if case["id"] in ("CASE-1", "CASE-2")]
    path = directory / "spec.yaml"
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    return path


def _invoke(args: list[str], *, bypass: bool = False) -> Result:
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("OPENAI_API_KEY", "sk-test")
        if bypass:
            patch.setenv("DESK_BYPASS", "read_portfolio")
        else:
            patch.delenv("DESK_BYPASS", raising=False)
        patch.chdir(APPS)
        return CliRunner().invoke(app, args)


def _test_args(out: Path, *extra: str) -> list[str]:
    spec = _desk_spec(out)
    return ["test", "--config", "desk.toml", "--spec", str(spec), "--output-dir", str(out), *extra]


def _run_desk(out: Path, bypass: bool) -> None:
    result = _invoke(_test_args(out), bypass=bypass)
    assert result.exit_code in (0, 1), result.output


@pytest.fixture(scope="module")
def bypass_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("evidence")
    _run_desk(out, bypass=True)
    return out


@pytest.fixture(scope="module")
def clean_run(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("evidence-clean")
    _run_desk(out, bypass=False)
    return out


def _report(directory: Path) -> dict:
    return json.loads((directory / "coverage.json").read_text(encoding="utf-8"))


def test_every_ref_points_at_an_event_of_the_same_run(bypass_run: Path) -> None:
    report = _report(bypass_run)
    evidence = read_evidence(bypass_run / "evidence.jsonl")
    assert evidence.header.run == report["run_id"]
    ids = {event.event for event in evidence.events}
    tables = ("cases", "escalations", "identity_checks", "controls", "door_controls")
    for table in tables:
        for row in report[table]:
            assert row["evidence"] is not None
            assert set(row["evidence"]) <= ids, (table, row)
    case_rows = [row for row in report["cases"] if row["status"] != "ERROR"]
    assert all(row["evidence"] for row in case_rows)


def test_no_tool_argument_values_are_kept(bypass_run: Path) -> None:
    evidence = read_evidence(bypass_run / "evidence.jsonl")
    for event in evidence.events:
        if event.type == "harness.job":
            assert "args" not in event.detail
            assert isinstance(event.detail["arg_names"], list)


def test_inspect_shows_the_bypass(bypass_run: Path) -> None:
    failing = "CASE-2"  # the IAM denies it, yet the bypassed side effect ran
    assert {r["id"]: r["status"] for r in _report(bypass_run)["cases"]}[failing] == "FAIL_EXECUTION"
    result = CliRunner().invoke(
        app, ["inspect", "--case", failing, "--output-dir", str(bypass_run)]
    )
    assert result.exit_code == 0, result.output
    assert "side effect of read_portfolio counted" in result.output
    assert "IAM" in result.output and "-> deny" in result.output


def test_inspect_shows_a_passing_case(clean_run: Path) -> None:
    passing = next(row["id"] for row in _report(clean_run)["cases"] if row["status"] == "PASS")
    assert passing == "CASE-1"
    result = CliRunner().invoke(app, ["inspect", "--case", passing, "--output-dir", str(clean_run)])
    assert result.exit_code == 0, result.output
    assert "-> allow" in result.output


def test_coverage_removes_a_stale_evidence_file(bypass_run: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "evidence.jsonl").write_bytes((bypass_run / "evidence.jsonl").read_bytes())
    _invoke(["coverage", "--config", "desk.toml", "--output-dir", str(out)])
    assert not (out / "evidence.jsonl").exists()


def test_a_configuration_error_removes_both_stale_files(tmp_path: Path) -> None:
    (tmp_path / "evidence.jsonl").write_text("stale", encoding="utf-8")
    (tmp_path / "coverage.json").write_text("{}", encoding="utf-8")
    result = _invoke(["test", "--config", "missing.toml", "--output-dir", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert not (tmp_path / "evidence.jsonl").exists()
    assert not (tmp_path / "coverage.json").exists()


def test_no_harness_gives_authz_events_only(tmp_path: Path) -> None:
    result = _invoke(_test_args(tmp_path, "--no-harness"))
    assert result.exit_code in (0, 1), result.output
    evidence = read_evidence(tmp_path / "evidence.jsonl")
    kinds = {event.type for event in evidence.events}
    assert "authz.evaluated" in kinds
    assert not any(kind.startswith(("harness.", "door.", "effect.")) for kind in kinds)
    ids = {event.event for event in evidence.events}
    for row in _report(tmp_path)["cases"]:
        if row["status"] != "ERROR":
            assert row["evidence"]
            assert set(row["evidence"]) <= ids


def _failure_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str, error: Exception
) -> tuple[Result, Result, Path, Path]:
    normal_out = tmp_path / "normal"
    normal_out.mkdir()
    normal = _invoke(_test_args(normal_out), bypass=True)
    broken_out = tmp_path / "broken"
    broken_out.mkdir()
    (broken_out / "evidence.jsonl").write_text("stale", encoding="utf-8")

    def boom(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(target, boom)
    broken = _invoke(_test_args(broken_out), bypass=True)
    return normal, broken, normal_out, broken_out


def _assert_no_leak(result: Result, directory: Path, sentinel: str) -> None:
    assert sentinel not in result.output
    for path in directory.iterdir():
        assert sentinel not in path.read_text(encoding="utf-8"), path


def test_a_build_failure_keeps_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = "SENTINEL-do-not-leak-4242"
    normal, broken, _, out = _failure_run(
        tmp_path, monkeypatch, "lockwalk.testing.build_evidence", RuntimeError(sentinel)
    )
    assert broken.exit_code == normal.exit_code
    assert not (out / "evidence.jsonl").exists()
    warnings = _report(out)["warnings"]
    assert any("evidence file could not be built (RuntimeError)" in w for w in warnings)
    _assert_no_leak(broken, out, sentinel)


def test_a_write_failure_keeps_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = "SENTINEL-do-not-leak-5353"
    normal, broken, _, out = _failure_run(
        tmp_path, monkeypatch, "lockwalk.cli.write_evidence", OSError(sentinel)
    )
    assert broken.exit_code == normal.exit_code
    assert not (out / "evidence.jsonl").exists()
    assert sorted(path.name for path in out.iterdir()) == ["coverage.json", "spec.yaml"]
    report = _report(out)
    assert report["run_id"] is None
    for table in ("cases", "escalations", "identity_checks", "controls", "door_controls"):
        assert all(row["evidence"] is None for row in report[table]), table
    assert any("evidence file could not be written (OSError)" in w for w in report["warnings"])
    _assert_no_leak(broken, out, sentinel)
