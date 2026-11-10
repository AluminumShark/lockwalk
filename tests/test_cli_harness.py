"""The command line for door tests: --no-harness, and coverage never starts a worker."""

import json
from pathlib import Path

import pytest
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from typer.testing import CliRunner

from lockwalk import cli
from lockwalk.harness import runner as harness_runner

APPS = Path(__file__).resolve().parent / "harness_apps"
runner = CliRunner()


@pytest.fixture
def no_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any attempt to build a HarnessRunner fails the test."""

    def refuse(*args: object, **kwargs: object) -> None:
        pytest.fail("a harness worker must not be started")

    monkeypatch.setattr(harness_runner.HarnessRunner, "__init__", refuse)
    monkeypatch.chdir(APPS)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")


def test_test_no_harness_asks_only_the_iam(no_worker, tmp_path):
    # desk_raises.toml has a [harness] whose hooks file raises: with --no-harness it is unused.
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app,
        ["test", "--config", "desk_raises.toml", "--no-harness", "--output-dir", str(out)],
    )
    assert result.exit_code == 0, result.stdout
    assert "door (" not in result.stdout
    assert "--no-harness: the door tests in [harness] of desk_raises.toml are skipped." in (
        result.stdout.replace("\n", " ")
    )
    report = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    assert all(case["door"] is None for case in report["cases"])
    assert report["identity_checks"] == []
    assert report["door_controls"] == []


def test_coverage_ignores_harness_and_never_starts_a_worker(no_worker, tmp_path):
    out = tmp_path / "out"
    result = runner.invoke(
        cli.app, ["coverage", "--config", "desk_raises.toml", "--output-dir", str(out)]
    )
    assert result.exit_code in (0, 1), result.stdout
    assert "door (" not in result.stdout
    assert (out / "coverage.json").exists()


def test_the_option_is_documented():
    result = runner.invoke(cli.app, ["test", "--help"])
    assert result.exit_code == 0
    assert "--no-harness" in result.stdout
    coverage_help = runner.invoke(cli.app, ["coverage", "--help"])
    assert "--no-harness" not in coverage_help.stdout
