"""lockwalk test on examples/multi_agent, asking the plain-Python demo policy.

Discovery imports app.py in a worker subprocess, which is slow. reuse_discovery keeps each
worker result for the whole module, and the default run is shared by the tests that only
read its output. Nothing calls a model or the network.
"""

import json
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from lockwalk_iam_expectations import (
    BROKEN_CASES,
    CASES,
    DENY_ONLY_CASES,
    ESCALATIONS,
    case_statuses,
    escalations,
)
from typer.testing import CliRunner

from lockwalk import cli, testing
from lockwalk.models import CoverageReport, Verdict
from lockwalk.policy.base import Decision, Query
from lockwalk.spec_loader import load_spec
from lockwalk.testing import run_test

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "multi_agent"
CONFIG = EXAMPLE / ".lockwalk.toml"
DEMO = REPO_ROOT / "tests" / "iam_demo" / "demo_decide.py"
DECIDE = f"python:{DEMO}:decide"
DECIDE_BROKEN = f"python:{DEMO}:decide_broken"

runner = CliRunner()


@dataclass(frozen=True)
class Run:
    code: int
    stdout: str
    report: dict | None


def run_cli(output: Path, *args: str | Path) -> Run:
    """Run `lockwalk test` against the example's config, writing the report under output."""
    arguments = ["test", "--config", str(CONFIG), "--output-dir", str(output), *map(str, args)]
    result = runner.invoke(cli.app, arguments)
    path = output / "coverage.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return Run(result.exit_code, result.stdout, report)


@pytest.fixture(scope="module")
def default_run(tmp_path_factory: pytest.TempPathFactory) -> Run:
    """The default spec against the correct demo policy, run once."""
    return run_cli(tmp_path_factory.mktemp("default"), "--policy", DECIDE)


def test_the_default_spec_finds_the_escalation(default_run):
    assert default_run.code == 1, default_run.stdout
    report = default_run.report
    assert report is not None
    assert case_statuses(report) == CASES
    assert escalations(report) == ESCALATIONS
    assert report["controls"], "no positive controls were reported"
    assert all(control["allowed"] for control in report["controls"])
    assert report["mode"] == "test"
    assert report["schema_version"] == "5"
    assert report["policy_adapter"].startswith("python:")


def test_the_default_spec_shows_the_cases_and_escalation_blocks(default_run):
    lines = default_run.stdout.splitlines()
    assert "Cases:" in lines
    assert any(line.startswith("Escalation checks:") for line in lines)
    assert any(line.startswith("Gate: FAIL") for line in lines)


def test_a_broken_policy_fails_the_deny_case(tmp_path):
    result = run_cli(tmp_path, "--policy", DECIDE_BROKEN)
    assert result.code == 1, result.stdout
    assert result.report is not None
    assert case_statuses(result.report) == BROKEN_CASES


def test_deny_only_cases_are_inconclusive_without_a_positive_control(tmp_path):
    result = run_cli(tmp_path, "--policy", DECIDE, "--spec", EXAMPLE / "deny-only-spec.yaml")
    assert result.code == 1, result.stdout
    assert result.report is not None
    assert case_statuses(result.report) == DENY_ONLY_CASES
    assert "Positive controls missing:" in result.stdout
    assert "portfolio:read on portfolio" in result.stdout


def test_ask_every_hop_asks_about_each_hop(tmp_path, monkeypatch):
    config = tmp_path / ".lockwalk.toml"
    config.write_text(
        textwrap.dedent(
            f"""            [lockwalk]
            registry = "{(EXAMPLE / "registry.yaml").as_posix()}"
            spec = "{(EXAMPLE / "security-spec.yaml").as_posix()}"
            fixtures = "{(EXAMPLE / "fixtures.yaml").as_posix()}"

            [policy]
            adapter = "python"
            target = "{DEMO.as_posix()}:decide"
            ask_every_hop = true
            """
        ),
        encoding="utf-8",
    )
    # Inventory targets given directly resolve against the current directory.
    monkeypatch.chdir(EXAMPLE)
    report = run_test(config, python=["app:OPENAI_ENTRY_AGENTS", "app:pricing_agent"])
    as_json = report.model_dump(mode="json")
    assert case_statuses(as_json) == CASES
    for case in as_json["cases"]:
        assert len(case["decision"]["hops"]) == len(case["path"]) + 1, case["id"]


def test_without_an_iam_to_ask_the_run_exits_2(tmp_path):
    result = runner.invoke(
        cli.app,
        [
            "test",
            "--registry",
            str(EXAMPLE / "registry.yaml"),
            "--spec",
            str(EXAMPLE / "security-spec.yaml"),
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 2, result.stdout
    assert "test needs an IAM to ask: give --policy, or add [policy] to .lockwalk.toml" in (
        result.stdout
    )


def test_a_decide_that_raises_makes_only_its_case_an_error(tmp_path):
    decide = tmp_path / "raising_decide.py"
    decide.write_text(
        DEMO.read_text(encoding="utf-8")
        + textwrap.dedent(
            """

            _good = decide


            def decide(subject, action, resource, context):
                if resource.get("id") == "p-bob":  # only CASE-002 asks about Bob's portfolio
                    raise RuntimeError("boom")
                return _good(subject, action, resource, context)
            """
        ),
        encoding="utf-8",
    )
    result = run_cli(tmp_path / "out", "--policy", f"python:{decide}:decide")
    assert result.code == 2, result.stdout
    assert result.report is not None
    assert case_statuses(result.report) == {**CASES, "CASE-002": "ERROR"}
    assert result.report["exit_code"] == 2


def test_a_failed_run_leaves_no_stale_report(tmp_path):
    stale = tmp_path / "coverage.json"
    stale.write_text("{}", encoding="utf-8")
    result = run_cli(tmp_path, "--policy", "nonsense")
    assert result.code == 2, result.stdout
    assert not stale.exists()


def test_coverage_still_writes_a_static_report(tmp_path):
    result = runner.invoke(
        cli.app, ["coverage", "--config", str(CONFIG), "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 1, result.stdout
    report = json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8"))
    assert report["mode"] == "static"
    assert report["controls"] == []
    assert report["escalations"] == []


def test_the_python_api_gives_the_same_statuses_as_the_cli(default_run):
    report = run_test(CONFIG, policy=DECIDE)
    assert isinstance(report, CoverageReport)
    assert report.mode == "test"
    as_json = report.model_dump(mode="json")
    assert case_statuses(as_json) == CASES
    assert escalations(as_json) == ESCALATIONS
    assert report.exit_code == 1


class FakeAdapter:
    """Allows everything, remembers close(), and has a note of its own."""

    label = "fake"
    batch_size = 100

    def __init__(self) -> None:
        self.closed = False

    def decide(self, queries: Sequence[Query]) -> list[Decision]:
        return [Decision(verdict=Verdict.ALLOW) for _ in queries]

    def notes(self) -> tuple[str, ...]:
        return ("the fake PDP has no batch endpoint",)

    def close(self) -> None:
        self.closed = True


def test_adapter_notes_reach_the_report_and_the_adapter_is_closed(monkeypatch):
    adapter = FakeAdapter()
    monkeypatch.setattr(testing, "make_adapter", lambda *_: adapter)
    report = run_test(CONFIG, policy=DECIDE)
    assert "the fake PDP has no batch endpoint" in report.warnings
    assert adapter.closed


def test_the_adapter_is_closed_when_a_later_step_crashes(monkeypatch):
    adapter = FakeAdapter()
    monkeypatch.setattr(testing, "make_adapter", lambda *_: adapter)

    def crash(*_args, **_kwargs):
        raise RuntimeError("crash after the adapter was built")

    monkeypatch.setattr(testing, "build_queries", crash)
    with pytest.raises(RuntimeError):
        run_test(CONFIG, policy=DECIDE)
    assert adapter.closed


def test_query_warnings_come_before_adapter_notes(tmp_path, monkeypatch):
    data = yaml.safe_load((EXAMPLE / "fixtures.yaml").read_text(encoding="utf-8"))
    del data["subjects"]["bob"]
    del data["resources"]["alice-order"]
    del data["probes"]["subjects"]["trader"]  # a probe must point at a fixture that exists
    fixtures = tmp_path / "fixtures.yaml"
    fixtures.write_text(yaml.safe_dump(data), encoding="utf-8")
    monkeypatch.setattr(testing, "make_adapter", lambda *_: FakeAdapter())
    result = run_cli(tmp_path / "out", "--policy", DECIDE, "--fixtures", fixtures)
    assert result.report is not None, result.stdout
    warnings = result.report["warnings"]
    note = "the fake PDP has no batch endpoint"
    assert note in warnings
    missing = [w for w in warnings if "bob" in w or "alice-order" in w]
    assert any("bob" in w for w in missing), warnings
    assert any("alice-order" in w for w in missing), warnings
    assert all(warnings.index(w) < warnings.index(note) for w in missing)
    for line in (note, *missing):
        assert f"  - {line}" in result.stdout


def test_a_run_that_fails_after_the_settings_leaves_no_stale_report(tmp_path):
    stale = tmp_path / "coverage.json"
    stale.write_text("{}", encoding="utf-8")
    result = run_cli(tmp_path, "--policy", DECIDE, "--fixtures", tmp_path / "missing.yaml")
    assert result.code == 2, result.stdout
    assert not stale.exists()


def test_the_deny_only_spec_stays_in_sync_with_the_main_spec():
    main = {case.id: case for case in load_spec(EXAMPLE / "security-spec.yaml").cases}
    deny_only = load_spec(EXAMPLE / "deny-only-spec.yaml").cases
    assert deny_only
    for case in deny_only:
        assert case == main[case.id], case.id
