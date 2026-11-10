"""lockwalk diff on reports written by real `coverage` and `test` runs.

Every report comes from the real commands through CliRunner, and every output is under
tmp_path. Discovery of the Cedar example is shared through reuse_discovery.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from lockwalk_iam_expectations import BROKEN_CASES, CASES, case_statuses
from typer.testing import CliRunner

from lockwalk import cli
from lockwalk.diff import NO_CHANGES
from lockwalk.diff_markdown import MARKER

REPO_ROOT = Path(__file__).resolve().parents[1]
FINANCE = REPO_ROOT / "examples" / "finance_agent"
EXAMPLE = REPO_ROOT / "examples" / "iam_cedar"
CEDAR_CONFIG = EXAMPLE / ".lockwalk.toml"
BROKEN_POLICY = f"python:{EXAMPLE / 'iam_bridge.py'}:decide_broken"

runner = CliRunner()


@dataclass(frozen=True)
class Run:
    code: int
    stdout: str
    path: Path


def run_coverage(output: Path, *args: str | Path) -> Run:
    result = runner.invoke(cli.app, ["coverage", "--output-dir", str(output), *map(str, args)])
    return Run(result.exit_code, result.stdout, output / "coverage.json")


def run_cedar_test(output: Path, *args: str | Path) -> Run:
    arguments = [
        "test",
        "--config",
        str(CEDAR_CONFIG),
        "--no-harness",
        "--output-dir",
        str(output),
        *map(str, args),
    ]
    result = runner.invoke(cli.app, arguments)
    return Run(result.exit_code, result.stdout, output / "coverage.json")


def diff(*args: str | Path) -> tuple[int, str]:
    result = runner.invoke(cli.app, ["diff", *map(str, args)])
    return result.exit_code, result.stdout


def diff_json(base: Path, head: Path) -> dict:
    code, out = diff("--base", base, "--head", head, "--format", "json")
    assert code == 0, out
    return json.loads(out)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class RunPair:
    base: Run
    head: Run


@pytest.fixture(scope="module")
def finance(tmp_path_factory: pytest.TempPathFactory) -> RunPair:
    root = tmp_path_factory.mktemp("finance")
    registry = yaml.safe_load((FINANCE / "registry.yaml").read_text(encoding="utf-8"))
    registry["tools"].append(
        {
            "id": "delete_portfolio",
            "action": "portfolio:delete",
            "risk": "critical",
            "resource_type": "portfolio",
            "supported_agents": ["finance-agent"],
        }
    )
    head_registry = root / "registry-head.yaml"
    head_registry.write_text(yaml.safe_dump(registry), encoding="utf-8")
    config = root / ".lockwalk.toml"
    config.write_text(
        f"[lockwalk]\nregistry = '{FINANCE / 'registry.yaml'}'\n"
        f"spec = '{FINANCE / 'security-spec.yaml'}'\n",
        encoding="utf-8",
    )
    base = run_coverage(root / "base", "--config", config)
    head = run_coverage(root / "head", "--config", config, "--registry", head_registry)
    return RunPair(base, head)


@pytest.fixture(scope="module")
def cedar(tmp_path_factory: pytest.TempPathFactory) -> RunPair:
    root = tmp_path_factory.mktemp("cedar")
    base = run_cedar_test(root / "base")
    head = run_cedar_test(root / "head", "--policy", BROKEN_POLICY)
    return RunPair(base, head)


def test_the_finance_runs_set_up_the_scenario(finance):
    assert finance.base.code == 0, finance.base.stdout
    assert finance.head.code == 1, finance.head.stdout


def test_new_tool_without_spec_in_text(finance):
    code, out = diff("--base", finance.base.path, "--head", finance.head.path)
    assert code == 0, out
    assert "New tools without spec (1):" in out
    assert "delete_portfolio (risk=critical)" in out
    assert "head gate: FAIL" in out


def test_new_tool_without_spec_in_json(finance):
    document = diff_json(finance.base.path, finance.head.path)
    assert document["head_status"] == "FAIL"
    assert [t["id"] for t in document["tools_added_without_spec"]] == ["delete_portfolio"]
    new = [v for v in document["new_violations"] if v["tool"] == "delete_portfolio"]
    assert "fail_on_unspecified_risk" in [v["rule"] for v in new]
    assert document["no_longer_reported"] == []


def test_new_tool_without_spec_in_markdown(finance):
    code, out = diff(
        "--base", finance.base.path, "--head", finance.head.path, "--format", "markdown"
    )
    assert code == 0, out
    assert out.startswith(MARKER)
    assert "`delete_portfolio` (risk: `critical`)" in out


def test_swapping_base_and_head_fixes_the_violation(finance):
    document = diff_json(finance.head.path, finance.base.path)
    assert document["head_status"] == "PASS"
    fixed = [v for v in document["no_longer_reported"] if v["tool"] == "delete_portfolio"]
    assert "fail_on_unspecified_risk" in [v["rule"] for v in fixed]
    assert document["new_violations"] == []
    assert [t["id"] for t in document["tools_removed"]] == ["delete_portfolio"]


def test_a_broken_deny_policy_run_sets_up_the_scenario(cedar):
    assert cedar.base.code == 1, cedar.base.stdout
    assert case_statuses(read(cedar.base.path)) == CASES
    assert cedar.head.code == 1, cedar.head.stdout
    assert case_statuses(read(cedar.head.path)) == BROKEN_CASES


def _moved_to_fail() -> dict[str, tuple[str, str]]:
    return {
        case: (CASES[case], status)
        for case, status in BROKEN_CASES.items()
        if CASES[case] == "PASS" and status == "FAIL_POLICY"
    }


def test_broken_policy_cases_get_worse_in_json(cedar):
    moved = _moved_to_fail()
    assert moved
    document = diff_json(cedar.base.path, cedar.head.path)
    worse = {c["id"]: (c["base"], c["head"]) for c in document["cases_worse"]}
    assert worse == moved
    assert document["cases_better"] == []
    assert document["warnings"] == []


def test_broken_policy_cases_in_text_and_markdown(cedar):
    moved = _moved_to_fail()
    code, text = diff("--base", cedar.base.path, "--head", cedar.head.path)
    assert code == 0, text
    assert f"Cases that got worse ({len(moved)}):" in text
    assert "PASS -> FAIL_POLICY" in text
    code, markdown = diff(
        "--base", cedar.base.path, "--head", cedar.head.path, "--format", "markdown"
    )
    assert code == 0, markdown
    assert markdown.startswith(MARKER)
    for case in moved:
        assert f"`{case}`" in markdown
    assert "`PASS` -> `FAIL_POLICY`" in markdown


def test_reports_from_different_commands_are_not_compared(tmp_path, cedar):
    base = run_coverage(tmp_path / "base", "--config", CEDAR_CONFIG)
    assert base.path.exists(), base.stdout
    assert read(base.path)["mode"] != read(cedar.head.path)["mode"]
    code, text = diff("--base", base.path, "--head", cedar.head.path)
    assert code == 0, text
    assert "different commands" in text
    assert "Cases that got" not in text
    assert "Other case changes" not in text
    document = diff_json(base.path, cedar.head.path)
    for name in ("cases_worse", "cases_better", "cases_other"):
        assert document[name] == []


def test_a_head_with_errors_is_never_reported_as_plain_no_changes(tmp_path, cedar):
    # A policy file that does not exist: every case errors, and a report is still written.
    missing = tmp_path / "no_such_policy.py"
    head = run_cedar_test(tmp_path / "head", "--policy", f"python:{missing}:decide")
    assert head.code == 2, head.stdout
    errors = read(head.path)["errors"]
    assert errors
    secrets = [str(missing), "could not start", errors[0]]
    base = cedar.base.path

    document = diff_json(base, head.path)
    assert document["head_status"] == "ERROR"
    assert document["incomplete"] is True
    outputs = {
        "json": json.dumps(document),
        "text": diff("--base", base, "--head", head.path)[1],
        "markdown": diff("--base", base, "--head", head.path, "--format", "markdown")[1],
    }
    for name, out in outputs.items():
        for secret in secrets:
            assert secret not in out, name
    assert "ERROR" in outputs["text"]
    assert "ERROR" in outputs["markdown"]
    for name in ("text", "markdown"):
        assert NO_CHANGES not in outputs[name]
    assert document["no_longer_reported"] == []
    assert document["head_violations"] > 0
    assert outputs["text"].splitlines()[0] == "lockwalk diff - head gate: ERROR - see warnings"
    for name in ("text", "markdown"):
        assert "No longer reported" not in outputs[name], name
    assert "head report has errors" in outputs["text"]
    assert "head report has errors" in outputs["markdown"]


def test_no_base_shows_the_warning(finance):
    code, out = diff("--head", finance.head.path)
    assert code == 0, out
    assert "no base report was given" in out
    document = json.loads(diff("--head", finance.head.path, "--format", "json")[1])
    assert document["base_given"] is False
    assert document["head_status"] == "FAIL"


def test_identical_reports_have_no_changes(finance):
    path = finance.head.path
    code, out = diff("--base", path, "--head", path)
    assert code == 0, out
    assert NO_CHANGES in out
    code, markdown = diff("--base", path, "--head", path, "--format", "markdown")
    assert code == 0, markdown
    assert NO_CHANGES in markdown


@pytest.mark.parametrize("output_format", ["text", "markdown"])
def test_the_output_is_deterministic(cedar, output_format):
    arguments = ("--base", cedar.base.path, "--head", cedar.head.path, "--format", output_format)
    first = diff(*arguments)
    second = diff(*arguments)
    assert first[0] == 0
    assert first == second
