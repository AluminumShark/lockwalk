"""lockwalk test on examples/iam_cedar: Cedar must match the plain-Python reference policy.

Discovery imports examples/multi_agent/app.py in a worker subprocess; reuse_discovery shares
its result between the three runs. Nothing calls a model or the network.
"""

import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
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

from lockwalk import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "iam_cedar"
CONFIG = EXAMPLE / ".lockwalk.toml"

runner = CliRunner()


@dataclass(frozen=True)
class Run:
    code: int
    stdout: str
    report: dict | None


def run_cli(output: Path, *args: str | Path) -> Run:
    # --no-harness: these are the expectations for the IAM only. The door tests of the
    # same example are in test_iam_cedar_door.py.
    arguments = [
        "test",
        "--config",
        str(CONFIG),
        "--no-harness",
        "--output-dir",
        str(output),
        *map(str, args),
    ]
    result = runner.invoke(cli.app, arguments)
    path = output / "coverage.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return Run(result.exit_code, result.stdout, report)


@pytest.fixture(scope="module")
def default_run(tmp_path_factory: pytest.TempPathFactory) -> Run:
    return run_cli(tmp_path_factory.mktemp("default"))


@pytest.fixture(scope="module")
def broken_run(tmp_path_factory: pytest.TempPathFactory) -> Run:
    policy = f"python:{EXAMPLE / 'iam_bridge.py'}:decide_broken"
    return run_cli(tmp_path_factory.mktemp("broken"), "--policy", policy)


@pytest.fixture(scope="module")
def deny_only_run(tmp_path_factory: pytest.TempPathFactory) -> Run:
    spec = REPO_ROOT / "examples" / "multi_agent" / "deny-only-spec.yaml"
    return run_cli(tmp_path_factory.mktemp("deny_only"), "--spec", spec)


def test_cedar_matches_the_reference_on_cases_and_escalations(default_run):
    assert default_run.code == 1, default_run.stdout
    report = default_run.report
    assert report is not None
    assert case_statuses(report) == CASES
    assert escalations(report) == ESCALATIONS
    assert all(control["allowed"] for control in report["controls"])
    assert report["policy_adapter"] == "python:iam_bridge.py:decide"


def test_a_broken_cedar_policy_fails_the_deny_case(broken_run):
    assert broken_run.code == 1, broken_run.stdout
    assert broken_run.report is not None
    assert case_statuses(broken_run.report) == BROKEN_CASES


def test_deny_only_cases_are_inconclusive_under_cedar(deny_only_run):
    assert deny_only_run.code == 1, deny_only_run.stdout
    assert deny_only_run.report is not None
    assert case_statuses(deny_only_run.report) == DENY_ONLY_CASES


def _load_bridge():
    spec = importlib.util.spec_from_file_location("iam_cedar_bridge", EXAMPLE / "iam_bridge.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bridge = _load_bridge()


def _user(user_id: str, roles: list[str] | None = None) -> dict:
    properties = {} if roles is None else {"roles": roles}
    return {"type": "user", "id": user_id, "properties": properties}


def test_a_non_ascii_id_is_judged_not_silently_denied():
    owner = "".join(map(chr, (0x738B, 0x5C0F, 0x660E)))  # a non-ASCII id
    portfolio = {"type": "portfolio", "id": "p-1", "properties": {"owner": owner}}
    action = {"name": "portfolio:read"}
    assert bridge.decide(_user(owner, ["analyst"]), action, portfolio, {}) is True
    assert bridge.decide(_user("bob", ["analyst"]), action, portfolio, {}) is False


def test_a_user_without_roles_is_denied_not_an_error():
    symbol = {"type": "stock_symbol", "id": "2330.TW"}
    assert bridge.decide(_user("alice"), {"name": "market:read"}, symbol, {}) is False


def test_an_unmapped_type_raises():
    thing = {"type": "spaceship", "id": "s-1"}
    with pytest.raises(ValueError, match="no Cedar type for 'spaceship'"):
        bridge.decide(_user("alice", ["analyst"]), {"name": "market:read"}, thing, {})


def test_a_cedar_evaluation_error_raises(monkeypatch):
    broken = bridge.cedarpy.PolicySet.from_str(
        "permit (principal, action, resource) when { resource.missing == 1 };"
    )
    monkeypatch.setattr(bridge, "_policy_set", lambda policy_file: broken)
    symbol = {"type": "stock_symbol", "id": "2330.TW"}
    with pytest.raises(ValueError, match=r"^cedar: "):
        bridge.decide(_user("alice", ["analyst"]), {"name": "market:read"}, symbol, {})
