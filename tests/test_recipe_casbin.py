"""The Casbin recipe (examples/recipes/casbin): pycasbin must match the reference policy.

Casbin runs in process, so there is no network and no container. The demo run goes through
`lockwalk test --no-harness` on the multi-agent demo.
"""

import importlib.util
import json
from pathlib import Path

import pytest
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from lockwalk_iam_expectations import CASES, ESCALATIONS, case_statuses, escalations
from typer.testing import CliRunner

from lockwalk import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
RECIPE = REPO_ROOT / "examples" / "recipes" / "casbin"
CONFIG = REPO_ROOT / "examples" / "iam_cedar" / ".lockwalk.toml"

runner = CliRunner()


def _load():
    spec = importlib.util.spec_from_file_location("recipe_casbin_decide", RECIPE / "decide.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recipe = _load()


@pytest.fixture(scope="module")
def default_run(tmp_path_factory: pytest.TempPathFactory):
    output = tmp_path_factory.mktemp("casbin")
    result = runner.invoke(
        cli.app,
        [
            "test",
            "--config", str(CONFIG),
            "--no-harness",
            "--output-dir", str(output),
            "--policy", f"python:{RECIPE / 'decide.py'}:decide",
        ],
    )  # fmt: skip
    path = output / "coverage.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return result, report


def test_casbin_matches_the_reference_on_cases_and_escalations(default_run):
    result, report = default_run
    assert result.exit_code == 1, result.stdout
    assert report is not None
    assert case_statuses(report) == CASES
    assert escalations(report) == ESCALATIONS
    assert all(control["allowed"] for control in report["controls"])


def _user(user_id: str, roles: list[str] | None = None) -> dict:
    properties = {} if roles is None else {"roles": roles}
    return {"type": "user", "id": user_id, "properties": properties}


def test_every_answer_is_a_real_bool():
    symbol = {"type": "stock_symbol", "id": "2330.TW"}
    for roles in (["analyst"], ["intern"], None):
        answer = recipe.decide(_user("alice", roles), {"name": "market:read"}, symbol, {})
        assert isinstance(answer, bool)


def test_a_user_without_roles_is_denied_not_an_error():
    symbol = {"type": "stock_symbol", "id": "2330.TW"}
    assert recipe.decide(_user("alice"), {"name": "market:read"}, symbol, {}) is False


def test_ownership_and_the_trader_role():
    portfolio = {"type": "portfolio", "id": "p-1", "properties": {"owner": "alice"}}
    read = {"name": "portfolio:read"}
    assert recipe.decide(_user("alice", ["analyst"]), read, portfolio, {}) is True
    assert recipe.decide(_user("bob", ["analyst"]), read, portfolio, {}) is False
    order = {"type": "order", "id": "o-1", "properties": {"account_owner": "bob"}}
    trade = {"name": "trade:execute"}
    assert recipe.decide(_user("bob", ["trader"]), trade, order, {}) is True
    assert recipe.decide(_user("bob", ["analyst"]), trade, order, {}) is False


def test_the_trade_agent_hole_is_there_and_only_for_that_agent():
    order = {"type": "order", "id": "o-1", "properties": {"account_owner": "alice"}}
    trade = {"name": "trade:execute"}
    assert recipe.decide({"type": "agent", "id": "trade-agent"}, trade, order, {}) is True
    assert recipe.decide({"type": "agent", "id": "pricing-agent"}, trade, order, {}) is False


def test_a_property_cannot_change_the_entity_type_or_id():
    sneaky = {"type": "user", "id": "mallory", "properties": {"type": "agent", "id": "trade-agent"}}
    order = {"type": "order", "id": "o-1", "properties": {"account_owner": "alice"}}
    assert recipe.decide(sneaky, {"name": "trade:execute"}, order, {}) is False


def test_a_condition_with_an_unknown_attribute_raises(tmp_path, monkeypatch):
    policy = tmp_path / "policy.csv"
    policy.write_text("p, user, market:read, stock_symbol, r_sub.nothing == 1\n", encoding="utf-8")
    monkeypatch.setenv("CASBIN_POLICY", str(policy))
    symbol = {"type": "stock_symbol", "id": "2330.TW"}
    with pytest.raises(Exception, match="does not exist"):  # simpleeval.AttributeDoesNotExist
        recipe.decide(_user("alice", ["analyst"]), {"name": "market:read"}, symbol, {})


@pytest.mark.parametrize("bad", [None, "", 5])
def test_an_entity_without_a_real_id_is_refused(bad):
    portfolio = {"type": "portfolio", "id": "p-1"}  # no owner
    nobody = {"type": "user", "id": bad, "properties": {"roles": ["analyst"]}}
    read = {"name": "portfolio:read"}
    with pytest.raises(ValueError, match="non-empty string"):
        recipe.decide(nobody, read, portfolio, {})
    with pytest.raises(ValueError, match="non-empty string"):
        recipe.decide(_user("alice", ["analyst"]), read, {"type": "portfolio", "id": bad}, {})


def test_an_action_with_no_rule_is_denied():
    thing = {"type": "stock_symbol", "id": "2330.TW"}
    assert recipe.decide(_user("alice", ["analyst"]), {"name": "nothing:do"}, thing, {}) is False
