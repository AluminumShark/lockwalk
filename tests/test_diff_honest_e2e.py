"""lockwalk diff on reports written by real `coverage` runs of examples/multi_agent.

Each variant is a copy of the example in tmp_path with one real edit (a waivers file, a spec
change, a smaller or stricter gate). Waivers are dated from a patched clock. Every report
comes from the real command through CliRunner.
"""

import json
import shutil
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import pytest
import yaml
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from typer.testing import CliRunner

from lockwalk import cli, waivers

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI = REPO_ROOT / "examples" / "multi_agent"
TODAY = date(2026, 11, 8)
OWNER_LATER = "carol-the-new-owner@example.com"
ACTOR_NEW = "mallory-secret-actor"

runner = CliRunner()


@dataclass(frozen=True)
class Run:
    code: int
    report: Path


@pytest.fixture(scope="module", autouse=True)
def fixed_today() -> Iterator[None]:
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(waivers, "today", lambda: TODAY)
        yield


@pytest.fixture(scope="module")
def make(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., Run]:
    root = tmp_path_factory.mktemp("desk")

    def _make(
        name: str,
        *,
        edit_spec: Callable[[dict], None] | None = None,
        strict: bool = False,
        waivers_file: str | None = None,
        owner: str | None = None,
        expires: str | None = None,
    ) -> Run:
        folder = root / name
        shutil.copytree(MULTI, folder, ignore=shutil.ignore_patterns("__pycache__", "traces"))
        if edit_spec is not None:
            path = folder / "security-spec.yaml"
            spec = yaml.safe_load(path.read_text(encoding="utf-8"))
            edit_spec(spec)
            path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        if strict:
            config = folder / ".lockwalk.toml"
            text = config.read_text(encoding="utf-8")
            old = 'fail_on_unspecified_risk = ["critical", "unknown"]'
            assert old in text
            config.write_text(
                text.replace(old, 'fail_on_unspecified_risk = ["low", "critical", "unknown"]'),
                encoding="utf-8",
            )
        arguments = [
            "coverage",
            "--config",
            str(folder / ".lockwalk.toml"),
            "--output-dir",
            str(folder / "out"),
        ]
        if waivers_file is not None:
            path = folder / waivers_file
            text = path.read_text(encoding="utf-8")
            if owner is not None:
                text = text.replace("alice@example.com", owner)
            if expires is not None:
                text = text.replace("2027-01-31", expires)
            path.write_text(text, encoding="utf-8")
            arguments += ["--waivers", str(path)]
        result = runner.invoke(cli.app, arguments)
        assert (folder / "out" / "coverage.json").exists(), result.stdout
        return Run(result.exit_code, folder / "out" / "coverage.json")

    return _make


def diff(base: Run, head: Run, fmt: str = "text") -> str:
    result = runner.invoke(
        cli.app, ["diff", "--base", str(base.report), "--head", str(head.report), "--format", fmt]
    )
    assert result.exit_code == 0, result.stdout
    return result.stdout


def diff_json(base: Run, head: Run) -> dict:
    return json.loads(diff(base, head, "json"))


@pytest.fixture(scope="module")
def plain(make: Callable[..., Run]) -> Run:
    run = make("plain")
    assert run.code == 1
    return run


@pytest.fixture(scope="module")
def waived(make: Callable[..., Run]) -> Run:
    run = make("waived", waivers_file="waivers.yaml")
    assert run.code == 0
    return run


def test_a_waiver_added_is_newly_waived_and_not_fixed(plain, waived):
    for fmt in ("text", "markdown"):
        out = diff(plain, waived, fmt)
        assert "Newly waived (2)" in out
        assert "No longer reported" not in out
        assert "ixed" not in out
        assert "RULE-001" in out
        assert "RULE-002" in out
        assert "WAIVE-001" in out
        assert "Waiver changes (2)" in out
    document = diff_json(plain, waived)
    assert document["no_longer_reported"] == []
    assert document["new_violations"] == []
    assert len(document["newly_waived"]) == 2
    assert document["schema_version"] == "2"


def test_a_waiver_removed_makes_the_violations_new(plain, waived):
    document = diff_json(waived, plain)
    assert len(document["new_violations"]) == 2
    assert document["newly_waived"] == []
    assert document["no_longer_reported"] == []
    assert "New problems (2)" in diff(waived, plain)


def test_a_later_expiry_shows_both_dates_and_never_the_owner(make, waived):
    later = make(
        "later",
        waivers_file="waivers.yaml",
        owner=OWNER_LATER,
        expires="2027-02-01",
    )
    for fmt in ("text", "markdown", "json"):
        out = diff(waived, later, fmt)
        assert "2027-01-31" in out
        assert "2027-02-01" in out
        assert "WAIVE-001" in out
        assert "alice@example.com" not in out
        assert OWNER_LATER not in out
        assert "owner" in out
        assert "accepted" not in out
    assert "Waiver changes (2)" in diff(waived, later)


def _set_expect(spec: dict) -> None:
    case = next(c for c in spec["cases"] if c["id"] == "CASE-002")
    case["expect"] = "allow"


def test_a_changed_expected_answer_is_not_no_changes(make, plain):
    head = make("expect", edit_spec=_set_expect)
    for fmt in ("text", "markdown"):
        out = diff(plain, head, fmt)
        assert "Changes to what a case checks (1)" in out
        assert "CASE-002" in out
        assert "No changes" not in out
    text = diff(plain, head)
    row = next(line for line in text.splitlines() if "CASE-002" in line)
    assert "EXPECT deny -> allow" in row
    assert "**expect** `deny` -> `allow`" in diff(plain, head, "markdown")


def test_a_changed_role_and_actor(make, plain):
    def edit(spec: dict) -> None:
        case = next(c for c in spec["cases"] if c["id"] == "CASE-001")
        case["actor"] = ACTOR_NEW
        case["role"] = "trader"

    head = make("actor", edit_spec=edit)
    for fmt in ("text", "markdown", "json"):
        out = diff(plain, head, fmt)
        assert ACTOR_NEW not in out
        assert "actor" in out
        assert "CASE-001" in out
    assert "role analyst -> trader" in diff(plain, head)
    assert (
        "alice" not in diff(plain, head, "json").split("cases_changed")[1].split("cases_other")[0]
    )


def test_a_removed_rule_is_listed_and_its_violation_is_no_longer_reported(make, plain):
    def edit(spec: dict) -> None:
        spec["never_reaches"] = [r for r in spec["never_reaches"] if r["id"] != "RULE-002"]

    head = make("norule", edit_spec=edit)
    for fmt in ("text", "markdown"):
        out = diff(plain, head, fmt)
        assert "Rule changes (1)" in out
        assert "removed: RULE-002" in out.replace("`", "")
        assert "No longer reported (1)" in out
        assert "Newly waived" not in out
    assert diff_json(plain, head)["rules_removed"][0]["id"] == "RULE-002"


def _cover_get_quote(spec: dict) -> None:
    spec["cases"].append(
        {
            "id": "CASE-006",
            "actor": "alice",
            "role": "analyst",
            "path": ["supervisor", "finance-agent"],
            "tool": "get_quote",
            "action": "market:quote",
            "resource_fixture": "TSMC",
            "expect": "allow",
        }
    )


def test_a_real_fix_is_no_longer_reported_and_not_newly_waived(make):
    base = make("strict", strict=True)
    head = make("strict-fixed", strict=True, edit_spec=_cover_get_quote)
    document = diff_json(base, head)
    gone = [v for v in document["no_longer_reported"] if v.get("tool") == "get_quote"]
    assert gone
    assert document["newly_waived"] == []
    assert "No longer reported" in diff(base, head)
    assert "ixed" not in diff(base, head)


def test_no_base_counts_waived_and_fills_no_new_list(waived):
    result = runner.invoke(cli.app, ["diff", "--head", str(waived.report), "--format", "json"])
    document = json.loads(result.stdout)
    assert document["waived"] == 2
    for name in (
        "newly_waived",
        "waivers_added",
        "waivers_removed",
        "waivers_changed",
        "cases_changed",
        "rules_added",
        "rules_removed",
        "rules_changed",
    ):
        assert document[name] == [], name
    text = runner.invoke(cli.app, ["diff", "--head", str(waived.report)]).stdout
    assert "2 waived" in text.splitlines()[0]


def test_a_waived_rule_removed_from_the_spec_is_no_longer_reported(make, waived):
    def edit(spec: dict) -> None:
        spec["never_reaches"] = [r for r in spec["never_reaches"] if r["id"] != "RULE-002"]

    head = make("waived-norule", edit_spec=edit, waivers_file="waivers.yaml")
    document = diff_json(waived, head)
    assert [v["rule_id"] for v in document["no_longer_reported"]] == ["RULE-002"]
    assert document["newly_waived"] == []
    assert document["new_violations"] == []
    for fmt in ("text", "markdown"):
        out = diff(waived, head, fmt)
        assert "No longer reported (1)" in out
        assert "No changes" not in out
