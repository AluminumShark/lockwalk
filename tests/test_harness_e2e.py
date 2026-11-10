"""lockwalk test with door tests, end to end, on tests/harness_apps/desk.

Every variant is one run_test call with real worker subprocesses (the survey, a scripted run
per case, and a direct run per case). Nothing calls a model or the network: the agents use
lockwalk's fake models, and the worker blocks every connection. Expected results follow
the door table and the door controls of judge_harness.
"""

import json
import tempfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from lockwalk.models import CoverageReport, DoorStatus, IdentityResult
from lockwalk.report import render_coverage, write_report
from lockwalk.testing import run_test

APPS = Path(__file__).resolve().parent / "harness_apps"
ALL_CASES = ("CASE-1", "CASE-2", "CASE-3", "CASE-4", "CASE-5", "CASE-6")

pytestmark = pytest.mark.filterwarnings("ignore")


@pytest.fixture(scope="module")
def variant() -> Iterator[Callable[..., CoverageReport]]:
    """run(config, cases, **env) -> the report. The environment is restored afterwards."""
    patch = pytest.MonkeyPatch()
    patch.setenv("OPENAI_API_KEY", "sk-test")
    scratch = tempfile.TemporaryDirectory(prefix="lockwalk-e2e-")

    def run(
        config: str = "desk.toml", cases: tuple[str, ...] = ALL_CASES, **env: str
    ) -> CoverageReport:
        spec = yaml.safe_load((APPS / "desk" / "security-spec.yaml").read_text(encoding="utf-8"))
        spec["cases"] = [case for case in spec["cases"] if case["id"] in cases]
        spec_path = Path(scratch.name) / f"spec-{'-'.join(cases)}.yaml"
        spec_path.write_text(yaml.safe_dump(spec), encoding="utf-8")
        with pytest.MonkeyPatch.context() as local:
            for key, value in env.items():
                local.setenv(key, value)
            return run_test(APPS / config, cwd=APPS, spec=str(spec_path))

    try:
        yield run
    finally:
        patch.undo()
        scratch.cleanup()


@pytest.fixture(scope="module")
def default(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant()


@pytest.fixture(scope="module")
def bypass(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant(cases=("CASE-1", "CASE-2"), DESK_BYPASS="read_portfolio")


@pytest.fixture(scope="module")
def switch(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant(cases=("CASE-1", "CASE-2"), DESK_SWITCH="1")


@pytest.fixture(scope="module")
def network(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant(cases=("CASE-6",), DESK_NETWORK="1")


@pytest.fixture(scope="module")
def bad_path(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant(cases=("CASE-3", "CASE-4"), DESK_BAD_PATH="1")


@pytest.fixture(scope="module")
def no_door(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant("desk_nodoor.toml", cases=("CASE-1", "CASE-2"))


@pytest.fixture(scope="module")
def raising(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant("desk_raises.toml", cases=("CASE-1", "CASE-2"))


@pytest.fixture(scope="module")
def stage_one(
    variant: Callable[..., CoverageReport], tmp_path_factory: pytest.TempPathFactory
) -> CoverageReport:
    spec = yaml.safe_load((APPS / "desk" / "security-spec.yaml").read_text(encoding="utf-8"))
    path = tmp_path_factory.mktemp("stage-one") / "spec.yaml"
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    with pytest.MonkeyPatch.context() as local:
        local.setenv("OPENAI_API_KEY", "sk-test")
        return run_test(APPS / "desk.toml", cwd=APPS, spec=str(path), no_harness=True)


def case(report: CoverageReport, case_id: str) -> Any:
    return next(row for row in report.cases if row.id == case_id)


def identity(report: CoverageReport, case_id: str) -> Any:
    return next(row for row in report.identity_checks if row.case_id == case_id)


def runs(report: CoverageReport, case_id: str) -> dict[str, Any]:
    door = case(report, case_id).door
    assert door is not None
    return {run.mode: run for run in door.runs}


def statuses(report: CoverageReport) -> dict[str, tuple[str, str | None]]:
    return {
        row.id: (row.status.value, row.door.status.value if row.door else None)
        for row in report.cases
    }


# ---- default: the door is right everywhere ----


def test_default_every_door_is_ok(default):
    assert statuses(default) == {name: ("PASS", "OK") for name in ALL_CASES}
    assert default.exit_code == 0, default.errors
    assert default.errors == ()
    assert not default.gate.violations


def test_default_runs_both_modes_and_counts_side_effects(default):
    for name in ALL_CASES:
        by_mode = runs(default, name)
        assert set(by_mode) == {"scripted", "direct"}
        allowed = name in ("CASE-1", "CASE-3", "CASE-5", "CASE-6")
        for run in by_mode.values():
            assert run.side_effect_calls == (1 if allowed else 0), name
            assert run.door_calls and all(call.decision is allowed for call in run.door_calls)


def test_default_identity_checks_match_with_the_delegation_chain(default):
    assert [row.case_id for row in default.identity_checks] == list(ALL_CASES)
    for row in default.identity_checks:
        assert row.result is IdentityResult.MATCH, row
        assert {obs.mode for obs in row.observations} == {"scripted", "direct"}
    chain = identity(default, "CASE-3").observations[0].observed[0]
    assert chain["id"] == "bob"
    assert chain["act"]["id"] == "trade-agent"
    assert chain["act"]["act"]["id"] == "finance-agent"
    assert chain["act"]["act"]["act"]["id"] == "supervisor"


def test_default_door_controls_are_proven_for_every_tool(default):
    rows = {row.tool: row for row in default.door_controls}
    assert set(rows) == {"execute_trade", "get_stock_price", "read_portfolio", "read_report"}
    assert all(row.proven and row.proven_by for row in rows.values())
    assert rows["read_portfolio"].proven_by == "CASE-1 (scripted)"


def test_default_coverage_json_holds_the_door_sections(default, tmp_path):
    path = write_report(default, tmp_path, generated_at=datetime.now(UTC), version="test")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["cases"][0]["door"]["status"] == "OK"
    assert {run["mode"] for run in data["cases"][0]["door"]["runs"]} == {"scripted", "direct"}
    assert len(data["identity_checks"]) == 6
    assert {row["tool"] for row in data["door_controls"]} >= {"read_portfolio"}


def test_default_terminal_output_shows_the_door_lines(default):
    text = "\n".join(render_coverage(default, ()))
    assert "door (scripted): OK, side effect ran 1 time(s), door saw user alice" in text
    assert "door (direct): OK, side effect ran 0 time(s), door saw user bob" in text
    assert "Identity checks: 6 MATCH" in text
    assert "Gate: PASS" in text


# ---- DESK_BYPASS: the tool skips the door ----


def test_bypass_runs_the_side_effect_before_the_door_asks(bypass):
    assert statuses(bypass) == {
        "CASE-1": ("FAIL_EXECUTION", "FAIL_EXECUTION"),
        "CASE-2": ("FAIL_EXECUTION", "FAIL_EXECUTION"),
    }
    assert bypass.exit_code == 1
    for mode, run in runs(bypass, "CASE-2").items():
        assert run.side_effect_calls == 1, mode
        assert any(
            "the IAM denied this, but the side effect of 'read_portfolio' ran 1 time(s) "
            "before the door asked the IAM" in note
            for note in run.notes
        )
    for run in runs(bypass, "CASE-1").values():
        assert any("the door was bypassed" in note for note in run.notes)
    cases = [v.case_id for v in bypass.gate.violations if v.rule == "case"]
    assert cases == ["CASE-1", "CASE-2"]


def test_bypass_has_no_identity_to_check_because_the_door_never_ran(bypass):
    # The door was never asked, so lockwalk saw no identity (NOT_RUN).
    assert {row.result for row in bypass.identity_checks} == {IdentityResult.NOT_RUN}
    assert all(row.proven for row in bypass.door_controls)


# ---- DESK_SWITCH: the handoff replaces the user with the agent ----


def test_switch_is_an_identity_mismatch_seen_by_scripted_mode(switch):
    for name in ("CASE-1", "CASE-2"):
        row = identity(switch, name)
        assert row.result is IdentityResult.MISMATCH
        by_mode = {obs.mode: obs for obs in row.observations}
        scripted = by_mode["scripted"]
        assert scripted.result is IdentityResult.MISMATCH
        assert scripted.expected == {"type": "user", "id": "alice"}
        assert scripted.observed == ({"type": "agent", "id": "finance-agent"},)
    mismatches = [
        v.case_id for v in switch.gate.violations if v.rule == "fail_on_identity_mismatch"
    ]
    assert mismatches == ["CASE-1", "CASE-2"]
    assert switch.exit_code == 1


def test_switch_asks_the_iam_with_the_observed_agent(switch):
    # The observed identity replaces the declared one: the IAM denies the agent, so the case
    # that expected allow is FAIL_POLICY. Direct mode then also calls the tool as that agent.
    assert case(switch, "CASE-1").status.value == "FAIL_POLICY"
    assert "expected allow, but the IAM denied finance-agent -> read_portfolio" in (
        case(switch, "CASE-1").notes
    )
    direct = {obs.mode: obs for obs in identity(switch, "CASE-1").observations}["direct"]
    assert direct.result is IdentityResult.MATCH
    assert direct.expected == {"type": "agent", "id": "finance-agent"}


def test_switch_door_is_inconclusive_when_the_denied_tool_was_never_counted(switch):
    # Every run of read_portfolio is denied (the agent identity), so SIDE_EFFECTS was never
    # shown to count it: no door control, INCONCLUSIVE instead of a PASS.
    assert [row.proven for row in switch.door_controls] == [False]
    for name in ("CASE-1", "CASE-2"):
        door = case(switch, name).door
        assert door.status is DoorStatus.INCONCLUSIVE
        assert all(run.side_effect_calls == 0 for run in door.runs)
        assert any("no door control" in note for run in door.runs for note in run.notes)
    assert case(switch, "CASE-2").status.value == "INCONCLUSIVE"
    assert ("fail_on_inconclusive_case", "CASE-2") in {
        (v.rule, v.case_id) for v in switch.gate.violations
    }


# ---- DESK_NETWORK: the tool opens a connection ----


def test_network_attempt_is_an_error_naming_the_host(network):
    assert statuses(network) == {"CASE-6": ("ERROR", "ERROR")}
    assert network.exit_code == 2
    base = "the code tried to connect to 203.0.113.1; door tests block the network"
    by_mode = runs(network, "CASE-6")
    assert by_mode["direct"].status is DoorStatus.ERROR
    assert by_mode["direct"].notes == (base,)
    assert by_mode["scripted"].status is DoorStatus.ERROR
    assert by_mode["scripted"].notes == (base + ", so the fake model may not have taken effect",)
    assert network.errors == (
        f"CASE-6: door (scripted): {base}, so the fake model may not have taken effect",
        f"CASE-6: door (direct): {base}",
    )


def test_network_error_runs_do_not_prove_a_door_control(network):
    assert [(row.tool, row.proven) for row in network.door_controls] == [("read_report", False)]


# ---- DESK_BAD_PATH: the side effect is reached through a reference lockwalk cannot replace ----


def test_bad_path_allowed_trade_is_an_error(bad_path):
    door = case(bad_path, "CASE-3").door
    assert door.status is DoorStatus.ERROR
    for run in door.runs:
        assert run.side_effect_calls == 0
        assert any(
            "the IAM allowed this, but the side effect did not run and the door did not deny it"
            in note
            for note in run.notes
        )
    assert bad_path.exit_code == 2


def test_bad_path_denied_trade_has_no_door_control(bad_path):
    door = case(bad_path, "CASE-4").door
    assert door.status is DoorStatus.INCONCLUSIVE
    assert any("no door control" in note for run in door.runs for note in run.notes)
    assert [(row.tool, row.proven) for row in bad_path.door_controls] == [("execute_trade", False)]
    assert ("fail_on_inconclusive_case", "CASE-4") in {
        (v.rule, v.case_id) for v in bad_path.gate.violations
    }


# ---- hooks without DOOR ----


def test_without_door_scripted_mode_is_skipped_with_a_warning(no_door):
    assert "scripted mode needs DOOR in the hooks file; no route was run" in no_door.warnings
    for name in ("CASE-1", "CASE-2"):
        door = case(no_door, name).door
        assert [run.mode for run in door.runs] == ["direct"]
        assert door.status is DoorStatus.OK
        assert any(note.startswith("scripted: no DOOR") for note in door.notes)
        assert runs(no_door, name)["direct"].door_calls == ()
    assert {row.result for row in no_door.identity_checks} == {IdentityResult.NOT_RUN}
    assert [(row.tool, row.proven) for row in no_door.door_controls] == [("read_portfolio", True)]


# ---- a hooks file that raises on import ----


def test_a_raising_hooks_file_makes_every_door_an_error(raising):
    assert raising.exit_code == 2
    for name in ("CASE-1", "CASE-2"):
        door = case(raising, name).door
        assert door.status is DoorStatus.ERROR
        assert door.runs == ()
        assert door.notes[0].startswith("the door tests could not start: ")
        assert "RuntimeError" in door.notes[0]
    assert raising.identity_checks == ()
    assert raising.door_controls == ()


def test_a_raising_hooks_file_does_not_leak_its_secret(raising, tmp_path):
    path = write_report(raising, tmp_path, generated_at=datetime.now(UTC), version="test")
    shown = "\n".join(render_coverage(raising, ())) + path.read_text(encoding="utf-8")
    assert "user:pass" not in shown
    assert "db.internal" in shown  # the message itself is kept, only the credentials go


# ---- --no-harness ----


def test_no_harness_gives_the_stage_one_result(stage_one):
    assert all(row.door is None for row in stage_one.cases)
    assert stage_one.identity_checks == ()
    assert stage_one.door_controls == ()
    assert [row.status.value for row in stage_one.cases] == ["PASS"] * 6
    assert stage_one.exit_code == 0
