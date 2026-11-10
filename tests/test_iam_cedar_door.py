"""The door demo: examples/iam_cedar with [harness], run against Cedar.

Three real runs of run_test, one per variant: the default, the bypass
switch, and the own-identity switch. Workers are real subprocesses. Nothing calls a model or
the network: the agents run with lockwalk's fake models and the side effects are counters.
The expected statuses follow the door table and the door controls of judge_harness.
"""

import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from lockwalk_iam_expectations import CASES, ESCALATIONS

from lockwalk.models import CoverageReport, DoorStatus, IdentityResult
from lockwalk.testing import run_test

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "iam_cedar"

pytestmark = pytest.mark.filterwarnings("ignore")


@pytest.fixture(scope="module")
def variant() -> Iterator[Callable[..., CoverageReport]]:
    patch = pytest.MonkeyPatch()
    patch.setenv("OPENAI_API_KEY", "sk-test")
    patch.delenv("LOCKWALK_DEMO_BYPASS", raising=False)
    patch.delenv("LOCKWALK_DEMO_OWN_IDENTITY", raising=False)

    def run(**env: str) -> CoverageReport:
        with pytest.MonkeyPatch.context() as local:
            for key, value in env.items():
                local.setenv(key, value)
            return run_test(cwd=EXAMPLE)

    try:
        yield run
    finally:
        patch.undo()


@pytest.fixture(scope="module")
def default(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant()


@pytest.fixture(scope="module")
def bypass(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant(LOCKWALK_DEMO_BYPASS="read_portfolio")


@pytest.fixture(scope="module")
def own_identity(variant: Callable[..., CoverageReport]) -> CoverageReport:
    return variant(LOCKWALK_DEMO_OWN_IDENTITY="finance-agent")


def case(report: CoverageReport, case_id: str) -> Any:
    return next(row for row in report.cases if row.id == case_id)


def identity(report: CoverageReport, case_id: str) -> Any:
    return next(row for row in report.identity_checks if row.case_id == case_id)


def door_status(report: CoverageReport, case_id: str) -> str:
    door = case(report, case_id).door
    assert door is not None
    return door.status.value


def runs(report: CoverageReport, case_id: str) -> dict[str, Any]:
    door = case(report, case_id).door
    assert door is not None
    return {run.mode: run for run in door.runs}


# ---- default: the door is right everywhere ----


def test_default_keeps_the_stage_one_results(default):
    assert {row.id: row.status.value for row in default.cases} == CASES
    assert default.exit_code == 1
    found = {
        (row.case_id, row.role, row.tool, row.via): row.result.value for row in default.escalations
    }
    assert found == ESCALATIONS


def test_default_every_tested_door_is_ok(default):
    for name in ("CASE-001", "CASE-002", "CASE-004", "CASE-005"):
        assert door_status(default, name) == "OK", name
        assert set(runs(default, name)) == {"scripted", "direct"}
    allowed = {"CASE-001": 1, "CASE-002": 0, "CASE-004": 1, "CASE-005": 1}
    for name, count in allowed.items():
        for run in runs(default, name).values():
            assert run.side_effect_calls == count, name


def test_default_identity_checks_match(default):
    assert [row.result for row in default.identity_checks] == [IdentityResult.MATCH] * 5
    seen = identity(default, "CASE-004").observations[0].observed[0]
    assert (seen["type"], seen["id"]) == ("agent", "trade-agent")
    seen = identity(default, "CASE-001").observations[0].observed[0]
    assert (seen["type"], seen["id"]) == ("user", "alice")


def test_default_case_003_scripted_run_is_not_run_but_direct_is_tested(default):
    # finance-agent -> pricing-agent is a calls edge: lockwalk cannot script it.
    door = case(default, "CASE-003").door
    assert door is not None and door.status is DoorStatus.OK
    assert [run.mode for run in door.runs] == ["direct"]
    assert any("declared with calls only" in note for note in door.notes)
    call = door.runs[0].door_calls[0].subject
    assert call["id"] == "alice"
    assert call["act"]["id"] == "pricing-agent"


def test_default_door_controls_are_proven(default):
    rows = {row.tool: row for row in default.door_controls}
    assert set(rows) == {"read_portfolio", "execute_trade", "get_stock_price"}
    assert all(row.proven for row in rows.values())


# ---- LOCKWALK_DEMO_BYPASS: the tool skips the door ----


def test_bypass_is_fail_execution_even_when_the_iam_would_allow(bypass):
    for name in ("CASE-001", "CASE-002"):
        assert case(bypass, name).status.value == "FAIL_EXECUTION", name
        assert door_status(bypass, name) == "FAIL_EXECUTION", name
        for run in runs(bypass, name).values():
            assert run.side_effect_calls == 1
    notes = [n for run in runs(bypass, "CASE-002").values() for n in run.notes]
    assert any(
        "the IAM denied this, but the side effect of 'read_portfolio' ran 1 time" in n
        for n in notes
    )
    notes = [n for run in runs(bypass, "CASE-001").values() for n in run.notes]
    assert any("the door was bypassed" in n for n in notes)
    assert bypass.exit_code == 1


def test_bypass_leaves_the_other_tools_alone(bypass):
    for name in ("CASE-004", "CASE-005"):
        assert door_status(bypass, name) == "OK", name
    assert case(bypass, "CASE-005").status.value == "FAIL_POLICY"


def test_bypass_identity_is_not_run_because_the_door_never_saw_the_call(bypass):
    for name in ("CASE-001", "CASE-002"):
        assert identity(bypass, name).result is IdentityResult.NOT_RUN


# ---- LOCKWALK_DEMO_OWN_IDENTITY: the handoff drops the user ----


def test_own_identity_is_an_identity_mismatch_seen_by_scripted_mode(own_identity):
    for name in ("CASE-001", "CASE-002"):
        row = identity(own_identity, name)
        assert row.result is IdentityResult.MISMATCH, name
        scripted = {obs.mode: obs for obs in row.observations}["scripted"]
        assert scripted.result is IdentityResult.MISMATCH
        assert scripted.expected == {"type": "user", "id": "alice"}
        assert scripted.observed == ({"type": "agent", "id": "finance-agent"},)
    mismatches = [
        v.case_id for v in own_identity.gate.violations if v.rule == "fail_on_identity_mismatch"
    ]
    assert mismatches == ["CASE-001", "CASE-002"]
    assert own_identity.exit_code == 1


def test_own_identity_asks_the_iam_with_the_observed_agent(own_identity):
    # Cedar denies the agent finance-agent on portfolios, so the case that expected allow is
    # FAIL_POLICY, and the deny case has no door control left (nothing was ever counted).
    assert case(own_identity, "CASE-001").status.value == "FAIL_POLICY"
    assert case(own_identity, "CASE-002").status.value == "INCONCLUSIVE"
    for name in ("CASE-001", "CASE-002"):
        assert door_status(own_identity, name) == "INCONCLUSIVE", name
    assert [(row.tool, row.proven) for row in own_identity.door_controls if not row.proven] == [
        ("read_portfolio", False)
    ]


def test_own_identity_leaves_the_other_cases_alone(own_identity):
    for name in ("CASE-004", "CASE-005"):
        assert door_status(own_identity, name) == "OK", name
        assert identity(own_identity, name).result is IdentityResult.MATCH


# ---- the demo door itself ----


def test_the_demo_door_denies_an_unknown_resource_without_running_the_tool(monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE.parent / "multi_agent"))
    import demo_door  # imported from the example directory, as the workers do

    ran: list[str] = []

    @demo_door.guarded("portfolio:read", lambda portfolio_id: {"p-1": {}}[portfolio_id])
    def tool(portfolio_id: str) -> str:
        ran.append(portfolio_id)
        return "done"

    demo_door.set_decider(lambda subject, action, resource, context: True)
    try:
        with demo_door.as_identity({"type": "user", "id": "alice"}):
            assert tool("p-1") == "done"
            with pytest.raises(PermissionError, match="unknown resource"):
                tool("p-unknown")
    finally:
        demo_door.set_decider(None)
        sys.modules.pop("demo_door", None)
    assert ran == ["p-1"]


def test_the_demo_door_fails_closed_without_a_decider(monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE.parent / "multi_agent"))
    import demo_door

    try:
        demo_door.set_decider(None)
        with pytest.raises(RuntimeError, match="no IAM"):
            demo_door.check({"type": "user", "id": "alice"}, "x", {})
    finally:
        sys.modules.pop("demo_door", None)
