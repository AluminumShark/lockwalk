"""Hardening: route length cap and the exit-code guard."""

from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from lockwalk.analyzer import UNEXPLAINED_ERROR, with_harness_outcome, with_test_outcome
from lockwalk.config import GateConfig
from lockwalk.harness.verdicts import HarnessOutcome
from lockwalk.inventory.agent_shapes import MAX_AGENT_DEPTH
from lockwalk.judge import CaseOutcome, PolicyOutcome
from lockwalk.models import (
    MAX_ROUTE_AGENTS,
    CaseStatus,
    DoorResult,
    DoorRun,
    DoorStatus,
    EscalationResult,
    EscalationRow,
    Risk,
    TestScenario,
)


def _scenario(path: list[str]) -> TestScenario:
    return TestScenario(
        id="CASE-001",
        actor="user",
        role="r",
        path=tuple(path),
        tool="t",
        action="read",
        resource_fixture="f",
        expect="allow",
    )


def test_a_route_of_the_maximum_length_is_accepted():
    assert len(_scenario([f"a{i}" for i in range(MAX_ROUTE_AGENTS)]).path or ()) == 32


def test_a_longer_route_is_a_spec_error():
    with pytest.raises(ValidationError, match="path has 33 agents; at most 32 are allowed"):
        _scenario([f"a{i}" for i in range(MAX_ROUTE_AGENTS + 1)])


def _empty_outcome(
    *,
    cases: Mapping[str, CaseOutcome] | None = None,
    escalations: tuple[EscalationRow, ...] = (),
    errors: tuple[str, ...] = (),
) -> PolicyOutcome:
    return PolicyOutcome(
        cases=cases or {},
        escalations=escalations,
        controls=(),
        errors=errors,
        warnings=(),
        violations=(),
    )


def test_error_case_without_an_error_line_gives_exit_2(make_report):
    outcome = _empty_outcome(
        cases={"CASE-001": CaseOutcome(status=CaseStatus.ERROR, decision=None, problems=("p",))}
    )
    result = with_test_outcome(make_report(), outcome, policy_adapter="t")
    assert result.errors == (UNEXPLAINED_ERROR,)
    assert result.exit_code == 2


def test_error_escalation_without_an_error_line_gives_exit_2(make_report):
    row = EscalationRow(
        case_id=None,
        role="r",
        tool="t",
        via="a",
        risk=Risk.HIGH,
        mode="agent",
        path=("a",),
        result=EscalationResult.ERROR,
        notes=("n",),
    )
    result = with_test_outcome(
        make_report(), _empty_outcome(escalations=(row,)), policy_adapter="t"
    )
    assert result.errors == (UNEXPLAINED_ERROR,)
    assert result.exit_code == 2


def test_error_door_without_an_error_line_gives_exit_2(make_report):
    base = with_test_outcome(make_report(), _empty_outcome(), policy_adapter="t")
    run = DoorRun(
        mode="direct",
        status=DoorStatus.ERROR,
        subject={"type": "user", "id": "alice"},
        side_effect_calls=0,
        notes=("died",),
    )
    door = DoorResult(status=DoorStatus.ERROR, runs=(run,))
    result = with_harness_outcome(base, HarnessOutcome(doors={"CASE-001": door}), GateConfig())
    assert result.errors == (UNEXPLAINED_ERROR,)
    assert result.exit_code == 2


def test_route_cap_equals_the_walk_depth() -> None:
    assert MAX_ROUTE_AGENTS == MAX_AGENT_DEPTH


def test_guard_line_and_real_harness_errors_both_stay(make_report):
    base = with_test_outcome(
        make_report(),
        _empty_outcome(
            cases={"CASE-001": CaseOutcome(status=CaseStatus.ERROR, decision=None, problems=("p",))}
        ),
        policy_adapter="t",
    )
    assert base.errors == (UNEXPLAINED_ERROR,)
    result = with_harness_outcome(base, HarnessOutcome(errors=("door broke",)), GateConfig())
    assert result.errors == (UNEXPLAINED_ERROR, "door broke")
    assert result.exit_code == 2


def test_an_explained_error_is_left_alone(make_report):
    outcome = _empty_outcome(
        cases={"CASE-001": CaseOutcome(status=CaseStatus.ERROR, decision=None, problems=("p",))},
        errors=("CASE-001: p",),
    )
    result = with_test_outcome(make_report(), outcome, policy_adapter="t")
    assert result.errors == ("CASE-001: p",)
