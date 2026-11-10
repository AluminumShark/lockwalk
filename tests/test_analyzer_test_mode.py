"""with_test_outcome: fold a PolicyOutcome into the static report."""

from collections.abc import Mapping

from conftest import finance_case

from lockwalk.analyzer import with_test_outcome
from lockwalk.judge import CaseOutcome, PolicyOutcome
from lockwalk.models import (
    CaseDecision,
    CaseStatus,
    GateViolation,
    PathVerdict,
    RuleResult,
)


def _decision(verdict: PathVerdict = PathVerdict.ALLOW) -> CaseDecision:
    return CaseDecision(verdict=verdict, hops=())


def _outcome(
    *,
    cases: Mapping[str, CaseOutcome] | None = None,
    errors: tuple[str, ...] = (),
    warnings: tuple[str, ...] = (),
    violations: tuple[GateViolation, ...] = (),
) -> PolicyOutcome:
    return PolicyOutcome(
        cases=cases or {},
        escalations=(),
        controls=(),
        errors=errors,
        warnings=warnings,
        violations=violations,
    )


def _all_pass() -> dict[str, CaseOutcome]:
    return {
        f"CASE-00{n}": CaseOutcome(status=CaseStatus.PASS, decision=_decision())
        for n in (1, 2, 3, 4)
    }


def _violation(rule_id: str = "RULE-001") -> GateViolation:
    return GateViolation(rule="never_reaches", rule_id=rule_id, result=RuleResult.FAIL)


class FakeAdapterNotes:
    """Stands in for adapter.notes(): the caller passes them as extra_warnings."""

    @staticmethod
    def notes() -> tuple[str, ...]:
        return ("the PDP has no batch endpoint; questions were sent one by one",)


def test_statuses_decisions_and_notes_replace_the_static_ones(make_report):
    report = make_report()
    assert {c.status for c in report.cases} == {CaseStatus.UNTESTED}
    cases = _all_pass()
    cases["CASE-003"] = CaseOutcome(
        status=CaseStatus.FAIL_POLICY,
        decision=_decision(PathVerdict.ALLOW),
        notes=("expected deny, but the IAM allowed it",),
    )
    result = with_test_outcome(report, _outcome(cases=cases), policy_adapter="python:x:decide")
    by_id = {c.id: c for c in result.cases}
    assert by_id["CASE-001"].status is CaseStatus.PASS
    assert by_id["CASE-001"].decision == _decision()
    assert by_id["CASE-003"].status is CaseStatus.FAIL_POLICY
    assert by_id["CASE-003"].notes == ("expected deny, but the IAM allowed it",)
    assert result.mode == "test"
    assert result.policy_adapter == "python:x:decide"
    assert report.mode == "static"  # the input is not changed


def test_metrics_are_recounted(make_report):
    cases = _all_pass()
    cases["CASE-004"] = CaseOutcome(status=CaseStatus.INCONCLUSIVE, decision=_decision())
    result = with_test_outcome(make_report(), _outcome(cases=cases), policy_adapter="a")
    metrics = result.metrics
    assert metrics.cases_by_status["PASS"] == 3
    assert metrics.cases_by_status["INCONCLUSIVE"] == 1
    assert metrics.cases_by_status["UNTESTED"] == 0
    assert metrics.executed_cases == 4
    assert metrics.execution_coverage == 1.0
    assert metrics.verified_pass_rate == 0.75


def test_no_cases_gives_no_rates(make_report):
    report = make_report(cases=[])
    result = with_test_outcome(report, _outcome(), policy_adapter="a")
    assert result.metrics.execution_coverage is None
    assert result.metrics.verified_pass_rate is None


def test_static_error_cases_are_kept(make_report):
    bad = finance_case("CASE-009", "finance-agent", "no_such_tool", "x:y", "TSMC", "allow")
    report = make_report(extra_cases=[bad])
    static = {c.id: c for c in report.cases}
    assert static["CASE-009"].status is CaseStatus.ERROR
    assert report.exit_code == 2
    result = with_test_outcome(report, _outcome(cases=_all_pass()), policy_adapter="a")
    kept = {c.id: c for c in result.cases}["CASE-009"]
    assert kept == static["CASE-009"]
    assert kept.decision is None
    assert result.metrics.executed_cases == 4
    assert result.metrics.cases_by_status["ERROR"] == 1
    assert result.errors == report.errors
    assert result.exit_code == 2


def test_outcome_problems_replace_the_static_ones_only_when_there_are_some(make_report):
    cases = _all_pass()
    cases["CASE-002"] = CaseOutcome(
        status=CaseStatus.ERROR, decision=None, problems=("fixture 'x' is missing",)
    )
    result = with_test_outcome(make_report(), _outcome(cases=cases), policy_adapter="a")
    by_id = {c.id: c for c in result.cases}
    assert by_id["CASE-002"].problems == ("fixture 'x' is missing",)
    assert by_id["CASE-001"].problems == ()


def test_errors_give_exit_2_violations_alone_give_exit_1_neither_gives_0(make_report):
    report = make_report()
    clean = with_test_outcome(report, _outcome(cases=_all_pass()), policy_adapter="a")
    assert (clean.exit_code, clean.gate.passed) == (0, True)

    failing = with_test_outcome(
        report, _outcome(cases=_all_pass(), violations=(_violation(),)), policy_adapter="a"
    )
    assert (failing.exit_code, failing.gate.passed) == (1, False)

    broken = with_test_outcome(
        report,
        _outcome(cases=_all_pass(), errors=("CASE-001: boom",), violations=(_violation(),)),
        policy_adapter="a",
    )
    assert broken.exit_code == 2  # an error wins over a violation
    assert broken.gate.passed is False


def test_lists_keep_the_static_ones_first(make_report):
    base = make_report(extra_tools=["extra_tool"])
    # The static gate already has violations and warnings of its own.
    assert base.warnings and base.gate.violations
    outcome = _outcome(
        cases=_all_pass(),
        errors=("outcome error",),
        warnings=("outcome warning",),
        violations=(_violation(),),
    )
    result = with_test_outcome(
        base, outcome, policy_adapter="a", extra_warnings=FakeAdapterNotes.notes()
    )
    assert result.errors == (*base.errors, "outcome error")
    assert result.warnings == (
        *base.warnings,
        "outcome warning",
        *FakeAdapterNotes.notes(),
    )
    assert result.gate.violations == (*base.gate.violations, _violation())


def test_adapter_notes_reach_the_report_warnings(make_report):
    result = with_test_outcome(
        make_report(),
        _outcome(cases=_all_pass()),
        policy_adapter="authzen",
        extra_warnings=FakeAdapterNotes.notes(),
    )
    assert FakeAdapterNotes.notes()[0] in result.warnings


def test_error_answers_are_not_executed_scenarios(make_report):
    cases = {
        f"CASE-00{n}": CaseOutcome(
            status=CaseStatus.ERROR, decision=_decision(PathVerdict.ERROR), notes=("PDP down",)
        )
        for n in (1, 2, 3, 4)
    }
    result = with_test_outcome(make_report(), _outcome(cases=cases), policy_adapter="a")
    assert result.metrics.executed_cases == 0
    assert result.metrics.execution_coverage == 0.0
