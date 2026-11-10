"""Everything `lockwalk test` does, as a function (the Python API)."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from lockwalk import __version__
from lockwalk.analyzer import analyze, with_harness_outcome, with_test_outcome
from lockwalk.config import HarnessConfig, PolicyConfig, PythonSourceConfig
from lockwalk.errors import COMMAND_LINE, StructuralError
from lockwalk.evidence import Evidence
from lockwalk.evidence_build import RunRecorder, build_evidence
from lockwalk.fixtures import load_fixtures
from lockwalk.harness.plan import (
    DirectPlan,
    ScriptedPlan,
    observed_subjects,
    plan_direct,
    plan_scripted,
)
from lockwalk.harness.protocol import Observed, Survey, TargetRef
from lockwalk.harness.runner import HarnessRunner
from lockwalk.harness.verdicts import judge_harness
from lockwalk.judge import judge
from lockwalk.models import CoverageReport
from lockwalk.pipeline import collect, finish, load_waivers_for, require_registry_and_spec
from lockwalk.planner import plan_cases
from lockwalk.policy.base import Decision
from lockwalk.policy.factory import make_adapter
from lockwalk.queries import build_queries
from lockwalk.runner import ask_all
from lockwalk.settings import RunSettings, resolve_settings


@dataclass(frozen=True)
class PolicyRun:
    report: CoverageReport
    notes: tuple[str, ...]  # the settings' notes only; adapter notes are in report.warnings
    # What `lockwalk test` writes to evidence.jsonl; None when it could not be built.
    evidence: Evidence | None = None


def run_policy_test(settings: RunSettings) -> PolicyRun:
    """Everything `lockwalk test` does except printing and writing coverage.json."""
    registry, spec = require_registry_and_spec(settings, "test")
    waivers = load_waivers_for(settings)  # before any source is read, so a bad file fails fast
    if settings.policy is None:
        raise StructuralError(
            COMMAND_LINE,
            ["test needs an IAM to ask: give --policy, or add [policy] to .lockwalk.toml"],
        )
    # Built before any source is read, so a header problem fails fast.
    adapter = make_adapter(settings.policy, settings.policy_base_dir or Path.cwd())
    recorder = RunRecorder()
    answers: dict[str, Decision] = {}
    try:
        fixtures = load_fixtures(settings.fixtures, registry) if settings.fixtures else None
        inventory, graph = collect(settings, registry)
        plan = plan_cases(spec, inventory, graph)
        static = analyze(inventory, spec, plan, settings.gate, graph)
        queries = build_queries(plan, graph, inventory, fixtures, settings.policy)
        harness = settings.harness
        runner: HarnessRunner | None = None
        survey: Survey | str = ""
        survey_ok = False
        scripted_plan = ScriptedPlan()
        scripted: dict[str, Observed] = {}
        if harness is not None:
            # Order: survey, scripted runs, then the IAM, then direct runs.
            runner = HarnessRunner(
                harness,
                settings.harness_base_dir or Path.cwd(),
                targets=_python_targets(settings),
                allow_hosts=_allowed_hosts(harness, settings.policy),
            )
            survey = runner.survey()
            survey_ok = isinstance(survey, Survey) and not survey.problems
            if isinstance(survey, Survey) and survey_ok:
                scripted_plan = plan_scripted(
                    plan, queries, graph, registry, fixtures, survey, harness.modes
                )
            scripted = {
                case_id: recorder.run_job(runner, job)
                for case_id, job in scripted_plan.jobs.items()
            }
            observed = observed_subjects(scripted_plan, scripted)
            if observed:
                queries = build_queries(
                    plan, graph, inventory, fixtures, settings.policy, observed=observed
                )
        answers = ask_all(adapter, queries.queries(), on_batch=recorder.batch_sent)
        outcome = judge(queries, answers, settings.gate)
        report = with_test_outcome(
            static,
            outcome,
            policy_adapter=adapter.label,
            extra_warnings=(*queries.warnings, *adapter.notes()),
        )
        if harness is not None and runner is not None:
            direct_plan = DirectPlan()
            if isinstance(survey, Survey) and survey_ok:
                direct_plan = plan_direct(plan, queries, outcome, fixtures, survey, harness.modes)
            direct = {
                case_id: tuple(recorder.run_job(runner, job) for job in jobs)
                for case_id, jobs in direct_plan.jobs.items()
            }
            found = judge_harness(
                queries=queries,
                answers=answers,
                survey=survey,
                scripted_plan=scripted_plan,
                scripted=scripted,
                direct_plan=direct_plan,
                direct=direct,
                gate=settings.gate,
            )
            report = with_harness_outcome(report, found, settings.gate)
    finally:
        adapter.close()
    recorder.finish()
    final = finish(report, waivers)
    try:
        evidence, with_refs = build_evidence(
            recorder,
            queries=queries,
            answers=answers,
            report=final,
            policy_adapter=adapter.label,
            version=__version__,
        )
    except Exception as exc:
        # A run never loses its report because the timeline could not be built. Only the
        # exception type is named: its message could carry anything.
        warning = (
            f"the evidence file could not be built ({type(exc).__name__}); "
            "lockwalk inspect has no timeline for this run"
        )
        failed = final.model_copy(update={"warnings": (*final.warnings, warning)})
        return PolicyRun(report=failed, notes=settings.notes, evidence=None)
    return PolicyRun(report=with_refs, notes=settings.notes, evidence=evidence)


def _python_targets(settings: RunSettings) -> tuple[TargetRef, ...]:
    """The [[inventory.python]] sources, with the directory each is resolved from."""
    return tuple(
        TargetRef(target=entry.config.target, base_dir=str(entry.base_dir))
        for entry in settings.sources
        if isinstance(entry.config, PythonSourceConfig)
    )


def _allowed_hosts(harness: HarnessConfig, policy: PolicyConfig | None) -> tuple[str, ...]:
    """Hosts the worker's network guard lets through: [harness] allow_hosts and the PDP."""
    hosts = list(harness.allow_hosts)
    if policy is not None and policy.adapter == "authzen" and policy.url:
        host = urlsplit(policy.url).hostname
        if host:
            hosts.append(host.lower())
    return tuple(hosts)


def run_test(
    config_path: str | Path | None = None,
    *,
    cwd: Path | None = None,
    registry: str | None = None,
    spec: str | None = None,
    fixtures: str | None = None,
    waivers: str | None = None,
    policy: str | None = None,
    mcp: Sequence[str] = (),
    python: Sequence[str] = (),
    tools_json: Sequence[str] = (),
    no_harness: bool = False,
) -> CoverageReport:
    """The Python API. Paths are resolved as on the command line.

    Returns the CoverageReport. It never writes or removes coverage.json.
    It writes no files at all: the report has run_id and evidence refs, but there is no
    evidence file; run_policy_test(...).evidence has the events. Bad input raises
    StructuralError. The settings' notes (for example that --policy replaced [policy]) are
    available through run_policy_test(resolve_settings(...)).notes.
    """
    settings = resolve_settings(
        cwd=cwd or Path.cwd(),
        config_path=Path(config_path) if config_path is not None else None,
        registry=registry,
        spec=spec,
        fixtures=fixtures,
        waivers=waivers,
        policy=policy,
        mcp=mcp,
        python=python,
        tools_json=tools_json,
        no_harness=no_harness,
    )
    return run_policy_test(settings).report
