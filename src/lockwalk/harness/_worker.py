"""Subprocess side of the door test harness.

Run as: python -P -m lockwalk.harness._worker <request.json> <output-dir>

One process runs one job (a survey, one direct call, or one scripted run), so no state
carries over between cases. In order:
1. the network guard goes in, before any user code is imported;
2. the hooks file is loaded, which imports the user's app; then the [[inventory.python]]
   targets are resolved and walked the way static discovery walks them;
3. the SIDE_EFFECTS functions become counters and the DOOR gets a recorder;
4. <output-dir>/imported is written, so the parent switches from import_timeout_s to
   timeout_s;
5. the job runs, and <output-dir>/result.json is written.
stdout and stderr go nowhere the parent reads: the user's code may print anything.
"""

import asyncio
import contextlib
import inspect
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from lockwalk.harness import direct, guard, hooks, objects, patching, scripted
from lockwalk.harness.events import MAX_EVENTS, EventLog
from lockwalk.harness.protocol import (
    MAX_DOOR_CALLS,
    AgentInfo,
    DirectJob,
    Observation,
    ScriptedJob,
    Survey,
    SurveyJob,
    TargetRef,
    WorkerRequest,
    WorkerResult,
    reduce_subject,
)
from lockwalk.harness.script import NotRun, Script
from lockwalk.inventory._python_worker import items_of, resolve
from lockwalk.inventory.normalize import describe_error


class IdentityError(Exception):
    """set_identity did not give a usable context manager."""


def write_file(out_dir: Path, name: str, text: str) -> None:
    """Write atomically, so the parent never reads half a file."""
    temp = out_dir / f"{name}.tmp"
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, out_dir / name)


def _text(exc: BaseException) -> str:
    try:
        return str(exc)
    except BaseException:
        return ""


def resolve_targets(targets: Sequence[TargetRef]) -> tuple[list[object], list[str]]:
    """The objects the targets point at, each resolved from its own base directory."""
    values: list[object] = []
    problems: list[str] = []
    home = os.getcwd()
    for ref in targets:
        try:
            os.chdir(ref.base_dir)
            values.extend(items_of(resolve(ref.target)))
        except BaseException as exc:  # importing runs the user's code
            problems.append(f"target {ref.target!r}: {describe_error(exc)}")
        finally:
            os.chdir(home)
    return values, problems


def build_survey(
    loaded: hooks.Hooks,
    found: objects.Found,
    installed: patching.Installed,
    target_problems: Sequence[str],
) -> Survey:
    agents = {
        agent_id: AgentInfo(
            id=agent_id,
            framework=found.frameworks.get(agent_id, "other"),
            agent_tools={
                target: direct.tool_info(name, wrapper)
                for target, (name, wrapper) in found.agent_tools.get(agent_id, {}).items()
            },
        )
        for agent_id in found.agents
    }
    return Survey(
        side_effects=dict(loaded.side_effects),
        door=loaded.door is not None,
        run_path=loaded.run_path is not None,
        tools={name: direct.tool_info(name, obj) for name, obj in found.tools.items()},
        agents=agents,
        replaced=dict(installed.replaced),
        problems=(*target_problems, *installed.problems),
        warnings=found.warnings,
    )


def open_identity(loaded: hooks.Hooks, subject: dict[str, Any]) -> Any:
    """Call set_identity and enter what it returns. IdentityError when that fails."""
    try:
        manager = loaded.set_identity(subject)
    except BaseException as exc:
        raise IdentityError(f"set_identity raised {describe_error(exc)}") from None
    if not (hasattr(manager, "__enter__") and hasattr(manager, "__exit__")):
        raise IdentityError(
            f"set_identity must return a context manager; it returned {type(manager).__name__}"
        )
    try:
        manager.__enter__()
    except BaseException as exc:
        raise IdentityError(f"entering set_identity raised {describe_error(exc)}") from None
    return manager


def close_identity(manager: Any) -> None:
    with contextlib.suppress(BaseException):  # what the run saw is already recorded
        manager.__exit__(None, None, None)


def note_identity(log: EventLog, subject: dict[str, Any]) -> None:
    """Put the run's identity on the timeline, reduced so no property value is kept."""
    reduced = reduce_subject(subject)
    if reduced is not None:
        log.identity(reduced)


def with_timeline(seen: Observation, log: EventLog) -> Observation:
    entries, dropped = log.timeline()
    return seen.model_copy(
        update={"timeline": entries, "timeline_dropped": dropped, "elapsed_ms": log.elapsed_ms()}
    )


def run_direct(
    job: DirectJob, loaded: hooks.Hooks, found: objects.Found, log: EventLog
) -> Observation:
    tool = found.tools.get(job.tool)
    if tool is None:
        return Observation(
            error=f"tool {job.tool!r} was not found in the [[inventory.python]] targets"
        )
    try:
        manager = open_identity(loaded, job.subject)
    except IdentityError as exc:
        return Observation(error=str(exc))
    note_identity(log, job.subject)
    start = log.mark()  # after set_identity: door calls made while entering it are not the tool's
    try:
        outcome = direct.call(tool, job.args)
    finally:
        close_identity(manager)
    window = log.window(
        job.tool, start, None, door_configured=loaded.door is not None, keep=MAX_DOOR_CALLS
    )
    return Observation(
        side_effect_calls=window.side_effect_calls,
        door_calls=window.door_calls,
        door_calls_dropped=window.door_calls_dropped,
        bypass=window.bypass,
        exception=outcome.exception,
        exception_message=outcome.message,
    )


def run_scripted(
    job: ScriptedJob, loaded: hooks.Hooks, found: objects.Found, log: EventLog
) -> Observation:
    seen_agents: set[str] = set()
    for step in job.steps:
        if step.agent in seen_agents:
            return Observation(
                not_run=(
                    f"the route visits agent {step.agent!r} more than once; "
                    "scripted mode takes each agent's step once"
                )
            )
        seen_agents.add(step.agent)
    script = Script(job, log)
    if job.use_run_path and loaded.run_path is None:
        return Observation(error="the job needs run_path, but the hooks file has none")
    try:
        manager = open_identity(loaded, job.subject)
    except IdentityError as exc:
        return Observation(error=str(exc))
    note_identity(log, job.subject)
    exception: str | None = None
    message: str | None = None
    try:
        if job.use_run_path and loaded.run_path is not None:
            script.open_whole_run()
            result = loaded.run_path(list(job.route), job.subject, job.tool, dict(job.args))
            if inspect.isawaitable(result):
                asyncio.run(_wait(result))
        else:
            scripted.run(job, script, found)
    except NotRun as exc:
        return Observation(not_run=_text(exc) or "scripted mode cannot run this route")
    except BaseException as exc:  # the run may end with what the tool or the door raised
        exception, message = type(exc).__name__, _text(exc)
    finally:
        close_identity(manager)
    seen = script.observation(door_configured=loaded.door is not None)
    if seen.not_run is not None:
        if exception is not None:
            return Observation(not_run=f"{seen.not_run}; the run raised {exception}: {message}")
        return seen
    return seen.model_copy(update={"exception": exception, "exception_message": message})


async def _wait(awaitable: Any) -> Any:
    return await awaitable


def execute(request: WorkerRequest, out_dir: Path) -> WorkerResult:
    shield = guard.install(request.allow_hosts)
    for base in dict.fromkeys(ref.base_dir for ref in request.targets):
        sys.path.insert(0, base)
    sys.path.insert(0, str(Path(request.hooks).parent))
    log = EventLog()
    try:
        loaded = hooks.load(Path(request.hooks))
    except hooks.HooksError as exc:
        return WorkerResult(fatal="; ".join(exc.problems) or "the hooks file cannot be used")
    except BaseException as exc:  # importing the hooks file runs the user's code
        return WorkerResult(fatal=f"loading the hooks file raised {describe_error(exc)}")
    values, target_problems = resolve_targets(request.targets)
    try:
        found = objects.find(values)
    except BaseException as exc:
        return WorkerResult(fatal=f"finding the agents and tools raised {describe_error(exc)}")
    installed = patching.install(loaded, log)
    write_file(out_dir, "imported", "")
    log.begin()
    job = request.job
    if isinstance(job, SurveyJob):
        return WorkerResult(survey=build_survey(loaded, found, installed, target_problems))
    problems = (*target_problems, *installed.problems)
    if problems:
        return WorkerResult(observation=with_timeline(Observation(error="; ".join(problems)), log))
    if isinstance(job, DirectJob):
        seen = run_direct(job, loaded, found, log)
    else:
        seen = run_scripted(job, loaded, found, log)
    if log.overflowed:
        seen = Observation(
            error=f"the run recorded more than {MAX_EVENTS} side effect and door calls"
        )
    if shield.blocked:
        seen = seen.model_copy(update={"blocked_hosts": tuple(shield.blocked)})
    return WorkerResult(observation=with_timeline(seen, log))


MAX_TEXT = 64 * 1024  # bounds the result file; the parent masks and cuts to 300 later
MAX_SCRUB_DEPTH = 200
CAPPED_KEYS = frozenset({"exception_message", "not_run", "error", "fatal"})


def _scrub(value: Any, key: str | None = None, depth: int = 0) -> Any:
    """JSON-safe copy: lone surrogates replaced, tuples as lists, long messages cut."""
    if depth > MAX_SCRUB_DEPTH:
        return None
    if isinstance(value, str):
        text = value.encode("utf-8", "replace").decode("utf-8")
        return text[:MAX_TEXT] if key in CAPPED_KEYS else text
    if isinstance(value, dict):
        return {
            (k if not isinstance(k, str) else _scrub(k)): _scrub(v, k, depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub(v, None, depth + 1) for v in value]
    return value


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    out_dir = Path(argv[2])
    try:
        request = WorkerRequest.model_validate_json(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result = WorkerResult(fatal=f"unreadable request: {type(exc).__name__}")
    else:
        try:
            result = execute(request, out_dir)
        except BaseException as exc:  # nothing the user's code does may skip the result
            result = WorkerResult(fatal=f"the harness worker failed: {describe_error(exc)}")
    try:
        text = json.dumps(_scrub(result.model_dump(mode="python")))
    except BaseException as exc:
        text = WorkerResult(
            fatal=f"the run result cannot be written: {type(exc).__name__}"
        ).model_dump_json()
    write_file(out_dir, "result.json", text)
    return 0


if __name__ == "__main__":
    code = main(sys.argv)
    # Skip interpreter shutdown: a thread started by the user's code would otherwise keep
    # the process alive after the result is written.
    os._exit(code)
