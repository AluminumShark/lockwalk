"""The worker subprocess: the file protocol, the hooks and the three kinds of job."""

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from lockwalk.harness import _worker, guard, hooks, objects
from lockwalk.harness.direct import CallOutcome
from lockwalk.harness.events import EventLog
from lockwalk.harness.protocol import (
    DirectJob,
    Observation,
    ScriptedJob,
    Step,
    SurveyJob,
    TargetRef,
    WorkerRequest,
    WorkerResult,
)


def run_worker(tmp_path: Path, request_text: str) -> WorkerResult:
    request = tmp_path / "request.json"
    request.write_text(request_text, encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(
        [sys.executable, "-P", "-m", "lockwalk.harness._worker", str(request), str(out)],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=60,
        check=True,
    )
    return WorkerResult.model_validate_json((out / "result.json").read_text(encoding="utf-8"))


def test_an_unreadable_request_is_a_fatal_result(tmp_path: Path) -> None:
    result = run_worker(tmp_path, "{not json")
    assert result.fatal is not None and "unreadable request" in result.fatal


def test_a_missing_hooks_file_is_a_fatal_result(tmp_path: Path) -> None:
    request = WorkerRequest(
        hooks=str(tmp_path / "missing_hooks.py"),
        targets=(TargetRef(target="app:agents", base_dir=str(tmp_path)),),
        allow_hosts=(),
        job=SurveyJob(),
    )
    result = run_worker(tmp_path, request.model_dump_json())
    assert result.fatal is not None
    assert not (tmp_path / "out" / "imported").exists()
    json.loads((tmp_path / "out" / "result.json").read_text(encoding="utf-8"))


USER = {"type": "user", "id": "alice"}


class EnteringIdentity:
    """A set_identity context manager that calls the door while it is entered."""

    def __init__(self, log: EventLog) -> None:
        self.log = log

    def __enter__(self) -> None:
        self.log.door({"subject": USER, "decision": True})

    def __exit__(self, *exc: object) -> None:
        return None


def test_run_direct_window_starts_after_set_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    log = EventLog()
    loaded: Any = SimpleNamespace(
        set_identity=lambda subject: EnteringIdentity(log), door="app.door"
    )
    found = objects.Found(tools={"t": object()})

    def fake_call(obj: object, args: object) -> CallOutcome:
        log.side_effect("t")
        return CallOutcome()

    monkeypatch.setattr(_worker.direct, "call", fake_call)
    job = DirectJob(case_id="C", tool="t", args={}, subject=USER)
    seen = _worker.run_direct(job, loaded, found, log)
    assert seen.bypass is True
    assert seen.door_calls == ()


def test_scrub_makes_lone_surrogates_writable(tmp_path: Path) -> None:
    bad = "a" + chr(0xDCFF) + "b"
    result = WorkerResult(observation=Observation(exception_message=bad))
    text = json.dumps(_worker._scrub(result.model_dump(mode="python")))
    back = WorkerResult.model_validate_json(text)
    assert back.observation is not None
    assert back.observation.exception_message is not None
    assert back.observation.exception_message.startswith("a")
    assert back.observation.exception_message.endswith("b")


def test_main_writes_a_result_for_surrogates_and_caps_long_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        WorkerRequest(hooks="h.py", targets=(), allow_hosts=(), job=SurveyJob()).model_dump_json(),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    out.mkdir()
    big = "x" * (_worker.MAX_TEXT + 5)
    observation = Observation(
        exception_message="a" + chr(0xDCFF) + "b",
        not_run=big,
        error=big,
        door_calls=({"error": big},),
    )
    monkeypatch.setattr(
        _worker, "execute", lambda req, out_dir: WorkerResult(observation=observation)
    )
    assert _worker.main(["w", str(request), str(out)]) == 0
    back = WorkerResult.model_validate_json((out / "result.json").read_text(encoding="utf-8"))
    assert back.observation is not None
    assert len(back.observation.not_run or "") == _worker.MAX_TEXT
    assert len(back.observation.error or "") == _worker.MAX_TEXT
    assert len(back.observation.door_calls[0]["error"]) == _worker.MAX_TEXT
    assert (back.observation.exception_message or "").startswith("a")


def test_a_route_that_visits_an_agent_twice_is_not_run() -> None:
    job = ScriptedJob(
        case_id="C",
        route=("a", "b"),
        tool="t",
        args={},
        subject=USER,
        steps=(
            Step(agent="a", kind="handoff", target="b"),
            Step(agent="a", kind="tool", target="t", tool="t"),
        ),
    )
    loaded: Any = SimpleNamespace(set_identity=None, door=None, run_path=None)
    seen = _worker.run_scripted(job, loaded, objects.Found(), EventLog())
    assert seen.not_run is not None and "more than once" in seen.not_run


def test_execute_turns_systemexit_from_the_hooks_file_into_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(path: Path) -> object:
        raise SystemExit(3)

    monkeypatch.setattr(guard, "install", lambda allow_hosts: guard.Guard())
    monkeypatch.setattr(hooks, "load", boom)
    monkeypatch.setattr(sys, "path", list(sys.path))
    request = WorkerRequest(
        hooks=str(tmp_path / "h.py"), targets=(), allow_hosts=(), job=SurveyJob()
    )
    result = _worker.execute(request, tmp_path)
    assert result.fatal is not None and "SystemExit" in result.fatal


def test_resolve_targets_restores_the_cwd_after_a_failing_target(tmp_path: Path) -> None:
    before = os.getcwd()
    values, problems = _worker.resolve_targets(
        [TargetRef(target="no_such_module_xyz:agents", base_dir=str(tmp_path))]
    )
    assert values == [] and len(problems) == 1
    assert os.getcwd() == before


def test_run_direct_records_the_identity_on_the_timeline(monkeypatch: pytest.MonkeyPatch) -> None:
    log = EventLog()
    loaded: Any = SimpleNamespace(
        set_identity=lambda subject: contextlib.nullcontext(), door="app.door"
    )
    found = objects.Found(tools={"t": object()})

    def fake_call(obj: object, args: object) -> CallOutcome:
        log.door({"subject": USER, "decision": False})
        return CallOutcome()

    monkeypatch.setattr(_worker.direct, "call", fake_call)
    job = DirectJob(case_id="C", tool="t", args={}, subject={**USER, "properties": {"x": 1}})
    _worker.run_direct(job, loaded, found, log)
    entries, _ = log.timeline()
    assert [entry.kind for entry in entries] == ["identity", "door"]
    assert entries[0].data == USER  # reduced: properties are never kept


def test_execute_attaches_the_timeline_to_the_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log_holder: list[EventLog] = []
    real = _worker.EventLog

    def remember() -> EventLog:
        log = real()
        log_holder.append(log)
        return log

    monkeypatch.setattr(_worker, "EventLog", remember)
    monkeypatch.setattr(_worker.guard, "install", lambda hosts: SimpleNamespace(blocked=[]))
    monkeypatch.setattr(
        _worker.hooks,
        "load",
        lambda path: SimpleNamespace(
            set_identity=lambda subject: contextlib.nullcontext(),
            door=None,
            side_effects={},
            run_path=None,
        ),
    )
    monkeypatch.setattr(_worker, "resolve_targets", lambda targets: ([], []))
    monkeypatch.setattr(
        _worker.objects, "find", lambda values: objects.Found(tools={"t": object()})
    )
    monkeypatch.setattr(
        _worker.patching, "install", lambda loaded, log: SimpleNamespace(replaced={}, problems=())
    )

    def fake_call(obj: object, args: object) -> CallOutcome:
        log_holder[0].side_effect("t")
        return CallOutcome()

    monkeypatch.setattr(_worker.direct, "call", fake_call)
    request = WorkerRequest(
        hooks=str(tmp_path / "hooks.py"),
        targets=(),
        allow_hosts=(),
        job=DirectJob(case_id="C", tool="t", args={}, subject=USER),
    )
    result = _worker.execute(request, tmp_path)
    seen = result.observation
    assert seen is not None
    assert [entry.kind for entry in seen.timeline] == ["identity", "effect"]
    assert seen.elapsed_ms is not None and seen.timeline_dropped == 0


def test_door_call_while_entering_set_identity_comes_before_the_identity_entry() -> None:
    log = EventLog()

    class Manager:
        def __enter__(self) -> None:
            log.door({"subject": USER, "decision": True})

        def __exit__(self, *args: object) -> None:
            return None

    loaded: Any = SimpleNamespace(set_identity=lambda subject: Manager(), door="app.door")
    found = objects.Found(tools={"t": object()})
    job = DirectJob(case_id="C", tool="t", args={}, subject=USER)
    _worker.run_direct(job, loaded, found, log)
    entries, _ = log.timeline()
    assert [e.kind for e in entries] == ["door", "identity"]
    assert entries[0].seq < entries[1].seq


def test_failure_returns_carry_elapsed_ms(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def broken(subject: object) -> Any:
        raise RuntimeError("no")

    loaded: Any = SimpleNamespace(set_identity=broken, door=None)
    log = EventLog()
    job = DirectJob(case_id="C", tool="t", args={}, subject=USER)
    seen = _worker.with_timeline(
        _worker.run_direct(job, loaded, objects.Found(tools={"t": object()}), log), log
    )
    assert seen.error is not None and seen.elapsed_ms is not None
    assert seen.timeline == ()

    monkeypatch.setattr(_worker.guard, "install", lambda hosts: SimpleNamespace(blocked=[]))
    monkeypatch.setattr(_worker.hooks, "load", lambda path: loaded)
    monkeypatch.setattr(_worker, "resolve_targets", lambda targets: ([], ["target broken"]))
    monkeypatch.setattr(_worker.objects, "find", lambda values: objects.Found())
    monkeypatch.setattr(
        _worker.patching, "install", lambda loaded, log: SimpleNamespace(replaced={}, problems=())
    )
    request = WorkerRequest(hooks=str(tmp_path / "h.py"), targets=(), allow_hosts=(), job=job)
    result = _worker.execute(request, tmp_path)
    assert result.observation is not None and result.observation.elapsed_ms is not None


def test_observation_rejects_a_timeline_over_the_limit() -> None:
    entry = {"seq": 1, "at_ms": 0.0, "kind": "effect", "tool": "t"}
    with pytest.raises(ValueError):
        Observation.model_validate({"timeline": [entry] * 201})
