"""The harness runner: timeouts, kills, validation, and masking."""

import os
import sys
import time
from pathlib import Path

import pytest

from lockwalk.config import HarnessConfig
from lockwalk.harness import runner
from lockwalk.harness.protocol import MAX_DOOR_CALLS, DirectJob, ScriptedJob
from lockwalk.harness.runner import HarnessRunner

TESTS_DIR = Path(__file__).parent
IMPORT_S = 1.0
RUN_S = 0.5


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> HarnessRunner:
    monkeypatch.setattr(runner, "WORKER", "harness_apps.fake_worker")
    monkeypatch.setenv("PYTHONPATH", str(TESTS_DIR))
    config = HarnessConfig(hooks="hooks.py", timeout_s=RUN_S, import_timeout_s=IMPORT_S)
    return HarnessRunner(config, tmp_path, [], ["example.com"])


def job(case_id: str) -> DirectJob:
    return DirectJob(case_id=case_id, tool="t", args={}, subject={"type": "user", "id": "a"})


def test_ok_run_is_converted_and_masked(harness: HarnessRunner) -> None:
    seen = harness.run(job("ok"))
    assert seen.side_effect_calls == 1
    assert seen.exception == "ValueError"
    assert seen.door_calls[0].subject == {"type": "user", "id": "a"}
    assert seen.door_calls[0].decision is True
    assert seen.door_calls[1].error is not None
    assert "user:pass@" not in repr(seen)
    assert seen.exception_message is not None and "boom" in seen.exception_message
    assert seen.not_run is not None and seen.error is not None
    assert len(seen.blocked_hosts) == 1


def test_scripted_job_also_runs(harness: HarnessRunner) -> None:
    scripted = ScriptedJob(
        case_id="ok", route=("a",), tool="t", args={}, subject={"type": "user", "id": "a"}
    )
    assert harness.run(scripted).side_effect_calls == 1


def test_hang_during_import_is_killed(harness: HarnessRunner) -> None:
    start = time.monotonic()
    seen = harness.run(job("hang-import"))
    assert time.monotonic() - start < IMPORT_S + 3
    assert seen.error == "timed out after 1s while importing the app"


def test_hang_during_run_is_killed(harness: HarnessRunner) -> None:
    start = time.monotonic()
    seen = harness.run(job("hang-run"))
    assert time.monotonic() - start < IMPORT_S + RUN_S + 3
    assert seen.error == "timed out after 0.5s while running the case"


def test_exit_without_result(harness: HarnessRunner) -> None:
    seen = harness.run(job("crash"))
    assert seen.error == "the harness worker exited with code 3 without a result"


def test_worker_that_dies_while_writing_the_result(harness: HarnessRunner) -> None:
    # The real worker dies like this when writing result.json raises (for example a full disk).
    seen = harness.run(job("write-fails"))
    assert seen.error == "the harness worker exited with code 1 without a result"


def test_junk_result(harness: HarnessRunner) -> None:
    assert harness.run(job("junk")).error == "the harness worker wrote an unreadable result"


def test_big_result(harness: HarnessRunner) -> None:
    seen = harness.run(job("big"))
    assert seen.error == "the harness worker wrote a result larger than 8 MiB"


def test_unreadable_door_call_is_an_error_call(harness: HarnessRunner) -> None:
    seen = harness.run(job("bad-door"))
    assert seen.error is None
    assert len(seen.door_calls) == 1
    assert seen.door_calls[0].error == "the door recorder sent an unreadable door call"
    assert seen.door_calls[0].subject is None


def test_empty_error_and_not_run_never_stay_empty(harness: HarnessRunner) -> None:
    seen = harness.run(job("empty-error"))
    assert seen.error == "unknown error"
    assert seen.exception_message == ""  # an exception with no message is legitimate
    assert harness.run(job("empty-not-run")).not_run == "unknown error"


def test_exception_name_must_be_an_identifier(harness: HarnessRunner) -> None:
    assert harness.run(job("bad-exception")).exception == "unknown"


def test_noisy_worker_output_is_ignored(harness: HarnessRunner) -> None:
    seen = harness.run(job("prints"))
    assert seen.error is None and seen.side_effect_calls == 1


def test_survey_is_masked(harness: HarnessRunner) -> None:
    survey = harness.survey()
    assert not isinstance(survey, str)
    assert survey.door is True
    assert "user:pass@" not in repr(survey)
    assert survey.problems and survey.warnings


def test_survey_fatal_is_a_masked_string(
    monkeypatch: pytest.MonkeyPatch, harness: HarnessRunner
) -> None:
    monkeypatch.setenv("LOCKWALK_FAKE_SURVEY", "fatal")
    outcome = harness.survey()
    assert isinstance(outcome, str)
    assert "user:pass@" not in outcome and "cannot load" in outcome


def test_survey_without_survey(monkeypatch: pytest.MonkeyPatch, harness: HarnessRunner) -> None:
    monkeypatch.setenv("LOCKWALK_FAKE_SURVEY", "none")
    assert harness.survey() == "the harness worker sent no survey"


def test_fatal_becomes_run_error(harness: HarnessRunner) -> None:
    # Only a survey job normally gets fatal or a survey; a misbehaving worker may send either.
    seen = harness.run(job("survey-fatal"))
    assert seen.error is not None
    assert "user:pass@" not in seen.error and "cannot load" in seen.error


def test_result_without_observation(harness: HarnessRunner) -> None:
    seen = harness.run(job("survey-ok"))
    assert seen.error == "the harness worker sent no observation"


def test_real_worker_with_missing_hooks_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = HarnessConfig(hooks="missing_hooks.py", timeout_s=10, import_timeout_s=30)
    outcome = HarnessRunner(config, tmp_path, [], []).survey()
    assert isinstance(outcome, str) and outcome


def test_reduced_two_link_chain_is_accepted(harness: HarnessRunner) -> None:
    seen = harness.run(job("reduced-chain"))
    assert seen.error is None
    assert len(seen.door_calls) == 1
    assert seen.door_calls[0].error is None
    assert seen.door_calls[0].decision is True


def test_dropped_door_calls_make_the_run_an_error(harness: HarnessRunner) -> None:
    seen = harness.run(job("dropped"))
    assert len(seen.door_calls) == 1
    error = seen.door_calls[0].error
    assert error is not None and error.startswith("3 more door calls")
    assert str(MAX_DOOR_CALLS) in error


def test_result_that_is_a_directory_is_unreadable(harness: HarnessRunner) -> None:
    seen = harness.run(job("dir-result"))
    assert seen.error == "the harness worker wrote an unreadable result"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_result_that_is_a_symlink_is_unreadable(harness: HarnessRunner) -> None:
    seen = harness.run(job("symlink-result"))
    assert seen.error == "the harness worker wrote an unreadable result"


def test_overlong_exception_name_is_unknown(harness: HarnessRunner) -> None:
    assert harness.run(job("long-exception")).exception == "unknown"


def _alive(pid: int) -> bool:
    if sys.platform != "win32":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = ctypes.c_ulong()
    kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
    kernel32.CloseHandle(ctypes.c_void_p(handle))
    return code.value == 259  # STILL_ACTIVE


def test_grandchild_does_not_outlive_the_run(harness: HarnessRunner) -> None:
    seen = harness.run(job("grandchild"))
    assert seen.error is None and seen.exception_message is not None
    pid = int(seen.exception_message)
    deadline = time.monotonic() + 5
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not _alive(pid)


def test_timeline_is_converted(harness: HarnessRunner) -> None:
    seen = harness.run(job("timeline"))
    assert [item.kind for item in seen.timeline] == ["identity", "door", "effect"]
    assert seen.timeline[0].subject == {"type": "user", "id": "a"}
    assert seen.timeline[1].call is not None and seen.timeline[1].call.decision is True
    assert seen.timeline[2].tool == "t"
    assert seen.timeline_dropped == 4 and seen.elapsed_ms == 3.0


def test_unreadable_timeline_entries_fail_closed_and_are_masked(harness: HarnessRunner) -> None:
    seen = harness.run(job("timeline-junk"))
    assert seen.timeline[0].subject is None
    assert seen.timeline[1].call is not None and seen.timeline[1].call.error is not None
    assert "user:pass@" not in (seen.timeline[2].tool or "")


def test_a_timeline_over_the_limit_is_an_error(harness: HarnessRunner) -> None:
    seen = harness.run(job("timeline-too-long"))
    assert seen.error is not None


def test_oversized_timeline_text_is_unreadable(harness: HarnessRunner) -> None:
    seen = harness.run(job("timeline-big"))
    assert seen.timeline[0].subject is None
    assert seen.timeline[1].call is not None and seen.timeline[1].call.error is not None
    assert seen.timeline[2].tool == "t"


def test_timeline_shapes_fail_closed_and_ids_are_masked(harness: HarnessRunner) -> None:
    seen = harness.run(job("timeline-shapes"))
    assert seen.timeline[0].call is not None and seen.timeline[0].call.error is not None
    assert seen.timeline[1].subject is None  # properties are not a reduced subject
    masked = seen.timeline[2].subject
    assert masked is not None and "user:pass@" not in masked["id"]
    assert seen.timeline[3].tool == "?"
