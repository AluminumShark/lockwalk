"""Start the harness worker for one job, with two timeouts.

The parent and the worker talk through files in a temporary directory (see _worker): the
worker writes <out>/imported after importing the user's app, then <out>/result.json. Both
appear atomically. Worker stdout and stderr go to DEVNULL because they can hold secrets.
Anything malformed becomes an error, never a PASS.
"""

import contextlib
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, BinaryIO

from pydantic import ValidationError

from lockwalk.config import HarnessConfig
from lockwalk.harness.protocol import (
    MAX_DOOR_CALLS,
    DirectJob,
    Job,
    Observed,
    ScriptedJob,
    Survey,
    SurveyJob,
    TargetRef,
    TimelineEntry,
    TimelineItem,
    WorkerRequest,
    WorkerResult,
    has_long_string,
    reduce_subject,
)
from lockwalk.inventory.base import truncate
from lockwalk.inventory.python import _kill_tree
from lockwalk.models import DoorCall
from lockwalk.urls import redact_urls

WORKER = "lockwalk.harness._worker"
POLL_S = 0.05
MAX_RESULT_BYTES = 8 * 1024 * 1024
EXIT_WAIT_S = 2.0
MAX_EXCEPTION_NAME = 200
UNREADABLE_DOOR_CALL = "the door recorder sent an unreadable door call"


def clean(text: str) -> str:
    """Mask URL credentials first, then truncate."""
    return truncate(redact_urls(text)) or "unknown error"


def _clean_optional(text: str | None) -> str | None:
    """None stays None; anything else is masked and never empty (an empty error fails open)."""
    return None if text is None else clean(text)


class HarnessRunner:
    def __init__(
        self,
        config: HarnessConfig,
        base_dir: Path,
        targets: Sequence[TargetRef],
        allow_hosts: Sequence[str],
    ) -> None:
        self._config = config
        self._base_dir = base_dir
        self._targets = tuple(targets)
        self._allow_hosts = tuple(allow_hosts)

    def survey(self) -> Survey | str:
        """The survey, or why the door tests cannot start (masked, truncated)."""
        result = self._execute(SurveyJob())
        if isinstance(result, str):
            return clean(result)
        if result.fatal is not None:
            return clean(result.fatal)
        if result.survey is None:
            return "the harness worker sent no survey"
        survey = result.survey
        return survey.model_copy(
            update={
                "problems": tuple(clean(item) for item in survey.problems),
                "warnings": tuple(clean(item) for item in survey.warnings),
            }
        )

    def run(self, job: DirectJob | ScriptedJob) -> Observed:
        """One run in a fresh subprocess. Never raises: failures are Observed(error=...)."""
        result = self._execute(job)
        if isinstance(result, str):
            return Observed(error=clean(result))
        if result.fatal is not None:
            return Observed(error=clean(result.fatal))
        seen = result.observation
        if seen is None:
            return Observed(error="the harness worker sent no observation")
        door_calls = tuple(_door_call(raw) for raw in seen.door_calls)
        if seen.door_calls_dropped > 0:
            # Partial door evidence could hide a deny or an identity mismatch: fail closed.
            door_calls += (
                DoorCall(
                    error=(
                        f"{seen.door_calls_dropped} more door calls in the tool's window "
                        f"were not kept; lockwalk keeps {MAX_DOOR_CALLS}"
                    )
                ),
            )
        return Observed(
            side_effect_calls=seen.side_effect_calls,
            door_calls=door_calls,
            bypass=seen.bypass,
            exception=_exception_name(seen.exception),
            exception_message=(
                seen.exception_message
                if not seen.exception_message
                else clean(seen.exception_message)
            ),
            not_run=_clean_optional(seen.not_run),
            blocked_hosts=tuple(clean(host) for host in seen.blocked_hosts),
            error=_clean_optional(seen.error),
            timeline=tuple(
                _timeline_item(entry) for entry in sorted(seen.timeline, key=lambda e: e.seq)
            ),
            timeline_dropped=seen.timeline_dropped,
            elapsed_ms=seen.elapsed_ms,
        )

    def _execute(self, job: Job) -> WorkerResult | str:
        """Run one job in a fresh worker. A string is an error message."""
        with tempfile.TemporaryDirectory(
            prefix="lockwalk-harness-", ignore_cleanup_errors=True
        ) as tmp:
            request_path = Path(tmp) / "request.json"
            out = Path(tmp) / "out"
            try:
                request = WorkerRequest.model_validate(
                    {
                        "hooks": str((self._base_dir / self._config.hooks).resolve()),
                        "targets": self._targets,
                        "allow_hosts": self._allow_hosts,
                        "job": job,
                    }
                )
                request_path.write_text(request.model_dump_json(), encoding="utf-8")
                out.mkdir()
            except (OSError, ValueError) as exc:
                return f"cannot prepare the harness request: {type(exc).__name__}"
            command = [sys.executable, "-P", "-m", WORKER, str(request_path), str(out)]
            env = {
                **os.environ,
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "LOCKWALK_HARNESS": "1",
                "PYDANTIC_AI_NO_BANNER": "1",
                "OPENAI_AGENTS_DISABLE_TRACING": "1",
            }
            try:
                process = subprocess.Popen(
                    command,
                    cwd=self._base_dir,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=sys.platform != "win32",
                )
            except OSError as exc:
                # Never str(exc): it holds paths.
                reason = f": {exc.strerror}" if exc.strerror else ""
                return f"cannot start the harness worker: {type(exc).__name__}{reason}"
            job_object = _JobObject.attach(process) if sys.platform == "win32" else None
            try:
                return self._collect(process, out)
            finally:
                _stop(process)
                if job_object is not None:
                    job_object.close()  # kills every process still in the job

    def _collect(self, process: "subprocess.Popen[bytes]", out: Path) -> WorkerResult | str:
        imported, result_path = out / "imported", out / "result.json"
        importing = True
        limit = self._config.import_timeout_s
        deadline = time.monotonic() + limit
        while True:
            if importing and os.path.lexists(imported):
                importing = False
                limit = self._config.timeout_s
                deadline = time.monotonic() + limit
            if os.path.lexists(result_path):
                break
            if _exited(process):
                if os.path.lexists(result_path):  # written just before the exit
                    break
                _stop(process)
                return f"the harness worker exited with code {process.returncode} without a result"
            if time.monotonic() >= deadline:
                if importing and os.path.lexists(imported):  # the marker came late
                    continue
                _stop(process)
                where = "importing the app" if importing else "running the case"
                return f"timed out after {limit:g}s while {where}"
            time.sleep(POLL_S)
        result = _read_result(result_path)
        if isinstance(result, str):
            return result
        wait_for_exit(process)
        return result


def open_regular(path: Path) -> BinaryIO:
    """Open a regular file for binary reading: no symlink, no device, no FIFO.

    Raises OSError when the path is anything else. Shared with the observe reader.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise OSError("not a regular file")
    handle = os.fdopen(os.open(path, flags), "rb")
    try:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise OSError("not a regular file")
    except BaseException:
        handle.close()
        raise
    return handle


def read_bounded(path: Path, limit: int) -> bytes:
    """At most limit + 1 bytes of a regular file (one extra byte shows it was too big)."""
    with open_regular(path) as handle:
        return handle.read(limit + 1)


def wait_for_exit(process: "subprocess.Popen[bytes]") -> None:
    """After the result file appeared: give the worker EXIT_WAIT_S to exit by itself."""
    wait_until = time.monotonic() + EXIT_WAIT_S
    while not _exited(process) and time.monotonic() < wait_until:
        time.sleep(POLL_S)


def _read_result(path: Path) -> WorkerResult | str:
    """Read result.json with a bound: a regular file, at most MAX_RESULT_BYTES."""
    unreadable = "the harness worker wrote an unreadable result"
    too_big = "the harness worker wrote a result larger than 8 MiB"
    try:
        data = read_bounded(path, MAX_RESULT_BYTES)
    except OSError:
        return unreadable
    if len(data) > MAX_RESULT_BYTES:
        return too_big
    try:
        return WorkerResult.model_validate_json(data)
    except (ValueError, ValidationError):
        return unreadable


_posix: Any = os  # the POSIX-only names below are absent on Windows and some others
_HAS_WAITID = hasattr(os, "waitid") and hasattr(os, "WNOWAIT")


def _exited(process: "subprocess.Popen[bytes]") -> bool:
    """Whether the worker has exited. On POSIX it is not reaped yet, so the process group
    id stays reserved until _stop kills the group."""
    if process.returncode is not None:
        return True
    if _HAS_WAITID:
        try:
            flags = _posix.WEXITED | _posix.WNOHANG | _posix.WNOWAIT
            return _posix.waitid(_posix.P_PID, process.pid, flags) is not None
        except ChildProcessError:
            return True
    return process.poll() is not None


def _stop(process: "subprocess.Popen[bytes]") -> None:
    """Kill what the worker left behind, and reap it. Safe to call twice."""
    if process.returncode is not None:  # reaped: its pid may be reused, never signal it
        return
    if sys.platform != "win32" and _HAS_WAITID:
        # The leader is alive or an unreaped zombie, so the group id cannot be reused.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            _posix.killpg(process.pid, signal.SIGKILL)
        process.wait()
        return
    # Windows (a Job Object adds the grandchildren; see _JobObject) and POSIX without
    # os.waitid: only kill a worker that is still running.
    if process.poll() is None:
        _kill_tree(process)


class _JobObject:
    """A Windows Job Object that kills every process in it when its handle closes.

    The worker is assigned right after Popen, so a child it started before the assignment
    is not in the job (a small race). If any ctypes call fails there is no job, and the
    runner keeps the taskkill /T behavior of _kill_tree.
    """

    def __init__(self, handle: int, kernel32: Any) -> None:
        self._handle = handle
        self._kernel32 = kernel32

    @classmethod
    def attach(cls, process: "subprocess.Popen[bytes]") -> "_JobObject | None":
        if sys.platform != "win32":
            return None  # Windows only; this also lets type checkers drop ctypes.WinDLL
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                wintypes.LPVOID,
                wintypes.DWORD,
            ]
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

            class BasicLimits(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in ("a", "b", "c", "d", "e", "f")]

            class ExtendedLimits(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", BasicLimits),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return None
            limits = ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            ok = kernel32.SetInformationJobObject(
                handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
            )
            process_handle = getattr(process, "_handle", None)
            if ok and process_handle is not None:
                ok = kernel32.AssignProcessToJobObject(handle, int(process_handle))
            if not ok:
                kernel32.CloseHandle(handle)
                return None
            return cls(int(handle), kernel32)
        except (OSError, AttributeError, ValueError, TypeError):
            return None

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._kernel32.CloseHandle(self._handle)


def _clean_subject(subject: dict[str, Any]) -> dict[str, Any]:
    """The subject with type and id of every link masked like other worker text."""
    out: dict[str, Any] = {"type": clean(subject["type"]), "id": clean(subject["id"])}
    act = subject.get("act")
    if act is not None:
        out["act"] = _clean_subject(act)
    return out


def _timeline_item(entry: TimelineEntry) -> TimelineItem:
    """Check one timeline entry like a door call: anything odd is kept as unreadable."""
    data = entry.data
    big = data is not None and has_long_string(data)
    if entry.kind == "door":
        call = DoorCall(error=UNREADABLE_DOOR_CALL) if big else _door_call(data or {})
        if call.subject is not None:
            call = DoorCall(subject=_clean_subject(call.subject), decision=call.decision)
        return TimelineItem(seq=entry.seq, at_ms=entry.at_ms, kind="door", call=call)
    if entry.kind == "identity":
        subject = None
        if data is not None and not big and reduce_subject(data) == data:
            subject = _clean_subject(data)
        return TimelineItem(seq=entry.seq, at_ms=entry.at_ms, kind="identity", subject=subject)
    return TimelineItem(
        seq=entry.seq,
        at_ms=entry.at_ms,
        kind="effect",
        tool=clean(entry.tool) if entry.tool else "?",
    )


def _exception_name(name: str | None) -> str | None:
    if name is None:
        return None
    if (
        name
        and len(name) <= MAX_EXCEPTION_NAME
        and all(part.isidentifier() for part in name.split("."))
    ):
        return name
    return "unknown"


def _door_call(raw: dict[str, object]) -> DoorCall:
    error = raw.get("error")
    if set(raw) == {"error"} and isinstance(error, str):
        return DoorCall(error=clean(error))
    subject, decision = raw.get("subject"), raw.get("decision")
    if (
        set(raw) == {"subject", "decision"}
        and isinstance(subject, dict)
        and reduce_subject(subject) == subject
        and type(decision) is bool
    ):
        return DoorCall(subject=subject, decision=decision)
    return DoorCall(error=UNREADABLE_DOOR_CALL)
