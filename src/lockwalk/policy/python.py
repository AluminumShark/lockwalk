"""Policy adapter that runs the user's own decide() function in a long-lived subprocess.

The worker talks JSON lines over stdin and stdout (see _decide_worker). The user's code may
print, hang, crash, raise, or return junk; every one of those becomes an ERROR answer. The
worker's stderr is never read, because it can hold secrets.
"""

import contextlib
import json
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from lockwalk.config import PolicyConfig
from lockwalk.inventory.base import truncate
from lockwalk.inventory.python import _kill_tree
from lockwalk.masking import SecretValues
from lockwalk.models import Verdict
from lockwalk.policy.base import Decision, Query, error_decision
from lockwalk.urls import redact_urls

WORKER = "lockwalk.policy._decide_worker"
IMPORT_TIMEOUT_S = 30.0
CLOSE_WAIT_S = 2.0
MAX_LINE_BYTES = 1024 * 1024
QUEUE_LINES = 8
SKIPPED = "skipped: the decide worker timed out on an earlier question"
OVERSIZED_MESSAGE = "the decide worker sent an answer larger than 1 MiB"


class _WorkerFailure(Exception):
    """The worker did not answer properly; the message goes into every ERROR answer."""

    def __init__(self, message: str, *, timed_out: bool = False) -> None:
        super().__init__(message)
        self.timed_out = timed_out


def _environment_secrets() -> SecretValues:
    """The values of this process's environment, which the decide worker inherits.

    A decide() often reads a credential from the environment and may echo it in an
    exception. Values shorter than the masking limit are not hidden.
    """
    return SecretValues((f"env {name!r}", value) for name, value in os.environ.items())


class _Oversized:
    """Marker put on the queue when the worker sent a line longer than MAX_LINE_BYTES."""


_OVERSIZED = _Oversized()
_Item = str | None | _Oversized


def _put(lines: "queue.Queue[_Item]", item: _Item, stop: threading.Event) -> bool:
    """Put an item, giving up once the worker was discarded so the thread cannot hang."""
    while not stop.is_set():
        try:
            lines.put(item, timeout=0.2)
        except queue.Full:
            continue
        return True
    return False


def _read_lines(stream: Any, lines: "queue.Queue[_Item]", stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_LINE_BYTES:
                _put(lines, _OVERSIZED, stop)
                return
            if not _put(lines, raw.decode("utf-8", errors="replace"), stop):
                return
    except (OSError, ValueError):
        pass
    _put(lines, None, stop)


class PythonAdapter:
    def __init__(self, config: PolicyConfig, base_dir: Path) -> None:
        if config.target is None:
            raise ValueError("adapter 'python' needs 'target'")
        self._config = config
        self._target = config.target
        self._base_dir = base_dir
        self._process: subprocess.Popen[bytes] | None = None
        self._lines: queue.Queue[_Item] = queue.Queue(maxsize=QUEUE_LINES)
        self._stop = threading.Event()
        self._spawned = False
        self._batch = False
        self._start_error: str | None = None
        self._restarts = 0
        self._timed_out = False  # set by _send when the last exchange timed out
        self._secrets = _environment_secrets()

    def _clean(self, message: str) -> str:
        """Hide known secret values and URL credentials, then shorten."""
        return truncate(redact_urls(self._secrets.scrub(message))) or "unknown error"

    @property
    def label(self) -> str:
        return self._config.label

    @property
    def batch_size(self) -> int:
        return self._config.batch_size

    def notes(self) -> tuple[str, ...]:
        if self._restarts:
            return (f"the decide worker was restarted {self._restarts} time(s)",)
        return ()

    def decide(self, queries: Sequence[Query]) -> list[Decision]:
        if not queries:
            return []
        timeout = self._config.timeout
        self._timed_out = False
        problem = self._ensure_worker()
        if problem is None and self._batch:
            return self._send(list(queries), timeout * len(queries))
        results: list[Decision] = []
        for query in queries:
            if self._timed_out:
                # A hanging decide() would otherwise cost one full timeout per question.
                results.append(error_decision(SKIPPED))
                continue
            # A crash discards the worker; the next query gets a fresh one.
            problem = self._ensure_worker()
            if problem is not None:
                results.append(error_decision(problem))
            else:
                results += self._send([query], timeout)
        return results

    def close(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        with contextlib.suppress(OSError, ValueError):
            if process.stdin is not None:
                process.stdin.close()
        self._stop.set()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=CLOSE_WAIT_S)
        # Never kill by pid once the process is reaped: the pid may belong to someone else.
        if process.poll() is None:
            _kill_tree(process)
        with contextlib.suppress(OSError, ValueError):
            if process.stdout is not None:
                process.stdout.close()

    def _spawn(self) -> None:
        self._secrets = _environment_secrets()
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        process = subprocess.Popen(
            [sys.executable, "-P", "-m", WORKER, self._target],
            cwd=self._base_dir,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=sys.platform != "win32",
        )
        assert process.stdout is not None
        if self._spawned:
            self._restarts += 1
        self._spawned = True
        self._process = process
        self._lines = queue.Queue(maxsize=QUEUE_LINES)
        self._stop = threading.Event()
        threading.Thread(
            target=_read_lines, args=(process.stdout, self._lines, self._stop), daemon=True
        ).start()

    def _ensure_worker(self) -> str | None:
        """Start the worker if needed. Return why it cannot run, or None when it is ready."""
        if self._start_error is not None:
            return self._start_error
        if self._process is not None:
            return None
        try:
            self._spawn()
            ready = self._wait_for_ready()
        except (OSError, _WorkerFailure) as exc:
            message = str(exc) if isinstance(exc, _WorkerFailure) else f"cannot start: {exc}"
            self._discard()
            # Permanent for this run: an import error does not fix itself.
            self._start_error = self._clean(f"the decide worker could not start: {message}")
            return self._start_error
        self._batch = ready
        return None

    def _wait_for_ready(self) -> bool:
        try:
            line = self._lines.get(timeout=IMPORT_TIMEOUT_S)
        except queue.Empty:
            raise _WorkerFailure(
                f"timed out after {IMPORT_TIMEOUT_S:g}s while importing the target"
            ) from None
        if line is None:
            raise _WorkerFailure("the decide worker exited while importing the target")
        if isinstance(line, _Oversized):
            raise _WorkerFailure(OVERSIZED_MESSAGE)
        try:
            message = json.loads(line)
        except ValueError:
            raise _WorkerFailure("the decide worker sent an unreadable start message") from None
        if isinstance(message, dict) and isinstance(message.get("fatal"), str):
            raise _WorkerFailure(message["fatal"])
        if (
            not isinstance(message, dict)
            or message.get("ready") is not True
            or not isinstance(message.get("batch"), bool)
        ):
            raise _WorkerFailure("the decide worker sent an unreadable start message")
        return message["batch"]

    def _discard(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
        self._stop.set()
        if process.poll() is None:
            _kill_tree(process)
        for stream in (process.stdin, process.stdout):
            with contextlib.suppress(OSError, ValueError):
                if stream is not None:
                    stream.close()

    def _send(self, chunk: list[Query], timeout: float) -> list[Decision]:
        started = time.monotonic()
        try:
            answers = self._exchange(chunk, timeout)
        except _WorkerFailure as exc:
            self._discard()
            self._timed_out = exc.timed_out
            return [error_decision(self._clean(str(exc))) for _ in chunk]
        latency = max(0.0, (time.monotonic() - started) * 1000 / len(chunk))
        return [self._decision(answer, latency) for answer in answers]

    def _exchange(self, chunk: list[Query], timeout: float) -> list[Any]:
        deadline = time.monotonic() + timeout
        self._write(chunk)
        line = self._read_line(deadline, timeout)
        return self._validate(line, len(chunk))

    def _write(self, chunk: list[Query]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise _WorkerFailure("the decide worker exited")
        payload = json.dumps({"queries": [query.to_authzen() for query in chunk]})
        try:
            process.stdin.write(payload.encode("utf-8") + b"\n")
            process.stdin.flush()
        except (OSError, ValueError):
            raise _WorkerFailure("the decide worker exited") from None

    def _read_line(self, deadline: float, timeout: float) -> str:
        try:
            line = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            raise _WorkerFailure(f"timed out after {timeout:g}s", timed_out=True) from None
        if line is None:
            raise _WorkerFailure("the decide worker exited")
        if isinstance(line, _Oversized):
            raise _WorkerFailure(OVERSIZED_MESSAGE)
        return line

    def _validate(self, line: str, count: int) -> list[Any]:
        unreadable = _WorkerFailure("the decide worker sent an unreadable answer")
        try:
            message = json.loads(line)
        except ValueError:
            raise unreadable from None
        answers = message.get("answers") if isinstance(message, dict) else None
        if not isinstance(answers, list) or len(answers) != count:
            raise unreadable
        if not all(self._well_formed(answer) for answer in answers):
            raise unreadable
        return answers

    @staticmethod
    def _well_formed(answer: Any) -> bool:
        if not isinstance(answer, dict):
            return False
        if "error" in answer:
            return isinstance(answer["error"], str)
        reason = answer.get("reason")
        return isinstance(answer.get("decision"), bool) and (
            reason is None or isinstance(reason, str)
        )

    def _decision(self, answer: dict[str, Any], latency: float) -> Decision:
        if "error" in answer:
            return error_decision(self._clean(answer["error"]), latency_ms=latency)
        reason = answer.get("reason")
        return Decision(
            verdict=Verdict.ALLOW if answer["decision"] else Verdict.DENY,
            reason=self._clean(reason) if reason else None,
            latency_ms=latency,
        )
