"""Run the user's reader function and check what it returns.

The function runs in a subprocess (see _reader_worker), started and cleaned up like the
harness worker. The parent never trusts the records file: it re-checks every limit while
reading, parses each line with duplicate keys refused, and validates it with ReaderRecord.
Every message that comes from user code is masked first and truncated second.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BeforeValidator,
    Field,
    StrictBool,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from lockwalk.harness.runner import (
    POLL_S,
    _exited,
    _JobObject,
    _stop,
    clean,
    open_regular,
    read_bounded,
    wait_for_exit,
)
from lockwalk.jsonvalues import reject_duplicate_keys
from lockwalk.masking import describe_validation_error
from lockwalk.models import Frozen
from lockwalk.observe.door import MAX_DOOR_TEXT, DoorRecord, act_links
from lockwalk.observe.spans import Limits, ReadProblem, ReadResult, Span, SpanKind

WORKER = "lockwalk.observe._reader_worker"
MAX_RESULT_BYTES = 64 * 1024
MAX_RECORD_PROBLEMS = 100
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

Text = Annotated[str, StringConstraints(min_length=1, max_length=MAX_DOOR_TEXT)]
Id = Annotated[str, StringConstraints(min_length=1, max_length=256)]


# A date and a time at least: pydantic would also read "1767225600" as an epoch time.
_ISO_START = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}")


def _iso_only(value: object) -> object:
    """Only ISO 8601 strings: an epoch number would be read as seconds or milliseconds."""
    if not isinstance(value, str) or not _ISO_START.match(value):
        raise ValueError("must be an ISO 8601 string with a time zone")
    return value


Moment = Annotated[AwareDatetime, BeforeValidator(_iso_only)]


class ReaderSubject(Frozen):
    type: Text
    id: Text
    # Given as nested {type, id, act} objects (outermost first); kept as (type, id) pairs.
    act: tuple[tuple[str, str], ...] = ()

    @field_validator("act", mode="before")
    @classmethod
    def _act_chain(cls, value: object) -> object:
        if value is None:
            return ()
        if not isinstance(value, dict):
            raise ValueError("must be an object with type and id")
        return act_links(value)  # raises ValueError without quoting the input


class ReaderDoor(Frozen):
    """One authorization record as the user's reader function returns it."""

    decision: Literal["allow", "deny", "error"]
    subject: ReaderSubject
    action: Text
    resource_type: Text | None = None
    tool_call_id: Text | None = None

    def to_record(self) -> DoorRecord:
        return DoorRecord(
            decision=self.decision,
            subject_type=self.subject.type,
            subject_id=self.subject.id,
            act=self.subject.act,
            action=self.action,
            resource_type=self.resource_type,
            tool_call_id=self.tool_call_id,
        )


class ReaderRecord(Frozen):
    """One span as the user's reader function returns it."""

    trace_id: Id
    span_id: Id
    parent_id: Id | None = None
    kind: SpanKind
    name: Text | None = None  # required for agent and tool
    caller: Text | None = None  # agent only
    from_: Text | None = Field(default=None, alias="from")  # handoff only
    to: Text | None = None  # handoff only
    start: Moment | None = None
    end: Moment | None = None
    user_id: Text | None = None
    authz: list[ReaderDoor] | None = None  # becomes child spans
    effect: StrictBool | None = None
    tool_call_id: Text | None = None  # tool only

    @field_validator("span_id", "parent_id")
    @classmethod
    def _no_hash(cls, value: str | None) -> str | None:
        # "#" is reserved for the child ids of authz items (`<span_id>#door<n>`).
        if value is not None and "#" in value:
            raise ValueError("must not contain '#'")
        return value

    @model_validator(mode="after")
    def _fields_match_kind(self) -> "ReaderRecord":
        if (self.kind in ("agent", "tool")) != (self.name is not None):
            raise ValueError("'name' is required for agent and tool spans, and only for them")
        if self.caller is not None and self.kind != "agent":
            raise ValueError("'caller' is only for agent spans")
        if self.tool_call_id is not None and self.kind != "tool":
            raise ValueError("'tool_call_id' is only for tool spans")
        both = self.from_ is not None and self.to is not None
        either = self.from_ is not None or self.to is not None
        if (self.kind == "handoff" and not both) or (self.kind != "handoff" and either):
            raise ValueError("'from' and 'to' are required for handoff spans, and only for them")
        return self


def _nanoseconds(moment: datetime | None) -> int | None:
    if moment is None:
        return None
    delta = moment - _EPOCH  # exact integer arithmetic, no float
    return ((delta.days * 86400 + delta.seconds) * 10**6 + delta.microseconds) * 1000


def _to_spans(record: ReaderRecord, where: str) -> list[Span]:
    """The record's span, then one child span per authz item (ids `<span_id>#door<n>`)."""
    start, end = _nanoseconds(record.start), _nanoseconds(record.end)
    spans = [
        Span(
            trace_id=record.trace_id,
            span_id=record.span_id,
            parent_id=record.parent_id,
            kind=record.kind,
            name=record.name,
            caller=record.caller,
            handoff_from=record.from_,
            handoff_to=record.to,
            start_ns=start,
            end_ns=end,
            where=where,
            effect=record.effect is True,
            user_id=record.user_id,
            tool_call_id=record.tool_call_id,
        )
    ]
    for number, item in enumerate(record.authz or (), start=1):
        spans.append(
            Span(
                trace_id=record.trace_id,
                span_id=f"{record.span_id}#door{number}",
                parent_id=record.span_id,
                kind="other",
                start_ns=start,
                end_ns=end,
                where=where,
                door=item.to_record(),
            )
        )
    return spans


@dataclass(frozen=True)
class _WorkerResult:
    count: int
    stopped: str | None
    error: str | None


def run_reader(
    target: str,
    *,
    cwd: Path,
    paths: Sequence[str],
    timeout_s: float,
    limits: Limits,
    only_trace: str | None = None,
) -> ReadResult:
    """Run the reader function and turn its records into Spans. Never raises."""
    sources = (f"reader {target}",)

    def failed(message: str) -> ReadResult:
        return ReadResult(sources=sources, problems=(ReadProblem(sources[0], message),))

    with tempfile.TemporaryDirectory(prefix="lockwalk-reader-", ignore_cleanup_errors=True) as tmp:
        request_path, out = Path(tmp) / "request.json", Path(tmp) / "out"
        request = {
            "target": target,
            "paths": list(paths),
            "max_records": limits.max_spans,
            "max_line_bytes": limits.max_line_bytes,
            "max_total_bytes": limits.max_total_bytes,
        }
        try:
            request_path.write_text(json.dumps(request), encoding="utf-8")
            out.mkdir()
        except (OSError, ValueError) as exc:
            return failed(f"cannot prepare the reader request: {type(exc).__name__}")
        command = [sys.executable, "-P", "-m", WORKER, str(request_path), str(out)]
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=sys.platform != "win32",
            )
        except OSError as exc:
            reason = f": {exc.strerror}" if exc.strerror else ""
            return failed(f"cannot start the reader: {type(exc).__name__}{reason}")
        job_object = None
        try:
            job_object = _JobObject.attach(process) if sys.platform == "win32" else None
            outcome = _wait(process, out / "result.json", timeout_s)
        finally:
            _stop(process)
            if job_object is not None:
                job_object.close()  # kills every process still in the job
        if outcome == "timeout":
            return failed(
                f"the reader did not finish within {timeout_s:g}s ([observe] reader_timeout_s)"
            )
        if outcome == "exited":
            return failed("the reader process exited without a result")
        result = _parse_result(out / "result.json", limits.max_spans)
        if isinstance(result, str):
            return failed(result)
        return _read_records(out / "records.jsonl", result, sources, limits, only_trace)


def _wait(process: "subprocess.Popen[bytes]", result_path: Path, timeout_s: float) -> str:
    """'done' when result.json exists, else 'timeout' or 'exited'."""
    deadline = time.monotonic() + timeout_s
    while not os.path.lexists(result_path):
        if _exited(process):
            if os.path.lexists(result_path):  # written just before the exit
                break
            return "exited"
        if time.monotonic() >= deadline:
            return "timeout"
        time.sleep(POLL_S)
    wait_for_exit(process)
    return "done"


def _parse_result(path: Path, max_records: int) -> _WorkerResult | str:
    unreadable = "the reader process wrote an unreadable result"
    try:
        data = read_bounded(path, MAX_RESULT_BYTES)
        if len(data) > MAX_RESULT_BYTES:
            return unreadable
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, ValueError, RecursionError):
        return unreadable
    if not isinstance(raw, dict) or set(raw) != {"count", "stopped", "error"}:
        return unreadable
    count, stopped, error = raw["count"], raw["stopped"], raw["error"]
    if type(count) is not int or not 0 <= count <= max_records:
        return unreadable
    if stopped not in (None, "too_many", "too_large"):
        return unreadable
    if error is not None and not isinstance(error, str):
        return unreadable
    return _WorkerResult(count, stopped, error)


def _read_records(
    path: Path,
    result: _WorkerResult,
    sources: tuple[str, ...],
    limits: Limits,
    only_trace: str | None,
) -> ReadResult:
    where = sources[0]
    problems: list[ReadProblem] = []
    spans: list[Span] = []
    skipped = 0
    truncated = False

    def bad(position: int, message: str) -> None:
        nonlocal skipped
        if len(problems) < MAX_RECORD_PROBLEMS:
            problems.append(ReadProblem(f"reader record {position}", clean(message)))
        else:
            skipped += 1

    if result.error is not None:
        problems.append(ReadProblem(where, f"the reader failed: {clean(result.error)}"))
    if result.stopped == "too_many":
        truncated = True
        problems.append(
            ReadProblem(
                where,
                f"the reader returned more than {limits.max_spans} records ([observe] max_spans)",
            )
        )
    elif result.stopped == "too_large":
        truncated = True
        problems.append(
            ReadProblem(
                where,
                "the reader's records are larger than the limit "
                "([observe] max_line_mb, max_total_mb)",
            )
        )
    try:
        with open_regular(path) as handle:
            total = 0
            for position in range(1, result.count + 1):
                line = handle.readline(limits.max_line_bytes + 2)
                total += len(line)
                if (
                    not line.endswith(b"\n")
                    or len(line) - 1 > limits.max_line_bytes
                    or total > limits.max_total_bytes
                ):
                    problems.append(ReadProblem(where, "the reader process wrote bad records"))
                    break
                try:
                    value = json.loads(
                        line.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
                    )
                except (ValueError, RecursionError):
                    bad(position, "the record is not valid UTF-8 JSON, or repeats a key")
                    continue
                try:
                    record = ReaderRecord.model_validate(value)
                except ValidationError as exc:
                    bad(position, describe_validation_error(exc))
                    continue
                if only_trace is None or record.trace_id == only_trace:
                    spans.extend(_to_spans(record, f"reader record {position}"))
    except OSError:
        problems.append(ReadProblem(where, "the reader process wrote an unreadable records file"))
    if skipped:
        problems.append(ReadProblem(where, f"{skipped} more records did not validate"))
    return ReadResult(
        spans=tuple(spans), sources=sources, problems=tuple(problems), truncated=truncated
    )
