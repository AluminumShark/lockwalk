"""The evidence file of `lockwalk test`: .lockwalk/evidence.jsonl.

The first line is an EvidenceHeader; every other line is one Event, in time order and
numbered E-0001, E-0002, ... The header's run id equals coverage.json's run_id, and its
`events` count lets a reader notice a file that was cut off. read_evidence trusts nothing:
anything unexpected is an EvidenceFileError, whose message never quotes the file.
"""

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self, TypeVar

from pydantic import Field, StrictInt, ValidationError, field_validator, model_validator

from lockwalk.jsonvalues import DuplicateKeyError, check_json_value, reject_duplicate_keys
from lockwalk.masking import describe_validation_error
from lockwalk.models import MAX_QUERY_DEPTH, EvidenceId, Frozen, HarnessMode, RunId
from lockwalk.output_files import write_text_atomic

EVIDENCE_FILE_NAME = "evidence.jsonl"
EVIDENCE_SCHEMA_VERSION = "1"
MAX_EVIDENCE_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
# The deepest detail is an authz.evaluated one: the request sits at depth 1, its subject at 2,
# and the subject's properties (up to MAX_QUERY_DEPTH levels) at 3.
MAX_DETAIL_DEPTH = MAX_QUERY_DEPTH + 3

EventType = Literal[
    "run.started",
    "run.finished",
    "authz.evaluated",
    "harness.job",
    "door.identity_set",
    "door.called",
    "effect.counted",
    "tool.raised",
    "run.error",
]
EventSource = Literal["test_runner", "policy_adapter", "harness"]
SOURCE_OF: dict[str, EventSource] = {
    "run.started": "test_runner",
    "run.finished": "test_runner",
    "authz.evaluated": "policy_adapter",
    "harness.job": "harness",
    "door.identity_set": "harness",
    "door.called": "harness",
    "effect.counted": "harness",
    "tool.raised": "harness",
    "run.error": "harness",
}
QueryId = Annotated[str, Field(pattern=r"^Q-[0-9]{4,}$")]
InvocationId = Annotated[str, Field(pattern=r"^I-[0-9]{4,}$")]


def event_id(number: int) -> str:
    return f"E-{number:04d}"


def query_id(number: int) -> str:
    return f"Q-{number:04d}"


def invocation_id(number: int) -> str:
    return f"I-{number:04d}"


def new_run_id() -> str:
    return uuid.uuid4().hex


def id_number(value: str) -> int:
    """The number of an E-, Q-, or I- id, for sorting (E-10000 sorts after E-9999).

    Expects an id that is already validated.
    """
    return int(value[2:])


class EvidenceHeader(Frozen):
    kind: Literal["lockwalk-evidence"] = "lockwalk-evidence"
    schema_version: Literal["1"] = EVIDENCE_SCHEMA_VERSION
    run: RunId
    lockwalk_version: str
    started_at: str  # UTC, like 2026-11-08T10:00:00Z
    events: Annotated[StrictInt, Field(ge=0)]  # how many event lines follow


class Event(Frozen):
    event: EvidenceId
    run: RunId
    time: Annotated[
        float, Field(ge=0, allow_inf_nan=False, strict=True)
    ]  # seconds since the run started
    source: EventSource
    type: EventType
    case: str | None = None
    mode: HarnessMode | None = None
    invocation: InvocationId | None = None
    query: QueryId | None = None
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detail")
    @classmethod
    def _detail_is_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_json_value(value, "detail", allow_null=True, max_depth=MAX_DETAIL_DEPTH)
        return value

    @model_validator(mode="after")
    def _fields_match_type(self) -> Self:
        if SOURCE_OF[self.type] != self.source:
            raise ValueError(f"{self.type} events come from {SOURCE_OF[self.type]}")
        if (self.type == "authz.evaluated") != (self.query is not None):
            raise ValueError("query is set exactly for authz.evaluated events")
        harness = self.source == "harness"
        if harness != (self.mode is not None):
            raise ValueError("mode is set exactly for harness events")
        if harness != (self.invocation is not None):
            raise ValueError("invocation is set exactly for harness events")
        if harness != (self.case is not None):
            raise ValueError("case is set exactly for harness events")
        return self


@dataclass(frozen=True)
class Evidence:
    header: EvidenceHeader
    events: tuple[Event, ...]


class EvidenceFileError(Exception):
    """evidence.jsonl cannot be trusted. The message says why, never quoting the file."""


def event_line(event: Event) -> str:
    """The JSON line write_evidence stores for one event (without the newline)."""
    return json.dumps(event.model_dump(mode="json"), ensure_ascii=False, allow_nan=False)


def event_line_bytes(event: Event) -> int:
    """Bytes of the event's line on disk, newline included (as write_text_atomic encodes it)."""
    return len(event_line(event).encode("utf-8", errors="backslashreplace")) + 1


def write_evidence(evidence: Evidence, output_dir: Path) -> Path:
    """Write <output_dir>/evidence.jsonl atomically and return its path."""
    lines = [evidence.header.model_dump_json()]
    lines.extend(event_line(event) for event in evidence.events)
    path = output_dir / EVIDENCE_FILE_NAME
    write_text_atomic(path, "\n".join(lines) + "\n", prefix=".evidence-")
    return path


def read_evidence(path: Path) -> Evidence:
    """Read and check evidence.jsonl.

    FileNotFoundError when it does not exist; any other OS error is an EvidenceFileError.
    """
    try:
        return _read(path)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise EvidenceFileError(f"{path.name} cannot be read ({type(exc).__name__})") from None


def _read(path: Path) -> Evidence:
    size = path.stat().st_size
    if size > MAX_EVIDENCE_BYTES:
        raise EvidenceFileError(f"{path.name} is larger than {MAX_EVIDENCE_BYTES >> 20} MiB")
    header: EvidenceHeader | None = None
    events: list[Event] = []
    last_time = 0.0
    with path.open("rb") as stream:
        number = 0
        while True:
            raw = stream.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            number += 1
            if len(raw) > MAX_LINE_BYTES:
                raise EvidenceFileError(
                    f"line {number} is longer than {MAX_LINE_BYTES} bytes including the newline"
                )
            item = _parse(raw, number)
            if header is None:
                header = _validate(EvidenceHeader, item, number)
                continue
            event = _validate(Event, item, number)
            if event.run != header.run:
                raise EvidenceFileError(f"line {number} belongs to another run")
            if event.event != event_id(len(events) + 1):
                raise EvidenceFileError(f"line {number}: event ids are not in order")
            if event.time < last_time:
                raise EvidenceFileError(f"line {number}: the time goes backwards")
            last_time = event.time
            events.append(event)
    if header is None:
        raise EvidenceFileError(f"{path.name} is empty")
    if len(events) != header.events:
        raise EvidenceFileError(
            f"{path.name} has {len(events)} events, but its header says {header.events}"
        )
    return Evidence(header=header, events=tuple(events))


def _parse(raw: bytes, number: int) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except DuplicateKeyError:
        raise EvidenceFileError(f"line {number}: a JSON object repeats a key") from None
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise EvidenceFileError(f"line {number} is not valid JSON") from None


_M = TypeVar("_M", bound=Frozen)  # a TypeVar, not 3.12 generics: the project supports 3.11


def _validate(model: type[_M], item: Any, number: int) -> _M:
    if not isinstance(item, dict):
        raise EvidenceFileError(f"line {number} is not a JSON object")
    try:
        return model.model_validate(item)
    except ValidationError as exc:
        raise EvidenceFileError(f"line {number}: {describe_validation_error(exc)}") from None
