"""The shapes every trace source is turned into.

OTLP files become RawSpan (ids, name, times, allowlisted attributes only). conventions.py
turns a RawSpan into a Span. A reader function returns Spans directly. Nothing here reads
files or runs code.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from lockwalk.config import ObserveConfig
from lockwalk.observe.door import DoorRecord
from lockwalk.observe.keys import BUILTIN_KEYS, SPAN_NAME

SpanKind = Literal["agent", "tool", "handoff", "other"]
ScalarValue = str | int | float | bool
MIB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    max_spans: int
    max_line_bytes: int
    max_total_bytes: int

    @classmethod
    def from_config(cls, config: ObserveConfig) -> "Limits":
        return cls(
            max_spans=config.max_spans,
            max_line_bytes=config.max_line_mb * MIB,
            max_total_bytes=config.max_total_mb * MIB,
        )


@dataclass(frozen=True, slots=True)
class RawSpan:
    """One OTLP span as read: only the attributes in the allowlist are kept."""

    trace_id: str  # 32 lower-case hex digits
    span_id: str  # 16 lower-case hex digits
    parent_id: str | None
    name: str  # used for matching only; never shown unless it matched
    start_ns: int | None
    end_ns: int | None
    attributes: Mapping[str, ScalarValue]
    where: str  # "<file name>:<line>", for messages
    # attributes is a plain mapping, not deep-frozen: treat it as read-only.


@dataclass(frozen=True, slots=True)
class Span:
    """One span after recognition, or as a reader function returned it."""

    trace_id: str
    span_id: str
    parent_id: str | None
    kind: SpanKind
    name: str | None = None  # agent or tool name as written in the trace; agent/tool only
    caller: str | None = None  # agent only: the explicit caller's name (graph.node.parent_id)
    handoff_from: str | None = None  # handoff only
    handoff_to: str | None = None  # handoff only
    start_ns: int | None = None
    end_ns: int | None = None
    unnamed_marker: bool = False  # kind "other" that had an agent or tool marker but no name
    where: str = ""
    door: DoorRecord | None = None  # at most one per span
    effect: bool = False  # lockwalk.effect = true on this span
    user_id: str | None = field(
        default=None, repr=False
    )  # the trace's user as seen on this span; never shown
    tool_call_id: str | None = None  # tool spans: gen_ai.tool.call.id


@dataclass(frozen=True)
class ReadProblem:
    where: str  # file and line, or "reader record N"
    message: str  # never quotes the input


@dataclass(frozen=True)
class ReadResult:
    raw: tuple[RawSpan, ...] = ()  # from OTLP files
    spans: tuple[Span, ...] = ()  # from a reader function, already recognized
    sources: tuple[str, ...] = ()  # what was read, for the report
    problems: tuple[ReadProblem, ...] = ()  # each makes the run exit 2
    warnings: tuple[str, ...] = ()
    truncated: bool = False  # a limit stopped the reading


def allowlist(config: ObserveConfig) -> frozenset[str]:
    """Every attribute observe may keep: the built-in ones, the ones the rules name, and the
    targets of [observe.attributes]."""
    keys = set(BUILTIN_KEYS)
    for rule in config.rules:
        keys.update(key for key in rule.when if key != SPAN_NAME)
        for source in (rule.name, rule.from_, rule.to, rule.tool_call_id):
            if source is not None and source != SPAN_NAME:
                keys.add(source)
    keys.update(config.attributes.values())
    return frozenset(keys)
