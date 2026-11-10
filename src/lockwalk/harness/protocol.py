"""What the harness parent and its worker subprocess send each other.

The parent writes a WorkerRequest to a JSON file; the worker writes a WorkerResult to
<output-dir>/result.json. Both sides validate with these models. The worker shares its
process with the user's code, so a result that does not validate is an ERROR, never a
PASS.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StrictInt, model_validator

from lockwalk.models import MAX_QUERY_DEPTH, DoorCall, Frozen

SCRIPTED_TEXT = "lockwalk scripted run"  # the user message, and every fake final answer
MAX_DOOR_CALLS = 20  # door calls kept per run; the rest are only counted
MAX_TIMELINE = 200  # timeline entries kept per run; the rest are only counted
MAX_TIMELINE_TEXT = 512  # characters per string in a timeline entry; more is not kept
TimelineKind = Literal["identity", "door", "effect"]

ToolKind = Literal["openai_agents", "langchain", "pydantic_ai", "agno", "crewai", "function"]
Framework = Literal["openai_agents", "pydantic_ai", "langgraph", "other"]
StepKind = Literal["handoff", "agent_tool", "tool", "pass"]


class TargetRef(Frozen):
    """One [[inventory.python]] target, and the directory it is resolved from."""

    target: str
    base_dir: str


class ToolInfo(Frozen):
    name: str
    kind: ToolKind
    input_schema: dict[str, Any] | None = None  # None: lockwalk could not read one
    callable: bool = True  # whether direct mode can call it
    why_not: str | None = None  # set exactly when callable is False

    @model_validator(mode="after")
    def _why_not_iff_not_callable(self) -> Self:
        if self.callable == (self.why_not is not None):
            raise ValueError("why_not is set exactly when the tool is not callable")
        return self


class AgentInfo(Frozen):
    id: str
    framework: Framework
    # wrapped agent id -> the tool that wraps it (OpenAI Agents SDK as_tool)
    agent_tools: dict[str, ToolInfo] = Field(default_factory=dict)


class Survey(Frozen):
    """What the hooks file and the targets hold. The parent plans every run from it."""

    side_effects: dict[str, str]  # tool name -> "module.attr"
    door: bool
    run_path: bool
    tools: dict[str, ToolInfo]
    agents: dict[str, AgentInfo]
    replaced: dict[str, int]  # tool name -> places its side effect function was replaced
    problems: tuple[str, ...] = ()  # anything here makes every door test ERROR
    warnings: tuple[str, ...] = ()


class Step(Frozen):
    """What one agent's fake model does on its first turn."""

    agent: str
    kind: StepKind
    target: str  # the next agent id; for kind "tool", the tool name
    tool: str | None = None  # the tool to call, for "agent_tool" and "tool"
    args: dict[str, Any] | None = None


class TimelineEntry(Frozen):
    """One moment of a run as the worker saw it.

    at_ms counts from the start of the job, after the user's code was imported. identity:
    data is the reduced subject the run started with; door: data is the recorded door call;
    effect: tool names the tool whose side effect was counted, and data is None.
    """

    seq: Annotated[StrictInt, Field(ge=1)]
    at_ms: Annotated[float, Field(ge=0, allow_inf_nan=False, strict=True)]
    kind: TimelineKind
    tool: str | None = None
    data: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _fields_match_kind(self) -> Self:
        effect = self.kind == "effect"
        if effect != (self.tool is not None):
            raise ValueError("tool is set exactly for effect entries")
        if effect == (self.data is not None):
            raise ValueError("data is set exactly for identity and door entries")
        return self


class SurveyJob(Frozen):
    mode: Literal["survey"] = "survey"


class DirectJob(Frozen):
    mode: Literal["direct"] = "direct"
    case_id: str
    tool: str
    args: dict[str, Any]
    subject: dict[str, Any]  # what set_identity receives


class ScriptedJob(Frozen):
    mode: Literal["scripted"] = "scripted"
    case_id: str
    route: tuple[str, ...]
    tool: str
    args: dict[str, Any]
    subject: dict[str, Any]  # the user the run starts as
    steps: tuple[Step, ...] = ()
    use_run_path: bool = False


Job = Annotated[SurveyJob | DirectJob | ScriptedJob, Field(discriminator="mode")]


class WorkerRequest(Frozen):
    hooks: str  # absolute path of the hooks file
    targets: tuple[TargetRef, ...]
    allow_hosts: tuple[str, ...]
    job: Job


class Observation(Frozen):
    """What one run saw, as the worker reports it. Messages are not masked yet.

    door_calls are already reduced by the door recorder: {"subject": reduce_subject(...),
    "decision": bool} or {"error": str}.
    """

    side_effect_calls: Annotated[StrictInt, Field(ge=0)] = 0
    door_calls: tuple[dict[str, Any], ...] = ()
    door_calls_dropped: Annotated[StrictInt, Field(ge=0)] = 0
    bypass: bool = False
    exception: str | None = None
    exception_message: str | None = None
    not_run: str | None = None
    blocked_hosts: tuple[str, ...] = ()
    error: str | None = None
    timeline: Annotated[tuple[TimelineEntry, ...], Field(max_length=MAX_TIMELINE)] = ()
    timeline_dropped: Annotated[StrictInt, Field(ge=0)] = 0
    elapsed_ms: Annotated[float, Field(ge=0, allow_inf_nan=False, strict=True)] | None = None


class WorkerResult(Frozen):
    fatal: str | None = None
    survey: Survey | None = None
    observation: Observation | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if sum(x is not None for x in (self.fatal, self.survey, self.observation)) != 1:
            raise ValueError("a worker result holds exactly one of fatal, survey, observation")
        return self


@dataclass(frozen=True)
class TimelineItem:
    """A TimelineEntry after the parent checked and cleaned it."""

    seq: int
    at_ms: float
    kind: TimelineKind
    tool: str | None = None  # effect
    call: DoorCall | None = None  # door: checked like Observed.door_calls
    subject: dict[str, Any] | None = None  # identity; None when the worker sent junk


@dataclass(frozen=True)
class Observed:
    """One run as the parent judges it: door calls checked, messages masked and truncated."""

    side_effect_calls: int = 0
    door_calls: tuple[DoorCall, ...] = ()
    bypass: bool = False
    exception: str | None = None
    exception_message: str | None = None
    not_run: str | None = None
    blocked_hosts: tuple[str, ...] = ()
    error: str | None = None  # set: the run is ERROR
    timeline: tuple[TimelineItem, ...] = ()
    timeline_dropped: int = 0
    elapsed_ms: float | None = None  # how long the job ran inside the worker


def has_long_string(value: object, limit: int = MAX_TIMELINE_TEXT) -> bool:
    """True if any string, dict key, or nested value is longer than limit. Linear, no recursion.

    Expects acyclic input (JSON, or reduce_subject output).
    """
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if len(item) > limit:
                return True
        elif isinstance(item, Mapping):
            for key, inner in item.items():
                stack.append(key)
                stack.append(inner)
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return False


def reduce_subject(value: object) -> dict[str, Any] | None:
    """type, id, and the act chain of a subject in lockwalk's format; None if malformed.

    In lockwalk's format the top-level act sits in properties.act, and inner links hold act
    directly. The result holds act directly at every level. Properties are
    dropped: the comparison uses only types and ids, and property values may be secret.
    The top-level act is read from properties.act when that exists, else from a direct act
    key, so reducing an already reduced subject changes nothing (idempotent).
    """
    out: dict[str, Any] | None = None
    current: dict[str, Any] | None = None
    item: object = value
    for depth in range(MAX_QUERY_DEPTH + 1):
        if not isinstance(item, Mapping):
            return None
        kind, ident = item.get("type"), item.get("id")
        if not isinstance(kind, str) or not isinstance(ident, str) or not kind or not ident:
            return None
        link: dict[str, Any] = {"type": kind, "id": ident}
        if current is None:
            out = link
        else:
            current["act"] = link
        current = link
        if depth == 0:
            properties = item.get("properties")
            if isinstance(properties, Mapping) and "act" in properties:
                item = properties["act"]
            else:
                item = item.get("act")  # an already reduced subject
        else:
            item = item.get("act")
        if item is None:
            return out
    return None  # deeper than MAX_QUERY_DEPTH
