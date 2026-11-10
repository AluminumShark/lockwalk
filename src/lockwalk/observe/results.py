"""What lockwalk observe reports."""

from typing import Annotated, Literal, Self, get_args

from pydantic import Field, StrictInt, model_validator

from lockwalk.models import MAX_ROUTE_AGENTS, Frozen, WaiverRow

MAX_EXAMPLES = 3  # example trace ids kept per row
OBSERVE_SCHEMA_VERSION = "2"
OBSERVE_FILE_NAME = "observe.json"

Count = Annotated[StrictInt, Field(ge=0)]
PositiveCount = Annotated[StrictInt, Field(ge=1)]
Examples = Annotated[tuple[str, ...], Field(min_length=1, max_length=MAX_EXAMPLES)]
# Text that comes from traces. Builders (checks.py) truncate to this length and mask
# secrets before constructing a row; the model only enforces the bound.
ShownText = Annotated[str, Field(max_length=200)]
ShownPath = Annotated[tuple[str, ...], Field(min_length=1, max_length=MAX_ROUTE_AGENTS)]
TIMESTAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"


class RouteRow(Frozen):
    """One observed edge: user -> entry agent, agent -> agent, or agent -> tool."""

    from_id: str  # "user" or an agent id
    to_id: str  # an agent id or a tool id
    to_kind: Literal["agent", "tool"]
    status: Literal["ON_MAP", "OFF_MAP"]
    count: PositiveCount
    traces: Examples
    suggestion: str | None = None  # set exactly for OFF_MAP
    waived_by: str | None = None

    @model_validator(mode="after")
    def _suggestion_iff_off_map(self) -> Self:
        if (self.status == "OFF_MAP") != (self.suggestion is not None):
            raise ValueError("suggestion is set exactly for OFF_MAP rows")
        if self.from_id == "user" and self.to_kind != "agent":
            raise ValueError("the user only reaches agents")
        return self


class UnknownRow(Frozen):
    """A name in the traces the map does not know, or a tool call with no calling agent."""

    kind: Literal["agent", "tool", "caller"]  # caller: name is the tool whose caller is unknown
    name: str  # URL credentials masked, cut to 200 characters
    count: PositiveCount
    traces: Examples
    waived_by: str | None = None


IdentityResultName = Literal["MATCH", "MISMATCH", "OBSERVED", "INCONCLUSIVE"]
GuardStatus = Literal[
    "GUARDED", "DENIED", "DENIED_UNVERIFIED", "BYPASS", "UNGUARDED", "INCONCLUSIVE"
]
PathStatus = Literal["TESTED", "TESTED_OTHER_PATH", "UNTESTED"]


class IdentityRow(Frozen):
    """The identity the door really received, for one path, tool and mode."""

    path: ShownPath  # "?" for unknown steps
    tool: str | None  # None: a record not linked to a tool call
    mode: Literal["user", "agent", "on_behalf_of", "undeclared"]
    expected: ShownText  # shown form, e.g. "the trace's user", "agent:trade-agent"
    observed: ShownText  # shown form: never a user id
    result: IdentityResultName
    count: PositiveCount
    traces: Examples
    notes: tuple[ShownText, ...] = ()
    test_results: tuple[ShownText, ...] = ()  # e.g. ("CASE-003 direct: MATCH",)
    waived_by: str | None = None


class GuardRow(Frozen):
    """Tool calls of one calling agent and tool, by how the door treated them."""

    agent: str | None  # None: no calling agent
    tool: ShownText  # tool id, or the name as written for unknown tools
    tool_known: bool
    counts: dict[GuardStatus, PositiveCount]  # only statuses that occurred
    by_time: Count  # how many of the calls were linked by time
    effect_without_record: Count  # UNGUARDED calls that had an effect marker
    traces: tuple[str, ...] = Field(default=(), max_length=MAX_EXAMPLES)  # non-GUARDED examples
    waived_by: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if not self.counts:
            raise ValueError("counts must not be empty")
        order = get_args(GuardStatus)
        ordered = {status: self.counts[status] for status in order if status in self.counts}
        object.__setattr__(self, "counts", ordered)  # stable key order in the JSON
        total = sum(ordered.values())
        if self.by_time > total:
            raise ValueError("by_time cannot exceed the number of calls")
        if self.effect_without_record > ordered.get("UNGUARDED", 0):
            raise ValueError("effect_without_record cannot exceed the UNGUARDED calls")
        if set(ordered) != {"GUARDED"} and not self.traces:
            raise ValueError("a row with calls other than GUARDED needs example traces")
        return self


class PathRow(Frozen):
    """A path real traffic took, and whether a case tests it."""

    path: ShownPath
    tool: ShownText
    incomplete: bool
    status: PathStatus
    count: PositiveCount
    traces: Examples
    waived_by: str | None = None


class ObserveTotals(Frozen):
    files: Count
    traces: Count
    spans: Count
    agent_spans: Count
    tool_calls: Count
    incomplete_traces: Count
    error_traces: Count
    unnamed_markers: Count
    door_records: Count = 0
    records_without_call: Count = 0
    records_by_time: Count = 0
    calls_with_record: Count = 0  # non-wrapper tool calls with at least one linked record


class ObserveWindow(Frozen):
    first: str | None = Field(default=None, pattern=TIMESTAMP)  # earliest span start, UTC
    last: str | None = Field(default=None, pattern=TIMESTAMP)  # latest span start


# "bypass" has no gate key: it always blocks.
ObserveRuleName = Literal[
    "fail_on_off_map_route",
    "fail_on_unknown_component",
    "bypass",
    "fail_on_identity_mismatch",
    "fail_on_inconclusive_observation",
    "fail_on_unguarded_call",
    "fail_on_untested_path",
]

# rule -> (fields that must be set, fields that may be set). All other fields must be None.
_VIOLATION_FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "fail_on_off_map_route": (frozenset({"from_id", "to_id"}), frozenset()),
    "fail_on_unknown_component": (frozenset({"kind", "name"}), frozenset()),
    "bypass": (frozenset({"tool"}), frozenset({"agent"})),
    "fail_on_unguarded_call": (frozenset({"tool"}), frozenset({"agent"})),
    "fail_on_identity_mismatch": (frozenset({"path"}), frozenset({"tool"})),
    "fail_on_inconclusive_observation": (
        frozenset({"subject"}),
        frozenset({"path", "tool", "agent"}),
    ),
    "fail_on_untested_path": (frozenset({"path", "tool"}), frozenset()),
}
_VIOLATION_KEYS = ("from_id", "to_id", "kind", "name", "agent", "tool", "path", "subject")


class ObserveViolation(Frozen):
    rule: ObserveRuleName
    from_id: str | None = None  # route rules
    to_id: str | None = None
    kind: Literal["agent", "tool", "caller"] | None = None  # unknown rules
    name: str | None = None
    agent: str | None = None  # guard rules; None: no calling agent
    tool: str | None = None
    path: ShownPath | None = None  # identity and path rules
    subject: Literal["identity", "guard"] | None = None  # the inconclusive rule

    @model_validator(mode="after")
    def _fields_match_rule(self) -> Self:
        required, optional = _VIOLATION_FIELDS[self.rule]
        for key in _VIOLATION_KEYS:
            present = getattr(self, key) is not None
            if key in required and not present:
                raise ValueError(f"{self.rule} violations must set {key}")
            if present and key not in required and key not in optional:
                raise ValueError(f"{self.rule} violations must not set {key}")
        if self.rule == "fail_on_inconclusive_observation":
            needed = "path" if self.subject == "identity" else "tool"
            if getattr(self, needed) is None:
                raise ValueError(f"an inconclusive {self.subject} violation must set {needed}")
            if self.subject == "guard" and self.path is not None:
                raise ValueError("an inconclusive guard violation must not set path")
            if self.subject == "identity" and self.agent is not None:
                raise ValueError("an inconclusive identity violation must not set agent")
        return self


class ObserveWaived(Frozen):
    violation: ObserveViolation
    waiver_id: str


class ObserveGate(Frozen):
    passed: bool
    violations: tuple[ObserveViolation, ...] = ()
    waived: tuple[ObserveWaived, ...] = ()

    @model_validator(mode="after")
    def _passed_iff_no_violations(self) -> Self:
        if self.passed != (not self.violations):
            raise ValueError("passed is true exactly when there are no violations")
        blocking = set(self.violations)
        if any(item.violation in blocking for item in self.waived):
            raise ValueError("a violation cannot be both blocking and waived")
        return self


class ObserveReport(Frozen):
    kind: Literal["observe"] = "observe"
    scenario_suite: str
    sources: tuple[str, ...]
    totals: ObserveTotals
    window: ObserveWindow
    routes: tuple[RouteRow, ...] = ()
    unknown: tuple[UnknownRow, ...] = ()
    identities: tuple[IdentityRow, ...] = ()
    guards: tuple[GuardRow, ...] = ()
    paths: tuple[PathRow, ...] = ()
    waivers: tuple[WaiverRow, ...] = ()
    gate: ObserveGate
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    exit_code: Literal[0, 1, 2]

    @model_validator(mode="after")
    def _exit_code(self) -> Self:
        expected = 2 if self.errors else (0 if self.gate.passed else 1)
        if self.exit_code != expected:
            raise ValueError(f"exit_code must be {expected}")
        return self
