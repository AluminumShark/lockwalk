"""Shared data types.

Models are immutable at the attribute level: fields cannot be reassigned. Dict
fields are not deep-frozen, so callers must treat them as read-only.
"""

import math
import unicodedata
from collections.abc import Mapping
from datetime import date
from enum import StrEnum
from functools import cached_property
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from lockwalk.jsonvalues import check_json_value
from lockwalk.urls import redact_url


class Frozen(BaseModel):
    """Base model: immutable, and unknown fields are rejected."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Risk(StrEnum):
    """Risk level of a tool. UNKNOWN means no registry entry declares it."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class CaseStatus(StrEnum):
    """Status of one spec case.

    Static mode only produces UNTESTED and ERROR; `lockwalk test` also produces PASS,
    FAIL_POLICY, and INCONCLUSIVE.
    """

    PASS = "PASS"
    FAIL_POLICY = "FAIL_POLICY"
    FAIL_EXECUTION = "FAIL_EXECUTION"
    UNTESTED = "UNTESTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class ToolCoverage(StrEnum):
    """Whether at least one spec case targets a tool."""

    SPECIFIED = "SPECIFIED"
    UNSPECIFIED = "UNSPECIFIED"


MAX_NAME_LENGTH = 200
# Control, format, surrogate, private-use, unassigned, line separator, paragraph separator.
FORBIDDEN_NAME_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def check_name(value: str) -> str:
    """Validate a tool or agent name; raise ValueError if it is not acceptable.

    Names are not limited to letters and digits, because some frameworks use
    human-readable tool names that contain spaces.
    """
    if not value:
        raise ValueError("name must not be empty")
    if len(value) > MAX_NAME_LENGTH:
        raise ValueError(f"name must be at most {MAX_NAME_LENGTH} characters")
    if value != value.strip():
        raise ValueError("name must not start or end with whitespace")
    if any(unicodedata.category(char) in FORBIDDEN_NAME_CATEGORIES for char in value):
        raise ValueError("name must not contain control, invisible, or unassigned characters")
    return value


def _check_text(value: str) -> str:
    if not value or value != value.strip():
        raise ValueError("must not be empty or start/end with whitespace")
    return value


def _coerce_schema_version(value: object) -> object:
    # YAML reads an unquoted 1 as an integer; treat it the same as "1".
    if type(value) is int and value == 1:
        return "1"
    return value


def _require_number(value: object) -> object:
    # pydantic would otherwise turn true/false into 1.0/0.0 seconds, and "5" into 5.0.
    if isinstance(value, bool):
        raise ValueError("must be a number, not a boolean")
    if not isinstance(value, int | float):
        raise ValueError("must be a number of seconds")
    return value


Name = Annotated[str, AfterValidator(check_name)]
NonEmptyStr = Annotated[str, AfterValidator(_check_text)]
SchemaVersion = Annotated[Literal["1"], BeforeValidator(_coerce_schema_version)]
CaseId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]
Seconds = Annotated[float, BeforeValidator(_require_number), Field(gt=0, le=600)]
SourceKind = Literal["registry", "mcp", "python", "json"]
Expectation = Literal["allow", "deny"]
DelegationMode = Literal["user", "agent", "on_behalf_of"]
# Whose identity one question is asked with. "undeclared": no delegation_mode is known, so
# lockwalk asks with both the user and the agent identity.
# "observed": scripted mode saw which identity the door really received, and lockwalk
# asked the IAM with that identity.
IdentityMode = Literal["user", "agent", "on_behalf_of", "undeclared", "observed"]

HarnessMode = Literal["direct", "scripted"]


class SpecState(StrEnum):
    """Spec state of a tool: YES has a valid case, ERROR has only invalid cases.

    Tools without any case have no state; reports show them as "NO".
    """

    YES = "yes"
    ERROR = "ERROR"


class NodeKind(StrEnum):
    """Kind of a node in the agent call graph. Tools are not nodes."""

    AGENT = "agent"
    REMOTE_AGENT = "remote_agent"
    MCP_SERVER = "mcp_server"


class EdgeKind(StrEnum):
    """How one node can reach another node or a tool."""

    USES_TOOL = "uses_tool"
    AGENT_AS_TOOL = "agent_as_tool"
    HANDOFF = "handoff"
    TEAM = "team"
    REMOTE = "remote"
    CALLS = "calls"


class Provenance(StrEnum):
    """Where an edge came from: read from code, guessed, or written by hand."""

    DISCOVERED = "discovered"
    INFERRED = "inferred"
    DECLARED = "declared"


class GraphNode(Frozen):
    """An agent, a remote agent, or an MCP server boundary.

    roles is None when no roles were declared. opaque nodes hide what lies behind them.
    tools_hidden means discovery could not read all of the agent's tools (a tools factory,
    a tool that raised, an unnamed MCP server, and so on); such an agent is always opaque,
    and declaring its `calls` cannot change that, because `calls` only lists agents.
    remote_url is already stripped of credentials, query, and fragment.
    """

    id: Name
    kind: NodeKind = NodeKind.AGENT
    entry: bool = False
    roles: tuple[str, ...] | None = None
    delegation_mode: DelegationMode | None = None
    opaque: bool = False
    tools_hidden: bool = False
    remote_url: Annotated[str, AfterValidator(redact_url)] | None = None
    sources: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _hidden_tools_are_opaque(self) -> Self:
        if self.tools_hidden and not self.opaque:
            raise ValueError("a node whose tools are hidden must be opaque")
        return self


class GraphEdge(Frozen):
    """One possible call. to_id names a tool when kind is USES_TOOL, otherwise a node.

    wrapped_by holds the names of the tools that made an AGENT_AS_TOOL edge, when discovery
    could read them (for example `ask_trade_agent` from `trade_agent.as_tool(...)`). It is
    empty when no name is known; observe then does not know the wrapper either.
    """

    from_id: Name
    to_id: Name
    kind: EdgeKind
    provenance: Provenance
    sources: tuple[str, ...] = ()
    wrapped_by: tuple[Name, ...] = ()


class GraphFragment(Frozen):
    """What one discovery source saw of the agent call graph."""

    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()


class ToolDescriptor(Frozen):
    """One tool as reported by any source, after normalization."""

    name: Name
    description: str | None = None
    hints: dict[str, StrictBool] = Field(default_factory=dict)


class SourceRef(Frozen):
    """Where tools came from, for example kind="mcp", label="mcp:finance-tools"."""

    kind: SourceKind
    label: str


class SourceResult(Frozen):
    """What one inventory source returned. A failed source may still carry some tools."""

    source: SourceRef
    ok: bool
    tools: tuple[ToolDescriptor, ...] = ()
    error: str | None = None
    warnings: tuple[str, ...] = ()
    agents: tuple[Name, ...] = ()
    graph: GraphFragment | None = None
    optional: bool = False

    @property
    def unavailable(self) -> bool:
        """An optional source that could not be read at all.

        It is treated as an opaque part of the graph, not as an error.
        """
        return self.optional and not self.ok and not self.tools


class InventoryTool(Frozen):
    """One tool after merging the registry with every discovery source."""

    id: str
    action: str | None
    risk: Risk
    resource_type: str | None
    supported_agents: tuple[str, ...]
    sources: tuple[str, ...]
    description: str | None
    hints: dict[str, StrictBool]


class Drift(Frozen):
    """Differences between the registry and what the discovery sources reported."""

    discovered_only: tuple[str, ...]
    registry_only: tuple[str, ...]
    complete: bool


class Inventory(Frozen):
    """Every known agent and tool, plus the state of each source."""

    agents: tuple[str, ...]
    tools: tuple[InventoryTool, ...]
    sources: tuple[SourceResult, ...]
    drift: Drift | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    # Registry delegation tools: tool id -> the agent it really is. Not part of `tools`.
    delegation_agents: dict[str, str] = Field(default_factory=dict)

    @cached_property
    def _tools_by_id(self) -> dict[str, InventoryTool]:
        """Tool id -> tool, built on first use. The first tool wins when an id repeats."""
        index: dict[str, InventoryTool] = {}
        for tool in self.tools:
            index.setdefault(tool.id, tool)
        return index

    def tool(self, tool_id: str) -> InventoryTool | None:
        """Return the first tool with this id, or None. Constant time after the first call."""
        return self._tools_by_id.get(tool_id)

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy the model; the lookup index is dropped so it is rebuilt from the copy's tools."""
        copied = super().model_copy(update=update, deep=deep)
        copied.__dict__.pop("_tools_by_id", None)
        return copied


class GraphDrift(Frozen):
    """Differences between registry agents and discovered agents."""

    discovered_only_agents: tuple[str, ...]
    declared_only_agents: tuple[str, ...]
    undeclared_edges: tuple[GraphEdge, ...]
    complete: bool


class AgentGraph(Frozen):
    """The merged agent call graph: registry declarations plus every discovery source.

    roles is the registry's top-level roles list; None turns every role feature off.
    """

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    entry_agents: tuple[str, ...]
    entry_inferred: bool
    roles: tuple[str, ...] | None
    drift: GraphDrift | None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def node(self, node_id: str) -> GraphNode | None:
        """Return the node with this id, or None."""
        return next((node for node in self.nodes if node.id == node_id), None)


EMPTY_GRAPH = AgentGraph(
    nodes=(), edges=(), entry_agents=(), entry_inferred=False, roles=None, drift=None
)


MAX_ROUTE_AGENTS = 32  # same limit as the agent walk (MAX_AGENT_DEPTH)

# Evidence of `lockwalk test`: coverage.json rows point at events of
# .lockwalk/evidence.jsonl by id, and the report's run_id ties the two files together.
RunId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
EvidenceId = Annotated[str, Field(pattern=r"^E-[0-9]{4,}$")]
# None: the report did not come from `lockwalk test`, so there is no evidence file.
EvidenceRefs = tuple[EvidenceId, ...] | None


class TestScenario(Frozen):
    """One hand-written case from security-spec.yaml. Set exactly one of agent or path."""

    __test__: ClassVar[bool] = False  # stop pytest from collecting this class

    id: CaseId
    actor: NonEmptyStr
    role: NonEmptyStr
    agent: Name | None = None
    path: tuple[Name, ...] | None = None
    tool: Name
    action: NonEmptyStr
    resource_fixture: NonEmptyStr
    expect: Expectation
    conditions: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    owner: str | None = None
    delegation_mode: DelegationMode | None = None

    @field_validator("conditions")
    @classmethod
    def _conditions_are_scalars(cls, value: dict[str, Any]) -> dict[str, Any]:
        if "lockwalk" in value:
            raise ValueError(
                "condition 'lockwalk' is reserved: lockwalk puts its own context under that key"
            )
        for key, item in value.items():
            if not isinstance(item, str | int | float | bool):
                raise ValueError(f"condition {key!r} must be a string, number, or boolean")
            if isinstance(item, float) and (math.isnan(item) or math.isinf(item)):
                raise ValueError(f"condition {key!r} must be a finite number")
        return value

    @model_validator(mode="after")
    def _agent_or_path(self) -> Self:
        if (self.agent is None) == (self.path is None):
            raise ValueError("set exactly one of 'agent' or 'path'")
        if self.path == ():
            raise ValueError("path must not be empty")
        if self.path is not None and len(self.path) > MAX_ROUTE_AGENTS:
            raise ValueError(
                f"path has {len(self.path)} agents; at most {MAX_ROUTE_AGENTS} are allowed"
            )
        return self

    @property
    def route(self) -> tuple[str, ...]:
        """The agents the case passes through, in order. An 'agent' case is a one-step route."""
        if self.path is not None:
            return self.path
        return () if self.agent is None else (self.agent,)


class NeverReachesRule(Frozen):
    """A rule: starting from an agent or a role, a tool or agent must never be reachable."""

    id: CaseId
    agent: Name | None = None
    role: NonEmptyStr | None = None
    tool: Name | None = None
    target_agent: Name | None = None
    reason: str | None = None
    owner: str | None = None

    @model_validator(mode="after")
    def _one_start_one_target(self) -> Self:
        if (self.agent is None) == (self.role is None):
            raise ValueError("set exactly one of 'agent' or 'role' as the starting point")
        if (self.tool is None) == (self.target_agent is None):
            raise ValueError("set exactly one of 'tool' or 'target_agent' as the target")
        return self


class PlannedCase(Frozen):
    """A spec case after it was checked against the inventory."""

    scenario: TestScenario
    status: CaseStatus
    problems: tuple[str, ...] = ()
    action_verified: bool = False

    @model_validator(mode="after")
    def _error_has_problems(self) -> Self:
        if self.status == CaseStatus.ERROR and not self.problems:
            raise ValueError("an ERROR case must list at least one problem")
        return self


# ---- Report models: the shape of coverage.json ----


class SourceSummary(Frozen):
    source: str
    ok: bool
    tool_count: int
    error: str | None
    optional: bool = False
    unavailable: bool = False


class ToolRow(Frozen):
    id: str
    risk: Risk
    action: str | None
    sources: tuple[str, ...]
    supported_agents: tuple[str, ...]
    hints: dict[str, StrictBool]
    coverage: ToolCoverage
    case_ids: tuple[str, ...]
    has_deny_case: bool


class InventorySection(Frozen):
    sources: tuple[SourceSummary, ...]
    agents: tuple[str, ...]
    tools: tuple[ToolRow, ...]
    drift: Drift | None


# Deep enough for any real attribute tree. pydantic's model_dump stops at about 100 levels
# (measured: 97 below the properties dict), so the cap must stay well under that.
MAX_QUERY_DEPTH = 64


class Verdict(StrEnum):
    """One answer from the IAM."""

    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"


class PathVerdict(StrEnum):
    """The combined answer for one hop or one whole route."""

    ALLOW = "allow"
    DENY = "deny"
    # The delegation_mode is not declared, and the user and the agent identity got
    # different answers, so lockwalk does not know which one the route really uses.
    UNKNOWN = "unknown"
    ERROR = "error"


class Answer(Frozen):
    """One question lockwalk asked the IAM, and its answer, as coverage.json shows them."""

    subject: dict[str, Any]  # the AuthZEN subject that was sent: type, id, properties
    verdict: Verdict
    reason: str | None = None  # the IAM's own reason; masked, then truncated
    # set exactly when verdict is ERROR; masked, then truncated
    error: str | None = Field(default=None, min_length=1)
    latency_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None

    @field_validator("subject")
    @classmethod
    def _subject_is_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Null is allowed: this is the full subject lockwalk sent, like Answer.subject.
        check_json_value(value, "subject", allow_null=True, max_depth=MAX_QUERY_DEPTH)
        return value

    @model_validator(mode="after")
    def _error_iff_error(self) -> Self:
        if (self.verdict is Verdict.ERROR) != (self.error is not None):
            raise ValueError("error must be set exactly when the verdict is error")
        return self


class HopResult(Frozen):
    """One step of a route: the caller asks to use the next agent, or (last) the tool."""

    caller: str  # "user" for the first hop, otherwise an agent id
    target: str  # an agent id, or the tool id for the tool hop
    kind: Literal["agent", "tool"]
    mode: IdentityMode
    verdict: PathVerdict
    answers: tuple[Answer, ...]  # one, or two (user, then agent) when mode is "undeclared"

    @model_validator(mode="after")
    def _answer_count_matches_mode(self) -> Self:
        expected = 2 if self.mode == "undeclared" else 1
        if len(self.answers) != expected:
            raise ValueError("a hop has two answers exactly when its mode is undeclared")
        return self


class CaseDecision(Frozen):
    """What the IAM said about one case's route."""

    verdict: PathVerdict
    hops: tuple[HopResult, ...]  # only the tool hop, unless [policy] ask_every_hop
    denied_hop: str | None = None  # "caller -> target" of the first hop that was denied


class EscalationResult(StrEnum):
    """Result of one escalation check. Upper case, like RuleResult."""

    ESCALATION = "ESCALATION"
    NONE = "NONE"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNCHECKED = "UNCHECKED"
    ERROR = "ERROR"


class EscalationRow(Frozen):
    """One escalation check: the route's identity against the user's own."""

    case_id: str | None  # the spec case it comes from; None for a role x tool row
    role: str
    tool: str
    via: str  # the agent that calls the tool
    risk: Risk
    mode: IdentityMode  # never "user": a call made with the user's identity cannot escalate
    path: tuple[str, ...]  # agent ids from the start agent to `via`
    result: EscalationResult
    user_answer: Answer | None = None
    path_answer: Answer | None = None
    notes: tuple[str, ...] = ()
    waived_by: str | None = None  # id of the waiver that covers this row
    evidence: EvidenceRefs = None

    @model_validator(mode="after")
    def _mode_is_not_user(self) -> Self:
        if self.mode == "user":
            raise ValueError("an escalation row never has mode 'user'")
        return self


class ControlRow(Frozen):
    """One positive control: did any question about this pair get an allow?"""

    action: str
    resource_type: str
    allowed: bool
    allowed_by: str | None = None  # the first question that got an allow, e.g. "CASE-001"
    evidence: EvidenceRefs = None


class DoorStatus(StrEnum):
    """The door part of a case. Upper case, like CaseStatus."""

    OK = "OK"
    FAIL_EXECUTION = "FAIL_EXECUTION"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    NOT_TESTED = "NOT_TESTED"


class DoorCall(Frozen):
    """One call of the user's DOOR for the tool, as read_door_call described it.

    subject keeps only type, id, and the act chain's types and ids (protocol.reduce_subject),
    because the identity check compares nothing else and property values may be secret.
    """

    subject: dict[str, Any] | None = None
    decision: StrictBool | None = None
    error: str | None = Field(default=None, min_length=1)  # masked, then truncated

    @field_validator("subject")
    @classmethod
    def _subject_is_json(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None:
            check_json_value(value, "subject", allow_null=False, max_depth=MAX_QUERY_DEPTH)
        return value

    @model_validator(mode="after")
    def _answer_or_error(self) -> Self:
        answered = self.error is None and self.subject is not None and self.decision is not None
        failed = self.error is not None and self.subject is None and self.decision is None
        if not (answered or failed):
            raise ValueError("a door call has a subject and a decision, or only an error")
        return self


class DoorRun(Frozen):
    """One judged door test run of a case: a direct call or a scripted run."""

    mode: HarnessMode
    status: DoorStatus  # never NOT_TESTED: a run that was not judged is not recorded
    subject: dict[str, Any]  # direct: the identity lockwalk set; scripted: the user
    side_effect_calls: Annotated[StrictInt, Field(ge=0)]
    door_calls: tuple[DoorCall, ...] = ()
    exception: str | None = None  # the type name of what the tool or the run raised
    notes: tuple[str, ...] = ()

    @field_validator("subject")
    @classmethod
    def _subject_is_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_json_value(value, "subject", allow_null=True, max_depth=MAX_QUERY_DEPTH)
        return value

    @model_validator(mode="after")
    def _judged(self) -> Self:
        if self.status is DoorStatus.NOT_TESTED:
            raise ValueError("a recorded door run is never NOT_TESTED")
        return self


class DoorResult(Frozen):
    """The door part of one case: the most severe run, or NOT_TESTED when none was judged."""

    status: DoorStatus
    runs: tuple[DoorRun, ...] = ()
    notes: tuple[str, ...] = ()  # why a mode did not run or was not judged

    @model_validator(mode="after")
    def _runs_match_status(self) -> Self:
        if self.status is DoorStatus.NOT_TESTED:
            if self.runs:
                raise ValueError("a NOT_TESTED door result has no runs")
        elif not self.runs and not (self.status is DoorStatus.ERROR and self.notes):
            raise ValueError(
                f"a {self.status.value} door result needs a run (only ERROR with a note has none)"
            )
        return self


class IdentityResult(StrEnum):
    """One identity check. Upper case, like RuleResult."""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    OBSERVED = "OBSERVED"  # nothing was declared to compare with
    NOT_RUN = "NOT_RUN"


class IdentityObservation(Frozen):
    """What one mode expected the door to receive, and what it received (reduced subjects)."""

    mode: HarnessMode
    expected: dict[str, Any] | None  # None in scripted mode when delegation_mode is undeclared
    observed: tuple[dict[str, Any], ...]
    result: IdentityResult


class IdentityCheckRow(Frozen):
    case_id: str
    path: tuple[str, ...]
    tool: str
    result: IdentityResult
    observations: tuple[IdentityObservation, ...] = ()
    notes: tuple[str, ...] = ()
    waived_by: str | None = None  # id of the waiver that covers this row
    evidence: EvidenceRefs = None


class DoorControlRow(Frozen):
    """One door control: was this tool's side effect counted at least once?"""

    tool: str
    proven: bool
    proven_by: str | None = None  # the first run that counted a call, e.g. "CASE-004 (direct)"
    evidence: EvidenceRefs = None


class CaseRow(Frozen):
    id: str
    agent: str
    path: tuple[str, ...] = ()
    tool: str
    action: str
    expect: Expectation
    actor: str | None = None  # the spec case's actor; None only in reports built by hand
    role: str | None = None  # the spec case's role
    status: CaseStatus
    action_verified: bool
    problems: tuple[str, ...]
    decision: CaseDecision | None = None  # set by `lockwalk test`
    notes: tuple[str, ...] = ()  # why a case is FAIL_POLICY or INCONCLUSIVE
    door: DoorResult | None = None  # set by `lockwalk test` when [harness] is used
    waived_by: str | None = None  # id of the waiver that covers this row
    evidence: EvidenceRefs = None


class Metrics(Frozen):
    registered_tools: int
    specified_cases: int
    executed_cases: int
    execution_coverage: float | None
    verified_pass_rate: float | None
    cases_by_status: dict[str, int]
    tools_without_spec: int


class RuleResult(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class ReachStatus(StrEnum):
    """Status of a role x tool row. Upper case, like RuleResult."""

    REACHABLE = "REACHABLE"
    INCONCLUSIVE = "INCONCLUSIVE"


class RuleRow(Frozen):
    """The result of one never_reaches rule.

    problems explains an ERROR, and also an INCONCLUSIVE result that no opaque node
    explains: a target tool that no agent is known to use, or a starting role that no
    entry agent lists.
    """

    id: str
    agent: str | None
    role: str | None
    tool: str | None
    target_agent: str | None
    result: RuleResult
    witness: tuple[GraphEdge, ...] = ()
    opaque_reached: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()
    reason: str | None = None
    waived_by: str | None = None  # id of the waiver that covers this row

    @model_validator(mode="after")
    def _error_has_problems(self) -> Self:
        if self.result == RuleResult.ERROR and not self.problems:
            raise ValueError("an ERROR rule must list at least one problem")
        return self


class ReachRow(Frozen):
    role: str
    tool: str
    risk: Risk
    status: ReachStatus
    witness: tuple[GraphEdge, ...] = ()
    delegation_mode: DelegationMode | None = None
    opaque_reached: tuple[str, ...] = ()
    covered_by: tuple[str, ...] = ()
    waived_by: str | None = None  # id of the waiver that covers this row


class GraphSection(Frozen):
    entry_agents: tuple[str, ...] = ()
    entry_inferred: bool = False
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    cycles: tuple[tuple[str, ...], ...] = ()
    opaque: tuple[str, ...] = ()
    unreachable: tuple[str, ...] = ()  # agent and remote agent ids no entry agent reaches
    drift: GraphDrift | None = None


GateRule = Literal[
    "fail_on_unspecified_risk",
    "require_deny_case_for_risk",
    "never_reaches",
    "fail_on_unspecified_role_risk",
    "case",  # a case is FAIL_POLICY or FAIL_EXECUTION: always a violation
    "fail_on_inconclusive_case",
    "fail_on_escalation",
    "fail_on_inconclusive_escalation",
    "fail_on_unchecked_escalation",
    "fail_on_identity_mismatch",
]


_GATE_FIELDS: dict[str, tuple[str, ...]] = {
    "fail_on_unspecified_risk": ("tool", "risk"),
    "require_deny_case_for_risk": ("tool", "risk"),
    "never_reaches": ("rule_id", "result"),
    "fail_on_unspecified_role_risk": ("role", "tool", "risk"),
    "case": ("case_id", "status"),
    "fail_on_inconclusive_case": ("case_id", "status"),
    "fail_on_escalation": ("role", "tool", "via"),
    "fail_on_inconclusive_escalation": ("role", "tool", "via"),
    "fail_on_unchecked_escalation": ("role", "tool", "via", "risk"),
    "fail_on_identity_mismatch": ("case_id",),
}


class GateViolation(Frozen):
    """One gate violation. Fields that do not apply to the rule are None."""

    rule: GateRule
    tool: str | None = None
    risk: Risk | None = None
    role: str | None = None
    rule_id: str | None = None
    result: RuleResult | None = None
    case_id: str | None = None
    status: CaseStatus | None = None
    via: str | None = None

    @model_validator(mode="after")
    def _fields_match_rule(self) -> Self:
        needed = _GATE_FIELDS[self.rule]
        missing = [name for name in needed if getattr(self, name) is None]
        if missing:
            raise ValueError(f"rule {self.rule!r} needs fields: {', '.join(missing)}")
        return self


WaiverStatus = Literal["applied", "expired", "unmatched", "not_allowed"]


# Note of a waiver that only `lockwalk test` can check; coverage shows it quietly.
TEST_ONLY_NOTE = "checked only by lockwalk test"
OBSERVE_ONLY_NOTE = "checked only by lockwalk observe"


class WaiverRow(Frozen):
    """One waiver and what it did in this run."""

    id: str
    owner: str
    expires: str  # ISO date, YYYY-MM-DD
    reason: str
    match: dict[str, Any]  # as written in the waivers file
    status: WaiverStatus
    matched: tuple[str, ...] = ()  # what it waived, or would have: "RULE-002", "CASE-006", ...
    note: str | None = None  # why it is not applied, in plain words

    @field_validator("expires")
    @classmethod
    def _valid_date(cls, value: str) -> str:
        date.fromisoformat(value)
        return value

    @field_validator("match")
    @classmethod
    def _valid_match(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_json_value(value, "match", allow_null=True, max_depth=MAX_QUERY_DEPTH)
        return value


class WaivedViolation(Frozen):
    violation: GateViolation
    waiver_id: str


class GateResult(Frozen):
    """passed means no unwaived violations."""

    passed: bool
    violations: tuple[GateViolation, ...]
    waived: tuple[WaivedViolation, ...] = ()


class CoverageReport(Frozen):
    """Everything the analyzer concluded. report.py adds version and time when writing JSON."""

    mode: Literal["static", "test"]
    scenario_suite: str
    spec_schema_version: str
    policy_adapter: str | None = None
    run_id: RunId | None = None  # set by `lockwalk test`; evidence.jsonl has the same id
    inventory: InventorySection
    cases: tuple[CaseRow, ...]
    metrics: Metrics
    registered_tools_without_spec: tuple[str, ...]
    high_risk_tools_without_deny_case: tuple[str, ...]
    agent_graph: GraphSection = Field(default_factory=GraphSection)
    reachability: tuple[ReachRow, ...] | None = None
    rules: tuple[RuleRow, ...] = ()
    escalations: tuple[EscalationRow, ...] = ()
    controls: tuple[ControlRow, ...] = ()
    identity_checks: tuple[IdentityCheckRow, ...] = ()
    door_controls: tuple[DoorControlRow, ...] = ()
    waivers: tuple[WaiverRow, ...] = ()
    gate: GateResult
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    exit_code: int

    @model_validator(mode="after")
    def _exit_code_matches_errors(self) -> Self:
        if bool(self.errors) != (self.exit_code == 2):
            raise ValueError("exit_code must be 2 exactly when there are errors")
        return self
