"""Load and validate .lockwalk.toml."""

import ipaddress
import re
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BeforeValidator,
    ConfigDict,
    Discriminator,
    Field,
    StrictBool,
    StrictInt,
    Tag,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from lockwalk.errors import StructuralError, format_validation_error
from lockwalk.inventory.targets import TargetError, parse_target
from lockwalk.masking import check_template, header_value_problem
from lockwalk.models import Frozen, Name, NonEmptyStr, Risk, Seconds, check_name
from lockwalk.observe.keys import BUILTIN_KEYS, MAPPABLE_KEYS, SPAN_NAME
from lockwalk.urls import check_http_url, redact_url

# 'mcp:' (4 characters) plus the name becomes a graph node id of at most 200 characters.
MAX_OPTIONAL_NAME_LENGTH = 196

# The characters an HTTP header name may hold (an RFC 9110 token).
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# Every config model that can hold env or header values hides inputs in pydantic's own
# error text, which would otherwise quote them. (Frozen's other settings are inherited.)
_SECRET_SAFE = ConfigDict(hide_input_in_errors=True)


def check_mcp_target(value: str) -> str:
    """Validate an MCP target such as stdio://server.py or http://host/mcp.

    The part after stdio:// is a filesystem path, relative or absolute (for example
    stdio://C:/tools/server.py).
    """
    if value != value.strip():
        raise ValueError("MCP target must not start or end with whitespace")
    if value.startswith("stdio://"):
        name = PurePath(value.removeprefix("stdio://")).name
        if not name.endswith(".py") or name == ".py":
            raise ValueError(
                "stdio:// targets must point to a .py file; "
                "use 'command' and 'args' in .lockwalk.toml to start other programs"
            )
        return value
    if value.startswith(("http://", "https://")):
        return check_http_url(value, "MCP URL")
    raise ValueError("MCP target must start with stdio://, http://, or https://")


def _check_entry_name(key: str, field: str) -> None:
    if not key or any(char.isspace() or not char.isprintable() for char in key):
        raise ValueError(
            f"names in '{field}' must be non-empty and contain no whitespace or control characters"
        )


def check_headers(value: dict[str, str]) -> dict[str, str]:
    """Check header names, the ${VAR} syntax, and the values. Messages never quote a value."""
    for key, item in value.items():
        _check_entry_name(key, "headers")
        if not HEADER_NAME.fullmatch(key):
            raise ValueError(f"{key!r} is not a valid HTTP header name")
        check_template(item, f"header {key!r}")
        # Expanded values are checked again at connect time.
        problem = header_value_problem(key, item, template=True)
        if problem is not None:
            raise ValueError(problem)
    return value


class McpSourceConfig(Frozen):
    """[[inventory.mcp]]: set exactly one of target or command.

    env (stdio servers) and headers (http(s) servers) may hold secrets. Their values are
    expanded only when lockwalk connects, and never reach reports, snapshots, or output.
    """

    model_config = _SECRET_SAFE

    name: NonEmptyStr | None = None
    target: str | None = None
    command: NonEmptyStr | None = None
    args: tuple[str, ...] = ()
    timeout_s: Seconds = 10.0
    agents: tuple[Name, ...] = ()
    optional: StrictBool = False
    env: dict[str, str] = Field(default_factory=dict, repr=False)
    headers: dict[str, str] = Field(default_factory=dict, repr=False)

    @field_validator("target")
    @classmethod
    def _valid_target(cls, value: str | None) -> str | None:
        return None if value is None else check_mcp_target(value)

    @field_validator("env", "headers")
    @classmethod
    def _valid_entries(cls, value: dict[str, str], info: ValidationInfo) -> dict[str, str]:
        field = info.field_name
        if field == "headers":
            return check_headers(value)
        for key, item in value.items():
            _check_entry_name(key, "env")
            if "=" in key:
                raise ValueError("env names must not contain '='")
            check_template(item, f"env {key!r}")
        return value

    @property
    def is_stdio(self) -> bool:
        """Whether lockwalk starts the server itself and talks to it over stdio."""
        return self.target is None or self.target.startswith("stdio://")

    @model_validator(mode="after")
    def _one_way_to_connect(self) -> Self:
        if (self.target is None) == (self.command is None):
            raise ValueError("set exactly one of 'target' or 'command'")
        if self.args and self.command is None:
            raise ValueError("'args' can only be used together with 'command'")
        if self.env and not self.is_stdio:
            raise ValueError("'env' only applies to stdio servers")
        if self.headers and self.is_stdio:
            raise ValueError("'headers' only applies to http(s) servers")
        if self.optional:
            if not self.agents:
                raise ValueError(
                    "'optional' sources must list 'agents', so lockwalk knows which "
                    "agents the unseen part of the graph hangs under"
                )
            if self.name is None:
                raise ValueError(
                    "'optional' sources need a 'name' "
                    "(it labels the part of the graph lockwalk cannot see)"
                )
            if len(self.name) > MAX_OPTIONAL_NAME_LENGTH:
                raise ValueError(
                    f"'name' of an 'optional' source must be at most "
                    f"{MAX_OPTIONAL_NAME_LENGTH} characters"
                )
            check_name(self.name)
        return self


class PythonSourceConfig(Frozen):
    """[[inventory.python]]: a '<module>:<attribute>' target holding tools.

    The format is checked here with the worker's own parser, so a malformed target is a
    config error before any worker starts. Whether the module and attribute exist is only
    known once the worker imports them.
    """

    target: NonEmptyStr
    agents: tuple[Name, ...] = ()
    timeout_s: Seconds = 30.0

    @field_validator("target")
    @classmethod
    def _valid_target(cls, value: str) -> str:
        try:
            parse_target(value)
        except TargetError as exc:
            raise ValueError(str(exc)) from None
        return value


class JsonSourceConfig(Frozen):
    """[[inventory.json]]: a JSON file listing tool descriptions."""

    path: NonEmptyStr
    agents: tuple[Name, ...] = ()


class InventoryConfig(Frozen):
    model_config = _SECRET_SAFE

    mcp: tuple[McpSourceConfig, ...] = ()
    python: tuple[PythonSourceConfig, ...] = ()
    # A field called "json" would shadow a BaseModel method, so the Python name differs.
    json_files: tuple[JsonSourceConfig, ...] = Field(default=(), alias="json")


# An HTTP PDP should answer fast; a decide() function may do more work.
DEFAULT_POLICY_TIMEOUT_S = {"authzen": 2.0, "python": 5.0}


class PolicyConfig(Frozen):
    """[policy]: which IAM `lockwalk test` asks, and how.

    headers may hold secrets. As with MCP headers, their ${VAR} references are expanded
    only when lockwalk connects, and the values never reach reports or output.
    """

    model_config = _SECRET_SAFE

    adapter: Literal["authzen", "python"]
    url: str | None = Field(default=None, repr=False)  # a query string may hold a token
    headers: dict[str, str] = Field(default_factory=dict, repr=False)
    target: NonEmptyStr | None = None
    timeout_s: Seconds | None = None
    batch_size: Annotated[StrictInt, Field(ge=1, le=1000)] = 100
    max_queries: Annotated[StrictInt, Field(ge=1, le=1_000_000)] = 5000
    ask_every_hop: StrictBool = False
    invoke_action: NonEmptyStr = "agent:invoke"
    # The subject property that holds the user's roles. Some IAMs read them elsewhere
    # (Cerbos reads "cerbos.roles").
    roles_property: NonEmptyStr = "roles"

    @field_validator("roles_property")
    @classmethod
    def _valid_roles_property(cls, value: str) -> str:
        if value == "act":
            raise ValueError(
                "roles_property cannot be 'act': lockwalk puts the delegation chain there"
            )
        return value

    @field_validator("url")
    @classmethod
    def _valid_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        check_http_url(value, "[policy] url")
        if urlsplit(value).username is not None:
            raise ValueError(
                "[policy] url must not hold a user name or password; put credentials in 'headers'"
            )
        return value

    @field_validator("headers")
    @classmethod
    def _valid_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return check_headers(value)

    @field_validator("target")
    @classmethod
    def _valid_target(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            _, _, call = parse_target(value)
        except TargetError as exc:
            raise ValueError(str(exc)) from None
        if call:
            raise ValueError("a decide target cannot end with '()': point at the function")
        return value

    @model_validator(mode="after")
    def _fields_match_adapter(self) -> Self:
        if self.adapter == "authzen":
            if self.url is None:
                raise ValueError("adapter 'authzen' needs 'url'")
            if self.target is not None:
                raise ValueError("'target' only applies to adapter 'python'")
        else:
            if self.target is None:
                raise ValueError("adapter 'python' needs 'target'")
            if self.url is not None or self.headers:
                raise ValueError("'url' and 'headers' only apply to adapter 'authzen'")
        return self

    @property
    def timeout(self) -> float:
        """timeout_s, or the adapter's default."""
        if self.timeout_s is not None:
            return self.timeout_s
        return DEFAULT_POLICY_TIMEOUT_S[self.adapter]

    @property
    def label(self) -> str:
        """policy_adapter in the report: the adapter and where it asks, without secrets."""
        if self.adapter == "authzen":
            return f"authzen:{redact_url(self.url or '')}"
        return f"python:{self.target}"


# A bare host name: no scheme, port, path, or user. IPv6 addresses are checked separately.
HOST_LABEL = re.compile(r"[a-z0-9]([a-z0-9_-]*[a-z0-9])?")
_HOST_MESSAGE = (
    "allow_hosts: {host!r} must be a host name or an IP address, without a scheme, port, "
    "path, or trailing dot; give internationalized names in punycode (xn--...)"
)


def _canonical_host(host: str) -> str:
    """Return the canonical form of an allowed host, so later comparisons can be exact."""
    try:
        if ":" in host:
            if "%" in host:
                raise ValueError("zone id")
            return str(ipaddress.IPv6Address(host))
        if host and all(c in "0123456789." for c in host):
            return str(ipaddress.IPv4Address(host))
    except ValueError:
        raise ValueError(_HOST_MESSAGE.format(host=host)) from None
    lowered = host.lower()
    if not all(HOST_LABEL.fullmatch(label) for label in lowered.split(".")):
        raise ValueError(_HOST_MESSAGE.format(host=host))
    return lowered


class HarnessConfig(Frozen):
    """[harness]: the door tests of `lockwalk test`."""

    hooks: NonEmptyStr
    modes: tuple[Literal["direct", "scripted"], ...] = ("direct", "scripted")
    timeout_s: Seconds = 10.0
    import_timeout_s: Seconds = 30.0
    allow_hosts: tuple[NonEmptyStr, ...] = ()

    @field_validator("modes")
    @classmethod
    def _valid_modes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("modes must list 'direct', 'scripted', or both")
        if len(set(value)) != len(value):
            raise ValueError("modes must not list a mode twice")
        return value

    @field_validator("allow_hosts")
    @classmethod
    def _valid_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_canonical_host(host) for host in value)


class GateConfig(Frozen):
    """[gate]: which findings make `lockwalk coverage` exit with 1."""

    fail_on_unspecified_risk: tuple[Risk, ...] = (Risk.CRITICAL, Risk.UNKNOWN)
    require_deny_case_for_risk: tuple[Risk, ...] = (Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN)
    fail_on_never_reaches_inconclusive: StrictBool = True
    fail_on_unspecified_role_risk: tuple[Risk, ...] = (Risk.CRITICAL, Risk.UNKNOWN)
    fail_on_inconclusive_case: StrictBool = True
    fail_on_escalation: StrictBool = True
    fail_on_inconclusive_escalation: StrictBool = True
    fail_on_unchecked_escalation: tuple[Risk, ...] = (Risk.CRITICAL, Risk.UNKNOWN)
    fail_on_identity_mismatch: StrictBool = True
    max_waiver_days: Annotated[StrictInt, Field(ge=1, le=3650)] = 90
    fail_on_off_map_route: StrictBool = True  # checked by lockwalk observe
    fail_on_unknown_component: StrictBool = True
    fail_on_inconclusive_observation: StrictBool = True
    fail_on_unguarded_call: tuple[Risk, ...] = (Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN)
    fail_on_untested_path: tuple[Risk, ...] = (Risk.CRITICAL, Risk.UNKNOWN)


MAX_OBSERVE_RULES = 100
MAX_RULE_CONDITIONS = 20
MAX_OBSERVE_ENTRIES = 1000  # per table or list in [observe]
MAX_OBSERVE_TEXT = 500


def _check_rule_value(value: str) -> str:
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("must not contain control characters")
    return value


# A value a rule's `when` matches: a string (empty strings and surrounding spaces are allowed),
# a boolean or an int64 integer. Floats are refused: equality on them is not reliable.
RuleValue = Annotated[str, AfterValidator(_check_rule_value), Field(max_length=500)]
RuleInt = Annotated[StrictInt, Field(ge=-(2**63), le=2**63 - 1)]


def _check_when_type(value: object) -> object:
    # One readable message instead of one pydantic error per union member.
    if not isinstance(value, str | bool | int):
        raise ValueError("a 'when' value must be a string, a boolean or an integer")
    return value


def _when_tag(value: object) -> str:
    # Picks the one union branch that validates, so an error names one reason only.
    return "bool" if isinstance(value, bool) else "int" if isinstance(value, int) else "str"


WhenValue = Annotated[
    Annotated[RuleValue, Tag("str")]
    | Annotated[StrictBool, Tag("bool")]
    | Annotated[RuleInt, Tag("int")],
    Discriminator(_when_tag),
    BeforeValidator(_check_when_type),
]
DoorDecision = Literal["allow", "deny", "error"]


def _check_observe_text(value: str) -> str:
    if not value or value != value.strip():
        raise ValueError("must not be empty or start/end with whitespace")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError("must not contain control characters")
    return value


# Every key and value string in [observe]: bounded, no control characters.
ObserveText = Annotated[
    str, AfterValidator(_check_observe_text), Field(max_length=MAX_OBSERVE_TEXT)
]


class ObserveRule(Frozen):
    """One [[observe.rules]] entry.

    when: every listed attribute must equal the value, with the same type (the key "span.name"
    is the span's own name). name says where an agent's or tool's name is; from and to say
    where a handoff's caller and callee names are. A door rule makes a decision-only door
    record (decision, and the tool call id from the attribute tool_call_id names); an effect
    rule makes an effect marker.
    """

    model_config = ConfigDict(populate_by_name=True)

    kind: Literal["agent", "tool", "handoff", "door", "effect"]
    when: dict[ObserveText, WhenValue] = Field(max_length=MAX_RULE_CONDITIONS)
    name: ObserveText | None = None
    from_: ObserveText | None = Field(default=None, alias="from")
    to: ObserveText | None = None
    decision: DoorDecision | None = None
    tool_call_id: ObserveText | None = None

    @model_validator(mode="after")
    def _fields_match_kind(self) -> Self:
        if not self.when:
            raise ValueError("'when' must list at least one attribute")
        if SPAN_NAME in self.when and not isinstance(self.when[SPAN_NAME], str):
            raise ValueError("a 'span.name' condition must be a string")
        naming = (self.name, self.from_, self.to)
        door_fields = (self.decision, self.tool_call_id)
        if self.kind == "door":
            if self.decision is None:
                raise ValueError("a door rule needs 'decision'")
            if any(item is not None for item in naming):
                raise ValueError("a door rule has no 'name', 'from' or 'to'")
            if self.tool_call_id == SPAN_NAME:
                raise ValueError("'tool_call_id' must name an attribute, not span.name")
            return self
        if self.kind == "effect":
            if any(item is not None for item in (*naming, *door_fields)):
                raise ValueError("an effect rule has only 'when'")
            return self
        if any(item is not None for item in door_fields):
            raise ValueError("'decision' and 'tool_call_id' are only for door rules")
        if self.kind == "handoff":
            if self.from_ is None or self.to is None:
                raise ValueError("a handoff rule needs 'from' and 'to'")
            if self.name is not None:
                raise ValueError("a handoff rule has no 'name'")
        else:
            if self.name is None:
                article = "an" if self.kind == "agent" else "a"
                raise ValueError(f"{article} {self.kind} rule needs 'name'")
            if self.from_ is not None or self.to is not None:
                raise ValueError("'from' and 'to' are only for handoff rules")
        return self


class ObserveConfig(Frozen):
    """[observe]: lockwalk observe."""

    traces: tuple[ObserveText, ...] = Field(default=(), max_length=MAX_OBSERVE_ENTRIES)
    reader: ObserveText | None = None
    reader_timeout_s: Seconds = 120.0
    # Each kept span costs roughly 1 KB of memory, so the hard cap is 5 GB of spans.
    max_spans: Annotated[StrictInt, Field(ge=1, le=5_000_000)] = 1_000_000
    max_line_mb: Annotated[StrictInt, Field(ge=1, le=1024)] = 64
    max_total_mb: Annotated[StrictInt, Field(ge=1, le=65_536)] = 4096
    test_report: ObserveText = ".lockwalk/coverage.json"  # read by lockwalk observe
    # name in traces -> agent id
    agents: dict[ObserveText, Name] = Field(default_factory=dict, max_length=MAX_OBSERVE_ENTRIES)
    # name in traces -> tool id
    tools: dict[ObserveText, Name] = Field(default_factory=dict, max_length=MAX_OBSERVE_ENTRIES)
    # lockwalk key -> attribute name in the traces (used by lockwalk observe)
    attributes: dict[ObserveText, ObserveText] = Field(
        default_factory=dict, max_length=MAX_OBSERVE_ENTRIES
    )
    rules: tuple[ObserveRule, ...] = Field(default=(), max_length=MAX_OBSERVE_RULES)

    @field_validator("reader")
    @classmethod
    def _reader_is_a_target(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                parse_target(value)
            except TargetError as exc:
                raise ValueError(str(exc)) from None
        return value

    @field_validator("attributes")
    @classmethod
    def _mappable(cls, value: dict[str, str]) -> dict[str, str]:
        unknown = sorted(set(value) - MAPPABLE_KEYS)
        if unknown:
            raise ValueError(
                f"[observe.attributes] can only map {', '.join(sorted(MAPPABLE_KEYS))}; "
                f"not {', '.join(unknown)}"
            )
        taken = [
            target for target in value.values() if target in BUILTIN_KEYS or target == SPAN_NAME
        ]
        if taken:
            raise ValueError(
                "[observe.attributes] targets must not be attributes lockwalk already reads "
                f"with their own meaning: {', '.join(sorted(set(taken)))}"
            )
        if len(set(value.values())) != len(value):
            raise ValueError("[observe.attributes] two keys map to the same target")
        return value

    @model_validator(mode="after")
    def _one_table_per_name(self) -> Self:
        both = sorted(set(self.agents) & set(self.tools))
        if both:
            raise ValueError(
                f"names listed in both [observe.agents] and [observe.tools]: {', '.join(both)}"
            )
        return self


class LockwalkSection(Frozen):
    registry: NonEmptyStr | None = None
    spec: NonEmptyStr | None = None
    output_dir: NonEmptyStr = ".lockwalk"
    fixtures: NonEmptyStr | None = None
    waivers: NonEmptyStr | None = None


class ConfigFile(Frozen):
    # Nested models render errors with the outermost model's settings.
    model_config = _SECRET_SAFE

    lockwalk: LockwalkSection = Field(default_factory=LockwalkSection)
    gate: GateConfig = Field(default_factory=GateConfig)
    inventory: InventoryConfig = Field(default_factory=InventoryConfig)
    policy: PolicyConfig | None = None
    harness: HarnessConfig | None = None
    observe: ObserveConfig = Field(default_factory=ObserveConfig)


@dataclass(frozen=True)
class LoadedConfig:
    """A parsed config file and where it was found."""

    path: Path
    file: ConfigFile

    @property
    def base_dir(self) -> Path:
        """Relative paths inside the file are resolved against this directory."""
        return self.path.parent


def load_config(path: Path) -> LoadedConfig:
    """Read and validate a .lockwalk.toml file. Any problem raises StructuralError."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StructuralError(str(path), [f"cannot read file: {exc}"]) from exc
    try:
        data = tomllib.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise StructuralError(str(path), [f"invalid TOML: {exc}"]) from exc
    except RecursionError as exc:
        raise StructuralError(str(path), ["the file is nested too deeply"]) from exc
    try:
        file = ConfigFile.model_validate(data)
    except ValidationError as exc:
        raise StructuralError(str(path), format_validation_error(exc)) from exc
    return LoadedConfig(path=path, file=file)
