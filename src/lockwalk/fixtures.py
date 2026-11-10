"""Load and validate fixtures.yaml: what the test identities and resources look like.

lockwalk puts these properties into its questions, so the IAM can apply its attribute
rules. `tool_args` is for the door tests and is never sent to
the IAM.
"""

from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError, field_validator

from lockwalk.errors import StructuralError, format_validation_error
from lockwalk.jsonvalues import check_json_value
from lockwalk.models import Frozen, Name, NonEmptyStr, SchemaVersion
from lockwalk.registry import Registry
from lockwalk.yamlio import load_yaml

MAX_PROPERTY_DEPTH = 8


def check_value(value: object, where: str) -> None:
    """Accept strings, finite numbers, booleans, and lists and mappings of them.

    No nulls, at most MAX_PROPERTY_DEPTH levels, and no list or mapping used twice (a YAML
    alias would otherwise let a short file expand exponentially). See lockwalk.jsonvalues,
    the shared checker, which also checks every query.
    """
    check_json_value(value, where, allow_null=False, max_depth=MAX_PROPERTY_DEPTH)


def _no_reserved(value: dict[str, Any], names: tuple[str, ...]) -> None:
    for name in names:
        if name in value:
            hint = "write roles under 'roles'" if name == "roles" else "it is the delegation chain"
            raise ValueError(f"properties.{name} is set by lockwalk ({hint})")


class SubjectFixture(Frozen):
    roles: tuple[NonEmptyStr, ...]
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("properties")
    @classmethod
    def _valid(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_value(value, "properties")
        _no_reserved(value, ("roles", "act"))
        return value


class AgentFixture(Frozen):
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("properties")
    @classmethod
    def _valid(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_value(value, "properties")
        _no_reserved(value, ("act",))
        return value


class ResourceFixture(Frozen):
    type: NonEmptyStr | None = None
    id: NonEmptyStr | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    tool_args: dict[str, Any] | None = None

    @field_validator("properties")
    @classmethod
    def _valid(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_value(value, "properties")
        return value

    @field_validator("tool_args")
    @classmethod
    def _valid_args(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        # None means the fixture gives no tool_args, so its cases are NOT_TESTED at the door;
        # {} means the tool takes no arguments.
        if value is not None:
            check_value(value, "tool_args")
        return value


class Probes(Frozen):
    """Who and what stands in for a role or a resource type in the escalation check."""

    subjects: dict[NonEmptyStr, NonEmptyStr] = Field(default_factory=dict)  # role -> subject
    resources: dict[NonEmptyStr, NonEmptyStr] = Field(default_factory=dict)  # type -> resource


class FixturesFile(Frozen):
    schema_version: SchemaVersion
    subjects: dict[NonEmptyStr, SubjectFixture] = Field(default_factory=dict)
    agents: dict[Name, AgentFixture] = Field(default_factory=dict)
    resources: dict[NonEmptyStr, ResourceFixture] = Field(default_factory=dict)
    probes: Probes = Field(default_factory=Probes)


def load_fixtures(path: Path, registry: Registry) -> FixturesFile:
    """Read and validate fixtures.yaml against the registry. Problems raise StructuralError."""
    data = load_yaml(path)
    if data is None:
        raise StructuralError(str(path), ["the file is empty"])
    if not isinstance(data, dict):
        raise StructuralError(str(path), ["the file must contain a mapping with schema_version"])
    try:
        fixtures = FixturesFile.model_validate(data)
    except ValidationError as exc:
        raise StructuralError(str(path), format_validation_error(exc)) from exc
    problems = cross_check(fixtures, registry)
    if problems:
        raise StructuralError(str(path), problems)
    return fixtures


def cross_check(fixtures: FixturesFile, registry: Registry) -> list[str]:
    """Names that must exist in the registry, and probes that must point at fixtures."""
    problems: list[str] = []
    agent_ids = set(registry.agent_ids)
    for name in fixtures.agents:
        if name not in agent_ids:
            problems.append(f"agents.{name}: agent {name!r} is not declared in the registry")
    for role, subject in fixtures.probes.subjects.items():
        where = f"probes.subjects.{role}"
        if registry.roles is None:
            problems.append(
                f"{where}: the registry has no top-level roles list, so roles cannot have probes"
            )
        elif role not in registry.roles:
            problems.append(f"{where}: role {role!r} is not in the registry roles list")
        found = fixtures.subjects.get(subject)
        if found is None:
            problems.append(f"{where}: subject {subject!r} is not under subjects")
        elif role not in found.roles:
            problems.append(f"{where}: subject {subject!r} does not have role {role!r}")
    for resource_type, name in fixtures.probes.resources.items():
        where = f"probes.resources.{resource_type}"
        resource = fixtures.resources.get(name)
        if resource is None:
            problems.append(f"{where}: resource {name!r} is not under resources")
        elif resource.type != resource_type:
            problems.append(f"{where}: resource {name!r} must have type {resource_type!r}")
    return problems
