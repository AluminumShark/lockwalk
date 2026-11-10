"""Load and validate registry.yaml: the hand-written list of agents and tools."""

from pathlib import Path

from pydantic import StrictBool, ValidationError, field_validator

from lockwalk.errors import StructuralError, format_validation_error
from lockwalk.models import DelegationMode, Frozen, Name, NonEmptyStr, Risk, SchemaVersion
from lockwalk.urls import check_http_url
from lockwalk.yamlio import load_yaml


class AgentDecl(Frozen):
    """One agent. calls=None means "not declared"; calls=() means "calls no agent"."""

    id: Name
    description: str | None = None
    entry: StrictBool = False
    roles: tuple[NonEmptyStr, ...] | None = None
    calls: tuple[Name, ...] | None = None
    remote: NonEmptyStr | None = None
    delegation_mode: DelegationMode | None = None

    @field_validator("remote")
    @classmethod
    def _http_url(cls, value: str | None) -> str | None:
        if value is not None:
            check_http_url(value, "remote")
        return value


class ToolDecl(Frozen):
    id: Name
    action: NonEmptyStr
    risk: Risk
    resource_type: NonEmptyStr | None = None
    supported_agents: tuple[Name, ...] = ()
    description: str | None = None


class DelegationToolDecl(Frozen):
    """A "tool" that is really another agent, for example an agent exposed over MCP."""

    id: Name
    agent: Name
    supported_agents: tuple[Name, ...] = ()
    description: str | None = None


class Registry(Frozen):
    schema_version: SchemaVersion
    roles: tuple[NonEmptyStr, ...] | None = None
    agents: tuple[AgentDecl, ...]
    tools: tuple[ToolDecl, ...]
    delegation_tools: tuple[DelegationToolDecl, ...] = ()

    @property
    def agent_ids(self) -> tuple[str, ...]:
        return tuple(agent.id for agent in self.agents)

    def tool(self, tool_id: str) -> ToolDecl | None:
        """Return the declared tool with this id, or None."""
        return next((tool for tool in self.tools if tool.id == tool_id), None)

    def agent(self, agent_id: str) -> AgentDecl | None:
        """Return the declared agent with this id, or None."""
        return next((agent for agent in self.agents if agent.id == agent_id), None)

    def delegation_tool(self, tool_id: str) -> DelegationToolDecl | None:
        """Return the declared delegation tool with this id, or None."""
        return next((tool for tool in self.delegation_tools if tool.id == tool_id), None)


def load_registry(path: Path) -> Registry:
    """Read and validate registry.yaml. Any problem raises StructuralError."""
    data = load_yaml(path)
    if data is None:
        raise StructuralError(str(path), ["the file is empty"])
    if not isinstance(data, dict):
        raise StructuralError(
            str(path), ["the file must contain a mapping with schema_version, agents, and tools"]
        )
    try:
        registry = Registry.model_validate(data)
    except ValidationError as exc:
        raise StructuralError(str(path), format_validation_error(exc)) from exc
    problems = _reference_problems(registry)
    if problems:
        raise StructuralError(str(path), problems)
    return registry


def _agent_list_problems(prefix: str, agent_ids: tuple[str, ...], known: set[str]) -> list[str]:
    """Report duplicate and undeclared agent ids in one list field."""
    problems: list[str] = []
    seen: set[str] = set()
    for index, agent_id in enumerate(agent_ids):
        if agent_id in seen:
            problems.append(f"{prefix}[{index}]: duplicate agent {agent_id!r}")
        seen.add(agent_id)
        if agent_id not in known:
            problems.append(f"{prefix}[{index}]: agent {agent_id!r} is not declared under agents")
    return problems


def _reference_problems(registry: Registry) -> list[str]:
    problems: list[str] = []
    agent_ids: set[str] = set()
    for index, agent in enumerate(registry.agents):
        if agent.id in agent_ids:
            problems.append(f"agents[{index}].id: duplicate agent id {agent.id!r}")
        agent_ids.add(agent.id)
    top_roles: set[str] = set()
    for index, role in enumerate(registry.roles or ()):
        if role in top_roles:
            problems.append(f"roles[{index}]: duplicate role {role!r}")
        top_roles.add(role)
    for index, agent in enumerate(registry.agents):
        if agent.roles is not None:
            if registry.roles is None:
                problems.append(f"agents[{index}].roles: declare the top-level 'roles' list first")
            if not agent.entry:
                problems.append(
                    f"agents[{index}].roles: only entry agents (entry: true) can list roles"
                )
            seen_roles: set[str] = set()
            for role_index, role in enumerate(agent.roles):
                if registry.roles is not None and role not in top_roles:
                    problems.append(
                        f"agents[{index}].roles[{role_index}]: "
                        f"role {role!r} is not in the top-level roles list"
                    )
                if role in seen_roles:
                    problems.append(f"agents[{index}].roles[{role_index}]: duplicate role {role!r}")
                seen_roles.add(role)
        if agent.calls is not None:
            problems.extend(_agent_list_problems(f"agents[{index}].calls", agent.calls, agent_ids))
    tool_ids: set[str] = set()
    for index, tool in enumerate(registry.tools):
        if tool.id in tool_ids:
            problems.append(f"tools[{index}].id: duplicate tool id {tool.id!r}")
        tool_ids.add(tool.id)
        problems.extend(
            _agent_list_problems(
                f"tools[{index}].supported_agents", tool.supported_agents, agent_ids
            )
        )
    delegation_ids: set[str] = set()
    for index, delegation in enumerate(registry.delegation_tools):
        if delegation.id in delegation_ids:
            problems.append(f"delegation_tools[{index}].id: duplicate tool id {delegation.id!r}")
        elif delegation.id in tool_ids:
            problems.append(
                f"delegation_tools[{index}].id: {delegation.id!r} is already used by a tool"
            )
        delegation_ids.add(delegation.id)
        if delegation.agent not in agent_ids:
            problems.append(
                f"delegation_tools[{index}].agent: "
                f"agent {delegation.agent!r} is not declared under agents"
            )
        problems.extend(
            _agent_list_problems(
                f"delegation_tools[{index}].supported_agents",
                delegation.supported_agents,
                agent_ids,
            )
        )
    return problems
