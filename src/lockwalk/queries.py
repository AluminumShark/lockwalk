"""Turn spec cases and role x tool routes into questions for the IAM.

Pure: no file, network, or clock access.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, NamedTuple

from pydantic import ValidationError

from lockwalk.config import PolicyConfig
from lockwalk.fixtures import FixturesFile, ResourceFixture, SubjectFixture
from lockwalk.graph.analysis import GraphIndex, index_graph, name_list, plural, role_callers
from lockwalk.harness.protocol import reduce_subject
from lockwalk.inventory.base import truncate
from lockwalk.models import (
    AgentGraph,
    CaseStatus,
    Expectation,
    IdentityMode,
    Inventory,
    InventoryTool,
    PlannedCase,
    Risk,
    TestScenario,
)
from lockwalk.policy.base import Entity, Query, QueryAction

ControlKey = tuple[str, str]  # (action name, resource type)


@dataclass(frozen=True)
class HopAsk:
    """The questions for one step of a route."""

    caller: str  # "user" for the first hop, otherwise an agent id
    target: str  # an agent id, or the tool id for the tool hop
    kind: Literal["agent", "tool"]
    mode: IdentityMode
    # (one,), or (user, agent) when mode is "undeclared". The hop's verdict is ERROR if any
    # answer is ERROR, the shared verdict if both agree, and UNKNOWN if they differ.
    queries: tuple[Query, ...]
    # The positive-control pair an allow here counts for: (invoke_action, "agent") for agent
    # hops, and (case action, resource type) for the tool hop.
    control: ControlKey


@dataclass(frozen=True)
class CaseAsk:
    """Everything lockwalk asks about one spec case."""

    case_id: str
    role: str
    tool: str
    expect: Expectation
    route: tuple[str, ...]  # the case's agents, in order
    risk: Risk
    # Agent hops in route order (only with ask_every_hop), then the tool hop. Empty
    # exactly when problems is not empty.
    hops: tuple[HopAsk, ...]
    # The user's own identity for the tool hop: the escalation comparison. None when the
    # tool hop's mode is "user". For "undeclared" it is the hop's user query.
    plain_user: Query | None
    problems: tuple[str, ...] = ()  # not empty: the case is ERROR and nothing is asked

    @property
    def tool_hop(self) -> HopAsk:
        """The tool hop. Only valid when problems is empty (hops is empty otherwise)."""
        return self.hops[-1]


@dataclass(frozen=True)
class RowAsk:
    """One role x tool x calling agent from the agent graph, for the escalation check."""

    role: str
    tool: str
    via: str
    risk: Risk
    mode: IdentityMode  # "agent", "on_behalf_of", or "undeclared"
    path: tuple[str, ...]  # agent ids from a start agent to via
    path_query: Query | None  # None exactly when unchecked is set
    user_query: Query | None  # None exactly when unchecked is set
    control: ControlKey | None  # None exactly when unchecked is set
    unchecked: str | None = None  # why the row is UNCHECKED


@dataclass(frozen=True)
class QueryPlan:
    # One CaseAsk per planned case whose PlannedCase status is not ERROR, in plan order. That
    # includes cases whose questions could not be built: they have problems set and empty
    # hops. Planned ERROR cases (ERROR before build_queries) are left out; their errors are
    # already in the static report.
    cases: tuple[CaseAsk, ...]
    rows: tuple[RowAsk, ...]  # role order, then inventory tool order, then via id
    warnings: tuple[str, ...]

    def queries(self) -> list[Query]:
        """Every question to ask, in plan order (duplicates included; ask_all removes them)."""
        found: list[Query] = []
        for case in self.cases:
            for hop in case.hops:
                found.extend(hop.queries)
            if case.plain_user is not None:
                found.append(case.plain_user)
        for row in self.rows:
            for query in (row.path_query, row.user_query):
                if query is not None:
                    found.append(query)
        return found


# Rows are added to the max_queries budget in this order: the riskiest first.
_RISK_RANK = {
    risk: rank
    for rank, risk in enumerate((Risk.UNKNOWN, Risk.CRITICAL, Risk.HIGH, Risk.MEDIUM, Risk.LOW))
}


def act_chain(agents: Sequence[str]) -> dict[str, Any]:
    """RFC 8693 style nesting: the last agent is outermost, the first innermost."""
    link: dict[str, Any] | None = None
    for agent in agents:
        link = (
            {"type": "agent", "id": agent}
            if link is None
            else {"type": "agent", "id": agent, "act": link}
        )
    if link is None:
        raise ValueError("a delegation chain needs at least one agent")
    return link


def _build_error(exc: ValidationError) -> str:
    errors = exc.errors()
    message = str(errors[0]["msg"]) if errors else str(exc)
    return f"the questions for this case cannot be built: {truncate(message)}"


def _copy(value: dict[str, Any]) -> dict[str, Any]:
    """A fresh copy of a context, so no list or dict object is shared between queries."""
    return {
        key: _copy(item)
        if isinstance(item, dict)
        else list(item)
        if isinstance(item, list)
        else item
        for key, item in value.items()
    }


def _context(
    case_id: str | None,
    route: Sequence[str],
    tool: str,
    conditions: dict[str, Any],
    *,
    row: tuple[str, str] | None = None,
    hop: tuple[str, str] | None = None,
) -> dict[str, Any]:
    lockwalk: dict[str, Any] = {"case": case_id}
    if row is not None:
        lockwalk["row"] = {"role": row[0], "tool": row[1]}
    lockwalk["path"] = list(route)
    lockwalk["tool"] = tool
    if hop is not None:
        lockwalk["hop"] = {"caller": hop[0], "target": hop[1]}
    return {"lockwalk": lockwalk, **_copy(conditions)}


def _user_entity(
    name: str, role: str, subject: SubjectFixture | None, roles_property: str
) -> Entity | str:
    """The user: the fixture's roles and properties, or just the one role without a fixture.

    The roles go in `roles_property`. A string is returned instead when the fixture sets
    that property itself: it is the problem to report.
    """
    if subject is None:
        return Entity(type="user", id=name, properties={roles_property: [role]})
    if roles_property in subject.properties:
        return (
            f"subject {name!r} in the fixtures sets properties.{roles_property}, "
            "which lockwalk fills from 'roles' ([policy] roles_property)"
        )
    return Entity(
        type="user",
        id=name,
        properties={roles_property: list(subject.roles), **subject.properties},
    )


def _resource_entity(kind: str, name: str, fixture: ResourceFixture | None) -> Entity:
    resource_id = fixture.id if fixture is not None and fixture.id is not None else name
    properties = _copy(fixture.properties) if fixture is not None else {}
    return Entity(type=kind, id=resource_id, properties=properties)


def obo(user: Entity, chain: Sequence[str]) -> Entity:
    """The user acting through a chain of agents (RFC 8693 `act`)."""
    return Entity(type="user", id=user.id, properties={**user.properties, "act": act_chain(chain)})


class _Asked(NamedTuple):
    queries: tuple[Query, ...]  # what the hop asks
    plain_user: Query | None  # the user's own question; None when the mode is "user"


class _Builder:
    """Shared lookups for building the questions of one run."""

    def __init__(
        self,
        graph: AgentGraph,
        inventory: Inventory,
        fixtures: FixturesFile | None,
        policy: PolicyConfig,
    ) -> None:
        self.tools: dict[str, InventoryTool] = {}
        for tool in inventory.tools:
            self.tools.setdefault(tool.id, tool)
        self.fixtures = fixtures
        self.policy = policy
        self.index: GraphIndex = index_graph(graph)
        # Agents used as the identity of a question, in first-use order.
        self.agent_uses: dict[str, None] = {}

    def agent(self, agent_id: str) -> Entity:
        fixture = self.fixtures.agents.get(agent_id) if self.fixtures is not None else None
        properties = dict(fixture.properties) if fixture is not None else {}
        return Entity(type="agent", id=agent_id, properties=properties)

    def agent_subject(self, agent_id: str) -> Entity:
        """An agent asking in its own name; remembered for the missing-fixture warning."""
        self.agent_uses[agent_id] = None
        return self.agent(agent_id)

    def mode_of(self, node_id: str) -> IdentityMode:
        node = self.index.nodes.get(node_id)
        if node is None or node.delegation_mode is None:
            return "undeclared"
        return node.delegation_mode

    def ask(
        self,
        mode: IdentityMode,
        user: Entity,
        caller: str,
        chain: Sequence[str],
        make: Callable[[Entity], Query],
    ) -> _Asked:
        """The questions one hop asks, by mode."""
        if mode == "user":
            return _Asked((make(user),), None)
        if mode == "agent":
            return _Asked((make(self.agent_subject(caller)),), make(user))
        if mode == "on_behalf_of":
            return _Asked((make(obo(user, chain)),), make(user))
        as_user = make(user)
        as_agent = make(self.agent_subject(caller))
        return _Asked((as_user, as_agent), as_user)


class _Missing:
    """Fixtures that were not found, with the cases that needed them (one warning each)."""

    def __init__(self) -> None:
        self.actors: dict[str, list[str]] = {}
        self.resources: dict[str, list[str]] = {}

    def warnings(self) -> list[str]:
        found = [
            f"actor {name!r} has no fixture; sending only its id and role (cases: {name_list(ids)})"
            for name, ids in self.actors.items()
        ]
        found.extend(
            f"resource fixture {name!r} is not defined; sending its name as the id, "
            f"with no properties (cases: {name_list(ids)})"
            for name, ids in self.resources.items()
        )
        return found


def _agent_hops(builder: _Builder, case: TestScenario, user: Entity) -> list[HopAsk]:
    """One hop per agent on the route (only with ask_every_hop)."""
    route = case.route
    invoke = QueryAction(name=builder.policy.invoke_action)
    hops: list[HopAsk] = []
    for i, target in enumerate(route):
        caller = "user" if i == 0 else route[i - 1]
        mode: IdentityMode = "user" if i == 0 else builder.mode_of(caller)
        context = _context(case.id, route, case.tool, case.conditions, hop=(caller, target))

        def make(subject: Entity, target: str = target, context: dict[str, Any] = context) -> Query:
            return Query(
                subject=subject,
                action=invoke,
                resource=builder.agent(target),
                context=_copy(context),
            )

        asked = builder.ask(mode, user, caller, route[:i], make)
        hops.append(
            HopAsk(
                caller=caller,
                target=target,
                kind="agent",
                mode=mode,
                queries=asked.queries,
                control=(builder.policy.invoke_action, "agent"),
            )
        )
    return hops


def _observed_entity(
    builder: _Builder, case: TestScenario, user: Entity, seen: Mapping[str, Any]
) -> Entity:
    """The subject of a question made with the identity the door received."""
    kind, ident = str(seen["type"]), str(seen["id"])
    entity: Entity
    if kind == "user":
        if ident == case.actor:
            entity = user
        else:
            fixtures = builder.fixtures
            subject = fixtures.subjects.get(ident) if fixtures is not None else None
            built = _user_entity(ident, case.role, subject, builder.policy.roles_property)
            entity = Entity(type="user", id=ident) if isinstance(built, str) else built
    elif kind == "agent":
        entity = builder.agent_subject(ident)
    else:
        entity = Entity(type=kind, id=ident)
    if "act" in seen:
        entity = Entity(
            type=entity.type,
            id=entity.id,
            properties={**_copy(entity.properties), "act": _copy(seen["act"])},
        )
    return entity


def _build_case(
    planned: PlannedCase,
    builder: _Builder,
    missing: _Missing,
    seen: Mapping[str, Any] | None = None,
) -> CaseAsk:
    case = planned.scenario
    fixtures = builder.fixtures
    inventory_tool = builder.tools.get(case.tool)
    risk = inventory_tool.risk if inventory_tool is not None else Risk.UNKNOWN
    route = case.route
    problems: list[str] = []

    def failed() -> CaseAsk:
        return CaseAsk(
            case.id, case.role, case.tool, case.expect, route, risk, (), None, tuple(problems)
        )

    try:
        subject = fixtures.subjects.get(case.actor) if fixtures is not None else None
        if subject is None:
            missing.actors.setdefault(case.actor, []).append(case.id)
        elif case.role not in subject.roles:
            problems.append(
                f"role {case.role!r} is not one of the roles of subject {case.actor!r} "
                f"in the fixtures ({', '.join(subject.roles)})"
            )
        built_user = _user_entity(case.actor, case.role, subject, builder.policy.roles_property)
        if isinstance(built_user, str):
            problems.append(built_user)

        name = case.resource_fixture
        fixture = fixtures.resources.get(name) if fixtures is not None else None
        if fixture is None:
            missing.resources.setdefault(name, []).append(case.id)
        kind = fixture.type if fixture is not None else None
        if kind is None and inventory_tool is not None:
            kind = inventory_tool.resource_type
        if kind is None:
            problems.append(
                f"resource fixture {name!r} has no type, and tool {case.tool!r} "
                "has no resource_type in the registry"
            )
        if problems or kind is None or isinstance(built_user, str):
            return failed()
        user = built_user

        caller = route[-1]
        mode: IdentityMode = case.delegation_mode or builder.mode_of(caller)
        action = QueryAction(name=case.action)
        context = _context(case.id, route, case.tool, case.conditions)
        hops = _agent_hops(builder, case, user) if builder.policy.ask_every_hop else []

        def make(subject: Entity) -> Query:
            return Query(
                subject=subject,
                action=action,
                resource=_resource_entity(kind, name, fixture),
                context=_copy(context),
            )

        asked = builder.ask(mode, user, caller, route, make)
        if seen is not None and (
            mode == "undeclared"
            or reduce_subject(asked.queries[0].subject.model_dump(mode="json")) != seen
        ):
            same_as_user = reduce_subject(user.model_dump(mode="json")) == seen
            asked = _Asked(
                (make(_observed_entity(builder, case, user, seen)),),
                None if same_as_user else make(user),
            )
            mode = "observed"
        hops.append(
            HopAsk(
                caller=caller,
                target=case.tool,
                kind="tool",
                mode=mode,
                queries=asked.queries,
                control=(case.action, kind),
            )
        )
        return CaseAsk(
            case.id,
            case.role,
            case.tool,
            case.expect,
            route,
            risk,
            tuple(hops),
            asked.plain_user,
            (),
        )
    except ValidationError as exc:
        problems.append(_build_error(exc))
        return failed()


def _unchecked_reason(fixtures: FixturesFile | None, role: str, tool: InventoryTool) -> str | None:
    if fixtures is None:
        return "no fixtures file, so there are no probes"
    if tool.action is None:
        return f"tool {tool.id!r} has no action in the registry"
    if tool.resource_type is None:
        return f"tool {tool.id!r} has no resource_type in the registry"
    if role not in fixtures.probes.subjects:
        return f"no probe subject for role {role!r} (probes.subjects)"
    resource_name = fixtures.probes.resources.get(tool.resource_type)
    if resource_name is None or resource_name not in fixtures.resources:
        return f"no probe resource for type {tool.resource_type!r} (probes.resources)"
    return None


def _unchecked_row(
    role: str, tool: InventoryTool, via: str, mode: IdentityMode, route: tuple[str, ...], why: str
) -> RowAsk:
    return RowAsk(role, tool.id, via, tool.risk, mode, route, None, None, None, why)


def _build_row(
    builder: _Builder,
    fixtures: FixturesFile,
    role: str,
    tool: InventoryTool,
    via: str,
    route: tuple[str, ...],
) -> RowAsk:
    """The questions of one row whose probes all exist (see _unchecked_reason)."""
    mode = builder.mode_of(via)
    if tool.action is None or tool.resource_type is None:
        raise AssertionError("_unchecked_reason checks the action and the resource type")
    kind = tool.resource_type
    try:
        subject_name = fixtures.probes.subjects[role]
        built_user = _user_entity(
            subject_name, role, fixtures.subjects.get(subject_name), builder.policy.roles_property
        )
        if isinstance(built_user, str):
            return _unchecked_row(role, tool, via, mode, route, built_user)
        user = built_user
        resource_name = fixtures.probes.resources[kind]
        fixture = fixtures.resources[resource_name]
        context = _context(None, route, tool.id, {}, row=(role, tool.id))
        action = QueryAction(name=tool.action)

        def make(subject: Entity) -> Query:
            return Query(
                subject=subject,
                action=action,
                resource=_resource_entity(kind, resource_name, fixture),
                context=_copy(context),
            )

        path_subject = obo(user, route) if mode == "on_behalf_of" else builder.agent(via)
        path_query = make(path_subject)
        user_query = make(user)
    except ValidationError as exc:
        return _unchecked_row(role, tool, via, mode, route, _build_error(exc))
    control = (tool.action, kind)
    return RowAsk(role, tool.id, via, tool.risk, mode, route, path_query, user_query, control, None)


def _case_keys(cases: Sequence[CaseAsk]) -> set[str]:
    keys: set[str] = set()
    for case in cases:
        keys.update(query.key() for hop in case.hops for query in hop.queries)
        if case.plain_user is not None:
            keys.add(case.plain_user.key())
    return keys


class _Slot(NamedTuple):
    """A row whose probes exist and whose questions are not built yet."""

    position: int
    role: str
    tool: InventoryTool
    via: str
    route: tuple[str, ...]


def _build_rows(
    builder: _Builder, graph: AgentGraph, inventory: Inventory, cases: Sequence[CaseAsk]
) -> tuple[list[RowAsk], int]:
    """The rows in order, and how many were left unasked because of max_queries.

    Rows are built in budget priority order (riskiest first, then row order), and a row's
    questions are only built while the budget can still take them.
    """
    fixtures = builder.fixtures
    if graph.roles is None or not inventory.tools:
        return [], 0
    rows: list[RowAsk | None] = []
    slots: list[_Slot] = []
    for role in graph.roles:
        by_tool: dict[str, list[tuple[str, tuple[str, ...]]]] = {}
        for caller, tool_id, route in role_callers(graph, role, index=builder.index):
            by_tool.setdefault(tool_id, []).append((caller, route))
        for tool in inventory.tools:
            for caller, route in by_tool.get(tool.id, ()):
                why = _unchecked_reason(fixtures, role, tool)
                if why is not None:
                    mode = builder.mode_of(caller)
                    rows.append(_unchecked_row(role, tool, caller, mode, route, why))
                else:
                    slots.append(_Slot(len(rows), role, tool, caller, route))
                    rows.append(None)
    limit = builder.policy.max_queries
    seen = _case_keys(cases)
    dropped = 0
    for slot in sorted(slots, key=lambda item: _RISK_RANK[item.tool.risk]):
        built: RowAsk | None = None
        # Every row adds at least one new question (its context holds the role, the tool, and
        # the path), so a full budget takes no more rows.
        if len(seen) < limit and fixtures is not None:
            built = _build_row(builder, fixtures, slot.role, slot.tool, slot.via, slot.route)
        if built is not None and (built.path_query is None or built.user_query is None):
            rows[slot.position] = built  # could not be built; it keeps its own reason
            continue
        if built is not None and built.path_query is not None and built.user_query is not None:
            fresh = {built.path_query.key(), built.user_query.key()} - seen
            if len(seen) + len(fresh) <= limit:
                seen |= fresh
                rows[slot.position] = built
                continue
        rows[slot.position] = _unchecked_row(
            slot.role,
            slot.tool,
            slot.via,
            builder.mode_of(slot.via),
            slot.route,
            f"not asked: [policy] max_queries = {limit} was reached",
        )
        dropped += 1
    return [row for row in rows if row is not None], dropped


def build_queries(
    plan: Sequence[PlannedCase],
    graph: AgentGraph,
    inventory: Inventory,
    fixtures: FixturesFile | None,
    policy: PolicyConfig,
    *,
    observed: Mapping[str, dict[str, Any]] | None = None,
) -> QueryPlan:
    """Build every question for the cases and the escalation rows.

    observed: case id -> the identity scripted mode saw the door receive (reduced, see
    harness.protocol.reduce_subject). The tool hop of such a case asks with that identity
    (mode "observed") unless it is the declared one.
    """
    builder = _Builder(graph, inventory, fixtures, policy)
    missing = _Missing()
    cases = tuple(
        _build_case(
            planned, builder, missing, observed.get(planned.scenario.id) if observed else None
        )
        for planned in plan
        if planned.status is not CaseStatus.ERROR
    )
    rows, dropped = _build_rows(builder, graph, inventory, cases)
    for row in rows:
        if row.unchecked is None and row.mode != "on_behalf_of":
            builder.agent_uses[row.via] = None
    warnings = missing.warnings()
    known = fixtures.agents if fixtures is not None else {}
    warnings.extend(
        f"agent {agent!r} has no fixture; sending only its id"
        for agent in builder.agent_uses
        if agent not in known
    )
    if dropped:
        was = "was" if dropped == 1 else "were"
        warnings.append(
            f"{dropped} escalation {plural('row', dropped)} {was} not asked because "
            f"[policy] max_queries = {policy.max_queries} was reached; narrow the probes"
        )
    return QueryPlan(cases=cases, rows=tuple(rows), warnings=tuple(warnings))
