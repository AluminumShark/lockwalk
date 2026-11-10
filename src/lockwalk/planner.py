"""Check each spec case against the inventory before anything runs."""

from lockwalk.models import AgentGraph, CaseStatus, Inventory, PlannedCase
from lockwalk.spec_loader import SpecFile


def plan_cases(
    spec: SpecFile, inventory: Inventory, graph: AgentGraph | None = None
) -> tuple[PlannedCase, ...]:
    """Mark each case UNTESTED, or ERROR when it refers to something that does not exist.

    Combinations outside a tool's supported_agents are allowed on purpose: they are the
    negative tests that check whether a denial really happens.

    Without a graph, only registry agents are known, so with no registry every case
    reports an undeclared agent. With a graph, every graph node id is known too
    (declared in the registry, or found by any source). The role check applies only
    when the registry has a top-level roles list: then a case whose role is not in that
    list is an ERROR; without the list, or without a graph, roles are not checked.

    When some graph node is not a registry agent, an unknown agent's message also says
    that discovery did not report it; otherwise the plain message is kept.
    Names, roles, and actions are matched exactly, case included.
    """
    agents = set(inventory.agents)
    discovery_knows_more = False
    if graph is not None:
        node_ids = {node.id for node in graph.nodes}
        discovery_knows_more = not node_ids <= agents
        agents |= node_ids
    unknown_suffix = " and no discovery source reported it" if discovery_knows_more else ""
    roles = graph.roles if graph is not None else None
    failed_sources = [source.source.label for source in inventory.sources if not source.ok]
    planned: list[PlannedCase] = []
    for case in spec.cases:
        problems: list[str] = []
        action_verified = False
        for name in dict.fromkeys(case.route):  # each unknown name is reported once
            if name not in agents:
                problems.append(f"agent {name!r} is not declared in the registry{unknown_suffix}")
        if roles is not None and case.role not in roles:
            problems.append(f"role {case.role!r} is not in the registry roles list")
        delegated_to = inventory.delegation_agents.get(case.tool)
        tool = inventory.tool(case.tool)
        if delegated_to is not None:
            problems.append(
                f"tool {case.tool!r} is a delegation to agent {delegated_to!r}; "
                "target the tools behind that agent instead"
            )
        elif tool is None:
            message = f"tool {case.tool!r} is not in the inventory"
            if failed_sources:
                message += (
                    " (it may be missing because these sources failed: "
                    f"{', '.join(failed_sources)})"
                )
            problems.append(message)
        elif tool.action is not None:
            if tool.action == case.action:
                action_verified = True
            else:
                problems.append(
                    f"action {case.action!r} does not match the registry action "
                    f"{tool.action!r} for tool {case.tool!r}"
                )
        planned.append(
            PlannedCase(
                scenario=case,
                status=CaseStatus.ERROR if problems else CaseStatus.UNTESTED,
                problems=tuple(problems),
                action_verified=action_verified,
            )
        )
    return tuple(planned)
