"""Merge the registry and every discovery source into one inventory, and report drift.

Risk, action, and resource type come only from the registry. A tool that only a discovery
source reports gets risk=unknown, which the default gate treats as blocking.
"""

from collections import Counter
from collections.abc import Mapping, Sequence

from lockwalk.models import (
    Drift,
    Inventory,
    InventoryTool,
    Risk,
    SourceRef,
    SourceResult,
    ToolDescriptor,
)
from lockwalk.registry import Registry, ToolDecl

# id(source result) -> its tools by name, in source order. Built once per merge, so looking
# up one tool never scans a source's whole tool list (that was quadratic in its size).
_ToolIndex = Mapping[int, Mapping[str, Sequence[ToolDescriptor]]]


def registry_source(registry: Registry, label: str) -> SourceResult:
    """Describe the registry itself as a source, so reports list it with the others."""
    tools = tuple(ToolDescriptor(name=t.id, description=t.description) for t in registry.tools)
    return SourceResult(source=SourceRef(kind="registry", label=label), ok=True, tools=tools)


def merge_inventory(
    discovered: Sequence[SourceResult],
    *,
    registry: Registry | None = None,
    registry_label: str = "registry",
) -> Inventory:
    """Combine the registry with what discovery sources reported.

    Tools from a source that partly failed are kept on purpose: the source error still makes
    the run exit 2, so the report is never trusted. The one exception is an optional source
    that was unreachable (failed with no tools): that is only a warning, and the run is not
    untrusted because of it. `supported_agents` is the registry's list
    plus the `agents` of every source that reports the tool. A discovered description is used
    only when the registry has none.

    A tool that more than one source reports is an error (see _conflict), except when every
    one of them is a Python source and they all describe it identically. Then the tool lists
    every source, and its `supported_agents` include the `agents` of each.

    A discovered tool whose name is a registry delegation tool id is not a tool row (the
    delegation tool is an agent). A source other than Python that reports one gets a warning,
    because a real tool with that name would otherwise vanish. It is not an error: exposing
    an agent over MCP is exactly what `delegation_tools` declares.
    """
    errors: list[str] = []
    warnings: list[str] = []
    delegation = {t.id: t.agent for t in registry.delegation_tools} if registry is not None else {}
    reporters: dict[str, list[SourceResult]] = {}
    shadowed: dict[str, list[str]] = {}
    for result in discovered:
        if not result.ok:
            if result.unavailable:
                consequence = (
                    "using registry declarations only"
                    if registry is not None
                    else "its tools are unknown"
                )
                warnings.append(
                    f"{result.source.label}: unavailable ({result.error or 'failed'}); "
                    f"{consequence}"
                )
            else:
                errors.append(f"{result.source.label}: {result.error or 'failed'}")
        warnings.extend(result.warnings)
        for tool in result.tools:
            if tool.name in delegation:
                # An agent exposed as a tool is declared under delegation_tools, so it is
                # not a tool row. A Python walk reports its own wrappers that way. Any other
                # source is told to the user, because a real tool that shares the id would
                # otherwise be skipped without a trace.
                labels = shadowed.setdefault(tool.name, [])
                if result.source.kind != "python" and result.source.label not in labels:
                    labels.append(result.source.label)
                continue
            reporters.setdefault(tool.name, []).append(result)

    for name, labels in shadowed.items():
        if labels:
            warnings.append(
                f"tool {name!r} is reported by {', '.join(labels)} but is declared as a "
                f"delegation tool for agent {delegation[name]!r}, so it is treated as that "
                "agent and gets no tool spec; if it is a real tool, give the delegation tool "
                "a different id"
            )

    declared_agents = registry.agent_ids if registry is not None else ()
    declared_agent_set = frozenset(declared_agents)
    if registry is not None:
        for result in discovered:
            for agent in result.agents:
                if agent not in declared_agent_set:
                    errors.append(
                        f"{result.source.label}: agent {agent!r} in 'agents' "
                        "is not declared in the registry"
                    )

    label_counts = Counter(result.source.label for result in discovered)
    mcp_labels = {result.source.label for result in discovered if result.source.kind == "mcp"}
    for label, count in label_counts.items():
        if count > 1:
            # An MCP source without a 'name' is labeled by its server name or program name
            # (for example mcp:npx), so two of them can easily share a label.
            fix = (
                "remove the duplicate, or set a distinct 'name' on one of these "
                "[[inventory.mcp]] sources"
                if label in mcp_labels
                else "remove the duplicate or give one of them a distinct name"
            )
            errors.append(f"two inventory sources share the label {label!r}; {fix}")

    index = _tool_index(discovered)
    for name, results in reporters.items():
        conflict = _conflict(name, results, index)
        if conflict is not None:
            errors.append(conflict)

    tool_ids = [tool.id for tool in registry.tools] if registry is not None else []
    declared = set(tool_ids)
    tool_ids.extend(name for name in reporters if name not in declared)
    decls: dict[str, ToolDecl] = {}
    for decl in registry.tools if registry is not None else ():
        decls.setdefault(decl.id, decl)  # the first one, like Registry.tool
    tools = tuple(
        _merge_tool(tool_id, decls.get(tool_id), registry_label, reporters.get(tool_id, []), index)
        for tool_id in tool_ids
    )

    sources: list[SourceResult] = []
    if registry is not None:
        sources.append(registry_source(registry, registry_label))
    sources.extend(discovered)

    drift, drift_warnings = _drift(registry, discovered, reporters)
    warnings.extend(drift_warnings)
    return Inventory(
        agents=declared_agents,
        tools=tools,
        sources=tuple(sources),
        drift=drift,
        delegation_agents=delegation,
        errors=tuple(errors),
        warnings=tuple(warnings),
    )


def _tool_index(results: Sequence[SourceResult]) -> _ToolIndex:
    index: dict[int, dict[str, list[ToolDescriptor]]] = {}
    for result in results:
        by_name = index.setdefault(id(result), {})
        if by_name:
            continue  # the same result object listed twice
        for tool in result.tools:
            by_name.setdefault(tool.name, []).append(tool)
    return index


def _descriptors(
    name: str, results: Sequence[SourceResult], index: _ToolIndex
) -> list[ToolDescriptor]:
    """Every descriptor named `name` in these results, in result order, then tool order."""
    return [tool for result in results for tool in index[id(result)].get(name, ())]


def _conflict(name: str, results: Sequence[SourceResult], index: _ToolIndex) -> str | None:
    """The error for a tool that several sources report, or None when they may share it.

    Python sources may share a tool when they describe it identically (name, description,
    and hints): several entry agents of one app often share sub-agents, so each walk reports
    the same tools. Any other overlap is an error, because two MCP servers or JSON exports can
    describe two different tools in exactly the same way.
    """
    labels = sorted({result.source.label for result in results})
    if len(labels) < 2:
        return None
    descriptors = _descriptors(name, results, index)
    identical = all(descriptor == descriptors[0] for descriptor in descriptors)
    if identical and all(result.source.kind == "python" for result in results):
        return None
    detail = "" if identical else " with different descriptions"
    return (
        f"tool {name!r} is reported by more than one discovery source{detail} "
        f"({', '.join(labels)}); rename it or remove one of the sources"
    )


def _merge_tool(
    tool_id: str,
    decl: ToolDecl | None,
    registry_label: str,
    results: Sequence[SourceResult],
    index: _ToolIndex,
) -> InventoryTool:
    sources: list[str] = [registry_label] if decl is not None else []
    sources.extend(result.source.label for result in results)
    agents: list[str] = list(decl.supported_agents) if decl is not None else []
    for result in results:
        agents.extend(agent for agent in result.agents if agent not in agents)
    descriptors = _descriptors(tool_id, results, index)
    description = decl.description if decl is not None and decl.description else None
    if description is None:
        description = next((d.description for d in descriptors if d.description), None)
    hints = next((d.hints for d in descriptors if d.hints), {})
    return InventoryTool(
        id=tool_id,
        action=decl.action if decl is not None else None,
        risk=decl.risk if decl is not None else Risk.UNKNOWN,
        resource_type=decl.resource_type if decl is not None else None,
        supported_agents=tuple(agents),
        sources=tuple(sources),
        description=description,
        hints=dict(hints),
    )


def _drift(
    registry: Registry | None,
    discovered: Sequence[SourceResult],
    reporters: dict[str, list[SourceResult]],
) -> tuple[Drift | None, list[str]]:
    if registry is None or not discovered:
        return None, []
    declared = {tool.id for tool in registry.tools}
    discovered_only = tuple(name for name in reporters if name not in declared)
    registry_only = tuple(tool.id for tool in registry.tools if tool.id not in reporters)
    warnings = [
        f"tool {name!r} was reported by a discovery source but is not declared "
        "in the registry, so its risk is unknown"
        for name in discovered_only
    ]
    complete = all(result.ok for result in discovered)
    suffix = "" if complete else " (this may be incomplete because a source failed)"
    warnings += [
        f"tool {name!r} is declared in the registry but no discovery source reported it{suffix}"
        for name in registry_only
    ]
    drift = Drift(
        discovered_only=discovered_only,
        registry_only=registry_only,
        complete=complete,
    )
    return drift, warnings
