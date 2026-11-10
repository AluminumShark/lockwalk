"""Build the merged agent call graph from the registry and every discovery source.

Nothing is run here: the graph only combines what the registry declares with what the
inventory sources already collected (tool lists, `agents` lists, and graph fragments).

Opacity: an `agent` or `remote_agent` node is known, so not opaque, only when
lockwalk knows what it calls, and no fragment reported that it could not read all of the
agent's tools (tools_hidden). It knows what the agent calls when the registry declares its
`calls` (even `calls: []`), or when at least one fragment reported it as a node with
opaque=False, which means discovery walked inside it. A walk does not count for an agent
the registry declares `remote:`. Every other agent is opaque, whether discovery reached it
only as an edge target, through a delegation tool, or not at all. `calls` never clears
tools_hidden: it lists agents, so it cannot stand in for tools that were not read.
`mcp_server` nodes follow their source: opaque unless matched to a source that is ok; an
unavailable source is always opaque.

Merge rules that nothing above settles, chosen here:
- A registry agent keeps every registry value except `opaque`; a fragment only adds its
  labels to `sources`.
- An agent that only discovery reported keeps the values of the first fragment that reported
  it. Later fragments fill values that are still unset.
- An agent named in a source's `agents` list that is not yet a node becomes a plain agent
  node. Without a registry, those names would otherwise turn configs written without a registry into
  graph errors.
- `GraphNode.entry` is rewritten to match `entry_agents`. It stays False for every node
  when no agent is marked and all of them are only treated as entries.
"""

from collections.abc import Iterable

from lockwalk.graph.analysis import reach
from lockwalk.models import (
    AgentGraph,
    EdgeKind,
    GraphDrift,
    GraphEdge,
    GraphNode,
    Inventory,
    NodeKind,
    Provenance,
    SourceResult,
    check_name,
)
from lockwalk.registry import AgentDecl, Registry
from lockwalk.urls import redact_url

AGENT_KINDS = frozenset({NodeKind.AGENT, NodeKind.REMOTE_AGENT})
NO_ENTRY_WARNING = "no agent is marked entry: true; every agent is treated as an entry point"
INCOMPLETE_SUFFIX = " (this may be incomplete because a source failed)"
NO_REGISTRY_HINT = (
    "without a registry, lockwalk cannot be told what agents call; "
    "add a registry and declare 'calls' to look past opaque agents"
)


def build_graph(
    registry: Registry | None, inventory: Inventory, *, registry_label: str = "registry"
) -> AgentGraph:
    """Merge registry declarations and discovery fragments into one agent call graph.

    `inventory` must come from merge_inventory with the same registry and registry_label.
    Problems that make the graph untrustworthy go to `errors`; everything else is a warning.
    """
    return _GraphBuilder(registry, inventory, registry_label).build()


def _unique(*groups: Iterable[str]) -> tuple[str, ...]:
    """Concatenate the groups, keeping the first occurrence of each label."""
    return tuple(dict.fromkeys(label for group in groups for label in group))


def _edge_order(edge: GraphEdge) -> tuple[str, str, str, str]:
    return (edge.from_id, edge.kind.value, edge.to_id, edge.provenance.value)


def _merge_edges(edges: Iterable[GraphEdge]) -> list[GraphEdge]:
    """Merge edges with the same (from_id, to_id, kind, provenance), then sort them."""
    merged: dict[tuple[str, str, EdgeKind, Provenance], GraphEdge] = {}
    for edge in edges:
        key = (edge.from_id, edge.to_id, edge.kind, edge.provenance)
        known = merged.get(key)
        merged[key] = (
            edge
            if known is None
            else known.model_copy(
                update={
                    "sources": _unique(known.sources, edge.sources),
                    "wrapped_by": _unique(known.wrapped_by, edge.wrapped_by),
                }
            )
        )
    return sorted(merged.values(), key=_edge_order)


def _registry_node(agent: AgentDecl, label: str) -> GraphNode:
    return GraphNode(
        id=agent.id,
        kind=NodeKind.REMOTE_AGENT if agent.remote is not None else NodeKind.AGENT,
        entry=agent.entry,
        roles=agent.roles,
        delegation_mode=agent.delegation_mode,
        opaque=agent.calls is None,  # final value set by _settle_opacity
        remote_url=redact_url(agent.remote) if agent.remote is not None else None,
        sources=(label,),
    )


class _GraphBuilder:
    """Runs the build steps in order. Each step reads and updates the shared state."""

    def __init__(self, registry: Registry | None, inventory: Inventory, label: str) -> None:
        self.registry = registry
        self.inventory = inventory
        self.label = label
        self.declared: dict[str, AgentDecl] = (
            {agent.id: agent for agent in registry.agents} if registry is not None else {}
        )
        self.nodes: dict[str, GraphNode] = {}  # insertion order is the node order
        self.edges: list[GraphEdge] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        # Ordered sets (dict keys): fragment node ids and fragment entries, first-seen order.
        self.fragment_ids: dict[str, None] = {}
        self.fragment_entries: dict[str, None] = {}
        self.reported: set[str] = set()  # agent ids that some discovered edge or node names
        # Node id -> (source label, opaque, tools_hidden) for every fragment that reports it.
        self.opacity: dict[str, list[tuple[str, bool, bool]]] = {}
        self.unknown: dict[str, None] = {}  # ordered set: agents opaque because not known
        self.has_fragment = False

    def build(self) -> AgentGraph:
        for agent in self.declared.values():
            self.nodes[agent.id] = _registry_node(agent, self.label)
        self._add_fragments()
        self._add_registry_edges()
        self._add_source_agents()
        self._settle_opacity()  # every agent node exists from here on
        self._add_delegation_edges()
        self._attach_mcp_boundaries()
        self._add_unavailable_sources()
        self.edges = _merge_edges(self.edges)
        undeclared = self._apply_declared_calls()
        entries, inferred = self._entries()
        drift = self._drift(undeclared)
        self._check_edges()
        marked = set() if inferred else set(entries)
        nodes = tuple(
            node
            if node.entry == (node.id in marked)
            else node.model_copy(update={"entry": node.id in marked})
            for node in self.nodes.values()
        )
        return AgentGraph(
            nodes=nodes,
            edges=tuple(self.edges),
            entry_agents=entries,
            entry_inferred=inferred,
            roles=self.registry.roles if self.registry is not None else None,
            drift=drift,
            errors=tuple(self.errors),
            warnings=tuple(self.warnings),
        )

    def _discovery_sources(self) -> list[SourceResult]:
        return [result for result in self.inventory.sources if result.source.kind != "registry"]

    def _declare(self, from_id: str, to_id: str, kind: EdgeKind, label: str) -> None:
        self.edges.append(
            GraphEdge(
                from_id=from_id,
                to_id=to_id,
                kind=kind,
                provenance=Provenance.DECLARED,
                sources=(label,),
            )
        )

    def _add_discovered(self, edge: GraphEdge) -> None:
        """Add an edge a source reported, pointing a delegation tool at its agent first.

        Without the rewrite, an agent that reaches `ask_oracle` would stop at a tool and
        never reach `oracle`, which would give a false PASS. The agents the final edge names
        count as reported by discovery.
        """
        agent = self.inventory.delegation_agents.get(edge.to_id)
        if edge.kind == EdgeKind.USES_TOOL and agent is not None:
            edge = edge.model_copy(update={"kind": EdgeKind.AGENT_AS_TOOL, "to_id": agent})
        self.reported.add(edge.from_id)
        if edge.kind != EdgeKind.USES_TOOL:
            self.reported.add(edge.to_id)
        self.edges.append(edge)

    def _mark_boundary(self, node_id: str, label: str | None, opaque: bool) -> None:
        """Set whether a boundary node is opaque, and add the label of its source, if any."""
        node = self.nodes[node_id]
        labels = () if label is None else (label,)
        self.nodes[node_id] = node.model_copy(
            update={"opaque": opaque, "sources": _unique(node.sources, labels)}
        )

    def _add_fragments(self) -> None:
        for result in self._discovery_sources():
            fragment = result.graph
            if fragment is None:
                continue
            label = result.source.label
            self.has_fragment = self.has_fragment or bool(fragment.nodes or fragment.edges)
            for node in fragment.nodes:
                self._merge_fragment_node(node, label)
            for edge in fragment.edges:
                self._add_discovered(
                    edge.model_copy(update={"sources": _unique(edge.sources, (label,))})
                )

    def _merge_fragment_node(self, node: GraphNode, label: str) -> None:
        """Merge one fragment node by id. `opaque` is decided later by _settle_opacity."""
        self.reported.add(node.id)
        self.fragment_ids.setdefault(node.id)
        if node.entry:
            self.fragment_entries.setdefault(node.id)
        self.opacity.setdefault(node.id, []).append((label, node.opaque, node.tools_hidden))
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node.model_copy(
                update={"sources": _unique(node.sources, (label,))}
            )
            return
        sources = _unique(existing.sources, node.sources, (label,))
        if node.id in self.declared:
            self.nodes[node.id] = existing.model_copy(update={"sources": sources})
            return
        self.nodes[node.id] = existing.model_copy(
            update={
                "sources": sources,
                "roles": existing.roles if existing.roles is not None else node.roles,
                "delegation_mode": existing.delegation_mode or node.delegation_mode,
                "remote_url": existing.remote_url or node.remote_url,
            }
        )

    def _settle_opacity(self) -> None:
        """Apply the opacity rule to every agent and remote_agent node.

        An agent is known only when its `calls` are declared, or when some fragment reported
        it with opaque=False (discovery walked inside it). Any other agent hides what it
        calls, so it is opaque; otherwise every rule through it would PASS unseen. A walk
        does not count for an agent the registry declares remote: a remote agent cannot be
        walked into, so that fragment saw a local stand-in with the same name.

        On top of that, an agent stays opaque (and tools_hidden) whenever some fragment
        could not read all of its tools, even with `calls` declared: `calls` names the
        agents it calls, not the tools it holds, so a tools factory or a tool that raised
        would otherwise give a false PASS.
        """
        for node_id, node in list(self.nodes.items()):
            if node.kind not in AGENT_KINDS:
                continue
            reports = self.opacity.get(node_id, [])
            hidden = [label for label, opaque, _ in reports if opaque]
            seen = [label for label, opaque, _ in reports if not opaque]
            tools_hidden = any(hides for _, _, hides in reports)
            decl = self.declared.get(node_id)
            calls_declared = decl is not None and decl.calls is not None
            declared_remote = decl is not None and decl.remote is not None
            walked = bool(seen) and not declared_remote
            unknown = not calls_declared and not walked
            opaque = unknown or tools_hidden
            if unknown and not tools_hidden:
                # Only a walk sets tools_hidden, and its warnings say what it could not read.
                # Declaring calls alone would not make such an agent known, so the hints
                # that suggest it are left out.
                self.unknown.setdefault(node_id)
            if (opaque, tools_hidden) != (node.opaque, node.tools_hidden):
                self.nodes[node_id] = node.model_copy(
                    update={"opaque": opaque, "tools_hidden": tools_hidden}
                )
            if opaque and declared_remote and seen:
                self.warnings.append(
                    f"agent {node_id!r} is declared remote in the registry but {seen[0]} "
                    "walked a local agent with that name; lockwalk keeps it opaque"
                )
            if calls_declared and tools_hidden:
                self.warnings.append(
                    f"agent {node_id!r} declares 'calls', but lockwalk could not read all of "
                    "its tools, so it stays opaque"
                )
            # Only when a fragment's walk cleared the flag that another source set.
            only_hidden = next((label for label in hidden if label not in seen), None)
            if walked and not opaque and not calls_declared and only_hidden is not None:
                self.warnings.append(
                    f"agent {node_id!r} is opaque in {only_hidden} but {seen[0]} saw it; "
                    "lockwalk assumes they are the same agent"
                )
        if self.registry is None and self.unknown:
            self.warnings.append(NO_REGISTRY_HINT)

    def _add_registry_edges(self) -> None:
        """Each agent's `calls`, and each registry tool's `supported_agents`."""
        if self.registry is None:
            return
        for agent in self.registry.agents:
            for callee in agent.calls or ():
                self._declare(agent.id, callee, EdgeKind.CALLS, self.label)
        for tool in self.registry.tools:
            for agent_id in tool.supported_agents:
                self._declare(agent_id, tool.id, EdgeKind.USES_TOOL, self.label)

    def _add_source_agents(self) -> None:
        """A source's `agents` use every tool it reports, except delegation tools."""
        delegation = self.inventory.delegation_agents
        for result in self._discovery_sources():
            label = result.source.label
            for agent_id in result.agents:
                if agent_id not in self.nodes:
                    self.nodes[agent_id] = GraphNode(id=agent_id, sources=(label,))
                for tool in result.tools:
                    if tool.name not in delegation:
                        self._declare(agent_id, tool.name, EdgeKind.USES_TOOL, label)

    def _add_delegation_edges(self) -> None:
        """Every agent that can use a delegation tool reaches the agent behind it."""
        if self.registry is None:
            return
        reporters = [
            (result, {tool.name for tool in result.tools})
            for result in self._discovery_sources()
            if result.agents
        ]
        for decl in self.registry.delegation_tools:
            users = [(agent_id, self.label) for agent_id in decl.supported_agents]
            for result, names in reporters:
                if decl.id in names:
                    users.extend((agent_id, result.source.label) for agent_id in result.agents)
            for agent_id, label in users:
                self._declare(agent_id, decl.agent, EdgeKind.AGENT_AS_TOOL, label)

    def _attach_mcp_boundaries(self) -> None:
        by_label: dict[str, SourceResult] = {}
        for result in self._discovery_sources():
            by_label.setdefault(result.source.label, result)
        for node_id, node in list(self.nodes.items()):
            if node.kind != NodeKind.MCP_SERVER:
                continue
            result = by_label.get(node_id)
            if result is None:
                self._mark_boundary(node_id, None, opaque=True)
                continue
            label = result.source.label
            self._mark_boundary(node_id, label, opaque=not result.ok)
            if not result.ok:
                continue
            for tool in result.tools:
                self._add_discovered(
                    GraphEdge(
                        from_id=node_id,
                        to_id=tool.name,
                        kind=EdgeKind.USES_TOOL,
                        provenance=Provenance.DISCOVERED,
                        sources=(label,),
                    )
                )

    def _add_unavailable_sources(self) -> None:
        for result in self._discovery_sources():
            if not result.unavailable:
                continue
            label = result.source.label
            try:
                check_name(label)
            except ValueError as exc:
                # Without a node the unseen region would vanish and could give a false PASS.
                self.errors.append(
                    f"optional source {label!r} cannot be shown in the agent graph because "
                    f"its label is not a valid id ({exc}); set a valid 'name' for it"
                )
                continue
            if label in self.nodes:
                self._mark_boundary(label, label, opaque=True)
            else:
                self.nodes[label] = GraphNode(
                    id=label, kind=NodeKind.MCP_SERVER, opaque=True, sources=(label,)
                )
            for agent_id in result.agents:
                self._declare(agent_id, label, EdgeKind.REMOTE, label)

    def _apply_declared_calls(self) -> list[GraphEdge]:
        """Declared calls drop non-tool inferred edges and flag unlisted ones.

        A discovered edge A -> B is declared when B is in A's 'calls', or when a delegation
        tool already declares A -> B (a declared agent_as_tool edge, made from the tool's
        `supported_agents` or from a source's `agents`). Edges to an mcp_server node are not
        flagged: 'calls' can only list agents, so the warning could never be fixed.
        """
        calls = {
            agent.id: frozenset(agent.calls)
            for agent in self.declared.values()
            if agent.calls is not None
        }
        delegations = {
            (edge.from_id, edge.to_id)
            for edge in self.edges
            if edge.kind == EdgeKind.AGENT_AS_TOOL and edge.provenance == Provenance.DECLARED
        }
        kept: list[GraphEdge] = []
        undeclared: list[GraphEdge] = []
        for edge in self.edges:
            allowed = calls.get(edge.from_id)
            if allowed is not None and edge.kind != EdgeKind.USES_TOOL:
                if edge.provenance == Provenance.INFERRED:
                    continue
                target = self.nodes.get(edge.to_id)
                if (
                    edge.provenance == Provenance.DISCOVERED
                    and edge.to_id not in allowed
                    and (edge.from_id, edge.to_id) not in delegations
                    and (target is None or target.kind != NodeKind.MCP_SERVER)
                ):
                    undeclared.append(edge)
                    self.warnings.append(
                        f"agent {edge.from_id!r} reaches {edge.to_id!r} "
                        f"({edge.kind.value}, {edge.provenance.value}) "
                        f"but its registry 'calls' does not list {edge.to_id!r}"
                    )
            kept.append(edge)
        self.edges = kept
        return undeclared

    def _entries(self) -> tuple[tuple[str, ...], bool]:
        entries = tuple(agent.id for agent in self.declared.values() if agent.entry)
        inferred = False
        if entries:
            self._warn_unmarked_targets(entries)
        if not entries:
            entries = tuple(
                node_id
                for node_id in self.fragment_entries
                if self.nodes[node_id].kind in AGENT_KINDS
            )
        if not entries:
            entries = tuple(node.id for node in self.nodes.values() if node.kind in AGENT_KINDS)
            inferred = bool(entries)
            if inferred:
                self.warnings.append(NO_ENTRY_WARNING)
        if self.registry is not None and self.registry.roles is not None:
            self.warnings.extend(
                f"entry agent {entry!r} lists no roles, so every role can use it"
                for entry in entries
                if self.nodes[entry].roles is None
            )
        return entries, inferred

    def _warn_unmarked_targets(self, entries: tuple[str, ...]) -> None:
        """Warn about top-level --python objects that no marked entry agent reaches.

        Such an object is often where users start talking to the system. If no entry agent
        reaches it, no role starts there or passes through it, so a rule could PASS without
        ever looking at the routes that start there. A target that an entry agent reaches
        is an ordinary sub-agent (pointing a target at one is how discovery is told about
        it), so it gets no warning. Reached is decided on the same edges, and with the same
        walk, as the unreachable list of the report (graph.analysis.unreachable_agents).
        """
        current = AgentGraph(
            nodes=tuple(self.nodes.values()),
            edges=tuple(self.edges),
            entry_agents=entries,
            entry_inferred=False,
            roles=None,
            drift=None,
        )
        reached = reach(current, entries).nodes
        self.warnings.extend(
            f"agent {node_id!r} is a top-level discovery target but is not marked "
            "entry: true; no role starts there"
            for node_id in self.fragment_entries
            if node_id not in reached and self.nodes[node_id].kind in AGENT_KINDS
        )

    def _drift(self, undeclared: list[GraphEdge]) -> GraphDrift | None:
        if self.registry is None or not self.has_fragment:
            return None
        complete = all(result.ok for result in self._discovery_sources())
        discovered_only = tuple(
            node_id
            for node_id in self.fragment_ids
            if node_id not in self.declared and self.nodes[node_id].kind in AGENT_KINDS
        )
        declared_only = tuple(
            agent.id
            for agent in self.declared.values()
            if agent.remote is None and agent.id not in self.reported
        )
        self.warnings.extend(
            f"agent {agent_id!r} was discovered but is not declared in the registry; "
            "its entry, roles, and delegation_mode are unknown"
            for agent_id in discovered_only
        )
        suffix = "" if complete else INCOMPLETE_SUFFIX
        self.warnings.extend(
            f"agent {agent_id!r} is declared in the registry but no discovery source "
            f"reported it{suffix}"
            for agent_id in declared_only
        )
        # Reported but not walked into. Declared-only agents already have a warning, and a
        # remote agent can never be walked into, so neither gets this one.
        self.warnings.extend(
            f"agent {agent.id!r} is declared in the registry but no discovery source could "
            "look inside it; declare its 'calls' or point lockwalk at its code"
            for agent in self.declared.values()
            if agent.id in self.unknown and agent.remote is None and agent.id not in declared_only
        )
        return GraphDrift(
            discovered_only_agents=discovered_only,
            declared_only_agents=declared_only,
            undeclared_edges=tuple(undeclared),
            complete=complete,
        )

    def _check_edges(self) -> None:
        messages: dict[str, None] = {}  # ordered set: one message per unknown endpoint
        for edge in self.edges:
            ends = (
                (edge.from_id,) if edge.kind == EdgeKind.USES_TOOL else (edge.from_id, edge.to_id)
            )
            for end in ends:
                if end not in self.nodes:
                    messages.setdefault(
                        f"edge {edge.from_id} -> {edge.to_id} refers to an unknown agent {end!r}"
                    )
        self.errors.extend(messages)
