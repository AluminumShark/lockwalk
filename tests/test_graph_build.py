"""Tests for building the merged agent call graph from the registry and discovery sources."""

import random
from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from pydantic import ValidationError

from lockwalk.graph.analysis import evaluate_rules
from lockwalk.graph.build import build_graph
from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import (
    AgentGraph,
    DelegationMode,
    EdgeKind,
    GraphDrift,
    GraphEdge,
    GraphFragment,
    GraphNode,
    NeverReachesRule,
    NodeKind,
    Provenance,
    RuleResult,
    SourceKind,
    SourceRef,
    SourceResult,
    ToolDescriptor,
)
from lockwalk.registry import Registry

REG = "registry:registry.yaml"
PY = "python:app:root"
NO_ENTRY = "no agent is marked entry: true; every agent is treated as an entry point"
INCOMPLETE = " (this may be incomplete because a source failed)"
NO_REGISTRY_HINT = (
    "without a registry, lockwalk cannot be told what agents call; "
    "add a registry and declare 'calls' to look past opaque agents"
)
NO_DRIFT = GraphDrift(
    discovered_only_agents=(), declared_only_agents=(), undeclared_edges=(), complete=True
)

AGENT = NodeKind.AGENT
MCP = NodeKind.MCP_SERVER
HANDOFF = EdgeKind.HANDOFF
TEAM = EdgeKind.TEAM
REMOTE = EdgeKind.REMOTE
CALLS = EdgeKind.CALLS
USES_TOOL = EdgeKind.USES_TOOL
AGENT_AS_TOOL = EdgeKind.AGENT_AS_TOOL
DISCOVERED = Provenance.DISCOVERED
INFERRED = Provenance.INFERRED
DECLARED = Provenance.DECLARED


def make_registry(
    agents: Sequence[Mapping[str, object]],
    tools: Sequence[Mapping[str, object]] = (),
    **extra: object,
) -> Registry:
    return Registry.model_validate(
        {"schema_version": "1", "agents": list(agents), "tools": list(tools), **extra}
    )


def tool_decl(tool_id: str, *agents: str) -> dict[str, object]:
    return {
        "id": tool_id,
        "action": f"{tool_id}:run",
        "risk": "high",
        "supported_agents": list(agents),
    }


def node(node_id: str, kind: NodeKind = AGENT, **fields: Any) -> GraphNode:
    return GraphNode(id=node_id, kind=kind, **fields)


def edge(
    from_id: str,
    to_id: str,
    kind: EdgeKind = HANDOFF,
    provenance: Provenance = DISCOVERED,
    sources: Sequence[str] = (),
) -> GraphEdge:
    return GraphEdge(
        from_id=from_id, to_id=to_id, kind=kind, provenance=provenance, sources=tuple(sources)
    )


def python_source(
    nodes: Sequence[GraphNode] = (),
    edges: Sequence[GraphEdge] = (),
    tools: Sequence[str] = (),
    *,
    label: str = PY,
) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="python", label=label),
        ok=True,
        tools=tuple(ToolDescriptor(name=name) for name in tools),
        graph=GraphFragment(nodes=tuple(nodes), edges=tuple(edges)),
    )


def mcp_source(
    label: str,
    *tools: str,
    ok: bool = True,
    error: str | None = None,
    agents: Sequence[str] = (),
    optional: bool = False,
) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="mcp", label=label),
        ok=ok,
        error=error,
        optional=optional,
        agents=tuple(agents),
        tools=tuple(ToolDescriptor(name=name) for name in tools),
    )


def build(registry: Registry | None, *sources: SourceResult) -> AgentGraph:
    inventory = merge_inventory(list(sources), registry=registry, registry_label=REG)
    return build_graph(registry, inventory, registry_label=REG)


def node_ids(graph: AgentGraph) -> list[str]:
    return [item.id for item in graph.nodes]


def edges_of(graph: AgentGraph) -> list[tuple[str, str, str, str]]:
    return [(e.from_id, e.kind.value, e.to_id, e.provenance.value) for e in graph.edges]


def get_node(graph: AgentGraph, node_id: str) -> GraphNode:
    found = graph.node(node_id)
    assert found is not None, f"node {node_id} missing"
    return found


def get_edge(
    graph: AgentGraph, from_id: str, to_id: str, kind: EdgeKind, provenance: Provenance
) -> GraphEdge:
    found = [
        e
        for e in graph.edges
        if (e.from_id, e.to_id, e.kind, e.provenance) == (from_id, to_id, kind, provenance)
    ]
    assert len(found) == 1, f"expected one edge {from_id} -> {to_id}, got {found}"
    return found[0]


# ---- 1. Registry nodes ----


def test_registry_agents_become_nodes_with_their_declared_fields():
    registry = make_registry(
        [
            {
                "id": "supervisor",
                "entry": True,
                "roles": ["analyst"],
                "delegation_mode": "user",
                "calls": ["oracle", "pricing"],
            },
            {"id": "oracle", "remote": "https://user:secret@oracle.example/a2a?token=t#frag"},
            {"id": "pricing", "remote": "https://pricing.example/a2a", "calls": []},
        ],
        roles=["analyst"],
    )
    graph = build(registry)
    assert node_ids(graph) == ["supervisor", "oracle", "pricing"]
    assert get_node(graph, "supervisor") == GraphNode(
        id="supervisor",
        kind=AGENT,
        entry=True,
        roles=("analyst",),
        delegation_mode="user",
        sources=(REG,),
    )
    assert get_node(graph, "oracle") == GraphNode(
        id="oracle",
        kind=NodeKind.REMOTE_AGENT,
        opaque=True,
        remote_url="https://oracle.example/a2a",
        sources=(REG,),
    )
    pricing = get_node(graph, "pricing")
    assert pricing.kind == NodeKind.REMOTE_AGENT
    assert pricing.opaque is False  # calls: [] is a declaration, so the node is not opaque
    assert "secret" not in graph.model_dump_json()
    assert "token" not in graph.model_dump_json()


def test_a_registry_without_agents_gives_an_empty_graph():
    graph = build(make_registry([], [tool_decl("get_price")]))
    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.entry_agents == ()
    assert graph.entry_inferred is False
    assert graph.drift is None
    assert graph.errors == ()
    assert graph.warnings == ()


def test_the_registry_label_comes_from_the_parameter():
    registry = make_registry([{"id": "a", "entry": True}], [tool_decl("t", "a")])
    default = build_graph(registry, merge_inventory([], registry=registry))
    assert get_node(default, "a").sources == ("registry",)
    assert default.edges[0].sources == ("registry",)
    custom = build_graph(
        registry,
        merge_inventory([], registry=registry, registry_label="registry:other.yaml"),
        registry_label="registry:other.yaml",
    )
    assert get_node(custom, "a").sources == ("registry:other.yaml",)
    assert custom.edges[0].sources == ("registry:other.yaml",)


# ---- 2. Fragment nodes and edges ----


def test_registry_values_win_over_fragment_values():
    registry = make_registry(
        [{"id": "supervisor", "entry": True, "delegation_mode": "user"}, {"id": "worker"}]
    )
    found = python_source(
        [
            node("supervisor", delegation_mode="agent", sources=("python:hint",)),
            node("worker", kind=NodeKind.REMOTE_AGENT, entry=True, delegation_mode="agent"),
        ],
        [edge("supervisor", "worker")],
    )
    graph = build(registry, found)
    supervisor = get_node(graph, "supervisor")
    assert supervisor.entry is True
    assert supervisor.delegation_mode == "user"
    assert supervisor.sources == (REG, "python:hint", PY)
    worker = get_node(graph, "worker")
    assert worker.kind == AGENT
    assert worker.entry is False
    assert worker.delegation_mode is None
    assert worker.sources == (REG, PY)


def test_discovered_only_nodes_keep_the_fragment_values():
    found = python_source(
        [node("root", entry=True), node("helper", delegation_mode="on_behalf_of")],
        [edge("root", "helper")],
    )
    graph = build(None, found)
    assert get_node(graph, "helper") == GraphNode(
        id="helper", delegation_mode="on_behalf_of", sources=(PY,)
    )


def test_two_sources_reporting_one_agent_give_one_node_and_merged_edges():
    first = python_source([node("a"), node("b")], [edge("a", "b")], label="python:one")
    second = python_source(
        [node("b"), node("a")],
        [edge("a", "b", sources=("hint",)), edge("b", "a")],
        label="python:two",
    )
    graph = build(None, first, second)
    assert node_ids(graph) == ["a", "b"]
    assert get_node(graph, "a").sources == ("python:one", "python:two")
    assert edges_of(graph) == [
        ("a", "handoff", "b", "discovered"),
        ("b", "handoff", "a", "discovered"),
    ]
    assert get_edge(graph, "a", "b", HANDOFF, DISCOVERED).sources == (
        "python:one",
        "hint",
        "python:two",
    )
    assert get_edge(graph, "b", "a", HANDOFF, DISCOVERED).sources == ("python:two",)


@pytest.mark.parametrize(("first", "second"), [(True, False), (False, True)])
def test_a_node_that_some_fragment_saw_for_real_is_not_opaque(first: bool, second: bool):
    one = python_source(
        [node("root", entry=True), node("helper", opaque=first)],
        [edge("root", "helper")],
        label="python:one",
    )
    two = python_source([node("helper", opaque=second)], label="python:two")
    graph = build(None, one, two)
    assert get_node(graph, "helper").opaque is False
    hidden, seen = ("python:one", "python:two") if first else ("python:two", "python:one")
    assert graph.warnings == (
        f"agent 'helper' is opaque in {hidden} but {seen} saw it; "
        "lockwalk assumes they are the same agent",
    )


def test_a_node_that_every_fragment_marks_opaque_stays_opaque():
    one = python_source(
        [node("root", entry=True), node("helper", opaque=True)],
        [edge("root", "helper")],
        label="python:one",
    )
    two = python_source([node("helper", opaque=True)], label="python:two")
    graph = build(None, one, two)
    assert get_node(graph, "helper").opaque is True
    # No disagreement warning: no fragment saw helper. Without a registry, only the hint.
    assert graph.warnings == (NO_REGISTRY_HINT,)


def test_declared_calls_make_an_agent_known_whatever_fragments_say():
    registry = make_registry([{"id": "root", "entry": True, "calls": []}])
    one = python_source([node("root", opaque=True)], label="python:one")
    two = python_source([node("root")], label="python:two")
    graph = build(registry, one, two)
    assert get_node(graph, "root").opaque is False
    # The declared calls, not a fragment's walk, make root known: no disagreement warning.
    assert graph.warnings == ()


def test_remote_agents_are_opaque_unless_their_calls_are_declared():
    registry = make_registry(
        [
            {"id": "desk", "entry": True},
            {"id": "oracle", "remote": "https://oracle.example/a2a"},
            {"id": "pricing", "remote": "https://pricing.example/a2a", "calls": []},
            {"id": "quotes", "remote": "https://quotes.example/a2a"},
        ]
    )
    found = python_source(
        [node("desk"), node("quotes"), node("pricing", opaque=True)],
        [edge("desk", "oracle", REMOTE), edge("desk", "pricing")],
    )
    graph = build(registry, found)
    assert get_node(graph, "oracle").opaque is True
    # P4: declared calls make pricing known, even though the fragment marks it opaque.
    assert get_node(graph, "pricing").opaque is False
    # N1: a remote agent cannot be walked into, so the fragment saw a local stand-in.
    assert get_node(graph, "quotes").opaque is True
    # A remote agent never gets the "look inside" warning; quotes gets the stand-in one.
    assert graph.warnings == (
        f"agent 'quotes' is declared remote in the registry but {PY} walked a local agent "
        "with that name; lockwalk keeps it opaque",
    )


def test_mcp_server_nodes_get_no_opacity_disagreement_warning():
    # Step 4 decides whether a server is opaque, from the state of its source.
    one = python_source(
        [node("root", entry=True), node("mcp:x", kind=MCP, opaque=True)],
        [edge("root", "mcp:x", REMOTE)],
        label="python:one",
    )
    two = python_source([node("mcp:x", kind=MCP)], label="python:two")
    graph = build(None, one, two)
    assert get_node(graph, "mcp:x").opaque is True  # no source is labelled mcp:x
    assert graph.warnings == ()


UNSEEN = (
    "agent 'billing' is declared in the registry but no discovery source could look inside "
    "it; declare its 'calls' or point lockwalk at its code"
)


def test_a_registry_agent_that_no_fragment_could_look_inside_is_opaque():
    # The desk -> billing probe: discovery only knows billing by name.
    registry = make_registry([{"id": "desk", "entry": True}, {"id": "billing"}])
    found = python_source(
        [node("desk"), node("billing", opaque=True)],
        [edge("desk", "billing")],
        label="python:app1:triage",
    )
    graph = build(registry, found)
    assert get_node(graph, "billing").opaque is True
    assert graph.drift == NO_DRIFT
    assert graph.warnings == (UNSEEN,)


def test_declared_calls_tell_lockwalk_what_lies_behind_an_unseen_registry_agent():
    registry = make_registry([{"id": "desk", "entry": True}, {"id": "billing", "calls": []}])
    found = python_source(
        [node("desk"), node("billing", opaque=True)],
        [edge("desk", "billing")],
        label="python:app1:triage",
    )
    graph = build(registry, found)
    assert get_node(graph, "billing").opaque is False
    assert graph.warnings == ()


def test_a_registry_agent_that_one_fragment_saw_fully_is_not_opaque():
    registry = make_registry([{"id": "desk", "entry": True}, {"id": "billing"}])
    triage = python_source(
        [node("desk"), node("billing", opaque=True)],
        [edge("desk", "billing")],
        label="python:app1:triage",
    )
    billing = python_source([node("billing")], label="python:app2:billing")
    graph = build(registry, triage, billing)
    assert get_node(graph, "billing").opaque is False
    assert graph.warnings == (
        "agent 'billing' is opaque in python:app1:triage but python:app2:billing saw it; "
        "lockwalk assumes they are the same agent",
    )


def test_no_disagreement_warning_when_one_source_both_hid_and_saw_the_agent():
    # Issue E: the first label that hid billing is also the first label that saw it.
    registry = make_registry([{"id": "desk", "entry": True}, {"id": "billing"}])
    found = python_source(
        [node("desk"), node("billing", opaque=True), node("billing")],
        [edge("desk", "billing")],
        label="python:app1:triage",
    )
    graph = build(registry, found)
    assert get_node(graph, "billing").opaque is False
    assert graph.warnings == ()


def test_the_disagreement_warning_names_a_source_that_only_hid_the_agent():
    # N2: triage both hid and saw billing, so the warning names the source that only hid it.
    registry = make_registry([{"id": "desk", "entry": True}, {"id": "billing"}])
    triage = python_source(
        [node("desk"), node("billing", opaque=True), node("billing")],
        [edge("desk", "billing")],
        label="python:app1:triage",
    )
    other = python_source([node("billing", opaque=True)], label="python:app2:billing")
    graph = build(registry, triage, other)
    assert get_node(graph, "billing").opaque is False
    assert graph.warnings == (
        "agent 'billing' is opaque in python:app2:billing but python:app1:triage saw it; "
        "lockwalk assumes they are the same agent",
    )


HIDDEN_TOOLS_WARNING = (
    "agent 'desk' declares 'calls', but lockwalk could not read all of its tools, "
    "so it stays opaque"
)


def test_declared_calls_cannot_clear_hidden_tools():
    """`calls` lists agents, so it cannot stand in for tools that discovery could not read."""
    registry = make_registry([{"id": "desk", "entry": True, "calls": []}])
    found = python_source([node("desk", opaque=True, tools_hidden=True)])
    graph = build(registry, found)
    desk = get_node(graph, "desk")
    assert (desk.opaque, desk.tools_hidden) == (True, True)
    assert graph.warnings == (HIDDEN_TOOLS_WARNING,)


def test_hidden_tools_in_one_fragment_keep_the_agent_opaque_when_another_saw_it():
    registry = make_registry([{"id": "desk", "entry": True}])
    one = python_source([node("desk", opaque=True, tools_hidden=True)], label="python:one")
    two = python_source([node("desk")], label="python:two")
    graph = build(registry, one, two)
    desk = get_node(graph, "desk")
    assert (desk.opaque, desk.tools_hidden) == (True, True)
    # Neither "declare its calls" (that would not help) nor "assumes they are the same".
    assert graph.warnings == ()


def test_hidden_tools_without_a_registry_give_no_calls_hint():
    found = python_source([node("desk", entry=True, opaque=True, tools_hidden=True)])
    graph = build(None, found)
    assert get_node(graph, "desk").tools_hidden is True
    assert graph.warnings == ()


def test_hidden_tools_keep_a_never_reaches_rule_inconclusive():
    """The tools factory probe: desk declares calls: [], another agent holds the tool."""
    registry = make_registry(
        [
            {"id": "desk", "entry": True, "calls": []},
            {"id": "back-office", "calls": []},
        ],
        [tool_decl("execute_trade", "back-office")],
    )
    found = python_source([node("desk", entry=True, opaque=True, tools_hidden=True)])
    inventory = merge_inventory([found], registry=registry, registry_label=REG)
    graph = build_graph(registry, inventory, registry_label=REG)
    rule = NeverReachesRule(id="RULE-001", agent="desk", tool="execute_trade")
    [row] = evaluate_rules(graph, [rule], inventory)
    assert (row.result, row.opaque_reached) == (RuleResult.INCONCLUSIVE, ("desk",))


def test_a_node_with_hidden_tools_must_be_opaque():
    with pytest.raises(ValidationError, match="hidden must be opaque"):
        GraphNode(id="desk", tools_hidden=True)


# ---- Opacity probes: agents that nobody walked into must stay opaque ----


def test_probe_p1_an_agent_reached_only_as_an_edge_target_is_opaque():
    registry = make_registry([{"id": "desk", "entry": True}, {"id": "billing"}])
    found = python_source([node("desk")], [edge("desk", "billing")], label="python:app1:triage")
    graph = build(registry, found)
    assert get_node(graph, "billing").opaque is True
    assert graph.drift == NO_DRIFT
    assert graph.warnings == (UNSEEN,)


def test_probe_p2_an_agent_behind_a_delegation_tool_a_fragment_uses_is_opaque():
    registry = make_registry(
        [{"id": "desk", "entry": True}, {"id": "billing"}],
        delegation_tools=[{"id": "ask_billing", "agent": "billing"}],
    )
    found = python_source([node("desk")], [edge("desk", "ask_billing", USES_TOOL)])
    graph = build(registry, found)
    assert edges_of(graph) == [("desk", "agent_as_tool", "billing", "discovered")]
    assert get_node(graph, "billing").opaque is True
    assert graph.drift == NO_DRIFT
    assert graph.warnings == (UNSEEN,)


def test_probe_p2b_an_agent_behind_a_delegation_tool_an_mcp_server_exposes_is_opaque():
    registry = make_registry(
        [{"id": "desk", "entry": True}, {"id": "billing"}],
        delegation_tools=[{"id": "ask_billing", "agent": "billing"}],
    )
    found = python_source(
        [node("desk"), node("mcp:billing-tools", kind=MCP)],
        [edge("desk", "mcp:billing-tools", REMOTE)],
    )
    graph = build(registry, found, mcp_source("mcp:billing-tools", "ask_billing"))
    assert ("mcp:billing-tools", "agent_as_tool", "billing", "discovered") in edges_of(graph)
    assert get_node(graph, "billing").opaque is True
    assert graph.drift == NO_DRIFT
    assert graph.warnings == (UNSEEN,)


def test_probe_p3_an_agent_no_fragment_mentions_is_opaque_with_only_the_drift_warning():
    # billing is reachable only through a declared delegation tool; discovery never names it.
    registry = make_registry(
        [{"id": "desk", "entry": True}, {"id": "billing"}],
        delegation_tools=[{"id": "ask_billing", "agent": "billing", "supported_agents": ["desk"]}],
    )
    graph = build(registry, python_source([node("desk")]))
    assert edges_of(graph) == [("desk", "agent_as_tool", "billing", "declared")]
    assert get_node(graph, "billing").opaque is True
    assert graph.drift is not None
    assert graph.drift.declared_only_agents == ("billing",)
    assert graph.warnings == (
        "agent 'billing' is declared in the registry but no discovery source reported it",
    )


def test_probe_p5_an_agent_known_only_from_a_source_agents_list_is_opaque():
    # Issue D: the node comes from a config 'agents' list, and no fragment reports it.
    graph = build(None, mcp_source("mcp:finance-tools", "get_price", agents=("finance",)))
    assert get_node(graph, "finance").opaque is True
    assert graph.warnings == (NO_REGISTRY_HINT, NO_ENTRY)


def test_without_a_registry_one_hint_covers_every_opaque_agent():
    # N6: nothing but a registry can declare 'calls', so say so once.
    found = python_source(
        [node("root", entry=True), node("left", opaque=True), node("right", opaque=True)],
        [edge("root", "left"), edge("root", "right")],
    )
    graph = build(None, found)
    assert [item.id for item in graph.nodes if item.opaque] == ["left", "right"]
    assert graph.warnings == (NO_REGISTRY_HINT,)


def test_without_a_registry_there_is_no_hint_when_nothing_is_opaque():
    found = python_source([node("root", entry=True), node("helper")], [edge("root", "helper")])
    graph = build(None, found, mcp_source("mcp:tools", "get_price"))
    assert graph.warnings == ()


def test_a_registry_only_graph_marks_every_agent_without_calls_opaque():
    agents: list[dict[str, object]] = [
        {"id": "supervisor", "entry": True, "calls": ["finance-agent"]},
        {"id": "research-agent"},
        {"id": "finance-agent"},
    ]
    tools = [tool_decl("get_stock_price", "research-agent", "finance-agent")]
    prices = mcp_source("mcp:finance-tools", "get_stock_price")
    graph = build(make_registry(agents, tools), prices)
    assert [(item.id, item.opaque) for item in graph.nodes] == [
        ("supervisor", False),
        ("research-agent", True),
        ("finance-agent", True),
    ]
    # No fragment, so no per-agent warning: the graph notes list the opaque agents.
    assert graph.warnings == ()
    agents[1] = {"id": "research-agent", "calls": []}
    graph = build(make_registry(agents, tools), prices)
    assert get_node(graph, "research-agent").opaque is False
    assert get_node(graph, "finance-agent").opaque is True
    assert graph.warnings == ()


def test_edges_that_differ_only_in_provenance_stay_separate():
    found = python_source(
        [node("a", entry=True), node("b")],
        [edge("a", "b", provenance=DISCOVERED), edge("a", "b", provenance=INFERRED)],
    )
    graph = build(None, found)
    assert edges_of(graph) == [
        ("a", "handoff", "b", "discovered"),
        ("a", "handoff", "b", "inferred"),
    ]


# ---- 3. Declared edges ----


def test_declared_edges_come_from_calls_supported_agents_and_source_agents():
    registry = make_registry(
        [
            {"id": "supervisor", "entry": True, "calls": ["finance"]},
            {"id": "finance"},
            {"id": "pricing"},
        ],
        [tool_decl("read_portfolio", "finance")],
        delegation_tools=[
            {"id": "ask_pricing", "agent": "pricing", "supported_agents": ["supervisor", "finance"]}
        ],
    )
    tools = mcp_source("mcp:finance-tools", "get_price", "ask_pricing", agents=("finance",))
    graph = build(registry, tools)
    assert edges_of(graph) == [
        ("finance", "agent_as_tool", "pricing", "declared"),
        ("finance", "uses_tool", "get_price", "declared"),
        ("finance", "uses_tool", "read_portfolio", "declared"),
        ("supervisor", "agent_as_tool", "pricing", "declared"),
        ("supervisor", "calls", "finance", "declared"),
    ]
    assert get_edge(graph, "supervisor", "finance", CALLS, DECLARED).sources == (REG,)
    assert get_edge(graph, "finance", "read_portfolio", USES_TOOL, DECLARED).sources == (REG,)
    assert get_edge(graph, "finance", "get_price", USES_TOOL, DECLARED).sources == (
        "mcp:finance-tools",
    )
    assert get_edge(graph, "supervisor", "pricing", AGENT_AS_TOOL, DECLARED).sources == (REG,)
    # Both the registry and the source say finance uses ask_pricing: one edge, both labels.
    assert get_edge(graph, "finance", "pricing", AGENT_AS_TOOL, DECLARED).sources == (
        REG,
        "mcp:finance-tools",
    )
    assert graph.errors == ()


def test_a_delegation_tool_reported_by_a_source_links_that_sources_agents():
    registry = make_registry(
        [{"id": "desk", "entry": True}, {"id": "oracle"}],
        delegation_tools=[{"id": "ask_oracle", "agent": "oracle"}],
    )
    graph = build(registry, mcp_source("mcp:oracle-tools", "ask_oracle", agents=("desk",)))
    assert edges_of(graph) == [("desk", "agent_as_tool", "oracle", "declared")]
    assert graph.edges[0].sources == ("mcp:oracle-tools",)


def test_agents_listed_by_a_source_become_nodes_without_a_registry():
    graph = build(None, mcp_source("mcp:finance-tools", "get_price", agents=("finance",)))
    # Opaque: no fragment walked inside finance and no registry declares its calls.
    assert graph.nodes == (GraphNode(id="finance", opaque=True, sources=("mcp:finance-tools",)),)
    assert edges_of(graph) == [("finance", "uses_tool", "get_price", "declared")]
    assert graph.errors == ()
    assert graph.roles is None


# ---- 4. MCP boundaries ----


def test_a_matched_mcp_server_node_gets_the_tools_of_its_source():
    registry = make_registry([{"id": "finance", "entry": True}])
    found = python_source(
        [node("finance"), node("mcp:finance-tools", kind=MCP, opaque=True)],
        [edge("finance", "mcp:finance-tools", REMOTE)],
    )
    tools = mcp_source("mcp:finance-tools", "get_price", "execute_trade")
    graph = build(registry, found, tools)
    server = get_node(graph, "mcp:finance-tools")
    assert server.opaque is False
    assert server.sources == (PY, "mcp:finance-tools")
    assert edges_of(graph) == [
        ("finance", "remote", "mcp:finance-tools", "discovered"),
        ("mcp:finance-tools", "uses_tool", "execute_trade", "discovered"),
        ("mcp:finance-tools", "uses_tool", "get_price", "discovered"),
    ]
    trade = get_edge(graph, "mcp:finance-tools", "execute_trade", USES_TOOL, DISCOVERED)
    assert trade.sources == ("mcp:finance-tools",)


def test_mcp_server_nodes_are_opaque_when_their_source_failed_or_is_missing():
    registry = make_registry([{"id": "finance", "entry": True}])
    found = python_source(
        [node("finance"), node("mcp:down", kind=MCP), node("mcp:elsewhere", kind=MCP)],
        [edge("finance", "mcp:down", REMOTE), edge("finance", "mcp:elsewhere", REMOTE)],
    )
    # A failed source may still carry some tools; its server node stays opaque anyway.
    down = mcp_source("mcp:down", "get_price", ok=False, error="bad item")
    graph = build(registry, found, down)
    assert get_node(graph, "mcp:down").opaque is True
    assert get_node(graph, "mcp:elsewhere").opaque is True
    assert get_node(graph, "mcp:elsewhere").sources == (PY,)
    assert [e for e in graph.edges if e.from_id.startswith("mcp:")] == []


def test_the_registry_source_is_never_an_mcp_boundary():
    registry = make_registry([{"id": "finance", "entry": True}], [tool_decl("get_price")])
    found = python_source([node("finance"), node(REG, kind=MCP)], [edge("finance", REG, REMOTE)])
    graph = build(registry, found)
    assert get_node(graph, REG).opaque is True
    assert [e for e in graph.edges if e.from_id == REG] == []


# ---- 4b. Delegation tools seen by discovery ----

ORACLE_REGISTRY = make_registry(
    [{"id": "finance", "entry": True}, {"id": "oracle"}],
    delegation_tools=[{"id": "ask_oracle", "agent": "oracle"}],
)
ORACLE_UNSEEN = (
    "agent 'oracle' is declared in the registry but no discovery source could look inside "
    "it; declare its 'calls' or point lockwalk at its code"
)


def test_a_fragment_edge_to_a_delegation_tool_reaches_the_agent_behind_it():
    found = python_source(
        [node("finance")], [edge("finance", "ask_oracle", USES_TOOL)], tools=["ask_oracle"]
    )
    graph = build(ORACLE_REGISTRY, found)
    assert edges_of(graph) == [("finance", "agent_as_tool", "oracle", "discovered")]
    assert graph.edges[0].sources == (PY,)
    # The rewritten edge names oracle, so discovery reported it: no declared-only drift.
    assert graph.drift == NO_DRIFT
    # But nobody walked inside oracle, so it is opaque.
    assert get_node(graph, "oracle").opaque is True
    assert graph.warnings == (ORACLE_UNSEEN,)


def test_an_mcp_server_that_exposes_a_delegation_tool_reaches_the_agent_behind_it():
    found = python_source(
        [node("finance"), node("mcp:oracle-tools", kind=MCP)],
        [edge("finance", "mcp:oracle-tools", REMOTE)],
    )
    tools = mcp_source("mcp:oracle-tools", "ask_oracle", "get_quote")
    graph = build(ORACLE_REGISTRY, found, tools)
    assert edges_of(graph) == [
        ("finance", "remote", "mcp:oracle-tools", "discovered"),
        ("mcp:oracle-tools", "agent_as_tool", "oracle", "discovered"),
        ("mcp:oracle-tools", "uses_tool", "get_quote", "discovered"),
    ]
    assert get_edge(graph, "mcp:oracle-tools", "oracle", AGENT_AS_TOOL, DISCOVERED).sources == (
        "mcp:oracle-tools",
    )
    assert graph.drift == NO_DRIFT
    assert get_node(graph, "oracle").opaque is True
    assert graph.warnings == (ORACLE_UNSEEN,)


def test_rewritten_delegation_edges_merge_with_identical_edges():
    found = python_source(
        [node("finance"), node("oracle")],
        [
            edge("finance", "ask_oracle", USES_TOOL),
            edge("finance", "oracle", AGENT_AS_TOOL, sources=("hint",)),
        ],
    )
    graph = build(ORACLE_REGISTRY, found)
    assert edges_of(graph) == [("finance", "agent_as_tool", "oracle", "discovered")]
    assert graph.edges[0].sources == (PY, "hint")
    assert graph.drift == NO_DRIFT
    assert graph.warnings == ()


def test_a_delegation_edge_from_an_agent_with_calls_is_declared_by_calls():
    registry = make_registry(
        [{"id": "finance", "entry": True, "calls": ["oracle"]}, {"id": "oracle"}],
        delegation_tools=[{"id": "ask_oracle", "agent": "oracle"}],
    )
    found = python_source([node("finance")], [edge("finance", "ask_oracle", USES_TOOL)])
    graph = build(registry, found)
    assert edges_of(graph) == [
        ("finance", "agent_as_tool", "oracle", "discovered"),
        ("finance", "calls", "oracle", "declared"),
    ]
    assert graph.drift == NO_DRIFT
    # No undeclared-edge warning; oracle itself is still unseen, so it is opaque.
    assert graph.warnings == (ORACLE_UNSEEN,)


# ---- 5. Optional sources that could not be read ----


def test_an_unavailable_optional_source_becomes_an_opaque_boundary():
    registry = make_registry([{"id": "finance", "entry": True}, {"id": "research"}])
    down = mcp_source(
        "mcp:vault", ok=False, error="timed out", optional=True, agents=("finance", "research")
    )
    graph = build(registry, down)
    assert node_ids(graph) == ["finance", "research", "mcp:vault"]
    assert get_node(graph, "mcp:vault") == GraphNode(
        id="mcp:vault", kind=MCP, opaque=True, sources=("mcp:vault",)
    )
    assert edges_of(graph) == [
        ("finance", "remote", "mcp:vault", "declared"),
        ("research", "remote", "mcp:vault", "declared"),
    ]
    assert get_edge(graph, "finance", "mcp:vault", REMOTE, DECLARED).sources == ("mcp:vault",)
    assert graph.errors == ()


def test_an_unavailable_source_merges_with_the_fragment_node_of_the_same_id():
    registry = make_registry([{"id": "finance", "entry": True}])
    found = python_source(
        [node("finance"), node("mcp:vault", kind=MCP)], [edge("finance", "mcp:vault", REMOTE)]
    )
    down = mcp_source("mcp:vault", ok=False, error="timed out", optional=True, agents=("finance",))
    graph = build(registry, found, down)
    assert node_ids(graph) == ["finance", "mcp:vault"]
    vault = get_node(graph, "mcp:vault")
    assert vault.opaque is True
    assert vault.sources == (PY, "mcp:vault")
    assert edges_of(graph) == [
        ("finance", "remote", "mcp:vault", "declared"),
        ("finance", "remote", "mcp:vault", "discovered"),
    ]


def test_failed_sources_that_are_not_unavailable_add_no_boundary_node():
    registry = make_registry([{"id": "finance", "entry": True}])
    down = mcp_source("mcp:vault", ok=False, error="refused", agents=("finance",))
    partial = mcp_source(
        "mcp:half", "get_price", ok=False, error="bad item", optional=True, agents=("finance",)
    )
    graph = build(registry, down, partial)
    assert graph.node("mcp:vault") is None
    assert graph.node("mcp:half") is None
    assert edges_of(graph) == [("finance", "uses_tool", "get_price", "declared")]


def test_an_unavailable_source_whose_label_is_not_a_valid_id_is_a_graph_error():
    label = "mcp:" + "x" * 300
    registry = make_registry([{"id": "finance", "entry": True}])
    down = mcp_source(label, ok=False, error="timed out", optional=True, agents=("finance",))
    graph = build(registry, down)
    assert graph.node(label) is None
    assert graph.edges == ()
    assert graph.errors == (
        f"optional source {label!r} cannot be shown in the agent graph because its label is "
        "not a valid id (name must be at most 200 characters); set a valid 'name' for it",
    )


# ---- 6. Declared calls override what discovery saw ----


def test_declared_calls_drop_inferred_edges_from_that_agent():
    registry = make_registry(
        [{"id": "manager", "entry": True, "calls": []}, {"id": "worker"}, {"id": "other"}]
    )
    found = python_source(
        [node("manager"), node("worker"), node("other")],
        [
            edge("manager", "worker", CALLS, INFERRED),
            edge("manager", "get_price", USES_TOOL, INFERRED),
            edge("worker", "other", CALLS, INFERRED),
        ],
        tools=["get_price"],
    )
    graph = build(registry, found)
    assert edges_of(graph) == [
        ("manager", "uses_tool", "get_price", "inferred"),
        ("worker", "calls", "other", "inferred"),
    ]
    assert graph.warnings == ()


def test_a_discovered_edge_missing_from_calls_is_kept_and_reported():
    registry = make_registry(
        [{"id": "manager", "entry": True, "calls": ["worker"]}, {"id": "worker"}, {"id": "auditor"}]
    )
    found = python_source(
        [node("manager"), node("worker"), node("auditor"), node("mcp:files", kind=MCP)],
        [
            edge("manager", "worker"),
            edge("manager", "auditor", TEAM),
            # An MCP server can never be listed in 'calls', so this edge is not reported.
            edge("manager", "mcp:files", REMOTE),
        ],
    )
    graph = build(registry, found)
    undeclared = edge("manager", "auditor", TEAM, sources=(PY,))
    assert undeclared in graph.edges
    assert get_edge(graph, "manager", "worker", HANDOFF, DISCOVERED).sources == (PY,)
    assert graph.drift is not None
    assert graph.drift.undeclared_edges == (undeclared,)
    assert graph.warnings == (
        "agent 'manager' reaches 'auditor' (team, discovered) "
        "but its registry 'calls' does not list 'auditor'",
    )


def test_an_undeclared_handoff_uses_the_documented_warning():
    registry = make_registry([{"id": "a", "entry": True, "calls": []}, {"id": "b"}])
    graph = build(registry, python_source([node("a"), node("b")], [edge("a", "b")]))
    assert graph.warnings == (
        "agent 'a' reaches 'b' (handoff, discovered) but its registry 'calls' does not list 'b'",
    )


def test_agents_without_declared_calls_keep_inferred_edges():
    registry = make_registry([{"id": "crew", "entry": True}, {"id": "writer"}])
    found = python_source([node("crew"), node("writer")], [edge("crew", "writer", CALLS, INFERRED)])
    graph = build(registry, found)
    assert edges_of(graph) == [("crew", "calls", "writer", "inferred")]


def test_delegation_tool_declarations_count_as_declared_calls():
    registry = make_registry(
        [
            {"id": "desk", "entry": True, "calls": []},
            {"id": "pricing"},
            {"id": "oracle"},
            {"id": "auditor"},
        ],
        delegation_tools=[
            {"id": "ask_pricing", "agent": "pricing", "supported_agents": ["desk"]},
            {"id": "ask_oracle", "agent": "oracle"},
            # Declared for pricing, not for desk, so it does not cover desk -> auditor.
            {"id": "ask_auditor", "agent": "auditor", "supported_agents": ["pricing"]},
        ],
    )
    found = python_source(
        [node("desk"), node("pricing"), node("oracle"), node("auditor")],
        [
            # Rewritten to desk -agent_as_tool-> pricing; declared by supported_agents.
            edge("desk", "ask_pricing", USES_TOOL),
            # Declared through the agents of the source that reports ask_oracle.
            edge("desk", "oracle"),
            # Neither 'calls' nor a delegation tool declares this one.
            edge("desk", "auditor"),
        ],
    )
    oracle_tools = mcp_source("mcp:oracle-tools", "ask_oracle", agents=("desk",))
    graph = build(registry, found, oracle_tools)
    assert edges_of(graph) == [
        ("desk", "agent_as_tool", "oracle", "declared"),
        ("desk", "agent_as_tool", "pricing", "declared"),
        ("desk", "agent_as_tool", "pricing", "discovered"),
        ("desk", "handoff", "auditor", "discovered"),
        ("desk", "handoff", "oracle", "discovered"),
        ("pricing", "agent_as_tool", "auditor", "declared"),
    ]
    undeclared = edge("desk", "auditor", sources=(PY,))
    assert graph.drift is not None
    assert graph.drift.undeclared_edges == (undeclared,)
    assert graph.warnings == (
        "agent 'desk' reaches 'auditor' (handoff, discovered) "
        "but its registry 'calls' does not list 'auditor'",
    )


# ---- 7. Entry agents ----


def test_registry_entries_come_first_in_registry_order():
    registry = make_registry([{"id": "b", "entry": True}, {"id": "a"}, {"id": "c", "entry": True}])
    found = python_source([node("a", entry=True), node("d", entry=True)])
    graph = build(registry, found)
    assert graph.entry_agents == ("b", "c")
    assert graph.entry_inferred is False
    assert [item.id for item in graph.nodes if item.entry] == ["b", "c"]


def test_discovered_entries_are_used_when_the_registry_marks_none():
    registry = make_registry([{"id": "a"}, {"id": "b"}])
    first = python_source(
        [node("x"), node("b", entry=True), node("c", entry=True)], label="python:one"
    )
    second = python_source([node("a", entry=True)], label="python:two")
    graph = build(registry, first, second)
    assert node_ids(graph) == ["a", "b", "x", "c"]
    assert graph.entry_agents == ("b", "c", "a")
    assert graph.entry_inferred is False
    assert [item.id for item in graph.nodes if item.entry] == ["a", "b", "c"]
    assert NO_ENTRY not in graph.warnings


def test_every_agent_is_an_entry_when_none_is_marked():
    registry = make_registry(
        [{"id": "finance"}, {"id": "oracle", "remote": "https://oracle.example/a2a"}]
    )
    found = python_source(
        [node("finance"), node("mcp:x", kind=MCP)], [edge("finance", "mcp:x", REMOTE)]
    )
    graph = build(registry, found)
    assert graph.entry_agents == ("finance", "oracle")
    assert graph.entry_inferred is True
    assert graph.warnings.count(NO_ENTRY) == 1
    assert not any(item.entry for item in graph.nodes)


def test_no_entry_warning_when_there_are_no_agents():
    graph = build(None, mcp_source("mcp:tools", "get_price"))
    assert graph.nodes == ()
    assert graph.entry_agents == ()
    assert graph.entry_inferred is False
    assert graph.warnings == ()


def test_entries_without_roles_warn_when_roles_are_enabled():
    registry = make_registry(
        [{"id": "desk", "entry": True, "roles": ["trader"]}, {"id": "open", "entry": True}],
        roles=["trader", "analyst"],
    )
    graph = build(registry)
    assert graph.roles == ("trader", "analyst")
    assert graph.warnings == ("entry agent 'open' lists no roles, so every role can use it",)


def test_entries_without_roles_do_not_warn_when_roles_are_off():
    graph = build(make_registry([{"id": "open", "entry": True}]))
    assert graph.roles is None
    assert graph.warnings == ()


# ---- 8. Graph drift ----


def test_graph_drift_needs_a_non_empty_fragment():
    registry = make_registry([{"id": "finance", "entry": True}, {"id": "research"}])
    graph = build(registry, python_source(tools=["get_price"]))
    assert graph.drift is None
    assert graph.warnings == ()


def test_graph_drift_needs_a_registry():
    graph = build(None, python_source([node("root", entry=True)], [edge("root", "root")]))
    assert graph.drift is None
    assert graph.warnings == ()


def test_graph_drift_lists_discovered_only_and_declared_only_agents():
    registry = make_registry(
        [
            {"id": "finance", "entry": True},
            {"id": "research"},
            {"id": "oracle", "remote": "https://oracle.example/a2a"},
        ]
    )
    found = python_source(
        [node("finance"), node("helper"), node("mcp:x", kind=MCP)],
        [edge("finance", "helper"), edge("finance", "mcp:x", REMOTE)],
    )
    graph = build(registry, found)
    assert graph.drift == GraphDrift(
        discovered_only_agents=("helper",),
        declared_only_agents=("research",),
        undeclared_edges=(),
        complete=True,
    )
    assert graph.warnings == (
        "agent 'helper' was discovered but is not declared in the registry; "
        "its entry, roles, and delegation_mode are unknown",
        "agent 'research' is declared in the registry but no discovery source reported it",
    )


def test_graph_drift_is_incomplete_when_a_source_failed():
    registry = make_registry([{"id": "finance", "entry": True}, {"id": "research"}])
    found = python_source([node("finance")])
    down = mcp_source("mcp:down", ok=False, error="refused")
    graph = build(registry, found, down)
    assert graph.drift is not None
    assert graph.drift.complete is False
    assert graph.warnings == (
        "agent 'research' is declared in the registry but no discovery source reported it"
        + INCOMPLETE,
    )


def test_an_agent_named_only_by_a_fragment_edge_counts_as_reported():
    registry = make_registry([{"id": "finance", "entry": True}, {"id": "pricing"}])
    graph = build(registry, python_source([node("finance")], [edge("finance", "pricing")]))
    assert graph.drift is not None
    assert graph.drift.declared_only_agents == ()
    assert graph.errors == ()


# ---- 9. Graph errors ----


def test_an_edge_that_names_an_unknown_agent_is_a_graph_error():
    found = python_source(
        [node("a", entry=True)],
        [
            edge("a", "ghost"),
            edge("phantom", "get_price", USES_TOOL),
            edge("a", "some_tool", USES_TOOL),
            edge("ghost", "ghost"),
        ],
    )
    graph = build(None, found)
    assert graph.errors == (
        "edge a -> ghost refers to an unknown agent 'ghost'",
        "edge ghost -> ghost refers to an unknown agent 'ghost'",
        "edge phantom -> get_price refers to an unknown agent 'phantom'",
    )


# ---- 10. Order and determinism ----


def test_nodes_and_edges_have_a_stable_order():
    registry = make_registry([{"id": "z", "entry": True}, {"id": "m"}])
    edges = [
        edge("z", "m"),
        edge("m", "z", TEAM),
        edge("a", "z"),
        edge("m", "get_price", USES_TOOL),
        edge("m", "z", HANDOFF, INFERRED),
        edge("m", "z"),
    ]
    nodes = [node("q"), node("a"), node("m")]
    forward = build(registry, python_source(nodes, edges, tools=["get_price"]))
    backward = build(registry, python_source(nodes, edges[::-1], tools=["get_price"]))
    assert node_ids(forward) == ["z", "m", "q", "a"]
    assert edges_of(forward) == [
        ("a", "handoff", "z", "discovered"),
        ("m", "handoff", "z", "discovered"),
        ("m", "handoff", "z", "inferred"),
        ("m", "team", "z", "discovered"),
        ("m", "uses_tool", "get_price", "discovered"),
        ("z", "handoff", "m", "discovered"),
    ]
    assert forward == backward
    assert build(registry, python_source(nodes, edges, tools=["get_price"])) == forward


# ---- The finance demo: a registry with no discovery fragment ----


def test_registry_only_graph_for_the_finance_demo(finance_registry: dict[str, Any]):
    registry = Registry.model_validate(finance_registry)
    tools = mcp_source("mcp:finance-tools", "get_stock_price", "read_portfolio", "execute_trade")
    graph = build(registry, tools)
    # Neither agent declares calls and no fragment walked inside them, so both are opaque.
    assert graph.nodes == (
        GraphNode(id="research-agent", opaque=True, sources=(REG,)),
        GraphNode(id="finance-agent", opaque=True, sources=(REG,)),
    )
    assert edges_of(graph) == [
        ("finance-agent", "uses_tool", "execute_trade", "declared"),
        ("finance-agent", "uses_tool", "get_stock_price", "declared"),
        ("finance-agent", "uses_tool", "read_portfolio", "declared"),
        ("research-agent", "uses_tool", "get_stock_price", "declared"),
    ]
    assert all(e.sources == (REG,) for e in graph.edges)
    assert graph.entry_agents == ("research-agent", "finance-agent")
    assert graph.entry_inferred is True
    assert graph.roles is None
    assert graph.drift is None
    assert graph.errors == ()
    assert graph.warnings == (NO_ENTRY,)


# ---- Warning order across steps ----


def test_warnings_come_in_step_order_undeclared_then_entries_then_drift():
    registry = make_registry([{"id": "lead", "calls": []}, {"id": "idle"}], roles=["analyst"])
    found = python_source([node("lead"), node("worker")], [edge("lead", "worker")])
    graph = build(registry, found)
    assert graph.entry_agents == ("lead", "idle", "worker")
    assert graph.warnings == (
        "agent 'lead' reaches 'worker' (handoff, discovered) "
        "but its registry 'calls' does not list 'worker'",
        NO_ENTRY,
        "entry agent 'lead' lists no roles, so every role can use it",
        "entry agent 'idle' lists no roles, so every role can use it",
        "entry agent 'worker' lists no roles, so every role can use it",
        "agent 'worker' was discovered but is not declared in the registry; "
        "its entry, roles, and delegation_mode are unknown",
        "agent 'idle' is declared in the registry but no discovery source reported it",
    )


def test_opacity_warnings_take_their_step_positions():
    # Disagreement comes from merging nodes (first); "look inside" is part of drift (last).
    registry = make_registry([{"id": "desk", "entry": True, "calls": []}, {"id": "billing"}])
    triage = python_source(
        [node("desk"), node("billing", opaque=True), node("worker", opaque=True)],
        [edge("desk", "worker")],
        label="python:app1:triage",
    )
    worker = python_source([node("worker")], label="python:app2:billing")
    graph = build(registry, triage, worker)
    assert graph.warnings == (
        "agent 'worker' is opaque in python:app1:triage but python:app2:billing saw it; "
        "lockwalk assumes they are the same agent",
        "agent 'desk' reaches 'worker' (handoff, discovered) "
        "but its registry 'calls' does not list 'worker'",
        "agent 'worker' was discovered but is not declared in the registry; "
        "its entry, roles, and delegation_mode are unknown",
        UNSEEN,
    )


# ---- Robustness: validated input never makes build_graph raise ----


@pytest.mark.parametrize("bad", ["", " lead", "a" + chr(0) + "b", "x" * 201])
def test_a_source_result_rejects_agents_that_are_not_valid_names(bad: str):
    with pytest.raises(ValidationError):
        SourceResult(source=SourceRef(kind="mcp", label="mcp:tools"), ok=True, agents=(bad,))


NAME_POOL = ["a", "b", "lead agent", "it's", "mcp:a", "mcp:b", REG, "x" * 200]
TOOL_POOL = ["get_price", "ask_a", "mcp:a", "a"]
# SourceRef.label is a plain string, so labels can be anything, including invalid node ids.
LABEL_POOL = ["mcp:a", "mcp:b", PY, "json:t.json", REG, "", " padded ", "mcp:" + "y" * 250]
LABEL_POOL.append("mcp:" + chr(0))
URL_POOL = [None, "https://user:secret@h.example/a2a?token=t#f", "http://h.example"]
MODES: list[DelegationMode | None] = [None, "user", "agent", "on_behalf_of"]
KINDS: list[SourceKind] = ["python", "mcp", "json"]


def _some(rng: random.Random, pool: Sequence[str], most: int = 3) -> list[str]:
    return rng.sample(list(pool), rng.randint(0, min(most, len(pool))))


def _random_registry(rng: random.Random) -> Registry | None:
    if rng.random() < 0.2:
        return None
    agents: list[dict[str, object]] = []
    for agent_id in _some(rng, NAME_POOL, 4):
        decl: dict[str, object] = {"id": agent_id, "entry": rng.random() < 0.3}
        if rng.random() < 0.5:
            decl["calls"] = _some(rng, NAME_POOL)
        if rng.random() < 0.3:
            decl["roles"] = ["analyst"]
        remote = rng.choice(URL_POOL)
        if remote is not None:
            decl["remote"] = remote
        decl["delegation_mode"] = rng.choice(MODES)
        agents.append(decl)
    tools = [tool_decl("get_price", *_some(rng, NAME_POOL))] if rng.random() < 0.7 else []
    delegation = [
        {"id": "ask_a", "agent": rng.choice(NAME_POOL), "supported_agents": _some(rng, NAME_POOL)}
    ]
    return make_registry(
        agents,
        tools,
        delegation_tools=delegation if rng.random() < 0.6 else [],
        roles=["analyst"] if rng.random() < 0.5 else None,
    )


def _random_fragment(rng: random.Random) -> GraphFragment | None:
    if rng.random() < 0.3:
        return None
    nodes = tuple(
        GraphNode(
            id=node_id,
            kind=rng.choice(list(NodeKind)),
            entry=rng.random() < 0.3,
            opaque=rng.random() < 0.3,
            roles=("analyst",) if rng.random() < 0.2 else None,
            delegation_mode=rng.choice(MODES),
            remote_url=rng.choice(URL_POOL),
        )
        for node_id in _some(rng, NAME_POOL, 4)
    )
    edges = tuple(
        GraphEdge(
            from_id=rng.choice(NAME_POOL),
            to_id=rng.choice(NAME_POOL + TOOL_POOL),
            kind=rng.choice(list(EdgeKind)),
            provenance=rng.choice(list(Provenance)),
        )
        for _ in range(rng.randint(0, 6))
    )
    return GraphFragment(nodes=nodes, edges=edges)


def _random_source(rng: random.Random) -> SourceResult:
    ok = rng.random() < 0.6
    return SourceResult(
        source=SourceRef(kind=rng.choice(KINDS), label=rng.choice(LABEL_POOL)),
        ok=ok,
        error=None if ok else "failed",
        optional=rng.random() < 0.5,
        tools=tuple(ToolDescriptor(name=name) for name in _some(rng, TOOL_POOL)),
        agents=tuple(_some(rng, NAME_POOL, 2)),
        graph=_random_fragment(rng),
    )


def test_build_graph_never_raises_on_validated_input():
    rng = random.Random(20261106)
    for _ in range(500):
        registry = _random_registry(rng)
        sources = [_random_source(rng) for _ in range(rng.randint(0, 3))]
        inventory = merge_inventory(sources, registry=registry, registry_label=REG)
        graph = build_graph(registry, inventory, registry_label=REG)
        assert build_graph(registry, inventory, registry_label=REG) == graph
        assert len({item.id for item in graph.nodes}) == len(graph.nodes)
        assert edges_of(graph) == sorted(edges_of(graph))
        dumped = graph.model_dump_json()
        assert "secret" not in dumped
        assert "token" not in dumped


UNMARKED_TARGET = (
    "agent 'trade-desk' is a top-level discovery target but is not marked entry: true; "
    "no role starts there"
)


def test_a_top_level_target_the_registry_does_not_mark_entry_warns():
    registry = make_registry(
        [{"id": "supervisor", "entry": True, "calls": []}, {"id": "trade-desk", "calls": []}]
    )
    found = python_source(
        [node("supervisor", entry=True), node("trade-desk", entry=True)], label="python:app"
    )
    graph = build(registry, found)
    assert graph.entry_agents == ("supervisor",)
    assert graph.warnings == (UNMARKED_TARGET,)
    assert get_node(graph, "trade-desk").entry is False


def test_no_unmarked_target_warning_for_a_target_an_entry_agent_reaches():
    """Pointing a target at a sub-agent is how discovery learns about it: no warning."""
    registry = make_registry(
        [
            {"id": "supervisor", "entry": True, "calls": ["pricing-agent"]},
            {"id": "pricing-agent", "calls": []},
            {"id": "trade-desk", "calls": []},
        ]
    )
    found = python_source(
        [
            node("supervisor", entry=True),
            node("pricing-agent", entry=True),
            node("trade-desk", entry=True),
        ],
        label="python:app",
    )
    graph = build(registry, found)
    assert graph.warnings == (UNMARKED_TARGET,)  # only trade-desk, which nothing reaches


def test_no_unmarked_target_warning_when_the_registry_marks_no_entry():
    registry = make_registry([{"id": "trade-desk", "calls": []}])
    found = python_source([node("trade-desk", entry=True)], label="python:app")
    graph = build(registry, found)
    assert graph.entry_agents == ("trade-desk",)
    assert UNMARKED_TARGET not in graph.warnings


def test_no_unmarked_target_warning_for_marked_targets_or_boundaries():
    registry = make_registry([{"id": "trade-desk", "entry": True, "calls": []}])
    found = python_source(
        [node("trade-desk", entry=True), node("mcp:x", kind=MCP, entry=True)], label="python:app"
    )
    graph = build(registry, found)
    assert not any("top-level discovery target" in warning for warning in graph.warnings)
