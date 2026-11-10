"""Agent and edge discovery, checked against real framework objects.

Each framework test only constructs objects and reads their attributes: no model is
called, no agent runs, and no MCP server is connected.

Tests whose names end in _version_pin pin framework details that lockwalk relies on
(private attributes, internal structures, default names, constructor fields). When a
framework upgrade breaks one of them, update the matching code in agent_shapes.py,
normalize.py, or mcp_naming.py, not just the test.
"""

import contextlib
import importlib.metadata
import inspect
import time
import warnings
from collections.abc import Generator, Sequence
from pathlib import Path
from typing import ClassVar, Literal, TypeVar

import pytest
from agents import Agent as OpenAIAgent
from agents import (
    FunctionTool,
    HostedMCPTool,
    ToolOriginType,
    WebSearchTool,
    function_tool,
    handoff,
)
from agents.handoffs import Handoff
from agents.mcp import MCPServerStdio, MCPServerStreamableHttp
from agno.agent import Agent as AgnoAgent
from agno.team import Team
from agno.tools import tool as agno_tool
from agno.tools.mcp import MCPTools
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import tool as lc_tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Command
from lockwalk_graph_helpers import assert_closed, edge_set, node_ids
from pydantic import BaseModel
from pydantic_ai import Agent as PydanticAgent
from pydantic_ai import RunContext
from pydantic_ai.toolsets import (
    AbstractToolset,
    CombinedToolset,
    FilteredToolset,
    FunctionToolset,
    PrefixedToolset,
)

from lockwalk.config import PythonSourceConfig
from lockwalk.graph.analysis import evaluate_rules
from lockwalk.graph.build import build_graph
from lockwalk.inventory import _python_worker
from lockwalk.inventory.agent_shapes import MAX_AGENT_DEPTH, discover, discover_graph
from lockwalk.inventory.merge import merge_inventory
from lockwalk.inventory.normalize import (
    agent_name,
    agent_tool_check,
    describe_error,
    has_agent_shape,
    has_static,
    normalize_items,
    tool_container_contents,
    wrapped_agent,
)
from lockwalk.inventory.python import PythonSource
from lockwalk.models import (
    GraphFragment,
    GraphNode,
    NeverReachesRule,
    NodeKind,
    RuleResult,
    SourceRef,
    SourceResult,
)
from lockwalk.registry import Registry
from lockwalk.urls import redact_urls


def node(fragment: GraphFragment, node_id: str) -> GraphNode:
    return next(item for item in fragment.nodes if item.id == node_id)


def type_name(kind: type) -> str:
    """How lockwalk names a type in its messages: module and qualified name."""
    return f"{kind.__module__}.{kind.__qualname__}"


def unnamed_warning(kind: type) -> str:
    return f"agent of type {type_name(kind)} has no name; set name= so lockwalk can show its edges"


def walk(*values: object) -> tuple[GraphFragment, list[str]]:
    fragment, found_warnings = discover_graph(list(values))
    assert_closed(fragment)
    return fragment, found_warnings


# ---- plain tools: behavior without a graph ----


def get_price(symbol: str) -> str:
    """Return the price of a stock symbol."""
    return symbol


def refund(order_id: str) -> str:
    """Refund an order."""
    return order_id


@lc_tool
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio."""
    return portfolio_id


def test_plain_tools_give_an_empty_fragment():
    fragment, found_warnings = walk(get_price, read_portfolio, {"name": "lookup"})
    assert fragment == GraphFragment()
    assert found_warnings == []


# ---- OpenAI Agents SDK ----


def openai_tool(function):
    return function_tool(function)


def test_openai_handoffs_are_discovered():
    billing = OpenAIAgent(name="billing", tools=[openai_tool(refund)])
    care = OpenAIAgent(name="care")
    triage = OpenAIAgent(name="triage", handoffs=[billing, handoff(care)])
    fragment, found_warnings = walk(triage)
    assert found_warnings == []
    assert node_ids(fragment) == ["triage", "billing", "care"]
    assert [n.entry for n in fragment.nodes] == [True, False, False]
    assert edge_set(fragment) == {
        ("triage", "billing", "handoff", "discovered"),
        ("triage", "care", "handoff", "discovered"),
        ("billing", "refund", "uses_tool", "discovered"),
    }


def test_openai_handoff_keeps_a_weakref_to_its_agent_version_pin():
    # handoff(agent) keeps the agent only in this private weak reference.
    care = OpenAIAgent(name="care")
    item = handoff(care)
    assert item.agent_name == "care"
    assert item._agent_ref is not None
    assert item._agent_ref() is care


def test_openai_handoff_known_only_by_name_gets_a_bare_node():
    async def invoke(context, arguments):
        raise AssertionError("never called")

    item = Handoff(
        tool_name="transfer_to_care",
        tool_description="Hand off to care.",
        input_json_schema={},
        on_invoke_handoff=invoke,
        agent_name="care",
    )
    assert item._agent_ref is None
    fragment, found_warnings = walk(OpenAIAgent(name="triage", handoffs=[item]))
    assert node_ids(fragment) == ["triage", "care"]
    # What a name-only agent can reach is unknown, so its bare node is opaque.
    assert node(fragment, "care") == GraphNode(id="care", opaque=True)
    assert edge_set(fragment) == {("triage", "care", "handoff", "discovered")}
    assert found_warnings == [
        "agent 'care' is known only by its name; lockwalk cannot see what it can reach, "
        "so declare it in the registry"
    ]


def test_openai_handoff_by_name_uses_the_real_agent_when_it_is_also_reached():
    async def invoke(context, arguments):
        raise AssertionError("never called")

    care = OpenAIAgent(name="care", tools=[openai_tool(refund)])
    by_name = Handoff(
        tool_name="transfer_to_care",
        tool_description="Hand off to care.",
        input_json_schema={},
        on_invoke_handoff=invoke,
        agent_name="care",
    )
    fragment, found_warnings = walk(OpenAIAgent(name="triage", handoffs=[by_name, care]))
    assert found_warnings == []
    assert ("care", "refund", "uses_tool", "discovered") in edge_set(fragment)
    assert node(fragment, "care").opaque is False

    # The real agent also wins when it is found later and deeper in the walk.
    deep = OpenAIAgent(name="deep", handoffs=[care])
    fragment, found_warnings = walk(
        OpenAIAgent(name="triage", handoffs=[by_name, OpenAIAgent(name="mid", handoffs=[deep])])
    )
    assert found_warnings == []
    assert node(fragment, "care").opaque is False
    assert ("care", "refund", "uses_tool", "discovered") in edge_set(fragment)


def test_openai_handoff_cycle_terminates():
    billing = OpenAIAgent(name="billing")
    triage = OpenAIAgent(name="triage", handoffs=[billing])
    billing.handoffs = [triage]
    fragment, _ = walk(triage)
    assert edge_set(fragment) == {
        ("triage", "billing", "handoff", "discovered"),
        ("billing", "triage", "handoff", "discovered"),
    }


def test_openai_as_tool_private_attributes_version_pin():
    # Agent.as_tool() marks its FunctionTool with these private attributes.
    billing = OpenAIAgent(name="billing")
    wrapper = billing.as_tool(tool_name="ask_billing", tool_description="Ask billing.")
    assert getattr(wrapper, "_is_agent_tool", None) is True
    assert getattr(wrapper, "_agent_instance", None) is billing
    assert wrapped_agent(wrapper) is billing
    assert tool_container_contents(wrapper) == [billing]


def test_openai_as_tool_is_an_agent_as_tool_edge_and_not_a_tool():
    billing = OpenAIAgent(name="billing", tools=[openai_tool(refund)])
    triage = OpenAIAgent(
        name="triage",
        tools=[
            billing.as_tool(tool_name="ask_billing", tool_description="Ask billing."),
            openai_tool(get_price),
        ],
    )
    fragment, found_warnings = walk(triage)
    assert found_warnings == []
    assert node_ids(fragment) == ["triage", "billing"]
    assert edge_set(fragment) == {
        ("triage", "billing", "agent_as_tool", "discovered"),
        ("triage", "get_price", "uses_tool", "discovered"),
        ("billing", "refund", "uses_tool", "discovered"),
    }
    # normalize_items stops at the wrapped agent; the graph walk collects its tools.
    tools, errors = normalize_items([triage])
    assert errors == []
    assert [t.name for t in tools] == ["get_price"]
    assert [t.name for t in discover([triage]).tools] == ["get_price", "refund"]


def test_openai_as_tool_cycle_is_not_a_normalize_error():
    first = OpenAIAgent(name="first")
    second = OpenAIAgent(name="second", tools=[first.as_tool(tool_name="a", tool_description="a")])
    first.tools = [second.as_tool(tool_name="b", tool_description="b"), openai_tool(refund)]
    tools, errors = normalize_items([first])
    assert errors == []
    assert [t.name for t in tools] == ["refund"]
    fragment, _ = walk(first)
    assert ("second", "first", "agent_as_tool", "discovered") in edge_set(fragment)


def test_openai_mcp_servers_are_boundary_nodes_without_connecting(no_network):
    files = MCPServerStdio(params={"command": "python", "args": ["-c", "pass"]}, name="files")
    remote = MCPServerStreamableHttp(
        params={"url": "http://admin:s3cr3t@localhost:9/mcp?token=t0ken"}
    )
    agent = OpenAIAgent(name="ops", mcp_servers=[files, remote])
    fragment, found_warnings = walk(agent)
    assert found_warnings == []
    # The SDK's default name embeds the full URL; lockwalk strips its credentials.
    assert remote.name == "streamable_http: http://admin:s3cr3t@localhost:9/mcp?token=t0ken"
    remote_id = "mcp:streamable_http: http://localhost:9/mcp"
    assert node_ids(fragment) == ["ops", "mcp:files", remote_id]
    assert node(fragment, "mcp:files").kind is NodeKind.MCP_SERVER
    assert node(fragment, remote_id).remote_url == "http://localhost:9/mcp"
    assert edge_set(fragment) == {
        ("ops", "mcp:files", "remote", "discovered"),
        ("ops", remote_id, "remote", "discovered"),
    }
    dumped = fragment.model_dump_json()
    assert "s3cr3t" not in dumped
    assert "t0ken" not in dumped
    assert files.session is None
    assert remote.session is None


# ---- Agno ----


@agno_tool
def lookup(query: str) -> str:
    """Look something up."""
    return query


def test_agno_team_members_are_team_edges_from_the_leader_only():
    researcher = AgnoAgent(name="researcher", tools=[get_price])
    writer = AgnoAgent(name="writer")
    team = Team(name="newsroom", members=[researcher, writer])
    fragment, found_warnings = walk(team)
    assert found_warnings == []
    assert node_ids(fragment) == ["newsroom", "researcher", "writer"]
    assert edge_set(fragment) == {
        ("newsroom", "researcher", "team", "discovered"),
        ("newsroom", "writer", "team", "discovered"),
        ("researcher", "get_price", "uses_tool", "discovered"),
    }


def test_agno_team_is_not_reported_as_a_tool_and_member_tools_are_collected():
    team = Team(name="newsroom", members=[AgnoAgent(name="researcher", tools=[get_price])])
    tools, errors = normalize_items([team])
    assert (tools, errors) == ([], [])
    assert [t.name for t in discover([team]).tools] == ["get_price"]


def test_agno_nested_team_with_leader_tools():
    newsroom = Team(name="newsroom", members=[AgnoAgent(name="writer")])
    org = Team(name="org", members=[newsroom, AgnoAgent(name="ceo")], tools=[lookup])
    fragment, _ = walk(org)
    assert edge_set(fragment) == {
        ("org", "newsroom", "team", "discovered"),
        ("org", "ceo", "team", "discovered"),
        ("org", "lookup", "uses_tool", "discovered"),
        ("newsroom", "writer", "team", "discovered"),
    }


def test_agno_unnamed_member_warns_and_its_tools_are_still_collected():
    team = Team(name="desk", members=[AgnoAgent(tools=[get_price])])
    found = discover([team])
    assert_closed(found.fragment)
    assert node_ids(found.fragment) == ["desk"]
    assert found.warnings == (unnamed_warning(AgnoAgent),)
    assert [t.name for t in found.tools] == ["get_price"]


def test_agno_mcp_tools_are_a_boundary_node(no_network):
    files = MCPTools(command="python -c pass", name="files")
    remote = MCPTools(
        url="http://admin:s3cr3t@localhost:9/mcp?token=t0ken", transport="streamable-http"
    )
    agent = AgnoAgent(name="ops", tools=[files, remote, get_price])
    fragment, found_warnings = walk(agent)
    assert found_warnings == []
    assert remote.name == "mcp_localhost_9_mcp"
    assert node_ids(fragment) == ["ops", "mcp:files", "mcp:mcp_localhost_9_mcp"]
    assert node(fragment, "mcp:mcp_localhost_9_mcp").remote_url == "http://localhost:9/mcp"
    assert edge_set(fragment) == {
        ("ops", "mcp:files", "remote", "discovered"),
        ("ops", "mcp:mcp_localhost_9_mcp", "remote", "discovered"),
        ("ops", "get_price", "uses_tool", "discovered"),
    }
    assert "s3cr3t" not in fragment.model_dump_json()
    assert files.session is None


# ---- LangGraph ----


class State(BaseModel):
    x: int = 0


def step(state: State) -> State:
    return state


def route_declared(state: State) -> Literal["b", "c"]:
    return "b"


def route_open(state: State) -> str:
    return "c"


def desk_graph():
    graph = StateGraph(State)
    for name in ("a", "b", "c"):
        graph.add_node(name, step)
    graph.add_node("tools", ToolNode([read_portfolio]))
    graph.add_edge(START, "a")
    graph.add_conditional_edges("a", route_declared)
    graph.add_conditional_edges("b", route_open)
    graph.add_conditional_edges("c", route_open, {"x": "tools", "y": END})
    graph.add_edge("tools", "a")
    return graph.compile(name="desk")


def test_langgraph_branch_ends_mark_open_routes_version_pin():
    branches = desk_graph().builder.branches
    assert branches["a"]["route_declared"].ends == {"b": "b", "c": "c"}
    assert branches["b"]["route_open"].ends is None
    assert branches["c"]["route_open"].ends == {"x": "tools", "y": END}


def test_langgraph_edges_branches_and_tool_node():
    fragment, found_warnings = walk(desk_graph())
    assert found_warnings == []
    assert node_ids(fragment) == ["desk", "desk:a", "desk:b", "desk:c"]
    assert node(fragment, "desk").entry is True
    assert edge_set(fragment) == {
        ("desk", "desk:a", "team", "discovered"),
        ("desk:a", "desk:b", "handoff", "discovered"),
        ("desk:a", "desk:c", "handoff", "discovered"),
        # An open router may go anywhere in its graph, ToolNodes included.
        ("desk:b", "desk:a", "handoff", "inferred"),
        ("desk:b", "desk:c", "handoff", "inferred"),
        ("desk:b", "read_portfolio", "uses_tool", "inferred"),
        # A route into the ToolNode is a tool use; the route out continues from c.
        ("desk:c", "read_portfolio", "uses_tool", "discovered"),
        ("desk:c", "desk:a", "handoff", "discovered"),
    }


def test_langgraph_graph_is_not_a_tool_and_its_tool_node_tools_are_collected():
    graph = desk_graph()
    assert normalize_items([graph]) == ([], [])
    assert [t.name for t in discover([graph]).tools] == ["read_portfolio"]


class FakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def react_agent(name: str | None):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # create_react_agent is deprecated in LangGraph 1.x
        from langgraph.prebuilt import create_react_agent  # ty: ignore[deprecated]

        return create_react_agent(  # ty: ignore[deprecated]
            FakeModel(responses=[]), [read_portfolio], name=name
        )


def test_langgraph_react_agent_target():
    fragment, found_warnings = walk(react_agent("finance-agent"))
    assert found_warnings == []
    assert node_ids(fragment) == ["finance-agent", "finance-agent:agent"]
    # agent -> tools -> agent loops back to itself, which adds no edge.
    assert edge_set(fragment) == {
        ("finance-agent", "finance-agent:agent", "team", "discovered"),
        ("finance-agent:agent", "read_portfolio", "uses_tool", "discovered"),
    }


# LangGraph reads the destinations from this return annotation.
def jumper(state: State) -> Command[Literal["researcher", "__end__"]]:
    return Command(goto="researcher")  # ty: ignore[invalid-return-type]


def free_jumper(state: State):
    return Command(goto="researcher")


def test_langgraph_subgraph_node_and_command_destinations_version_pin():
    researcher = react_agent(None)  # LangGraph's default name is "LangGraph"
    graph = StateGraph(State)
    graph.add_node("jumper", jumper)
    graph.add_node("free", free_jumper)
    graph.add_node("researcher", researcher)
    graph.add_node("dest", step, destinations=("free",))
    graph.add_edge(START, "jumper")
    graph.add_edge(["jumper", "free"], "dest")
    compiled = graph.compile(name="boss")
    assert compiled.builder.nodes["researcher"].runnable is researcher
    assert compiled.builder.nodes["jumper"].ends == ("researcher", "__end__")
    assert compiled.builder.nodes["free"].ends == ()

    fragment, found_warnings = walk(compiled)
    assert found_warnings == []
    assert node_ids(fragment) == [
        "boss",
        "boss:jumper",
        "boss:free",
        "boss:researcher",
        "boss:dest",
        "boss:researcher:agent",
    ]
    assert edge_set(fragment) == {
        ("boss", "boss:jumper", "team", "discovered"),
        # Command[Literal[...]] return annotation and destinations= are visible.
        ("boss:jumper", "boss:researcher", "handoff", "discovered"),
        ("boss:dest", "boss:free", "handoff", "discovered"),
        # add_edge with a list of starts (a join).
        ("boss:jumper", "boss:dest", "handoff", "discovered"),
        ("boss:free", "boss:dest", "handoff", "discovered"),
        ("boss:researcher", "boss:researcher:agent", "team", "discovered"),
        ("boss:researcher:agent", "read_portfolio", "uses_tool", "discovered"),
    }
    # free_jumper's Command(goto="researcher") is not declared anywhere, so it is not seen.
    assert ("boss:free", "boss:researcher", "handoff", "discovered") not in edge_set(fragment)


# ---- Pydantic AI ----


def test_pydantic_ai_named_agent_with_function_tools():
    agent = PydanticAgent("test", name="pricer", tools=[get_price, refund])  # ty: ignore[no-matching-overload]
    fragment, found_warnings = walk(agent)
    assert found_warnings == []
    assert node_ids(fragment) == ["pricer"]
    assert edge_set(fragment) == {
        ("pricer", "get_price", "uses_tool", "discovered"),
        ("pricer", "refund", "uses_tool", "discovered"),
    }


def test_pydantic_ai_in_tool_delegation_is_not_discovered():
    oracle = PydanticAgent("test", name="oracle")
    pricer = PydanticAgent("test", name="pricer")

    @pricer.tool_plain
    async def ask_oracle(question: str) -> str:
        """Ask the oracle."""
        return (await oracle.run(question)).output

    fragment, found_warnings = walk(pricer)
    assert found_warnings == []
    # The call to oracle.run() inside the tool body cannot be seen; declare it with calls.
    assert node_ids(fragment) == ["pricer"]
    assert edge_set(fragment) == {("pricer", "ask_oracle", "uses_tool", "discovered")}


def test_pydantic_ai_unnamed_agent_warns_and_keeps_its_tools():
    agent = PydanticAgent("test", tools=[get_price])  # ty: ignore[no-matching-overload]
    fragment, found_warnings = walk(agent)
    assert fragment == GraphFragment()
    assert found_warnings == [unnamed_warning(PydanticAgent)]
    assert [t.name for t in normalize_items([agent])[0]] == ["get_price"]


# ---- generic shape rules, with small stand-in objects ----


class Fake:
    """A stand-in agent: any attributes, given as keyword arguments."""

    def __init__(self, **attributes: object) -> None:
        self.__dict__.update(attributes)


def test_shape_rules():
    assert has_agent_shape(Fake(name="a", tools=[]))
    assert has_agent_shape(Fake(role="a", agents=[]))
    assert not has_agent_shape(Fake(name="a"))
    assert not has_agent_shape(Fake(name="a", tools={"t": get_price}))  # a toolset
    assert not has_agent_shape(Fake(name="a", functions={}, tools=[]))  # an Agno Toolkit
    assert not has_agent_shape({"name": "a", "tools": []})
    assert not has_agent_shape(Fake)


def test_every_non_tool_edge_ends_at_a_node_in_the_fragment():
    async def invoke(context, arguments):
        raise AssertionError("never called")

    by_name = Handoff(
        tool_name="t",
        tool_description="d",
        input_json_schema={},
        on_invoke_handoff=invoke,
        agent_name="ghost",
    )
    remote_member = Fake(name="remote-member")  # has a name but nothing to look inside
    leaf = Fake(name="leaf", tools=[get_price])
    chain: object = leaf
    for index in range(7):
        chain = Fake(name=f"level-{index}", handoffs=[chain])
    top = Fake(
        name="top",
        tools=[leaf, get_price],
        handoffs=[by_name, chain],
        members=[remote_member],
        mcp_servers=[Fake(name="srv")],
    )
    fragment, _ = walk(top, desk_graph(), react_agent("react"))
    targets = {e.to_id for e in fragment.edges if e.kind.value != "uses_tool"}
    assert targets <= set(node_ids(fragment))
    assert {"ghost", "remote-member", "mcp:srv"} <= targets


def test_agent_depth_limit_marks_the_last_agent_opaque():
    assert MAX_AGENT_DEPTH == 32
    agent: object = Fake(name="level-33", tools=[get_price])
    for index in range(32, -1, -1):
        agent = Fake(name=f"level-{index}", handoffs=[agent])
    fragment, found_warnings = walk(agent)
    assert node_ids(fragment) == [f"level-{index}" for index in range(33)]
    assert [n.opaque for n in fragment.nodes] == [False] * 32 + [True]
    assert found_warnings == [
        "agent 'level-32' is nested more than 32 agents deep; lockwalk shows it as opaque "
        "and only collects the tools below it"
    ]


def test_agent_depth_is_separate_from_tool_container_nesting():
    # Six agents deep is fine, although tool containers stop at five levels.
    agent: object = Fake(name="level-6", tools=[get_price])
    for index in range(5, -1, -1):
        agent = Fake(name=f"level-{index}", handoffs=[agent])
    fragment, found_warnings = walk(agent)
    assert found_warnings == []
    assert not any(n.opaque for n in fragment.nodes)
    assert ("level-6", "get_price", "uses_tool", "discovered") in edge_set(fragment)


def test_same_name_different_objects_keeps_the_first():
    first = Fake(name="billing", tools=[get_price])
    second = Fake(name="billing", tools=[refund])
    fragment, found_warnings = walk(Fake(name="triage", handoffs=[first, second]))
    assert node_ids(fragment) == ["triage", "billing"]
    assert edge_set(fragment) == {
        ("triage", "billing", "handoff", "discovered"),
        ("billing", "get_price", "uses_tool", "discovered"),
    }
    assert found_warnings == [
        "two different agents are named 'billing'; only the first one is shown"
    ]


def test_same_object_reached_twice_is_one_node():
    shared = Fake(name="shared", tools=[get_price])
    fragment, found_warnings = walk(
        Fake(name="a", handoffs=[shared]), Fake(name="b", members=[shared])
    )
    assert found_warnings == []
    assert node_ids(fragment) == ["a", "b", "shared"]
    assert [n.entry for n in fragment.nodes] == [True, True, False]


def test_bad_names_warn_instead_of_crashing():
    bell = chr(7)
    fragment, found_warnings = walk(
        Fake(
            name="ok", handoffs=[Fake(name=" padded ", tools=[]), Fake(name=f"a{bell}b", tools=[])]
        )
    )
    assert node_ids(fragment) == ["ok"]
    assert len(found_warnings) == 2
    assert found_warnings[0].startswith("agent name ' padded ' is not valid (")
    assert all(w.endswith("lockwalk cannot show its edges") for w in found_warnings)


def test_allow_delegation_gives_inferred_calls_between_coworkers():
    lead = Fake(role="lead", tools=[], allow_delegation=True)
    helper = Fake(role="helper", tools=[], allow_delegation=False)
    other = Fake(role="other", tools=[])
    manager = Fake(role="manager", tools=[])
    crew = Fake(name="crew", agents=[lead, helper, other], manager_agent=manager)
    fragment, _ = walk(crew)
    assert edge_set(fragment) == {
        ("crew", "lead", "team", "discovered"),
        ("crew", "helper", "team", "discovered"),
        ("crew", "other", "team", "discovered"),
        ("crew", "manager", "team", "discovered"),
        ("manager", "lead", "team", "discovered"),
        ("manager", "helper", "team", "discovered"),
        ("manager", "other", "team", "discovered"),
        ("lead", "helper", "calls", "inferred"),
        ("lead", "other", "calls", "inferred"),
    }


def test_non_list_links_and_non_agent_members_warn():
    fragment, found_warnings = walk(Fake(name="t", members=lambda: [], agents=[42]))
    assert node_ids(fragment) == ["t"]
    assert found_warnings == [
        "agent 't': members is a builtins.function, not a list; lockwalk cannot see what it holds",
        "agent 't': agents holds a builtins.int, which is not an agent; it is ignored",
    ]


def test_tool_problems_outside_normalize_scope_are_warnings():
    member = Fake(name="member", tools=[get_price, 42])
    found = discover([Fake(name="team", members=[member])])
    assert [t.name for t in found.tools] == ["get_price"]
    assert found.warnings == (
        "agent 'member': tool 1: cannot recognize a tool in a value of type builtins.int",
    )
    # The same problem in the top-level agent is a normalize error, not repeated here.
    assert discover([member]).warnings == ()


def test_mcp_server_without_a_name_warns():
    fragment, found_warnings = walk(Fake(name="a", mcp_servers=[object()]))
    assert node_ids(fragment) == ["a"]
    # The server the agent can reach is not shown, so what the agent reaches is unknown.
    assert node(fragment, "a").opaque is True
    assert found_warnings == [
        "MCP server of type builtins.object has no name; set name= so lockwalk can show it"
    ]


# ---- an agent is opaque when the walk dropped part of what it reaches ----


def test_a_complete_walk_leaves_every_agent_transparent():
    billing = OpenAIAgent(name="billing", tools=[openai_tool(refund)])
    fragment, _ = walk(OpenAIAgent(name="triage", handoffs=[billing]), desk_graph())
    assert not any(n.opaque for n in fragment.nodes)


def test_a_link_attribute_that_is_not_a_list_makes_the_agent_opaque():
    fragment, found_warnings = walk(Fake(name="t", members=lambda: []))
    assert node(fragment, "t").opaque is True
    assert found_warnings == [
        "agent 't': members is a builtins.function, not a list; lockwalk cannot see what it holds"
    ]


def test_an_unnamed_child_makes_its_parent_opaque():
    fragment, found_warnings = walk(Team(name="desk", members=[AgnoAgent(tools=[get_price])]))
    assert node(fragment, "desk").opaque is True
    assert found_warnings == [unnamed_warning(AgnoAgent)]


def test_a_child_with_an_invalid_name_makes_its_parent_opaque():
    fragment, found_warnings = walk(Fake(name="t", handoffs=[Fake(name=" padded ", tools=[])]))
    assert node_ids(fragment) == ["t"]
    assert node(fragment, "t").opaque is True
    assert len(found_warnings) == 1
    assert found_warnings[0].startswith("agent name ' padded ' is not valid (")


def test_a_duplicate_name_makes_the_parent_of_the_duplicate_opaque():
    first = Fake(name="billing", tools=[get_price])
    second = Fake(name="billing", tools=[refund])
    fragment, found_warnings = walk(
        Fake(name="a", handoffs=[first]), Fake(name="b", handoffs=[second])
    )
    # b's edge resolves to the first billing agent, which may not be the one b calls.
    assert ("b", "billing", "handoff", "discovered") in edge_set(fragment)
    assert node(fragment, "a").opaque is False
    assert node(fragment, "b").opaque is True
    assert node(fragment, "billing").opaque is False
    assert found_warnings == [
        "two different agents are named 'billing'; only the first one is shown"
    ]


def test_a_handoff_that_names_no_agent_makes_the_agent_opaque():
    fragment, found_warnings = walk(Fake(name="t", handoffs=[42]))
    assert node(fragment, "t").opaque is True
    assert found_warnings == [
        "agent 't': a handoff of type builtins.int names no agent; it is ignored"
    ]


def test_a_member_that_is_not_an_agent_makes_the_team_opaque():
    fragment, found_warnings = walk(Fake(name="t", agents=[42]))
    assert node(fragment, "t").opaque is True
    assert found_warnings == [
        "agent 't': agents holds a builtins.int, which is not an agent; it is ignored"
    ]


def test_an_unreadable_tool_makes_the_agent_opaque():
    # Outside normalize's reach: a warning here.
    member = Fake(name="member", tools=[get_price, 42])
    fragment, found_warnings = walk(Fake(name="team", members=[member]))
    assert node(fragment, "member").opaque is True
    assert node(fragment, "team").opaque is False
    assert found_warnings == [
        "agent 'member': tool 1: cannot recognize a tool in a value of type builtins.int"
    ]
    # Inside normalize's reach: normalize reports the error, and the agent is still opaque.
    fragment, found_warnings = walk(Fake(name="solo", tools=[42]))
    assert node(fragment, "solo").opaque is True
    assert found_warnings == []


def test_an_unreadable_tool_node_tool_makes_the_routing_node_opaque():
    class PartlyBrokenToolNode(RunnableLambda):
        tools_by_name: ClassVar[dict[str, object]] = {
            "read_portfolio": read_portfolio,
            "broken": 42,
        }

    graph = StateGraph(State)
    graph.add_node("a", step)
    graph.add_node("b", step)
    graph.add_node("tools", PartlyBrokenToolNode(step))
    graph.add_edge(START, "a")
    graph.add_edge("a", "tools")
    graph.add_edge("tools", "b")
    fragment, found_warnings = walk(graph.compile(name="g"))
    assert node(fragment, "g:a").opaque is True
    assert node(fragment, "g:b").opaque is False
    assert ("g:a", "read_portfolio", "uses_tool", "discovered") in edge_set(fragment)
    assert found_warnings == [
        "LangGraph node 'g:tools': tool 1: cannot recognize a tool in a value of type builtins.int"
    ]


def test_a_langgraph_node_with_an_invalid_id_makes_the_graph_opaque():
    graph = StateGraph(State)
    graph.add_node(" padded ", step)
    graph.add_edge(START, " padded ")
    fragment, found_warnings = walk(graph.compile(name="g"))
    assert node_ids(fragment) == ["g"]
    assert node(fragment, "g").opaque is True
    assert len(found_warnings) == 1
    assert found_warnings[0].startswith("LangGraph node id 'g: padded ' is not valid (")


def test_a_tools_factory_is_never_called_and_makes_the_team_opaque():
    calls: list[str] = []

    def factory() -> list[object]:
        calls.append("called")
        return [get_price]

    team = Team(name="lead", members=[AgnoAgent(name="writer")], tools=factory)
    agent = AgnoAgent(name="solo", tools=factory)
    fragment, found_warnings = walk(team, agent)
    assert calls == []
    assert node(fragment, "lead").opaque is True
    assert node(fragment, "writer").opaque is False
    # An agent whose only tools come from a factory is still an agent, not a tool.
    assert node(fragment, "solo").opaque is True
    assert normalize_items([agent]) == ([], [])
    assert calls == []
    assert found_warnings == [
        f"agent {name!r}: tools is a builtins.function, not a list; lockwalk does not "
        "call a tools factory, so it cannot see the tools it returns"
        for name in ("lead", "solo")
    ]


def test_a_tools_method_on_a_class_is_not_a_factory():
    class Capability:
        name = "capability"

        def tools(self) -> list[object]:
            raise AssertionError("never called")

    assert not has_agent_shape(Capability())


def test_a_manager_agent_that_is_not_an_agent_makes_the_crew_opaque():
    crew = Fake(name="crew", agents=[Fake(role="analyst", tools=[])], manager_agent=42)
    fragment, found_warnings = walk(crew)
    assert node(fragment, "crew").opaque is True
    assert found_warnings == [
        "agent 'crew': manager_agent is a builtins.int, which is not an agent; it is ignored"
    ]


def small_graph():
    graph = StateGraph(State)
    graph.add_node("a", step)
    graph.add_node("b", step)
    graph.add_edge(START, "a")
    graph.add_edge("a", "b")
    return graph.compile(name="g")


def _bad_edge_end(builder: object) -> None:
    builder.edges.add(("a", 42))  # ty: ignore[unresolved-attribute]


def _bad_branch_entry(builder: object) -> None:
    builder.branches["a"] = 42  # ty: ignore[unresolved-attribute]


def _bad_waiting_starts(builder: object) -> None:
    builder.waiting_edges = {("a", "b")}  # ty: ignore[unresolved-attribute]


def _bad_waiting_edges(builder: object) -> None:
    builder.waiting_edges = 42  # ty: ignore[unresolved-attribute]


@pytest.mark.parametrize(
    ("break_it", "problem"),
    [
        (_bad_edge_end, "edges has a route from a builtins.str to a builtins.int"),
        (_bad_branch_entry, "branches has an entry that is a builtins.int"),
        (_bad_waiting_starts, "waiting_edges has starts that are a builtins.str"),
        (_bad_waiting_edges, "waiting_edges is a builtins.int"),
    ],
)
def test_a_malformed_langgraph_route_makes_the_graph_opaque(break_it, problem):
    compiled = small_graph()
    break_it(compiled.builder)
    fragment, found_warnings = walk(compiled)
    assert node(fragment, "g").opaque is True
    assert found_warnings == [f"agent 'g': LangGraph {problem}; lockwalk skipped it"]
    assert ("g:a", "g:b", "handoff", "discovered") in edge_set(fragment)


def test_two_different_mcp_servers_with_one_id_warn():
    first = Fake(command="npx", args=["-y", "server-one"])
    second = Fake(command="npx", args=["-y", "server-two"])
    fragment, found_warnings = walk(
        Fake(name="a", mcp_servers=[first]), Fake(name="b", mcp_servers=[second])
    )
    assert node_ids(fragment) == ["a", "b", "mcp:npx"]
    assert node(fragment, "a").opaque is False
    # b's edge goes to the shared node, which may stand for the other server.
    assert node(fragment, "b").opaque is True
    assert found_warnings == [
        "two different MCP servers are both shown as 'mcp:npx'; give them distinct names"
    ]


def test_the_same_mcp_server_configured_twice_is_one_node():
    fragment, found_warnings = walk(
        Fake(name="a", mcp_servers=[Fake(command="npx", args=["server-one"])]),
        Fake(name="b", mcp_servers=[Fake(command="npx", args=["server-one"])]),
    )
    assert found_warnings == []
    assert node_ids(fragment) == ["a", "b", "mcp:npx"]
    assert not any(n.opaque for n in fragment.nodes)


# ---- the worker and the Python source ----


def test_a_raising_graph_walk_still_returns_the_tools(tmp_path: Path):
    module = tmp_path / "breaks_graph.py"
    module.write_text(
        "def get_price(symbol: str) -> str:\n"
        "    return symbol\n"
        "\n"
        "class Agent:\n"
        "    name = 'broken'\n"
        "    tools = [get_price]\n"
        "\n"
        "    @property\n"
        "    def handoffs(self):\n"
        "        raise RuntimeError('boom')\n"
        "\n"
        "agent = Agent()\n",
        encoding="utf-8",
    )
    payload = _python_worker.collect(f"{module}:agent")
    assert payload["tools"] == [{"name": "get_price", "description": None, "hints": {}}]
    assert payload["errors"] == []
    # Only the agent whose attribute raised is affected: it is shown, opaque.
    fragment = GraphFragment.model_validate(payload["graph"])
    assert fragment.nodes == (GraphNode(id="broken", entry=True, opaque=True),)
    assert edge_set(fragment) == {("broken", "get_price", "uses_tool", "discovered")}
    assert payload["graph_warnings"] == [
        "agent 'broken': reading it raised RuntimeError: boom; "
        "lockwalk could not see all of its edges"
    ]


def test_python_source_returns_the_graph_and_handoff_tools(write, tmp_path):
    write(
        "support.py",
        '''
        from agents import Agent, function_tool


        @function_tool
        def refund(order_id: str) -> str:
            """Refund an order."""
            return order_id


        billing = Agent(name="billing", tools=[refund])
        triage = Agent(name="triage", handoffs=[billing])
        ''',
    )
    result = PythonSource(PythonSourceConfig(target="support:triage"), tmp_path).read()
    assert result.ok, result.error
    assert [t.name for t in result.tools] == ["refund"]
    assert result.graph is not None
    assert node_ids(result.graph) == ["triage", "billing"]
    assert edge_set(result.graph) == {
        ("triage", "billing", "handoff", "discovered"),
        ("billing", "refund", "uses_tool", "discovered"),
    }


def test_python_source_passes_graph_warnings_through(write, tmp_path):
    write(
        "unnamed.py",
        """
        from pydantic_ai import Agent


        def get_price(symbol: str) -> str:
            return symbol


        agent = Agent("test", tools=[get_price])
        """,
    )
    result = PythonSource(PythonSourceConfig(target="unnamed:agent"), tmp_path).read()
    assert result.ok, result.error
    assert result.graph == GraphFragment()
    assert result.warnings == (unnamed_warning(PydanticAgent),)


def test_python_source_with_plain_tools_has_an_empty_graph(write, tmp_path):
    write(
        "plain.py", "def get_price(symbol: str) -> str:\n    return symbol\n\nTOOLS = [get_price]\n"
    )
    result = PythonSource(PythonSourceConfig(target="plain:TOOLS"), tmp_path).read()
    assert result.ok, result.error
    assert result.graph == GraphFragment()
    assert result.warnings == ()


@pytest.mark.parametrize(
    "graph_json",
    ['{"nodes": [{"id": ""}]}', '{"nodes": [], "edges": [], "extra": 1}', '"not a graph"'],
)
def test_an_invalid_graph_payload_is_unreadable(write, tmp_path, monkeypatch, graph_json):
    fake_dir = tmp_path / "fake"
    write(
        "fake/fake_worker.py",
        f"""
        import sys
        from pathlib import Path

        Path(sys.argv[2]).write_text(
            '{{"tools": [], "errors": [], "graph": {graph_json}}}', encoding="utf-8"
        )
        """,
    )
    monkeypatch.setenv("PYTHONPATH", str(fake_dir))
    monkeypatch.setattr("lockwalk.inventory.python.WORKER_MODULE", "fake_worker")
    result = PythonSource(PythonSourceConfig(target="x:y"), tmp_path).read()
    assert result.error == "the Python worker wrote an unreadable result"


def test_a_missing_graph_payload_is_an_empty_fragment(write, tmp_path, monkeypatch):
    fake_dir = tmp_path / "fake"
    write(
        "fake/old_worker.py",
        """
        import sys
        from pathlib import Path

        Path(sys.argv[2]).write_text('{"tools": [], "errors": []}', encoding="utf-8")
        """,
    )
    monkeypatch.setenv("PYTHONPATH", str(fake_dir))
    monkeypatch.setattr("lockwalk.inventory.python.WORKER_MODULE", "old_worker")
    result = PythonSource(PythonSourceConfig(target="x:y"), tmp_path).read()
    assert result.ok, result.error
    assert result.graph == GraphFragment()


# ---- no command arguments in node ids ----

SECRET = "SECRETMARK42"


def assert_secret_absent(fragment: GraphFragment, found_warnings: Sequence[str]) -> None:
    text = (fragment.model_dump_json() + "".join(found_warnings)).lower()
    assert SECRET.lower() not in text


def test_command_arguments_never_reach_node_ids_or_warnings(no_network):
    agno_default = MCPTools(command=f"npx -y srv --token {SECRET}")
    # Agno builds its default name and id from the whole command line, arguments included.
    assert SECRET.lower() in agno_default.name
    assert SECRET.lower() in agno_default.id
    agno_named = MCPTools(command=f"npx -y srv --token {SECRET}", name="files")
    openai_default = MCPServerStdio(
        params={"command": "/usr/bin/python3", "args": ["srv.py", "--token", SECRET]}
    )
    assert openai_default.name == "stdio: /usr/bin/python3"
    openai_named = MCPServerStdio(
        params={"command": "uvx", "args": ["--token", SECRET]}, name="github"
    )
    # An unknown framework that names a server after its command line.
    homemade = Fake(name=f"node-srv-{SECRET}", command="node", args=["srv.js", SECRET])
    # Arguments written into the command string itself, with no separate args.
    inline = Fake(name=f"npx-srv-{SECRET}", command=f"npx -y srv --token {SECRET}")
    # A URL or a path argument inside the command string, and no name at all.
    url_argument = Fake(command=f"npx mcp-remote https://h.example/s/{SECRET}")
    path_argument = Fake(command=f"node /opt/servers/{SECRET}")
    full_path = Fake(command=f"/usr/bin/node /opt/servers/{SECRET}/index.js")
    relative_path = Fake(command=f"/usr/bin/node servers/{SECRET}")
    quoted_path = Fake(command=f'"C:/Program Files/nodejs/npx.cmd" servers/{SECRET}')
    # Unquoted, a path with a space gives the harmless name "Program".
    spaced_path = Fake(command=f"C:/Program Files/nodejs/npx.cmd servers/{SECRET}")
    fragment, found_warnings = walk(
        AgnoAgent(name="ops", tools=[agno_default, agno_named]),
        OpenAIAgent(name="oai", mcp_servers=[openai_default, openai_named]),
        Fake(name="own", mcp_servers=[homemade]),
        Fake(name="inline", mcp_servers=[inline]),
        Fake(name="url", mcp_servers=[url_argument]),
        Fake(name="path", mcp_servers=[path_argument]),
        Fake(name="full", mcp_servers=[full_path]),
        Fake(name="relative", mcp_servers=[relative_path]),
        Fake(name="quoted", mcp_servers=[quoted_path]),
        Fake(name="spaced", mcp_servers=[spaced_path]),
    )
    assert node_ids(fragment) == [
        "ops",
        "oai",
        "own",
        "inline",
        "url",
        "path",
        "full",
        "relative",
        "quoted",
        "spaced",
        "mcp:npx",
        "mcp:files",
        "mcp:python3",
        "mcp:github",
        "mcp:node",
        "mcp:Program",
    ]
    edges = edge_set(fragment)
    for owner, server in [
        ("inline", "mcp:npx"),
        ("url", "mcp:npx"),
        ("path", "mcp:node"),
        ("full", "mcp:node"),
        ("relative", "mcp:node"),
        ("quoted", "mcp:npx"),
        ("spaced", "mcp:Program"),
    ]:
        assert (owner, server, "remote", "discovered") in edges
    assert_secret_absent(fragment, found_warnings)


def test_a_chosen_name_that_echoes_the_package_is_kept(no_network):
    server = MCPTools(command="npx -y @modelcontextprotocol/server-github", name="github")
    fragment, _ = walk(AgnoAgent(name="ops", tools=[server]))
    assert "mcp:github" in node_ids(fragment)


def test_mcp_client_presence_checks_run_no_property(no_network):
    class Unconnected:
        """Like mcp's Client: .session raises until the client connects."""

        name = "svc"
        server_params = None

        @property
        def session(self) -> object:
            raise RuntimeError("not connected")

    fragment, found_warnings = walk(Fake(name="a", tools=[Unconnected()]))
    assert found_warnings == []
    assert edge_set(fragment) == {("a", "mcp:svc", "remote", "discovered")}


def test_handoff_agent_ref_is_called_only_when_it_is_a_weak_reference():
    calls: list[str] = []

    def not_a_weakref() -> object:
        calls.append("called")
        return OpenAIAgent(name="care")

    item = Fake(agent_name="care", _agent_ref=not_a_weakref)
    fragment, _ = walk(Fake(name="triage", handoffs=[item]))
    assert calls == []
    assert node(fragment, "care") == GraphNode(id="care", opaque=True)


# ---- no network ----


class AccessLog:
    """Attribute reads on instances of some classes, recorded while watching."""

    def __init__(self) -> None:
        self.reads: list[str] = []
        self.watching = False

    @contextlib.contextmanager
    def watch(self) -> Generator[None, None, None]:
        self.watching = True
        try:
            yield
        finally:
            self.watching = False


def log_attribute_reads(
    monkeypatch: pytest.MonkeyPatch, classes: Sequence[type], *, fail: bool
) -> AccessLog:
    """Record every plain attribute read on these classes' instances while watching.

    inspect.getattr_static does not go through __getattribute__, so it is not recorded.
    """
    log = AccessLog()

    def getattribute(self: object, name: str) -> object:
        if log.watching:
            log.reads.append(name)
            if fail:
                raise AssertionError(f"{type(self).__name__}.{name} was read")
        return object.__getattribute__(self, name)

    for cls in classes:
        monkeypatch.setattr(cls, "__getattribute__", getattribute)
    return log


RemoteT = TypeVar("RemoteT")


def make_remote(cls: type[RemoteT], **stored: object) -> RemoteT:
    # RemoteAgent.__init__ imports agno.client, which needs fastapi (not installed), so the
    # object gets the plain fields that __init__ would store.
    value = object.__new__(cls)
    vars(value).update(
        {"agentos_client": None, "a2a_client": None, "_cached_config": None, **stored}
    )
    return value


@pytest.fixture
def remote_guard(monkeypatch: pytest.MonkeyPatch) -> AccessLog:
    """Agno remote objects: their network properties always fail, and while watching,
    every plain attribute read fails too."""
    from agno.agent import RemoteAgent
    from agno.team import RemoteTeam

    def refuse(self: object) -> object:
        raise AssertionError("a property that calls the network was read")

    classes = (RemoteAgent, RemoteTeam)
    for cls in classes:
        for name in ("name", "role", "tools", "description", "id"):
            monkeypatch.setattr(cls, name, property(refuse))
    return log_attribute_reads(monkeypatch, classes, fail=True)


def test_agno_remote_agents_are_opaque_and_never_read(no_network, remote_guard):
    from agno.agent import RemoteAgent
    from agno.team import RemoteTeam

    research = make_remote(
        RemoteAgent, agent_id="research", base_url="http://admin:s3cr3t@localhost:7777"
    )
    ops = make_remote(RemoteTeam, team_id="ops", base_url="https://agents.example.com")
    # Agno accepts remote members at run time, but its type hints do not list them.
    members = [research, ops, AgnoAgent(name="writer")]
    team = Team(name="org", members=members)  # ty: ignore[invalid-argument-type]
    lead = Fake(role="lead", tools=[], allow_delegation=True)
    crew = Fake(name="crew", agents=[research, lead])
    with remote_guard.watch():
        found = discover([team])
        crew_found = discover([crew])
        normalized = normalize_items([research, team, crew])
    assert remote_guard.reads == []
    assert_closed(found.fragment)
    assert found.warnings == ()
    assert node_ids(found.fragment) == ["org", "research", "ops", "writer"]
    assert node(found.fragment, "research") == GraphNode(
        id="research",
        kind=NodeKind.REMOTE_AGENT,
        opaque=True,
        remote_url="http://localhost:7777",
    )
    assert node(found.fragment, "ops").kind is NodeKind.REMOTE_AGENT
    assert edge_set(found.fragment) == {
        ("org", "research", "team", "discovered"),
        ("org", "ops", "team", "discovered"),
        ("org", "writer", "team", "discovered"),
    }
    assert "s3cr3t" not in found.fragment.model_dump_json()
    # A delegating coworker can still call the remote agent; the remote one is not read.
    assert edge_set(crew_found.fragment) == {
        ("crew", "research", "team", "discovered"),
        ("crew", "lead", "team", "discovered"),
        ("lead", "research", "calls", "inferred"),
    }
    assert normalized == ([], [])


def test_agno_remote_agent_without_a_stored_id_warns(no_network, remote_guard):
    from agno.agent import RemoteAgent

    team = Fake(name="t", members=[make_remote(RemoteAgent)])
    with remote_guard.watch():
        fragment, found_warnings = walk(team)
    assert remote_guard.reads == []
    assert node_ids(fragment) == ["t"]
    # The remote member is not shown, so what the team reaches is unknown.
    assert node(fragment, "t").opaque is True
    assert found_warnings == [
        "an Agno RemoteAgent was found; lockwalk does not read its properties because they "
        "call the network; declare it in the registry with remote:"
    ]


def test_langgraph_remote_graph_node_is_recognized_without_reading_it(no_network, monkeypatch):
    from langgraph.pregel.remote import RemoteGraph

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("get_graph() calls the server")

    monkeypatch.setattr(RemoteGraph, "get_graph", refuse)
    remote = RemoteGraph("research-assistant", url="http://localhost:9")
    graph = StateGraph(State)
    graph.add_node("local", step)
    graph.add_node("remote", remote)
    graph.add_edge(START, "local")
    graph.add_edge("local", "remote")
    compiled = graph.compile(name="boss")
    log = log_attribute_reads(monkeypatch, [RemoteGraph], fail=False)
    with log.watch():
        fragment, found_warnings = walk(compiled)
    assert log.reads == []
    assert found_warnings == []
    assert node_ids(fragment) == ["boss", "boss:local", "boss:remote"]
    assert node(fragment, "boss:remote") == GraphNode(
        id="boss:remote", kind=NodeKind.REMOTE_AGENT, opaque=True
    )
    assert edge_set(fragment) == {
        ("boss", "boss:local", "team", "discovered"),
        ("boss:local", "boss:remote", "handoff", "discovered"),
    }


# ---- one raising attribute costs only its own agent ----


class Raises:
    """Raise this exception from a property, by name."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def __get__(self, instance: object, owner: type | None = None) -> object:
        if instance is None:
            return self
        raise self.error


def test_a_raising_property_costs_only_its_agent():
    class Broken:
        name = "broken"
        tools: ClassVar[list[object]] = [get_price]
        handoffs = Raises(RuntimeError("boom"))

    sibling = Fake(name="sibling", tools=[refund])
    fragment, found_warnings = walk(Fake(name="team", members=[Broken(), sibling]))
    assert node(fragment, "broken").opaque is True
    assert node(fragment, "sibling").opaque is False
    assert node(fragment, "team").opaque is False
    assert ("broken", "get_price", "uses_tool", "discovered") in edge_set(fragment)
    assert ("sibling", "refund", "uses_tool", "discovered") in edge_set(fragment)
    assert found_warnings == [
        "agent 'broken': reading it raised RuntimeError: boom; "
        "lockwalk could not see all of its edges"
    ]


def test_a_getattr_that_raises_key_error_costs_only_the_parent_step():
    class Weird:
        def __getattr__(self, name: str) -> object:
            raise KeyError(name)

    sibling = Fake(name="sibling", tools=[])
    fragment, found_warnings = walk(Fake(name="team", members=[Weird(), sibling]))
    assert node_ids(fragment) == ["team", "sibling"]
    assert node(fragment, "team").opaque is True
    assert ("team", "sibling", "team", "discovered") in edge_set(fragment)
    assert len(found_warnings) == 1
    assert found_warnings[0].startswith("agent 'team': reading it raised KeyError:")


def test_a_raising_name_costs_only_the_parent_step():
    class Nameless:
        tools: ClassVar[list[object]] = []
        name = Raises(RuntimeError("no name today"))

    sibling = Fake(name="sibling", tools=[])
    fragment, found_warnings = walk(Fake(name="team", members=[Nameless(), sibling]))
    assert node(fragment, "team").opaque is True
    assert ("team", "sibling", "team", "discovered") in edge_set(fragment)
    assert found_warnings == [
        "agent 'team': reading it raised RuntimeError: no name today; "
        "lockwalk could not see all of its edges"
    ]


def test_a_raising_top_level_value_is_skipped():
    class Weird:
        def __getattr__(self, name: str) -> object:
            raise KeyError(name)

    fragment, found_warnings = walk(Weird(), Fake(name="fine", tools=[]))
    assert node_ids(fragment) == ["fine"]
    assert len(found_warnings) == 1
    assert "raised KeyError" in found_warnings[0]


def test_an_mcp_server_whose_name_raises_costs_only_its_owner():
    class Server:
        name = Raises(RuntimeError("no name"))

    fragment, found_warnings = walk(
        Fake(name="a", mcp_servers=[Server()]), Fake(name="b", mcp_servers=[Fake(name="ok")])
    )
    assert node(fragment, "a").opaque is True
    assert node(fragment, "b").opaque is False
    assert ("b", "mcp:ok", "remote", "discovered") in edge_set(fragment)
    assert found_warnings == [
        "agent 'a': reading it raised RuntimeError: no name; "
        "lockwalk could not see all of its edges"
    ]


def test_an_argument_whose_str_raises_falls_back_to_the_command():
    class Unprintable:
        def __str__(self) -> str:
            raise RuntimeError("no text")

    server = Fake(name="chosen-name", command="npx", args=[Unprintable()])
    fragment, found_warnings = walk(Fake(name="a", mcp_servers=[server]))
    # The argument cannot be compared with the name, so the name is not trusted.
    assert found_warnings == []
    assert edge_set(fragment) == {("a", "mcp:npx", "remote", "discovered")}


def test_a_branch_key_whose_eq_raises_is_a_route_problem():
    class Key:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("no comparing")

        def __hash__(self) -> int:
            return 1

    compiled = small_graph()
    compiled.builder.branches[Key()] = {"route": object()}
    fragment, found_warnings = walk(compiled)
    assert node(fragment, "g").opaque is True
    assert found_warnings == [
        f"agent 'g': LangGraph branches has a source that is a {type_name(Key)}; "
        "lockwalk skipped it"
    ]
    # Whose routes were lost cannot be told, so every node of the graph is opaque.
    assert all(n.opaque for n in fragment.nodes)
    assert ("g:a", "g:b", "handoff", "discovered") in edge_set(fragment)


# ---- exception text is redacted ----


def test_exception_text_loses_url_credentials_and_query():
    class Leaky:
        name = "leaky"
        tools: ClassVar[list[object]] = []
        handoffs = Raises(RuntimeError("token=t0k https://admin:s3cr3t@h.example/x?k=v4lue"))

    _, found_warnings = walk(Leaky())
    text = "".join(found_warnings)
    assert "https://h.example/x" in text
    assert "s3cr3t" not in text
    assert "v4lue" not in text
    # Plain text outside a URL cannot be recognized as a secret.
    assert "token=t0k" in text


def test_describe_error_survives_a_raising_str():
    class Unprintable(Exception):
        def __str__(self) -> str:
            raise RuntimeError("no text")

    assert describe_error(Unprintable()) == "Unprintable"
    assert describe_error(ValueError("")) == "ValueError"
    assert describe_error(ValueError("see https://u:p@h/x?k=v")) == "ValueError: see https://h/x"


def test_normalize_errors_redact_exception_text():
    class Broken:
        def get_tools(self) -> list[object]:
            raise RuntimeError("at https://admin:s3cr3t@h.example/x?k=v")

    _, errors = normalize_items([Broken()])
    assert errors == ["item 0: reading its tools raised RuntimeError: at https://h.example/x"]


# ---- the worker keeps the tools whatever the graph walk raises ----


def write_module(tmp_path: Path, name: str, source: str) -> Path:
    module = tmp_path / f"{name}.py"
    module.write_text(source, encoding="utf-8")
    return module


def test_a_system_exit_in_the_graph_walk_keeps_the_tools(tmp_path: Path):
    module = write_module(
        tmp_path,
        "exits_in_walk",
        "def get_price(symbol: str) -> str:\n"
        "    return symbol\n"
        "\n"
        "class Agent:\n"
        "    name = 'quitter'\n"
        "    tools = [get_price]\n"
        "\n"
        "    @property\n"
        "    def handoffs(self):\n"
        "        raise SystemExit(3)\n"
        "\n"
        "agent = Agent()\n",
    )
    payload = _python_worker.collect(f"{module}:agent")
    assert "fatal" not in payload
    assert payload["tools"] == [{"name": "get_price", "description": None, "hints": {}}]
    assert payload["graph"] == GraphFragment().model_dump(mode="json")
    assert payload["graph_warnings"] == ["reading the agent graph raised SystemExit: 3"]
    # Tools that only the walk finds may be missing, so the source must not look complete.
    assert payload["errors"] == [
        "reading the agent graph raised SystemExit: 3; tools that only the agent graph walk "
        "finds may be missing"
    ]


def test_an_exception_whose_str_raises_is_not_fatal(tmp_path: Path):
    module = write_module(
        tmp_path,
        "unprintable",
        "def get_price(symbol: str) -> str:\n"
        "    return symbol\n"
        "\n"
        "class Unprintable(Exception):\n"
        "    def __str__(self):\n"
        "        raise RuntimeError('no text')\n"
        "\n"
        "class Agent:\n"
        "    name = 'odd'\n"
        "    tools = [get_price]\n"
        "\n"
        "    @property\n"
        "    def handoffs(self):\n"
        "        raise Unprintable()\n"
        "\n"
        "agent = Agent()\n"
        "\n"
        "class Bad:\n"
        "    @property\n"
        "    def tools(self):\n"
        "        raise Unprintable()\n"
        "\n"
        "bad = Bad()\n",
    )
    payload = _python_worker.collect(f"{module}:agent")
    assert "fatal" not in payload
    assert payload["tools"] == [{"name": "get_price", "description": None, "hints": {}}]
    assert payload["graph_warnings"] == [
        "agent 'odd': reading it raised Unprintable; lockwalk could not see all of its edges"
    ]
    payload = _python_worker.collect(f"{module}:bad")
    assert "fatal" not in payload
    assert payload["errors"] == ["item 0: reading its tools raised Unprintable"]


def test_import_errors_are_described_safely(tmp_path: Path):
    module = write_module(
        tmp_path,
        "unprintable_import",
        "class Unprintable(Exception):\n"
        "    def __str__(self):\n"
        "        raise RuntimeError('no text')\n"
        "\n"
        "raise Unprintable()\n",
    )
    payload = _python_worker.collect(f"{module}:agent")
    assert payload == {"fatal": "importing the target raised Unprintable"}


# ---- scale and depth ----


def test_thousands_of_tools_are_deduplicated_in_one_pass(tmp_path: Path):
    tools = [{"name": f"tool_{index}"} for index in range(3000)]
    member = Fake(name="member", tools=tools)
    found = discover([Fake(name="team", members=[member]), member])
    assert len(found.tools) == 3000
    module = write_module(
        tmp_path,
        "many_tools",
        "class Agent:\n"
        "    def __init__(self, name, tools=(), members=()):\n"
        "        self.name = name\n"
        "        self.tools = list(tools)\n"
        "        self.members = list(members)\n"
        "\n"
        "TOOLS = [{'name': f'tool_{index}'} for index in range(3000)]\n"
        "member = Agent('member', tools=TOOLS)\n"
        "AGENTS = [Agent('team', tools=TOOLS[:1500], members=[member])]\n",
    )
    payload = _python_worker.collect(f"{module}:AGENTS")
    assert payload["errors"] == []
    names = [tool["name"] for tool in payload["tools"]]  # ty: ignore[not-iterable]
    assert len(names) == 3000
    assert len(set(names)) == 3000


def test_a_deep_as_tool_chain_keeps_every_tool(tmp_path: Path):
    agent = OpenAIAgent(name="level-6", tools=[openai_tool(refund)])
    for index in range(5, -1, -1):
        agent = OpenAIAgent(
            name=f"level-{index}",
            tools=[agent.as_tool(tool_name=f"ask_{index + 1}", tool_description="Ask.")],
        )
    tools, errors = normalize_items([agent])
    assert (tools, errors) == ([], [])
    found = discover([agent])
    assert [t.name for t in found.tools] == ["refund"]
    assert found.warnings == ()
    assert ("level-5", "level-6", "agent_as_tool", "discovered") in edge_set(found.fragment)
    module = write_module(
        tmp_path,
        "deep_chain",
        "from agents import Agent, function_tool\n"
        "\n"
        "@function_tool\n"
        "def refund(order_id: str) -> str:\n"
        "    '''Refund an order.'''\n"
        "    return order_id\n"
        "\n"
        "agent = Agent(name='level-6', tools=[refund])\n"
        "for index in range(5, -1, -1):\n"
        "    agent = Agent(\n"
        "        name=f'level-{index}',\n"
        "        tools=[agent.as_tool(tool_name=f'ask_{index + 1}', tool_description='Ask.')],\n"
        "    )\n",
    )
    payload = _python_worker.collect(f"{module}:agent")
    assert payload["errors"] == []
    assert payload["tools"] == [{"name": "refund", "description": "Refund an order.", "hints": {}}]


# ---- proxies that answer every attribute ----


def test_a_magic_mock_is_not_an_agent_and_is_never_called():
    from unittest.mock import MagicMock

    mock = MagicMock()
    assert not has_agent_shape(mock)
    fragment, found_warnings = walk(mock, Fake(name="team", members=[mock]))
    assert node_ids(fragment) == ["team"]
    assert mock.mock_calls == []
    assert len(found_warnings) == 1
    assert "which is not an agent" in found_warnings[0]
    tools, errors = normalize_items([mock])
    assert tools == []
    assert errors == [f"item 0: cannot recognize a tool in a value of type {type_name(MagicMock)}"]
    assert mock.mock_calls == []


def test_an_xmlrpc_proxy_is_never_contacted(no_network, monkeypatch):
    import xmlrpc.client

    requests: list[str] = []

    def record(self: object, name: str, params: object) -> None:
        requests.append(name)
        raise AssertionError("the proxy was called")

    monkeypatch.setattr(xmlrpc.client.ServerProxy, "_ServerProxy__request", record)
    proxy = xmlrpc.client.ServerProxy("http://127.0.0.1:9")
    assert not has_agent_shape(proxy)
    fragment, found_warnings = walk(proxy, Fake(name="team", members=[proxy]))
    assert requests == []
    assert node_ids(fragment) == ["team"]
    assert len(found_warnings) == 1
    assert "which is not an agent" in found_warnings[0]
    tools, errors = normalize_items([proxy])
    assert requests == []
    assert tools == []
    assert len(errors) == 1


# ---- framework details that lockwalk relies on ----


def test_agno_remote_constructors_store_ids_and_urls_version_pin():
    from agno.agent import RemoteAgent
    from agno.team import RemoteTeam
    from agno.workflow import RemoteWorkflow

    # lockwalk reads these fields with inspect.getattr_static, never through a property.
    assert {"agent_id", "base_url"} <= set(inspect.signature(RemoteAgent.__init__).parameters)
    assert {"team_id", "base_url"} <= set(inspect.signature(RemoteTeam.__init__).parameters)
    assert {"workflow_id", "base_url"} <= set(inspect.signature(RemoteWorkflow.__init__).parameters)
    assert isinstance(inspect.getattr_static(RemoteAgent, "name"), property)


def test_mcp_default_names_version_pin():
    # Agno builds its default name and id from the whole command line, arguments included,
    # and from the URL without credentials or query.
    stdio = MCPTools(command="npx -y srv --token abc")
    assert stdio.name == "mcp_npx_y_srv_token_abc"
    assert stdio.id == "mcp-npx-y-srv-token-abc"
    assert MCPTools(url="http://u:p@localhost:9/mcp?k=v").name == "mcp_localhost_9_mcp"
    # The OpenAI Agents SDK names a server after its command or its whole URL.
    assert MCPServerStdio(params={"command": "uvx", "args": ["x"]}).name == "stdio: uvx"
    assert (
        MCPServerStreamableHttp(params={"url": "http://u:p@h/mcp?k=v"}).name
        == "streamable_http: http://u:p@h/mcp?k=v"
    )


# ---- LangGraph route errors mark the nodes whose routes may be missing ----


class RouteSpec:
    """A StateNodeSpec stand-in whose .ends may raise."""

    def __init__(self, *, raise_ends: bool = False) -> None:
        self.runnable = step
        self.error_handler_node = None
        self._raise_ends = raise_ends

    @property
    def ends(self) -> object:
        if self._raise_ends:
            raise RuntimeError("no ends")
        return None


class RouteBuilder:
    """A StateGraph stand-in whose .branches may raise."""

    def __init__(self, *, raise_branches: bool = False, raise_ends_of: str = "") -> None:
        self.nodes = {name: RouteSpec(raise_ends=name == raise_ends_of) for name in ("a", "b")}
        self.edges = {("__start__", "a"), ("a", "b")}
        self.waiting_edges: set[object] = set()
        self._raise_branches = raise_branches

    @property
    def branches(self) -> object:
        if self._raise_branches:
            raise RuntimeError("no branches")
        return {}


def stand_in_graph(builder: RouteBuilder) -> Fake:
    return Fake(name="g", builder=builder, get_graph=lambda: None)


def test_raising_branches_make_every_node_of_the_graph_opaque():
    fragment, found_warnings = walk(stand_in_graph(RouteBuilder(raise_branches=True)))
    assert [(n.id, n.opaque) for n in fragment.nodes] == [
        ("g", True),
        ("g:a", True),
        ("g:b", True),
    ]
    # The plain edges were still read.
    assert ("g:a", "g:b", "handoff", "discovered") in edge_set(fragment)
    assert found_warnings == [
        "agent 'g': LangGraph reading branches raised RuntimeError: no branches; "
        "lockwalk skipped it"
    ]


def test_raising_node_ends_make_that_node_opaque():
    fragment, found_warnings = walk(stand_in_graph(RouteBuilder(raise_ends_of="b")))
    assert [(n.id, n.opaque) for n in fragment.nodes] == [
        ("g", True),
        ("g:a", False),
        ("g:b", True),
    ]
    assert found_warnings == [
        "agent 'g': LangGraph reading the routes of node 'b' raised RuntimeError: no ends; "
        "lockwalk skipped it"
    ]


def test_a_branch_entry_that_is_not_a_mapping_makes_its_node_opaque():
    compiled = small_graph()
    compiled.builder.branches["a"] = 42
    fragment, _ = walk(compiled)
    assert node(fragment, "g").opaque is True
    assert node(fragment, "g:a").opaque is True
    assert node(fragment, "g:b").opaque is False


# ---- nested tools are never lost (same result as without a graph) ----


def test_nested_agents_sharing_a_name_keep_their_tools(tmp_path: Path):
    module = write_module(
        tmp_path,
        "same_name",
        "class Fake:\n"
        "    def __init__(self, **attributes):\n"
        "        self.__dict__.update(attributes)\n"
        "\n"
        "def refund(order_id: str) -> str:\n"
        "    return order_id\n"
        "\n"
        "def wire(account: str) -> str:\n"
        "    return account\n"
        "\n"
        "AGENTS = [\n"
        "    Fake(name='a', tools=[Fake(name='helper', tools=[refund])]),\n"
        "    Fake(name='b', tools=[Fake(name='helper', tools=[wire])]),\n"
        "]\n",
    )
    payload = _python_worker.collect(f"{module}:AGENTS")
    assert payload["errors"] == []
    assert sorted(t["name"] for t in payload["tools"]) == ["refund", "wire"]  # ty: ignore[not-iterable]
    fragment = GraphFragment.model_validate(payload["graph"])
    # The second helper has no node of its own, and b's edge may point at the wrong one.
    assert node(fragment, "b").opaque is True


def test_as_tool_agents_sharing_a_name_keep_their_tools(tmp_path: Path):
    module = write_module(
        tmp_path,
        "same_name_as_tool",
        "from agents import Agent, function_tool\n"
        "\n"
        "@function_tool\n"
        "def refund(order_id: str) -> str:\n"
        "    'Refund an order.'\n"
        "    return order_id\n"
        "\n"
        "@function_tool\n"
        "def delete_user(user_id: str) -> str:\n"
        "    'Delete a user.'\n"
        "    return user_id\n"
        "\n"
        "one = Agent(name='helper', tools=[refund])\n"
        "two = Agent(name='helper', tools=[delete_user])\n"
        "AGENTS = [\n"
        "    Agent(name='a', tools=[one.as_tool(tool_name='h1', tool_description='x')]),\n"
        "    Agent(name='b', tools=[two.as_tool(tool_name='h2', tool_description='x')]),\n"
        "]\n",
    )
    payload = _python_worker.collect(f"{module}:AGENTS")
    assert payload["errors"] == []
    assert sorted(t["name"] for t in payload["tools"]) == ["delete_user", "refund"]  # ty: ignore[not-iterable]


def test_a_nested_agent_named_like_an_mcp_node_keeps_its_tools(tmp_path: Path):
    module = write_module(
        tmp_path,
        "mcp_like_name",
        "class Fake:\n"
        "    def __init__(self, **attributes):\n"
        "        self.__dict__.update(attributes)\n"
        "\n"
        "def delete_user(user_id: str) -> str:\n"
        "    return user_id\n"
        "\n"
        "AGENTS = [\n"
        "    Fake(name='a', mcp_servers=[Fake(name='files', command='npx', args=[])]),\n"
        "    Fake(name='b', tools=[Fake(name='mcp:files', tools=[delete_user])]),\n"
        "]\n",
    )
    payload = _python_worker.collect(f"{module}:AGENTS")
    assert payload["errors"] == []
    assert [t["name"] for t in payload["tools"]] == ["delete_user"]  # ty: ignore[not-iterable]
    fragment = GraphFragment.model_validate(payload["graph"])
    assert node(fragment, "b").opaque is True


# ---- a task whose agent cannot be read ----


def test_a_task_whose_agent_raises_is_a_task_without_an_agent():
    class Task:
        tools: ClassVar[list[object]] = [get_price]
        agent = Raises(RuntimeError("no agent"))

    crew = Fake(
        name="crew",
        agents=[Fake(role="analyst", tools=[]), Fake(role="writer", tools=[])],
        manager_agent=Fake(role="manager", tools=[]),
        tasks=[Task()],
    )
    fragment, found_warnings = walk(crew)
    assert node(fragment, "crew").opaque is True
    tool_edges = {e for e in edge_set(fragment) if e[1] == "get_price"}
    assert tool_edges == {
        ("analyst", "get_price", "uses_tool", "inferred"),
        ("writer", "get_price", "uses_tool", "inferred"),
        ("manager", "get_price", "uses_tool", "inferred"),
    }
    assert found_warnings == [
        "agent 'crew': reading a task's agent raised RuntimeError: no agent; "
        "lockwalk treats the task as having no agent",
        "agent 'crew': a task has tools but no agent, so the crew picks the agent at run "
        "time; lockwalk cannot tell which agent reaches those tools",
    ]


# ---- redacting URLs inside long texts ----


def test_redact_urls_is_linear_on_long_unbroken_runs():
    started = time.perf_counter()
    for text in (
        "a" * 400_000,
        "a" * 400_000 + "://" + "b" * 400_000,
        "-" * 400_000 + "://x",
        "a://" * 100_000,
        "://" * 130_000,
    ):
        redact_urls(text)
    assert time.perf_counter() - started < 1.0


def test_redact_urls_handles_many_urls_and_neighbouring_text():
    text = (
        "first https://u:p@a.example/x?k=v, then 'http://u2:p2@b.example/y#f' and "
        "9https://u3:p3@c.example/z(ftp://u4:p4@d.example)"
    )
    redacted = redact_urls(text)
    for secret in ("u:p", "k=v", "u2:p2", "#f", "u3:p3", "u4:p4"):
        assert secret not in redacted
    # Trailing punctuation stays outside the URL.
    assert redacted.startswith("first https://a.example/x, then 'http://b.example/y' and 9")
    assert redact_urls("no url here: just text") == "no url here: just text"
    assert redact_urls("://nothing before") == "://nothing before"


@pytest.mark.parametrize(
    "text",
    [
        "https://user:'S3CR'@host/x",
        "https://S3CR'TOKEN@host",
        "https://user:it's-S3CR@host/x",
        'https://user:pa"S3CR@host',
    ],
)
def test_a_quote_inside_a_url_does_not_end_it(text):
    # RFC 3986 allows "'" in the user name and password, so a quote never splits a URL.
    redacted = redact_urls(f"failed: {text} (retrying)")
    assert "S3CR" not in redacted
    assert "TOKEN" not in redacted
    assert redacted.startswith("failed: https://host")
    assert redacted.endswith(" (retrying)")


def test_trailing_punctuation_is_put_back_after_the_url():
    assert redact_urls("(https://u:p@h/x)") == "(https://h/x)"
    assert redact_urls("<https://u:p@h/x>;") == "<https://h/x>;"
    assert redact_urls("{'url': 'https://u:p@h/x'}") == "{'url': 'https://h/x'}"


# ---- leftovers: a hostile route entry, and tools far below the depth limit ----


def test_a_route_entry_whose_len_raises_makes_every_node_opaque():
    class Pair(tuple):
        def __len__(self) -> int:
            raise RuntimeError("no len")

    compiled = small_graph()
    compiled.builder.edges.add(Pair(("b", "a")))  # not equal to an edge already there
    fragment, found_warnings = walk(compiled)
    assert all(n.opaque for n in fragment.nodes)
    assert found_warnings == [
        "agent 'g': LangGraph reading its routes raised RuntimeError: no len; lockwalk skipped it"
    ]


def test_tools_far_below_the_agent_depth_limit_are_still_collected(tmp_path: Path):
    module = write_module(
        tmp_path,
        "deep_as_tool_chain",
        "from agents import Agent, function_tool\n"
        "\n"
        "@function_tool\n"
        "def delete_user(user_id: str) -> str:\n"
        "    'Delete a user.'\n"
        "    return user_id\n"
        "\n"
        "agent = Agent(name='level-35', tools=[delete_user])\n"
        "for index in range(34, -1, -1):\n"
        "    agent = Agent(\n"
        "        name=f'level-{index}',\n"
        "        tools=[agent.as_tool(tool_name=f'ask_{index + 1}', tool_description='Ask.')],\n"
        "    )\n",
    )
    payload = _python_worker.collect(f"{module}:agent")
    assert payload["errors"] == []
    assert [t["name"] for t in payload["tools"]] == ["delete_user"]  # ty: ignore[not-iterable]
    fragment = GraphFragment.model_validate(payload["graph"])
    assert_closed(fragment)
    # Agents beyond the limit get no node; the one at the limit is opaque.
    assert node_ids(fragment) == [f"level-{index}" for index in range(33)]
    assert node(fragment, "level-32").opaque is True


# ---- tools_hidden: the walk could not read all of an agent's tools ----


class Box:
    """A tool container that is not an agent (like an Agno Toolkit)."""

    def __init__(self, *tools: object) -> None:
        self.functions = {str(index): tool for index, tool in enumerate(tools)}


def nested_boxes(levels: int) -> object:
    value: object = get_price
    for _ in range(levels):
        value = Box(value)
    return value


def tools_factory() -> list[object]:
    raise AssertionError("a tools factory is never called")


class RaisingTools:
    """Shaped like an agent, but reading its tools raises (the shape check never reads
    _is_agent_tool, the tool reading does)."""

    name = "raising"
    tools: ClassVar[list[object]] = [get_price]
    _is_agent_tool = Raises(RuntimeError("no tools today"))


def tool_node_graph() -> object:
    class PartlyBrokenToolNode(RunnableLambda):
        tools_by_name: ClassVar[dict[str, object]] = {"read_portfolio": read_portfolio, "x": 42}

    graph = StateGraph(State)
    graph.add_node("a", step)
    graph.add_node("tools", PartlyBrokenToolNode(step))
    graph.add_edge(START, "a")
    graph.add_edge("a", "tools")
    return graph.compile(name="g")


def team_of(member: object) -> object:
    """Puts the member outside normalize's reach, so the walk itself reports its problems."""
    return Fake(name="team", members=[member])


HIDDEN_TOOLS = {
    "tools factory": (AgnoAgent(name="a", tools=tools_factory), "a"),
    "tools that are not a list": (Fake(name="a", handoffs=[], tools="get_price"), "a"),
    "a tools attribute that raises": (team_of(RaisingTools()), "raising"),
    "a tool that cannot be read": (team_of(Fake(name="a", tools=[get_price, 42])), "a"),
    "tool containers nested too deep": (team_of(Fake(name="a", tools=[nested_boxes(6)])), "a"),
    "an unnamed MCP server": (Fake(name="a", mcp_servers=[object()]), "a"),
    "an MCP server with an invalid name": (Fake(name="a", mcp_servers=[Fake(name="x ")]), "a"),
    "mcp_servers that are not a list": (Fake(name="a", mcp_servers=lambda: []), "a"),
    "a task with tools but no agent": (
        Fake(name="a", agents=[Fake(role="w", tools=[])], tasks=[Fake(tools=[get_price])]),
        "a",
    ),
    "a task whose tools are not a list": (
        Fake(name="a", agents=[], tasks=[Fake(tools="get_price", agent=None)]),
        "a",
    ),
    "a ToolNode tool that cannot be read": (tool_node_graph(), "g:a"),
}


@pytest.mark.parametrize("case", list(HIDDEN_TOOLS))
def test_an_agent_whose_tools_were_not_all_read_has_hidden_tools(case):
    value, node_id = HIDDEN_TOOLS[case]
    fragment, found_warnings = walk(value)
    found = node(fragment, node_id)
    assert (found.opaque, found.tools_hidden) == (True, True)
    assert found_warnings


def test_two_mcp_servers_sharing_an_id_hide_the_tools_of_the_second_owner():
    first = Fake(command="npx", args=["-y", "server-one"])
    second = Fake(command="npx", args=["-y", "server-two"])
    fragment, _ = walk(Fake(name="a", mcp_servers=[first]), Fake(name="b", mcp_servers=[second]))
    assert node(fragment, "a").tools_hidden is False
    assert node(fragment, "b").tools_hidden is True


OPAQUE_WITH_READABLE_TOOLS = {
    "a handoff that names no agent": (Fake(name="a", tools=[get_price], handoffs=[42]), "a"),
    "a member that is not an agent": (Fake(name="a", agents=[42]), "a"),
    "members that are not a list": (Fake(name="a", members=lambda: []), "a"),
    "an unnamed member": (Team(name="a", members=[AgnoAgent(tools=[get_price])]), "a"),
    "a manager_agent that is not an agent": (
        Fake(name="a", agents=[Fake(role="w", tools=[])], manager_agent=42),
        "a",
    ),
    "a handoff to an agent known only by name": (
        Fake(name="a", handoffs=[Fake(agent_name="care")]),
        "care",
    ),
}


@pytest.mark.parametrize("case", list(OPAQUE_WITH_READABLE_TOOLS))
def test_an_agent_that_misses_only_calls_to_agents_keeps_its_tools_readable(case):
    """Declaring `calls` can fill these gaps, so they do not hide tools."""
    value, node_id = OPAQUE_WITH_READABLE_TOOLS[case]
    fragment, _ = walk(value)
    found = node(fragment, node_id)
    assert (found.opaque, found.tools_hidden) == (True, False)


def test_the_depth_limit_does_not_hide_tools():
    agent: object = Fake(name="deepest", tools=[get_price])
    for index in range(MAX_AGENT_DEPTH, -1, -1):
        agent = Fake(name=f"level-{index}", handoffs=[agent])
    fragment, _ = walk(agent)
    last = fragment.nodes[-1]
    assert (last.id, last.opaque, last.tools_hidden) == ("level-32", True, False)


def test_a_complete_walk_hides_no_tools():
    billing = OpenAIAgent(name="billing", tools=[openai_tool(refund)])
    fragment, _ = walk(OpenAIAgent(name="triage", handoffs=[billing]), desk_graph())
    assert not any(n.tools_hidden for n in fragment.nodes)


# ---- the as_tool() canary fails closed ----

AS_TOOL_CHANGED = (
    "openai-agents {version} changed how as_tool() is stored; lockwalk cannot tell which "
    "tools wrap agents, so agents with function tools are treated as opaque"
)


def as_tool_desk() -> tuple[OpenAIAgent, OpenAIAgent, FunctionTool]:
    """supervisor -> finance-agent, which holds get_price and trade-agent as a tool."""
    trade = OpenAIAgent(name="trade-agent", tools=[openai_tool(refund)])
    wrapper = trade.as_tool(tool_name="ask_trade_agent", tool_description="Ask trade agent.")
    finance = OpenAIAgent(name="finance-agent", tools=[openai_tool(get_price), wrapper])
    supervisor = OpenAIAgent(name="supervisor", handoffs=[finance])
    return supervisor, finance, wrapper


def change_the_sdk(variant: str, monkeypatch: pytest.MonkeyPatch, finance: OpenAIAgent) -> None:
    """Simulate an SDK release that stores as_tool() differently.

    "agent moved": _is_agent_tool is still set, but the agent is kept somewhere else.
    "field removed": FunctionTool no longer has the _is_agent_tool field at all.
    "flag unused": the field is kept (default False), but as_tool() no longer sets it or
    _agent_instance; only the tool's origin still says that as_tool() made it.
    """
    if variant in ("agent moved", "flag unused"):
        for tool in finance.tools:
            if getattr(tool, "_is_agent_tool", False) is True:
                if variant == "flag unused":
                    object.__setattr__(tool, "_is_agent_tool", False)
                object.__setattr__(tool, "_agent_instance", None)
        return
    monkeypatch.delattr(FunctionTool, "_is_agent_tool")
    for tool in finance.tools:
        vars(tool).pop("_is_agent_tool", None)
        vars(tool).pop("_agent_instance", None)


VARIANTS = ["agent moved", "field removed", "flag unused"]


def test_agent_tool_check_on_the_pinned_sdk_version_pin():
    _, finance, wrapper = as_tool_desk()
    kind, agent = agent_tool_check(wrapper)
    assert kind == "agent"
    assert agent is not None
    assert agent_name(agent) == "trade-agent"
    assert agent_tool_check(openai_tool(get_price)) == ("plain", None)
    # The canary relies on the dataclass field's class default.
    assert inspect.getattr_static(FunctionTool, "_is_agent_tool") is False
    # Hosted tools never had the attribute and never wrap an agent, so they stay plain.
    assert not has_static(HostedMCPTool, "_is_agent_tool")
    assert agent_tool_check(WebSearchTool()) == ("plain", None)
    assert agent_tool_check(get_price) == ("plain", None)
    assert agent_tool_check(finance) == ("plain", None)


@pytest.mark.parametrize("variant", VARIANTS)
def test_a_changed_as_tool_makes_its_owner_opaque_and_keeps_the_inventory(variant, monkeypatch):
    supervisor, finance, wrapper = as_tool_desk()
    change_the_sdk(variant, monkeypatch, finance)
    assert agent_tool_check(wrapper) == ("unknown", None)
    assert wrapped_agent(wrapper) is None
    # normalize reads the wrapper as a plain tool, without an error.
    tools, errors = normalize_items([finance])
    assert ([t.name for t in tools], errors) == (["get_price", "ask_trade_agent"], [])
    found = discover([supervisor])
    owner = node(found.fragment, "finance-agent")
    assert (owner.opaque, owner.tools_hidden) == (True, True)
    assert node(found.fragment, "supervisor").opaque is False
    assert "trade-agent" not in node_ids(found.fragment)
    assert ("finance-agent", "ask_trade_agent", "uses_tool", "discovered") in edge_set(
        found.fragment
    )
    version = importlib.metadata.version("openai-agents")
    assert list(found.warnings) == [AS_TOOL_CHANGED.format(version=version)]


def canary_registry() -> Registry:
    """Every agent declares its calls, and trade-agent holds refund."""
    return Registry.model_validate(
        {
            "schema_version": "1",
            "roles": ["analyst"],
            "agents": [
                {
                    "id": "supervisor",
                    "entry": True,
                    "roles": ["analyst"],
                    "calls": ["finance-agent"],
                },
                {"id": "finance-agent", "calls": []},
                {"id": "trade-agent", "calls": []},
            ],
            "tools": [
                {
                    "id": "refund",
                    "action": "order:refund",
                    "risk": "critical",
                    "supported_agents": ["trade-agent"],
                }
            ],
        }
    )


@pytest.mark.parametrize("variant", VARIANTS)
def test_a_changed_as_tool_gives_inconclusive_not_pass(variant, monkeypatch):
    """Without the canary, finance-agent (calls: []) hid the route to refund: a false PASS."""
    supervisor, finance, _ = as_tool_desk()
    change_the_sdk(variant, monkeypatch, finance)
    found = discover([supervisor])
    source = SourceResult(
        source=SourceRef(kind="python", label="python:app:supervisor"),
        ok=True,
        tools=found.tools,
        graph=found.fragment,
    )
    registry = canary_registry()
    inventory = merge_inventory([source], registry=registry, registry_label="registry")
    graph = build_graph(registry, inventory, registry_label="registry")
    rule = NeverReachesRule(id="RULE-001", role="analyst", tool="refund")
    [row] = evaluate_rules(graph, [rule], inventory)
    assert (row.result, row.opaque_reached) == (RuleResult.INCONCLUSIVE, ("finance-agent",))


AS_TOOL_APP = '''
import os

from agents import Agent, FunctionTool, function_tool


@function_tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    raise RuntimeError("never called")


trade = Agent(name="trade-agent", tools=[execute_trade])
wrapper = trade.as_tool(tool_name="ask_trade_agent", tool_description="Ask the trade agent.")
if os.environ.get("LW_AS_TOOL_VARIANT") == "field removed":
    delattr(FunctionTool, "_is_agent_tool")
    for tool in (execute_trade, wrapper):
        vars(tool).pop("_is_agent_tool", None)
        vars(tool).pop("_agent_instance", None)
finance = Agent(name="finance-agent", tools=[wrapper])
'''


def test_the_python_source_reports_a_changed_as_tool(write, tmp_path, monkeypatch):
    write("desk.py", AS_TOOL_APP)
    source = PythonSource(PythonSourceConfig(target="desk:finance"), tmp_path)
    as_designed = source.read()
    assert as_designed.graph is not None
    assert node(as_designed.graph, "finance-agent").opaque is False
    monkeypatch.setenv("LW_AS_TOOL_VARIANT", "field removed")
    changed = source.read()
    assert changed.ok, changed.error
    assert [t.name for t in changed.tools] == ["ask_trade_agent"]
    assert changed.graph is not None
    owner = node(changed.graph, "finance-agent")
    assert (owner.opaque, owner.tools_hidden) == (True, True)
    assert any("changed how as_tool() is stored" in warning for warning in changed.warnings)


# ---- Pydantic AI toolsets that are resolved at run time ----


def runtime_warning(agent: str, kind: str) -> str:
    return (
        f"agent {agent!r} uses a toolset that is resolved at run time ({kind}); "
        "lockwalk cannot list its tools"
    )


def toolset(*functions: object) -> FunctionToolset:
    """A FunctionToolset of plain functions, which ty cannot match to its signature."""
    return FunctionToolset(list(functions))  # ty: ignore[invalid-argument-type]


def dynamic_agent() -> PydanticAgent:
    agent = PydanticAgent(name="dyn")

    @agent.toolset
    def pick_tools(ctx: RunContext[object]) -> AbstractToolset[object]:
        raise AssertionError("a toolset function is never called")

    return agent


RUNTIME_TOOLSETS = {
    "PrefixedToolset": lambda: PydanticAgent(
        name="dyn", toolsets=[PrefixedToolset(toolset(refund), prefix="p")]
    ),
    "FilteredToolset": lambda: PydanticAgent(
        name="dyn", toolsets=[FilteredToolset(toolset(refund), lambda ctx, tool: True)]
    ),
    "DynamicToolset": dynamic_agent,
}


@pytest.mark.parametrize("kind", list(RUNTIME_TOOLSETS))
def test_a_runtime_toolset_makes_the_agent_opaque_instead_of_failing(kind):
    agent = RUNTIME_TOOLSETS[kind]()
    # normalize leaves the toolset to the graph walk: no error, so the source does not fail.
    assert normalize_items([agent]) == ([], [])
    found = discover([agent])
    owner = node(found.fragment, "dyn")
    assert (owner.opaque, owner.tools_hidden) == (True, True)
    assert list(found.warnings) == [runtime_warning("dyn", kind)]
    assert found.tools == ()


def test_a_combined_toolset_is_opened_like_any_container():
    """A CombinedToolset lists its toolsets, so it is read; it is never an unnamed agent."""
    combined = CombinedToolset([toolset(refund), toolset(get_price)])
    assert not has_agent_shape(combined)
    agent = PydanticAgent(name="combined", toolsets=[combined])
    assert [t.name for t in normalize_items([agent])[0]] == ["refund", "get_price"]
    fragment, found_warnings = walk(agent)
    assert found_warnings == []
    assert node(fragment, "combined").opaque is False
    assert edge_set(fragment) == {
        ("combined", "refund", "uses_tool", "discovered"),
        ("combined", "get_price", "uses_tool", "discovered"),
    }


def test_a_runtime_toolset_inside_a_combined_toolset_is_found():
    inner = PrefixedToolset(toolset(refund), prefix="p")
    combined = CombinedToolset([toolset(get_price), inner])
    agent = PydanticAgent(name="combined", toolsets=[combined])
    assert [t.name for t in normalize_items([agent])[0]] == ["get_price"]
    fragment, found_warnings = walk(agent)
    owner = node(fragment, "combined")
    assert (owner.opaque, owner.tools_hidden) == (True, True)
    assert ("combined", "get_price", "uses_tool", "discovered") in edge_set(fragment)
    assert found_warnings == [runtime_warning("combined", "PrefixedToolset")]


def test_a_runtime_toolset_that_no_agent_holds_is_still_an_error():
    """Without an agent, nothing would stand for the hidden tools, so the source fails."""
    inner = PrefixedToolset(toolset(refund), prefix="p")
    message = "async get_tools() is not supported; point lockwalk at the tool list instead"
    assert normalize_items([inner]) == ([], [f"item 0: {message}"])
    assert normalize_items([CombinedToolset([inner])]) == ([], [f"item 0.0: {message}"])


class FakeMcpToolset(AbstractToolset):
    """Shaped like a Pydantic AI MCP toolset (fastmcp is not installed): an async
    get_tools(), and the MCP client verbs. Nothing here may be called."""

    @property
    def id(self) -> str | None:
        return "pricing"

    async def get_tools(self, ctx: object) -> dict:
        raise AssertionError("never called")

    async def call_tool(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("never called")

    async def list_tools(self) -> list[object]:
        raise AssertionError("never called")


def test_an_mcp_toolset_on_an_agent_is_a_boundary_not_an_error(no_network):
    agent = PydanticAgent(name="pricer", toolsets=[FakeMcpToolset()], tools=[get_price])  # ty: ignore[no-matching-overload]
    tools, errors = normalize_items([agent])
    assert ([t.name for t in tools], errors) == (["get_price"], [])
    fragment, found_warnings = walk(agent)
    assert found_warnings == []
    assert node(fragment, "mcp:pricing").kind is NodeKind.MCP_SERVER
    assert ("pricer", "mcp:pricing", "remote", "discovered") in edge_set(fragment)
    assert node(fragment, "pricer").opaque is False


PYDANTIC_RUNTIME_APP = '''
from pydantic_ai import Agent, RunContext
from pydantic_ai.toolsets import FunctionToolset, PrefixedToolset


def execute_trade(order: str) -> str:
    """Execute."""
    raise RuntimeError("never called")


prefixed = Agent(
    name="prefixed", toolsets=[PrefixedToolset(FunctionToolset([execute_trade]), prefix="p")]
)
dyn = Agent(name="dyn-agent")


@dyn.toolset
def pick_tools(ctx: RunContext[None]):
    return FunctionToolset([execute_trade])
'''


@pytest.mark.parametrize(
    ("target", "agent", "kind"),
    [("pyd:prefixed", "prefixed", "PrefixedToolset"), ("pyd:dyn", "dyn-agent", "DynamicToolset")],
)
def test_the_python_source_does_not_fail_on_a_runtime_toolset(write, tmp_path, target, agent, kind):
    write("pyd.py", PYDANTIC_RUNTIME_APP)
    result = PythonSource(PythonSourceConfig(target=target), tmp_path).read()
    assert result.ok, result.error
    assert result.graph is not None
    owner = node(result.graph, agent)
    assert (owner.opaque, owner.tools_hidden) == (True, True)
    assert runtime_warning(agent, kind) in result.warnings


# ---- an unreadable LangGraph route hides the tools behind it ----


def pick_tools(state: State) -> str:
    return "tools"


def routed_tool_graph() -> object:
    """desk: START -> router, and router -> tools (a ToolNode) through a path map."""
    graph = StateGraph(State)
    graph.add_node("router", step)
    graph.add_node("tools", ToolNode([read_portfolio]))
    graph.add_edge(START, "router")
    graph.add_conditional_edges("router", pick_tools, {"tools": "tools", "end": END})
    graph.add_edge("tools", END)
    return graph.compile(name="desk")


def test_an_unreadable_route_in_a_graph_with_a_tool_node_hides_tools():
    compiled = routed_tool_graph()
    fragment, _ = walk(compiled)
    assert ("desk:router", "read_portfolio", "uses_tool", "discovered") in edge_set(fragment)
    # A future LangGraph whose builder.branches is no longer a mapping.
    compiled.builder.branches = ("router", "opaque-structure")  # ty: ignore[unresolved-attribute]
    fragment, found_warnings = walk(compiled)
    assert found_warnings == [
        "agent 'desk': LangGraph branches is a builtins.tuple; lockwalk skipped it"
    ]
    assert ("desk:router", "read_portfolio", "uses_tool", "discovered") not in edge_set(fragment)
    for node_id in ("desk", "desk:router"):
        found = node(fragment, node_id)
        assert (found.opaque, found.tools_hidden) == (True, True), node_id


def test_an_unreadable_route_in_a_graph_without_a_tool_node_hides_no_tools():
    """Only agent edges can be lost, and `calls` can declare those."""
    compiled = small_graph()
    _bad_branch_entry(compiled.builder)
    fragment, _ = walk(compiled)
    assert [(n.id, n.opaque, n.tools_hidden) for n in fragment.nodes] == [
        ("g", True, False),
        ("g:a", True, False),
        ("g:b", False, False),
    ]


LANGGRAPH_ROUTE_APP = '''
import os
from typing import TypedDict

from langchain_core.tools import tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode


@tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    raise RuntimeError("never called")


class S(TypedDict):
    x: str


def router(state: S) -> S:
    return state


def pick(state: S) -> str:
    return "tools"


graph = StateGraph(S)
graph.add_node("router", router)
graph.add_node("tools", ToolNode([execute_trade]))
graph.add_edge(START, "router")
graph.add_conditional_edges("router", pick, {"tools": "tools", "end": END})
graph.add_edge("tools", END)
desk = graph.compile(name="desk")
if os.environ.get("LW_LANGGRAPH_ROUTES") == "changed":
    desk.builder.branches = ("router", "opaque-structure")
'''


def langgraph_route_rule(source: SourceResult) -> RuleResult:
    """The lgroute probe: desk and its router declare calls: [], and backoffice also holds
    execute_trade, so only the route into the ToolNode connects analysts to the tool."""
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "roles": ["analyst"],
            "agents": [
                {"id": "desk", "entry": True, "roles": ["analyst"], "calls": []},
                {"id": "desk:router", "calls": []},
                {"id": "backoffice", "calls": []},
            ],
            "tools": [
                {
                    "id": "execute_trade",
                    "action": "t:x",
                    "risk": "critical",
                    "supported_agents": ["backoffice"],
                }
            ],
        }
    )
    inventory = merge_inventory([source], registry=registry, registry_label="registry")
    graph = build_graph(registry, inventory, registry_label="registry")
    rule = NeverReachesRule(id="RULE-001", role="analyst", tool="execute_trade")
    [row] = evaluate_rules(graph, [rule], inventory)
    return row.result


def test_an_unreadable_route_to_a_tool_node_is_inconclusive_not_pass(write, tmp_path, monkeypatch):
    write("lg_desk.py", LANGGRAPH_ROUTE_APP)
    source = PythonSource(PythonSourceConfig(target="lg_desk:desk"), tmp_path)
    as_designed = source.read()
    assert as_designed.ok, as_designed.error
    assert langgraph_route_rule(as_designed) is RuleResult.FAIL
    monkeypatch.setenv("LW_LANGGRAPH_ROUTES", "changed")
    changed = source.read()
    assert changed.ok, changed.error
    assert langgraph_route_rule(changed) is RuleResult.INCONCLUSIVE


# ---- the as_tool() canary also reads the tool origin ----


def test_as_tool_records_its_origin_version_pin():
    _, _, wrapper = as_tool_desk()
    origin = inspect.getattr_static(wrapper, "_tool_origin")
    assert inspect.getattr_static(origin, "type") is ToolOriginType.AGENT_AS_TOOL
    assert ToolOriginType.AGENT_AS_TOOL == "agent_as_tool"
    assert inspect.getattr_static(openai_tool(get_price), "_tool_origin") is None


def drop_the_origin(monkeypatch: pytest.MonkeyPatch, *tools: object) -> None:
    """An SDK without _tool_origin: neither the class default nor the instance value."""
    monkeypatch.delattr(FunctionTool, "_tool_origin")
    for tool in tools:
        vars(tool).pop("_tool_origin", None)


def test_without_a_tool_origin_the_canary_works_as_before(monkeypatch):
    _, finance, wrapper = as_tool_desk()
    plain = openai_tool(get_price)
    drop_the_origin(monkeypatch, wrapper, plain, *finance.tools)
    kind, agent = agent_tool_check(wrapper)
    assert (kind, agent_name(agent)) == ("agent", "trade-agent")
    assert agent_tool_check(plain) == ("plain", None)
    # With neither signal left, a wrapper cannot be told from a plain tool.
    object.__setattr__(wrapper, "_is_agent_tool", False)
    object.__setattr__(wrapper, "_agent_instance", None)
    assert agent_tool_check(wrapper) == ("plain", None)


def test_a_wrapper_known_only_by_its_origin_is_still_followed():
    """The flag was not set, but the origin says as_tool() made it and the agent is there."""
    _, _, wrapper = as_tool_desk()
    object.__setattr__(wrapper, "_is_agent_tool", False)
    kind, agent = agent_tool_check(wrapper)
    assert (kind, agent_name(agent)) == ("agent", "trade-agent")


AS_TOOL_FLAG_APP = """
import os

from agents import Agent, function_tool


@function_tool
def execute_trade(order_id: str) -> str:
    \"\"\"Execute a trade.\"\"\"
    raise RuntimeError("never called")


@function_tool
def read_portfolio(pid: str) -> str:
    \"\"\"Read a portfolio.\"\"\"
    raise RuntimeError("never called")


trade = Agent(name="trade-agent", tools=[execute_trade])
wrapper = trade.as_tool(tool_name="ask_trade_agent", tool_description="Ask the trade agent.")
if os.environ.get("LW_AS_TOOL_VARIANT") == "flag unused":
    object.__setattr__(wrapper, "_is_agent_tool", False)
    object.__setattr__(wrapper, "_agent_instance", None)
finance = Agent(name="finance-agent", tools=[read_portfolio, wrapper])
supervisor = Agent(name="supervisor", handoffs=[finance])
trade_desk = Agent(name="trade-desk", handoffs=[trade])
ENTRIES = [supervisor, trade_desk]
"""


def flag_rule(source: SourceResult) -> RuleResult:
    """The astool2 probe: trade-desk also reaches trade-agent, so discovery finds a holder
    for execute_trade even when the wrapper is not followed. No agent declares calls."""
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "roles": ["analyst", "trader"],
            "agents": [
                {"id": "supervisor", "entry": True, "roles": ["analyst"]},
                {"id": "trade-desk", "entry": True, "roles": ["trader"]},
                {"id": "finance-agent"},
                {"id": "trade-agent"},
            ],
            "tools": [
                {"id": "read_portfolio", "action": "p:r", "risk": "high"},
                {"id": "execute_trade", "action": "t:x", "risk": "critical"},
                {"id": "ask_trade_agent", "action": "t:ask", "risk": "low"},
            ],
        }
    )
    inventory = merge_inventory([source], registry=registry, registry_label="registry")
    graph = build_graph(registry, inventory, registry_label="registry")
    rule = NeverReachesRule(id="RULE-001", role="analyst", tool="execute_trade")
    [row] = evaluate_rules(graph, [rule], inventory)
    return row.result


def test_a_wrapper_whose_flag_is_no_longer_set_is_inconclusive_not_pass(
    write, tmp_path, monkeypatch
):
    write("desk2.py", AS_TOOL_FLAG_APP)
    source = PythonSource(PythonSourceConfig(target="desk2:ENTRIES"), tmp_path)
    as_designed = source.read()
    assert as_designed.ok, as_designed.error
    assert flag_rule(as_designed) is RuleResult.FAIL
    monkeypatch.setenv("LW_AS_TOOL_VARIANT", "flag unused")
    changed = source.read()
    assert changed.ok, changed.error
    assert any("changed how as_tool() is stored" in warning for warning in changed.warnings)
    assert changed.graph is not None
    assert node(changed.graph, "finance-agent").tools_hidden is True
    assert flag_rule(changed) is RuleResult.INCONCLUSIVE


def test_wrapper_names_reach_the_agent_as_tool_edges():
    billing = OpenAIAgent(name="billing", instructions="x")
    first = OpenAIAgent(
        name="triage",
        tools=[
            billing.as_tool(tool_name="ask_billing", tool_description="a"),
            billing.as_tool(tool_name="ask_billing_again", tool_description="b"),
        ],
    )
    second = OpenAIAgent(
        name="support",
        tools=[billing.as_tool(tool_name="ask_billing", tool_description="c")],
    )
    fragment, _ = discover_graph([first, second])
    names = {
        (edge.from_id, edge.to_id): edge.wrapped_by
        for edge in fragment.edges
        if edge.kind.value == "agent_as_tool"
    }
    assert names == {
        ("triage", "billing"): ("ask_billing", "ask_billing_again"),
        ("support", "billing"): ("ask_billing",),
    }
