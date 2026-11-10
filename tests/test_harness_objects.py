"""Finding agent and tool objects for the harness."""

from harness_apps import object_agents as app

from lockwalk.harness.objects import find
from lockwalk.inventory.normalize import normalize_items


def test_openai_agents_handoff_and_as_tool():
    found = find([app.supervisor])
    assert set(found.agents) == {"supervisor", "finance-agent", "trade-agent"}
    assert found.agents["trade-agent"] is app.trade_agent
    assert set(found.frameworks.values()) == {"openai_agents"}
    assert set(found.tools) == {"read_portfolio", "execute_trade"}
    assert found.tools["execute_trade"] is app.execute_trade
    wrapper_name, wrapper = found.agent_tools["finance-agent"]["trade-agent"]
    assert wrapper_name == "ask_trade_agent"
    assert getattr(wrapper, "name", None) == "ask_trade_agent"
    assert "supervisor" not in found.agent_tools
    assert found.warnings == ()


def test_pydantic_agent():
    found = find([app.pydantic_agent])
    assert found.frameworks == {"research-agent": "pydantic_ai"}
    assert found.agents["research-agent"] is app.pydantic_agent
    assert "search_notes" in found.tools


def test_langgraph_react_agent_and_tool_node_tools():
    found = find([app.react])
    assert found.frameworks["lg-agent"] == "langgraph"
    assert found.agents["lg-agent"] is app.react
    assert found.tools["lookup_account"] is app.lookup_account


def test_react_agent_as_a_node_of_a_graph():
    found = find([app.parent_graph])
    assert found.frameworks["desk"] == "langgraph"
    assert "desk:worker" in found.agents
    assert found.agents["desk:worker"] is app.react
    assert found.frameworks["desk:worker"] == "langgraph"
    assert "lookup_account" in found.tools


def test_plain_tool_list_has_tools_and_no_agents():
    found = find([app.execute_trade, app.lookup_account])
    assert found.agents == {}
    assert set(found.tools) == {"execute_trade", "lookup_account"}


def test_hostile_values_do_not_raise():
    class Hostile:
        @property
        def tools(self):
            raise RuntimeError("boom")

    found = find([Hostile(), 3, None])
    assert found.agents == {}


def test_collector_default_changes_nothing():
    assert normalize_items([app.supervisor]) == normalize_items([app.supervisor], objects=None)


def test_user_package_named_agents_is_not_openai(monkeypatch):
    import sys
    import types

    from lockwalk.harness.objects import _framework_of

    fake = types.ModuleType("agents")

    class Agent:
        pass

    Agent.__module__ = "agents.agent"
    vars(fake)["Agent"] = Agent
    monkeypatch.setitem(sys.modules, "agents", fake)
    assert _framework_of(Agent()) == "other"

    class Own:
        pass

    Own.__module__ = "myapp.agents"
    vars(fake)["Agent"] = Own
    vars(fake)["function_tool"] = object
    vars(fake)["Runner"] = object
    assert _framework_of(Own()) == "other"


def test_duplicate_agent_names_never_get_the_wrong_wrapper():
    from agents import Agent

    first = Agent(name="dup", instructions="a")
    second = Agent(name="dup", instructions="b")
    boss = Agent(
        name="boss",
        handoffs=[first],
        tools=[second.as_tool(tool_name="ask_dup", tool_description="d")],
    )
    found = find([boss])
    recorded = found.agents["dup"]
    wrapper = found.agent_tools.get("boss", {}).get("dup")
    if recorded is second:
        assert wrapper is not None and wrapper[0] == "ask_dup"
    else:
        assert wrapper is None
