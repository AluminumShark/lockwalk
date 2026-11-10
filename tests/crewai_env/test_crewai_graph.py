"""CrewAI agents and crews in the agent graph, tested in their own environment.

Run with:

    UV_PROJECT_ENVIRONMENT=.venv-crewai uv run --no-default-groups --group crewai \
        pytest tests/crewai_env

Objects are only constructed; no crew is kicked off and no model is called. In the
normal dev environment CrewAI is missing and this module is skipped.
"""

from lockwalk_crewai_env import importorskip_crewai, otel_sdk_disabled  # noqa: F401
from lockwalk_graph_helpers import assert_closed, edge_set, node_ids

from lockwalk.inventory.agent_shapes import discover
from lockwalk.inventory.normalize import normalize_items
from lockwalk.models import NodeKind

importorskip_crewai("crewai")


def make_agent(role: str, **options):
    from crewai import Agent

    return Agent(role=role, goal="Help", backstory="Test agent", llm="gpt-4o-mini", **options)


def make_task(agent=None, **options):
    from crewai import Task

    return Task(description="Do it", expected_output="Done", agent=agent, **options)


def read_portfolio_tool():
    from crewai.tools import tool

    @tool("read_portfolio")
    def read_portfolio(portfolio_id: str) -> str:
        """Read a portfolio."""
        return portfolio_id

    return read_portfolio


def test_crewai_agent_has_a_role_and_no_name_version_pin():
    agent = make_agent("analyst")
    assert not hasattr(agent, "name")
    assert agent.role == "analyst"
    assert agent.allow_delegation is False


def test_crew_default_name_and_team_edges():
    from crewai import Crew

    analyst = make_agent("analyst", tools=[read_portfolio_tool()])
    writer = make_agent("writer")
    crew = Crew(agents=[analyst, writer], tasks=[make_task(analyst)])
    assert crew.name == "crew"
    found = discover([crew])
    assert_closed(found.fragment)
    assert found.warnings == ()
    assert node_ids(found.fragment) == ["crew", "analyst", "writer"]
    assert found.fragment.nodes[0].entry is True
    assert edge_set(found.fragment) == {
        ("crew", "analyst", "team", "discovered"),
        ("crew", "writer", "team", "discovered"),
        ("analyst", "read_portfolio", "uses_tool", "discovered"),
    }
    # The crew itself is not a tool; its agents' tools come from the graph walk.
    assert normalize_items([crew]) == ([], [])
    assert [t.name for t in found.tools] == ["read_portfolio"]


def test_hierarchical_manager_agent_reaches_every_agent():
    from crewai import Crew, Process

    analyst = make_agent("analyst")
    writer = make_agent("writer")
    manager = make_agent("manager", allow_delegation=True)
    crew = Crew(
        name="desk",
        agents=[analyst, writer],
        tasks=[make_task()],
        process=Process.hierarchical,
        manager_agent=manager,
    )
    assert manager not in crew.agents
    found = discover([crew])
    assert_closed(found.fragment)
    assert node_ids(found.fragment) == ["desk", "analyst", "writer", "manager"]
    assert edge_set(found.fragment) == {
        ("desk", "analyst", "team", "discovered"),
        ("desk", "writer", "team", "discovered"),
        ("desk", "manager", "team", "discovered"),
        ("manager", "analyst", "team", "discovered"),
        ("manager", "writer", "team", "discovered"),
    }


def test_manager_llm_creates_its_manager_only_at_kickoff():
    from crewai import Crew, Process

    crew = Crew(
        agents=[make_agent("analyst")],
        tasks=[make_task()],
        process=Process.hierarchical,
        manager_llm="gpt-4o-mini",
    )
    assert crew.manager_agent is None
    found = discover([crew])
    assert node_ids(found.fragment) == ["crew", "analyst"]


def test_allow_delegation_gives_inferred_calls_to_each_coworker():
    from crewai import Crew

    lead = make_agent("lead", allow_delegation=True)
    analyst = make_agent("analyst")
    writer = make_agent("writer")
    crew = Crew(agents=[lead, analyst, writer], tasks=[make_task(lead)])
    found = discover([crew])
    assert_closed(found.fragment)
    assert edge_set(found.fragment) == {
        ("crew", "lead", "team", "discovered"),
        ("crew", "analyst", "team", "discovered"),
        ("crew", "writer", "team", "discovered"),
        ("lead", "analyst", "calls", "inferred"),
        ("lead", "writer", "calls", "inferred"),
    }


def test_agent_mcps_are_boundary_nodes_without_secrets(no_network):
    from crewai.mcp import MCPServerHTTP, MCPServerStdio

    agent = make_agent(
        "ops",
        mcps=[
            MCPServerStdio(command="python", args=["-c", "pass", "--token", "argsecret"]),
            MCPServerHTTP(url="https://admin:s3cr3t@mcp.example.com/mcp?api_key=k3y"),
            "https://mcp.example.com/other?api_key=k3y2",
        ],
    )
    found = discover([agent])
    assert_closed(found.fragment)
    assert found.warnings == ()
    assert node_ids(found.fragment) == [
        "ops",
        "mcp:python",
        "mcp:https://mcp.example.com/mcp",
        "mcp:https://mcp.example.com/other",
    ]
    assert all(n.kind is NodeKind.MCP_SERVER for n in found.fragment.nodes[1:])
    assert found.fragment.nodes[2].remote_url == "https://mcp.example.com/mcp"
    # The stdio server has no name, so it is named after its command, never its arguments.
    dumped = found.fragment.model_dump_json() + "".join(found.warnings)
    for secret in ("argsecret", "s3cr3t", "k3y"):
        assert secret not in dumped


def test_task_tools_are_used_by_the_task_agent():
    from crewai import Crew

    analyst = make_agent("analyst")
    writer = make_agent("writer")
    task = make_task(analyst, tools=[read_portfolio_tool()])
    assert analyst.tools == []
    crew = Crew(agents=[analyst, writer], tasks=[task])
    found = discover([crew])
    assert_closed(found.fragment)
    assert found.warnings == ()
    # Tools given to a Task, not to its Agent, are still the agent's to use.
    assert edge_set(found.fragment) == {
        ("crew", "analyst", "team", "discovered"),
        ("crew", "writer", "team", "discovered"),
        ("analyst", "read_portfolio", "uses_tool", "discovered"),
    }
    assert not any(node.opaque for node in found.fragment.nodes)
    assert [t.name for t in found.tools] == ["read_portfolio"]


def test_task_tools_without_an_agent_make_the_crew_opaque():
    from crewai import Crew, Process

    analyst = make_agent("analyst")
    crew = Crew(
        name="desk",
        agents=[analyst],
        tasks=[make_task(tools=[read_portfolio_tool()])],
        process=Process.hierarchical,
        manager_agent=make_agent("manager"),
    )
    found = discover([crew])
    assert_closed(found.fragment)
    # The manager picks the agent at run time, so who reaches the tool is unknown.
    assert found.fragment.nodes[0].id == "desk"
    assert found.fragment.nodes[0].opaque is True
    assert found.warnings == (
        "agent 'desk': a task has tools but no agent, so the crew picks the agent at run "
        "time; lockwalk cannot tell which agent reaches those tools",
    )
    # Any agent of the crew, and the manager, may get the task, so all of them may reach
    # its tools; rules that start at a member see that.
    tool_edges = {e for e in edge_set(found.fragment) if e[1] == "read_portfolio"}
    assert tool_edges == {
        ("analyst", "read_portfolio", "uses_tool", "inferred"),
        ("manager", "read_portfolio", "uses_tool", "inferred"),
    }
    assert [t.name for t in found.tools] == ["read_portfolio"]
