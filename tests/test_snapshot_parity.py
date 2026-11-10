"""A snapshot replay gives the same findings as the live run it was saved from.

Each test sets up a project with a .lockwalk.toml, then runs the real CLI three times:
`coverage` (live), `discover --save-snapshot snap.json`, and `coverage --tools-json snap.json`,
which replaces every configured source with the snapshot. Rule results, role x tool rows,
opaque nodes, tools_hidden flags, and the exit code must be the same. The Python sources run
real framework objects in the worker subprocess; nothing calls a model or the network (the
unreachable MCP server is a free port on 127.0.0.1).
"""

import json
import shutil
from pathlib import Path

import pytest
from lockwalk_net_helpers import free_port
from typer.testing import CliRunner

from lockwalk import cli

runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[1]


def run(*args: str):
    return runner.invoke(cli.app, list(args))


def findings(directory: Path) -> tuple:
    report = json.loads((directory / "coverage.json").read_text(encoding="utf-8"))
    graph = report["agent_graph"]
    return (
        report["rules"],
        report["reachability"],
        graph["opaque"],
        {node["id"]: node["tools_hidden"] for node in graph["nodes"]},
        report["exit_code"],
    )


def assert_replay_matches_live(project: Path) -> tuple:
    """Run live, save a snapshot, replay it; return the live findings."""
    config = ["--config", str(project / ".lockwalk.toml")]
    live = run("coverage", *config, "--output-dir", "live")
    saved = run("discover", *config, "--save-snapshot", "snap.json")
    assert "Snapshot written to" in saved.stdout, saved.stdout
    replay = run("coverage", *config, "--tools-json", "snap.json", "--output-dir", "replay")
    assert "Inventory sources from the command line replace" in replay.stdout
    expected = findings(project / "live")
    assert findings(project / "replay") == expected
    assert (live.exit_code, replay.exit_code) == (expected[-1], expected[-1])
    return expected


def rule_results(found: tuple) -> list[tuple[str, str]]:
    return [(rule["id"], rule["result"]) for rule in found[0]]


@pytest.fixture
def project(tmp_path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


def write_project(project: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (project / name).write_text(text, encoding="utf-8")


PYTHON_CONFIG = """\
[lockwalk]
registry = "registry.yaml"
spec = "spec.yaml"
[[inventory.python]]
target = "{target}"
"""

TRADE_SPEC = """\
schema_version: '1'
scenario_suite: parity
cases:
  - {{id: C1, actor: a, role: analyst, agent: {agent}, tool: execute_trade, action: t:x,
     resource_fixture: x, expect: deny}}
never_reaches:
  - {{id: RULE-001, role: analyst, tool: execute_trade}}
"""


# ---- repro A: an agent whose tools come from a factory stays opaque ----

AGNO_APP = '''
from agno.agent import Agent


def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    raise RuntimeError("never called")


def trader_tools():
    raise RuntimeError("a tools factory is never called")


desk = Agent(name="desk", tools=trader_tools)
backoffice = Agent(name="backoffice", tools=[execute_trade])
ROOT = [desk, backoffice]
'''

AGNO_REGISTRY = """\
schema_version: '1'
roles: [analyst]
agents:
  - {id: desk, entry: true, roles: [analyst], delegation_mode: user, calls: []}
  - {id: backoffice, delegation_mode: agent, calls: []}
tools:
  - {id: execute_trade, action: t:x, risk: critical, supported_agents: [backoffice]}
"""


def test_an_agent_with_a_tools_factory_stays_opaque_on_replay(project):
    write_project(
        project,
        {
            "app.py": AGNO_APP,
            "registry.yaml": AGNO_REGISTRY,
            "spec.yaml": TRADE_SPEC.format(agent="desk"),
            ".lockwalk.toml": PYTHON_CONFIG.format(target="app.py:ROOT"),
        },
    )
    found = assert_replay_matches_live(project)
    assert rule_results(found) == [("RULE-001", "INCONCLUSIVE")]
    assert found[2] == ["desk"]
    assert found[3]["desk"] is True


# ---- repro B: an optional source that could not be read stays an opaque node ----


def test_an_unreadable_optional_source_stays_opaque_on_replay(project):
    write_project(
        project,
        {
            "registry.yaml": AGNO_REGISTRY,
            "spec.yaml": TRADE_SPEC.format(agent="desk"),
            ".lockwalk.toml": (
                '[lockwalk]\nregistry = "registry.yaml"\nspec = "spec.yaml"\n'
                '[[inventory.mcp]]\nname = "pricing"\n'
                f'target = "http://127.0.0.1:{free_port()}/mcp"\n'
                'optional = true\nagents = ["desk"]\ntimeout_s = 5\n'
            ),
        },
    )
    found = assert_replay_matches_live(project)
    assert rule_results(found) == [("RULE-001", "INCONCLUSIVE")]
    assert found[2] == ["mcp:pricing"]


# ---- the lgroute shape: a LangGraph route that cannot be read hides tools ----

LANGGRAPH_APP = '''
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

LANGGRAPH_REGISTRY = """\
schema_version: '1'
roles: [analyst]
agents:
  - {id: desk, entry: true, roles: [analyst], calls: []}
  - {id: "desk:router", calls: []}
  - {id: backoffice, calls: []}
tools:
  - {id: execute_trade, action: t:x, risk: critical, supported_agents: [backoffice]}
"""


@pytest.mark.parametrize(("routes", "result"), [("as built", "FAIL"), ("changed", "INCONCLUSIVE")])
def test_a_langgraph_graph_replays_with_its_hidden_tools(project, monkeypatch, routes, result):
    monkeypatch.setenv("LW_LANGGRAPH_ROUTES", routes)
    write_project(
        project,
        {
            "app.py": LANGGRAPH_APP,
            "registry.yaml": LANGGRAPH_REGISTRY,
            "spec.yaml": TRADE_SPEC.format(agent="desk"),
            ".lockwalk.toml": PYTHON_CONFIG.format(target="app.py:desk"),
        },
    )
    found = assert_replay_matches_live(project)
    assert rule_results(found) == [("RULE-001", result)]
    assert found[3]["desk:router"] is (routes == "changed")


# ---- the astool2 shape: an as_tool() wrapper whose flag is no longer set ----

AS_TOOL_APP = '''
import os

from agents import Agent, function_tool


@function_tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    raise RuntimeError("never called")


@function_tool
def read_portfolio(pid: str) -> str:
    """Read a portfolio."""
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
'''

AS_TOOL_REGISTRY = """\
schema_version: '1'
roles: [analyst, trader]
agents:
  - {id: supervisor, entry: true, roles: [analyst], delegation_mode: user}
  - {id: trade-desk, entry: true, roles: [trader], delegation_mode: user}
  - {id: finance-agent, delegation_mode: user}
  - {id: trade-agent, delegation_mode: agent}
tools:
  - {id: read_portfolio, action: p:r, risk: high}
  - {id: execute_trade, action: t:x, risk: critical}
  - {id: ask_trade_agent, action: t:ask, risk: low}
"""


@pytest.mark.parametrize(
    ("variant", "result"), [("as built", "FAIL"), ("flag unused", "INCONCLUSIVE")]
)
def test_an_as_tool_desk_replays_with_its_canary(project, monkeypatch, variant, result):
    monkeypatch.setenv("LW_AS_TOOL_VARIANT", variant)
    write_project(
        project,
        {
            "app.py": AS_TOOL_APP,
            "registry.yaml": AS_TOOL_REGISTRY,
            "spec.yaml": TRADE_SPEC.format(agent="supervisor"),
            ".lockwalk.toml": PYTHON_CONFIG.format(target="app.py:ENTRIES"),
        },
    )
    found = assert_replay_matches_live(project)
    assert rule_results(found) == [("RULE-001", result)]


# ---- the multi-agent example ----


def test_the_multi_agent_example_replays_the_same(project):
    shutil.copytree(
        REPO_ROOT / "examples" / "multi_agent",
        project,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(".lockwalk", "__pycache__"),
    )
    found = assert_replay_matches_live(project)
    assert rule_results(found) == [
        ("RULE-001", "FAIL"),
        ("RULE-002", "INCONCLUSIVE"),
        ("RULE-003", "PASS"),
    ]
    assert found[2] == ["market-oracle"]


# ---- the snapmix shape: one source with agents, one without ----

SNAPMIX_REGISTRY = """\
schema_version: '1'
roles: [analyst]
agents:
  - {id: finance-agent, entry: true, roles: [analyst], delegation_mode: user, calls: []}
  - {id: ops-agent, delegation_mode: agent, calls: []}
tools:
  - {id: get_stock_price, action: market:read, risk: low}
  - {id: read_portfolio, action: portfolio:read, risk: high}
  - {id: execute_trade, action: t:x, risk: critical}
  - {id: delete_portfolio, action: portfolio:delete, risk: critical}
  - {id: stub, action: ops:stub, risk: low}
"""


def test_mixed_sources_replay_the_same(project):
    shutil.copy(REPO_ROOT / "examples" / "finance_agent" / "mcp_server.py", project)
    write_project(
        project,
        {
            "ops.json": '[{"name": "stub"}]',
            "registry.yaml": SNAPMIX_REGISTRY,
            "spec.yaml": TRADE_SPEC.format(agent="finance-agent"),
            ".lockwalk.toml": (
                '[lockwalk]\nregistry = "registry.yaml"\nspec = "spec.yaml"\n'
                '[[inventory.json]]\npath = "ops.json"\nagents = ["ops-agent"]\n'
                '[[inventory.mcp]]\nname = "finance-tools"\ntarget = "stdio://mcp_server.py"\n'
            ),
        },
    )
    found = assert_replay_matches_live(project)
    assert rule_results(found) == [("RULE-001", "INCONCLUSIVE")]


REPLAY_WITH_AGENTS = """[lockwalk]
registry = "registry.yaml"
spec = "spec.yaml"
[[inventory.json]]
path = "snap.json"
agents = ["ops-agent"]
"""


def test_a_snapshot_cannot_take_agents_from_its_json_source(project):
    """With agents on the JSON source, ops-agent got every saved tool: a false PASS."""
    test_mixed_sources_replay_the_same(project)
    (project / "replay.toml").write_text(REPLAY_WITH_AGENTS, encoding="utf-8")
    result = run("coverage", "--config", str(project / "replay.toml"), "--output-dir", "agents")
    assert result.exit_code == 2, result.stdout
    assert (
        "  - json:snap.json: a snapshot keeps each source's agents; remove 'agents' from this "
        "[[inventory.json]]"
    ) in result.stdout.splitlines()
    rules = json.loads((project / "agents" / "coverage.json").read_text(encoding="utf-8"))["rules"]
    assert [(rule["id"], rule["result"]) for rule in rules] == [("RULE-001", "INCONCLUSIVE")]
