import pytest

from lockwalk.errors import StructuralError
from lockwalk.models import Risk
from lockwalk.registry import load_registry
from lockwalk.urls import redact_url

GOOD = """
schema_version: '1'
agents:
  - id: research-agent
  - id: finance-agent
tools:
  - id: get_stock_price
    action: market:read
    risk: low
    resource_type: stock_symbol
    supported_agents: [research-agent, finance-agent]
  - id: execute_trade
    action: trade:execute
    risk: critical
"""


def problems_of(write, text: str) -> tuple[str, ...]:
    path = write("registry.yaml", text)
    with pytest.raises(StructuralError) as info:
        load_registry(path)
    return info.value.problems


def test_loads_a_valid_registry(write):
    registry = load_registry(write("registry.yaml", GOOD))
    assert registry.agent_ids == ("research-agent", "finance-agent")
    tool = registry.tool("execute_trade")
    assert tool is not None
    assert tool.risk is Risk.CRITICAL
    assert tool.supported_agents == ()
    assert tool.resource_type is None
    assert registry.tool("missing") is None


def test_integer_schema_version_is_accepted(write):
    registry = load_registry(write("registry.yaml", GOOD.replace("'1'", "1")))
    assert registry.schema_version == "1"


def test_wrong_schema_version_is_rejected(write):
    problems = problems_of(write, GOOD.replace("'1'", "'2'"))
    assert problems[0].startswith("schema_version: Input should be '1'")


def test_misspelled_field_is_reported_with_its_path(write):
    problems = problems_of(write, GOOD.replace("risk: critical", "risks: critical"))
    assert set(problems) == {
        "tools[1].risk: Field required",
        "tools[1].risks: Extra inputs are not permitted",
    }


def test_risk_must_be_a_known_value(write):
    [problem] = problems_of(write, GOOD.replace("risk: low", "risk: severe"))
    assert problem.startswith("tools[0].risk: Input should be")
    assert "'unknown'" in problem


def test_explicit_unknown_risk_is_allowed(write):
    registry = load_registry(write("registry.yaml", GOOD.replace("risk: low", "risk: unknown")))
    tool = registry.tool("get_stock_price")
    assert tool is not None
    assert tool.risk is Risk.UNKNOWN


def test_missing_risk_is_an_error(write):
    assert problems_of(write, GOOD.replace("    risk: low\n", "")) == (
        "tools[0].risk: Field required",
    )


def test_duplicate_tool_id(write):
    text = GOOD + "  - id: get_stock_price\n    action: market:read\n    risk: low\n"
    assert problems_of(write, text) == ("tools[2].id: duplicate tool id 'get_stock_price'",)


def test_duplicate_agent_id(write):
    text = GOOD.replace("  - id: finance-agent\n", "  - id: finance-agent\n  - id: finance-agent\n")
    assert problems_of(write, text) == ("agents[2].id: duplicate agent id 'finance-agent'",)


def test_supported_agents_must_be_declared(write):
    text = GOOD.replace("[research-agent, finance-agent]", "[research-agent, ghost-agent]")
    assert problems_of(write, text) == (
        "tools[0].supported_agents[1]: agent 'ghost-agent' is not declared under agents",
    )


def test_top_level_must_be_a_mapping(write):
    [problem] = problems_of(write, "- a\n- b\n")
    assert "must contain a mapping" in problem


def test_empty_lists_are_allowed(write):
    registry = load_registry(write("registry.yaml", "schema_version: '1'\nagents: []\ntools: []\n"))
    assert registry.tools == ()


def test_empty_file(write):
    assert problems_of(write, "") == ("the file is empty",)


@pytest.mark.parametrize("value", ["''", "'  '", "' market:read'", "'market:read '"])
def test_blank_or_padded_action_is_rejected(write, value):
    [problem] = problems_of(write, GOOD.replace("action: market:read", f"action: {value}"))
    assert problem.startswith("tools[0].action:")
    assert "must not be empty" in problem


def test_empty_resource_type_is_rejected(write):
    [problem] = problems_of(write, GOOD.replace("stock_symbol", "''"))
    assert problem.startswith("tools[0].resource_type:")


def test_unknown_agent_field(write):
    text = GOOD.replace("  - id: research-agent\n", "  - id: research-agent\n    role: x\n")
    assert problems_of(write, text) == ("agents[0].role: Extra inputs are not permitted",)


def test_duplicate_yaml_key_is_reported(write):
    text = GOOD.replace("    risk: low\n", "    risk: low\n    risk: high\n")
    [problem] = problems_of(write, text)
    assert "duplicate key 'risk'" in problem


def test_duplicate_supported_agent(write):
    text = GOOD.replace("[research-agent, finance-agent]", "[research-agent, research-agent]")
    assert problems_of(write, text) == (
        "tools[0].supported_agents[1]: duplicate agent 'research-agent'",
    )


def test_several_problems_are_reported_together(write):
    text = GOOD + "  - id: get_stock_price\n    action: a:b\n    risk: low\n"
    text += "    supported_agents: [ghost-agent]\n"
    assert problems_of(write, text) == (
        "tools[2].id: duplicate tool id 'get_stock_price'",
        "tools[2].supported_agents[0]: agent 'ghost-agent' is not declared under agents",
    )


def test_missing_tools_key(write):
    assert problems_of(write, "schema_version: '1'\nagents: []\n") == ("tools: Field required",)


GRAPH = """\
schema_version: '1'
roles: [analyst, trader]
agents:
  - id: supervisor
    entry: true
    roles: [analyst]
    calls: [finance-agent]
    delegation_mode: user
  - id: finance-agent
    delegation_mode: agent
  - id: oracle
    remote: https://user:pw@oracle.example/a2a?k=1
    calls: []
tools:
  - id: execute_trade
    action: trade:execute
    risk: critical
    supported_agents: [finance-agent]
delegation_tools:
  - id: ask_oracle
    agent: oracle
    supported_agents: [finance-agent]
"""


def test_graph_fields_load(write):
    registry = load_registry(write("registry.yaml", GRAPH))
    supervisor, finance, oracle = registry.agents
    assert registry.roles == ("analyst", "trader")
    assert (supervisor.entry, supervisor.roles, supervisor.calls) == (
        True,
        ("analyst",),
        ("finance-agent",),
    )
    assert finance.roles is None and finance.calls is None
    assert finance.delegation_mode == "agent"
    assert oracle.calls == ()
    assert registry.delegation_tools[0].agent == "oracle"
    assert registry.delegation_tool("ask_oracle") is registry.delegation_tools[0]


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        (
            "roles: [analyst, trader]\n",
            "",
            "agents[0].roles: declare the top-level 'roles' list first",
        ),
        (
            "    roles: [analyst]\n",
            "    roles: [analyts]\n",
            "agents[0].roles[0]: role 'analyts' is not in the top-level roles list",
        ),
        (
            "    entry: true\n",
            "",
            "agents[0].roles: only entry agents (entry: true) can list roles",
        ),
        (
            "    calls: [finance-agent]\n",
            "    calls: [ghost]\n",
            "agents[0].calls[0]: agent 'ghost' is not declared under agents",
        ),
        (
            "    agent: oracle\n",
            "    agent: ghost\n",
            "delegation_tools[0].agent: agent 'ghost' is not declared under agents",
        ),
        (
            "  - id: ask_oracle\n",
            "  - id: execute_trade\n",
            "delegation_tools[0].id: 'execute_trade' is already used by a tool",
        ),
        (
            "    roles: [analyst]\n",
            "    roles: [analyst, analyst]\n",
            "agents[0].roles[1]: duplicate role 'analyst'",
        ),
        (
            "    agent: oracle\n    supported_agents: [finance-agent]\n",
            "    agent: oracle\n  - id: ask_oracle\n    agent: oracle\n",
            "delegation_tools[1].id: duplicate tool id 'ask_oracle'",
        ),
        (
            "    agent: oracle\n    supported_agents: [finance-agent]\n",
            "    agent: oracle\n    supported_agents: [ghost]\n",
            "delegation_tools[0].supported_agents[0]: agent 'ghost' is not declared under agents",
        ),
        (
            "roles: [analyst, trader]\n",
            "roles: [analyst, analyst]\n",
            "roles[1]: duplicate role 'analyst'",
        ),
    ],
)
def test_graph_reference_problems(write, old, new, expected):
    assert old in GRAPH
    assert expected in problems_of(write, GRAPH.replace(old, new))


def test_remote_must_be_an_http_url(write):
    text = GRAPH.replace("https://user:pw@oracle.example/a2a?k=1", "ftp://oracle")
    [problem] = problems_of(write, text)
    assert problem.startswith("agents[2].remote:")


def test_missing_top_level_roles_is_the_only_problem(write):
    text = GRAPH.replace("roles: [analyst, trader]\n", "")
    assert problems_of(write, text) == (
        "agents[0].roles: declare the top-level 'roles' list first",
    )


def test_entry_must_be_a_real_boolean(write):
    text = GRAPH.replace("entry: true", "entry: 'true'")
    [problem] = problems_of(write, text)
    assert problem.startswith("agents[0].entry:")


BAD_URLS = (
    "https://user:s\uff20cret@host/a2a",
    "https://user:pw@/x",
    "https://h/a b",
    "https://svc:abc/def@host/x",
    "https://u:1234/tok@host/x",
    "https://u:pa?ss@host/x",
    "https://host:99999/x",
    "https://host:abc/x",
    "https://host/a\u200bb",
)
# These fail the shape check, but redact_url can still describe them.
SHAPE_ONLY = (
    "https://user:pw@/x",
    "https://h/a b",
    "https://host:99999/x",
    "https://host:abc/x",
    "https://host/a\u200bb",
)
LEAKS = ("cret", "user:", "pw@", "def", "tok", "pa?ss", "svc:", "u:")


def test_remote_errors_never_leak_credentials(write):
    for bad in BAD_URLS:
        text = GRAPH.replace("https://user:pw@oracle.example/a2a?k=1", bad)
        problems = problems_of(write, text)
        assert problems and problems[0].startswith("agents[2].remote:")
        assert not any(leak in p for p in problems for leak in LEAKS)
        assert redact_url(bad) == "<invalid URL>" or bad in SHAPE_ONLY
