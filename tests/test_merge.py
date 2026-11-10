import time

import pytest

from lockwalk.config import JsonSourceConfig, McpSourceConfig, PythonSourceConfig
from lockwalk.inventory.collect import build_inventory, make_source
from lockwalk.inventory.jsonfile import JsonSource
from lockwalk.inventory.mcp import McpSource
from lockwalk.inventory.merge import merge_inventory
from lockwalk.inventory.python import PythonSource
from lockwalk.models import (
    Drift,
    Inventory,
    InventoryTool,
    Risk,
    SourceKind,
    SourceRef,
    SourceResult,
    ToolDescriptor,
)
from lockwalk.registry import Registry, load_registry
from lockwalk.settings import SourceEntry

REGISTRY = Registry.model_validate(
    {
        "schema_version": "1",
        "agents": [{"id": "research-agent"}, {"id": "finance-agent"}],
        "tools": [
            {
                "id": "get_stock_price",
                "action": "market:read",
                "risk": "low",
                "supported_agents": ["research-agent"],
            },
            {"id": "execute_trade", "action": "trade:execute", "risk": "critical"},
        ],
    }
)
LABEL = "registry:registry.yaml"


def source(
    kind: SourceKind,
    label: str,
    *names: str,
    ok: bool = True,
    error: str | None = None,
    agents: tuple[str, ...] = (),
    hints: dict[str, dict[str, bool]] | None = None,
) -> SourceResult:
    tools = tuple(ToolDescriptor(name=name, hints=(hints or {}).get(name, {})) for name in names)
    return SourceResult(
        source=SourceRef(kind=kind, label=label), ok=ok, error=error, agents=agents, tools=tools
    )


def tool_of(inventory: Inventory, tool_id: str) -> InventoryTool:
    tool = inventory.tool(tool_id)
    assert tool is not None, f"{tool_id} missing"
    return tool


def test_registry_alone_has_no_drift():
    inventory = merge_inventory([], registry=REGISTRY, registry_label=LABEL)
    assert inventory.drift is None
    assert [t.id for t in inventory.tools] == ["get_stock_price", "execute_trade"]
    assert tool_of(inventory, "execute_trade").risk is Risk.CRITICAL
    assert [s.source.label for s in inventory.sources] == [LABEL]
    assert inventory.agents == ("research-agent", "finance-agent")
    assert inventory.errors == ()


def test_tool_in_registry_and_mcp_is_merged():
    mcp = source(
        "mcp",
        "mcp:finance-tools",
        "get_stock_price",
        "execute_trade",
        hints={"execute_trade": {"destructiveHint": True}},
    )
    inventory = merge_inventory([mcp], registry=REGISTRY, registry_label=LABEL)
    trade = tool_of(inventory, "execute_trade")
    assert trade.sources == (LABEL, "mcp:finance-tools")
    assert trade.risk is Risk.CRITICAL
    assert trade.action == "trade:execute"
    assert trade.hints == {"destructiveHint": True}
    assert inventory.drift == Drift(discovered_only=(), registry_only=(), complete=True)
    assert inventory.warnings == ()


def test_discovered_only_tool_has_unknown_risk():
    mcp = source("mcp", "mcp:x", "get_stock_price", "execute_trade", "delete_portfolio")
    inventory = merge_inventory([mcp], registry=REGISTRY, registry_label=LABEL)
    tool = tool_of(inventory, "delete_portfolio")
    assert tool.risk is Risk.UNKNOWN
    assert tool.action is None
    assert tool.sources == ("mcp:x",)
    assert [t.id for t in inventory.tools] == [
        "get_stock_price",
        "execute_trade",
        "delete_portfolio",
    ]
    assert inventory.drift is not None
    assert inventory.drift.discovered_only == ("delete_portfolio",)
    assert inventory.warnings == (
        "tool 'delete_portfolio' was reported by a discovery source but is not declared "
        "in the registry, so its risk is unknown",
    )


def test_registry_only_tool_is_reported_as_drift():
    inventory = merge_inventory(
        [source("json", "json:t.json", "get_stock_price")], registry=REGISTRY, registry_label=LABEL
    )
    assert inventory.drift is not None
    assert inventory.drift.registry_only == ("execute_trade",)
    assert inventory.warnings == (
        "tool 'execute_trade' is declared in the registry but no discovery source reported it",
    )


def test_failed_source_is_an_error_and_makes_drift_incomplete():
    down = source("mcp", "mcp:down", ok=False, error="timed out after 10s")
    inventory = merge_inventory([down], registry=REGISTRY, registry_label=LABEL)
    assert inventory.errors == ("mcp:down: timed out after 10s",)
    assert inventory.drift is not None
    assert inventory.drift.complete is False


def test_same_tool_from_two_discovery_sources_is_a_conflict():
    inventory = merge_inventory(
        [source("mcp", "mcp:a", "lookup"), source("python", "python:m:T", "lookup")]
    )
    assert inventory.errors == (
        "tool 'lookup' is reported by more than one discovery source (mcp:a, python:m:T); "
        "rename it or remove one of the sources",
    )
    assert [t.id for t in inventory.tools] == ["lookup"]


def described(
    kind: SourceKind,
    label: str,
    *,
    description: str | None = "Look something up.",
    hints: dict[str, bool] | None = None,
    agents: tuple[str, ...] = (),
) -> SourceResult:
    """A source that reports one tool, 'lookup', with this description and these hints."""
    tool = ToolDescriptor(name="lookup", description=description, hints=hints or {})
    return SourceResult(
        source=SourceRef(kind=kind, label=label), ok=True, tools=(tool,), agents=agents
    )


def test_identical_tools_from_overlapping_python_walks_are_merged():
    """Several entry agents of one app share sub-agents, so their walks report the same tools."""
    first = described("python", "python:app:supervisor", agents=("research-agent",))
    second = described("python", "python:app:trade_desk", agents=("finance-agent",))
    inventory = merge_inventory([first, second], registry=REGISTRY, registry_label=LABEL)
    assert inventory.errors == ()
    lookup = tool_of(inventory, "lookup")
    assert lookup.sources == ("python:app:supervisor", "python:app:trade_desk")
    assert lookup.supported_agents == ("research-agent", "finance-agent")
    assert lookup.description == "Look something up."
    assert [t.id for t in inventory.tools] == ["get_stock_price", "execute_trade", "lookup"]
    assert inventory.drift is not None
    assert inventory.drift.discovered_only == ("lookup",)
    assert [w for w in inventory.warnings if "'lookup'" in w] == [
        "tool 'lookup' was reported by a discovery source but is not declared "
        "in the registry, so its risk is unknown"
    ]


def test_a_registry_tool_from_overlapping_python_walks_keeps_every_source():
    walks = [
        described("python", f"python:app:{name}", agents=("finance-agent",))
        for name in ("a", "b", "c")
    ]
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [{"id": "research-agent"}, {"id": "finance-agent"}],
            "tools": [
                {
                    "id": "lookup",
                    "action": "data:read",
                    "risk": "high",
                    "supported_agents": ["research-agent"],
                }
            ],
        }
    )
    inventory = merge_inventory(walks, registry=registry, registry_label=LABEL)
    assert inventory.errors == ()
    lookup = tool_of(inventory, "lookup")
    assert lookup.sources == (LABEL, "python:app:a", "python:app:b", "python:app:c")
    assert lookup.supported_agents == ("research-agent", "finance-agent")
    assert lookup.risk is Risk.HIGH


DIFFERENT = (
    "tool 'lookup' is reported by more than one discovery source with different "
    "descriptions ({labels}); rename it or remove one of the sources"
)
SAME = (
    "tool 'lookup' is reported by more than one discovery source ({labels}); "
    "rename it or remove one of the sources"
)


@pytest.mark.parametrize(
    "second",
    [
        described("python", "python:b:T", description="Look something else up."),
        described("python", "python:b:T", description=None),
        described("python", "python:b:T", hints={"readOnlyHint": True}),
    ],
    ids=["description", "no description", "hints"],
)
def test_python_walks_that_describe_a_tool_differently_conflict(second):
    inventory = merge_inventory([described("python", "python:a:T"), second])
    assert inventory.errors == (DIFFERENT.format(labels="python:a:T, python:b:T"),)


@pytest.mark.parametrize(
    ("sources", "message"),
    [
        ([described("mcp", "mcp:a"), described("python", "python:m:T")], SAME),
        ([described("python", "python:m:T"), described("json", "json:t.json")], SAME),
        ([described("mcp", "mcp:a"), described("mcp", "mcp:b")], SAME),
        (
            [described("mcp", "mcp:a"), described("python", "python:m:T", description="Other.")],
            DIFFERENT,
        ),
    ],
    ids=["mcp and python", "python and json", "two mcp", "mcp and python, different"],
)
def test_identical_tools_conflict_when_a_source_is_not_python(sources, message):
    """Two servers can describe two different tools the same way, so only Python walks merge."""
    inventory = merge_inventory(sources)
    labels = ", ".join(sorted(result.source.label for result in sources))
    assert inventory.errors == (message.format(labels=labels),)


def test_source_agents_are_added_and_checked():
    known = source("python", "python:m:T", "get_stock_price", agents=("finance-agent",))
    unknown = source("json", "json:t.json", "extra_tool", agents=("ghost-agent",))
    inventory = merge_inventory([known, unknown], registry=REGISTRY, registry_label=LABEL)
    assert tool_of(inventory, "get_stock_price").supported_agents == (
        "research-agent",
        "finance-agent",
    )
    assert (
        "json:t.json: agent 'ghost-agent' in 'agents' is not declared in the registry"
        in inventory.errors
    )


def test_without_a_registry_every_tool_is_discovered():
    inventory = merge_inventory([source("mcp", "mcp:x", "a", "b")])
    assert inventory.agents == ()
    assert inventory.drift is None
    assert [t.risk for t in inventory.tools] == [Risk.UNKNOWN, Risk.UNKNOWN]
    assert inventory.errors == ()


def test_make_source_picks_the_matching_class(tmp_path):
    assert isinstance(
        make_source(SourceEntry(McpSourceConfig(target="http://h/mcp"), tmp_path)), McpSource
    )
    assert isinstance(
        make_source(SourceEntry(PythonSourceConfig(target="m:T"), tmp_path)), PythonSource
    )
    assert isinstance(
        make_source(SourceEntry(JsonSourceConfig(path="t.json"), tmp_path)), JsonSource
    )


def test_build_inventory_reads_sources_and_labels_the_registry(write, tmp_path):
    registry_path = write(
        "registry.yaml",
        """
        schema_version: '1'
        agents: []
        tools:
          - id: get_stock_price
            action: market:read
            risk: low
        """,
    )
    write("tools.json", '[{"name": "get_stock_price"}, {"name": "delete_portfolio"}]')
    entries = (SourceEntry(config=JsonSourceConfig(path="tools.json"), base_dir=tmp_path),)
    inventory = build_inventory(
        entries, registry=load_registry(registry_path), registry_path=registry_path
    )
    assert [s.source.label for s in inventory.sources] == [LABEL, "json:tools.json"]
    assert [t.id for t in inventory.tools] == ["get_stock_price", "delete_portfolio"]


def test_duplicate_source_labels_are_rejected():
    mcp = source("mcp", "mcp:a", "get_stock_price")
    inventory = merge_inventory([mcp, mcp], registry=REGISTRY, registry_label=LABEL)
    assert inventory.errors == (
        "two inventory sources share the label 'mcp:a'; remove the duplicate, or set a "
        "distinct 'name' on one of these [[inventory.mcp]] sources",
    )


def test_failed_source_keeps_partial_tools_and_flags_incomplete_drift():
    down = source("mcp", "mcp:down", "get_stock_price", "ghost", ok=False, error="boom")
    inventory = merge_inventory([down], registry=REGISTRY, registry_label=LABEL)
    assert "ghost" in [t.id for t in inventory.tools]
    assert tool_of(inventory, "ghost").risk is Risk.UNKNOWN
    assert "mcp:down: boom" in inventory.errors
    registry_only = [w for w in inventory.warnings if "'execute_trade'" in w]
    assert len(registry_only) == 1
    assert registry_only[0].endswith("(this may be incomplete because a source failed)")


def test_registry_description_wins_and_discovered_fills_gaps():
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [],
            "tools": [
                {"id": "a", "action": "x:read", "risk": "low", "description": "from registry"},
            ],
        }
    )
    found = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:x"),
        ok=True,
        tools=(
            ToolDescriptor(name="a", description="from mcp"),
            ToolDescriptor(name="b", description="first found"),
        ),
    )
    inventory = merge_inventory([found], registry=registry, registry_label=LABEL)
    assert tool_of(inventory, "a").description == "from registry"
    assert tool_of(inventory, "b").description == "first found"


def test_discovered_only_tools_follow_discovery_order_across_sources():
    inventory = merge_inventory(
        [source("mcp", "mcp:a", "z1", "z2"), source("json", "json:b.json", "y1")],
        registry=REGISTRY,
        registry_label=LABEL,
    )
    assert [t.id for t in inventory.tools] == [
        "get_stock_price",
        "execute_trade",
        "z1",
        "z2",
        "y1",
    ]


def test_failed_optional_source_is_a_warning_not_an_error():
    result = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:partner"),
        ok=False,
        error="connection refused",
        optional=True,
        agents=("finance-agent",),
    )
    inventory = merge_inventory([result], registry=REGISTRY)
    assert inventory.errors == ()
    assert (
        "mcp:partner: unavailable (connection refused); "
        "using registry declarations only" in inventory.warnings
    )
    assert inventory.drift is not None and inventory.drift.complete is False


def test_delegation_tools_are_not_inventory_tools():
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [{"id": "research-agent"}, {"id": "finance-agent"}],
            "tools": [{"id": "real_tool", "action": "a:b", "risk": "low"}],
            "delegation_tools": [{"id": "ask_x", "agent": "finance-agent"}],
        }
    )
    inventory = merge_inventory([source("mcp", "mcp:x", "ask_x", "real_tool")], registry=registry)
    assert "ask_x" not in [t.id for t in inventory.tools]
    assert inventory.delegation_agents == {"ask_x": "finance-agent"}
    assert inventory.drift is not None
    assert "ask_x" not in inventory.drift.discovered_only
    # Not a drift warning; the only mention is the delegation notice for the MCP source.
    assert [w for w in inventory.warnings if "ask_x" in w and "delegation" not in w] == []


def test_optional_source_with_tools_and_an_error_is_still_an_error():
    result = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:partner"),
        ok=False,
        error="bad item",
        optional=True,
        tools=(ToolDescriptor(name="get_stock_price"),),
    )
    inventory = merge_inventory([result], registry=REGISTRY)
    assert inventory.errors == ("mcp:partner: bad item",)


def test_optional_ok_source_adds_no_unavailable_warning():
    result = SourceResult(source=SourceRef(kind="mcp", label="mcp:partner"), ok=True, optional=True)
    inventory = merge_inventory([result], registry=REGISTRY)
    assert not any("unavailable" in w for w in inventory.warnings)


def test_failed_optional_source_without_registry_says_tools_are_unknown():
    result = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:partner"),
        ok=False,
        error="timed out",
        optional=True,
    )
    inventory = merge_inventory([result])
    assert inventory.errors == ()
    assert "mcp:partner: unavailable (timed out); its tools are unknown" in inventory.warnings


def test_delegation_tool_reported_by_two_sources_is_not_a_conflict():
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [{"id": "finance-agent"}],
            "tools": [],
            "delegation_tools": [{"id": "ask_x", "agent": "finance-agent"}],
        }
    )
    inventory = merge_inventory(
        [source("mcp", "mcp:a", "ask_x"), source("mcp", "mcp:b", "ask_x")], registry=registry
    )
    assert inventory.errors == ()


# ---- merging is linear in the number of tools ----


def test_merging_many_tools_is_linear():
    """30k tools from one source used to take about 18 seconds (quadratic)."""
    count = 30_000
    tools = tuple(ToolDescriptor(name=f"tool-{n}") for n in range(count))
    source = SourceResult(
        source=SourceRef(kind="json", label="json:big.json"), ok=True, tools=tools
    )
    python = SourceResult(
        source=SourceRef(kind="python", label="python:app:a"),
        ok=True,
        tools=tools[:1000],
    )
    other = SourceResult(
        source=SourceRef(kind="python", label="python:app:b"),
        ok=True,
        tools=tools[:1000],
    )
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [],
            "tools": [
                {"id": f"tool-{n}", "action": "x:y", "risk": "low"} for n in range(0, count, 3)
            ],
        }
    )
    started = time.perf_counter()
    inventory = merge_inventory([source, python, other], registry=registry)
    elapsed = time.perf_counter() - started
    assert len(inventory.tools) == count
    # The two Python sources share identical tools; the JSON source makes them conflicts.
    assert len(inventory.errors) == 1000
    assert elapsed < 5.0, elapsed


def test_merge_keeps_duplicates_within_one_source_in_order():
    """A source that lists one name twice keeps the first description, as before."""
    first = ToolDescriptor(name="t", description=None)
    second = ToolDescriptor(name="t", description="second", hints={"readOnlyHint": True})
    result = SourceResult(
        source=SourceRef(kind="json", label="json:t"), ok=True, tools=(first, second)
    )
    [tool] = merge_inventory([result]).tools
    assert (tool.description, tool.hints, tool.sources) == (
        "second",
        {"readOnlyHint": True},
        ("json:t", "json:t"),
    )


# ---- a discovered tool named like a delegation tool is visible, not silent ----


def _delegation_registry(*ids: str) -> Registry:
    return Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [{"id": "finance-agent"}],
            "tools": [],
            "delegation_tools": [{"id": tool_id, "agent": "finance-agent"} for tool_id in ids],
        }
    )


@pytest.mark.parametrize("kind", ["mcp", "json"])
def test_non_python_source_reporting_a_delegation_id_warns(kind):
    inventory = merge_inventory(
        [source(kind, f"{kind}:x", "ask_x", "other")], registry=_delegation_registry("ask_x")
    )
    shown = [w for w in inventory.warnings if "ask_x" in w and "delegation" in w]
    assert len(shown) == 1 and f"{kind}:x" in shown[0]
    assert "ask_x" not in [t.id for t in inventory.tools]  # still not a tool row
    assert inventory.errors == ()


def test_delegation_id_warning_lists_each_source_once_per_id():
    inventory = merge_inventory(
        [source("mcp", "mcp:a", "ask_x"), source("json", "json:b", "ask_x", "ask_y")],
        registry=_delegation_registry("ask_x", "ask_y"),
    )
    shown = [w for w in inventory.warnings if "delegation" in w]
    assert len(shown) == 2
    assert any("ask_x" in w and "mcp:a" in w and "json:b" in w for w in shown)


def test_python_source_reporting_a_delegation_id_is_the_wrapper_and_does_not_warn():
    inventory = merge_inventory(
        [source("python", "python:app:a", "ask_x")], registry=_delegation_registry("ask_x")
    )
    assert not any("delegation" in w for w in inventory.warnings)


def test_delegation_id_warning_is_absent_without_a_collision():
    inventory = merge_inventory(
        [source("mcp", "mcp:a", "other")], registry=_delegation_registry("ask_x")
    )
    assert not any("delegation" in w for w in inventory.warnings)
