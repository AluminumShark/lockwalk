import warnings

import pytest
from agents import Agent as OpenAIAgent
from agents import function_tool
from agno.agent import Agent
from agno.tools import Toolkit
from agno.tools import tool as agno_tool
from langchain_core.tools import BaseTool, BaseToolkit, StructuredTool, tool
from langgraph.prebuilt import ToolNode
from pydantic_ai import Agent as PydanticAgent
from pydantic_ai import Tool as PydanticTool
from pydantic_ai.toolsets import FunctionToolset

from lockwalk.inventory.base import dedupe, failed, finish, truncate
from lockwalk.inventory.normalize import (
    NormalizeError,
    descriptor_from_dict,
    descriptor_from_object,
    normalize_items,
    tool_container_contents,
)
from lockwalk.models import SourceRef, ToolDescriptor


@tool
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio."""
    return portfolio_id


@tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    return order_id


def test_mcp_dict_with_annotations():
    descriptor = descriptor_from_dict(
        {
            "name": "delete_portfolio",
            "description": "Delete a portfolio.",
            "inputSchema": {"type": "object"},
            "annotations": {"destructiveHint": True, "title": "Delete", "readOnlyHint": "yes"},
        }
    )
    assert descriptor == ToolDescriptor(
        name="delete_portfolio", description="Delete a portfolio.", hints={"destructiveHint": True}
    )


def test_anthropic_dict():
    descriptor = descriptor_from_dict(
        {"name": "get_weather", "description": "Get the weather.", "input_schema": {}}
    )
    assert descriptor == ToolDescriptor(name="get_weather", description="Get the weather.")


def test_openai_chat_dict():
    descriptor = descriptor_from_dict(
        {
            "type": "function",
            "function": {"name": "get_weather", "description": "Weather.", "parameters": {}},
        }
    )
    assert descriptor == ToolDescriptor(name="get_weather", description="Weather.")


def test_openai_flat_dict():
    descriptor = descriptor_from_dict({"type": "function", "name": "get_weather", "parameters": {}})
    assert descriptor == ToolDescriptor(name="get_weather")


def test_dict_without_a_name():
    with pytest.raises(NormalizeError, match="no string 'name'"):
        descriptor_from_dict({"description": "nameless"})


def test_object_with_a_name_attribute():
    class FakeTool:
        name = "search"
        description = "Search the web."

    assert descriptor_from_object(FakeTool()) == ToolDescriptor(
        name="search", description="Search the web."
    )


def test_langchain_tools():
    def _trade(order_id: str) -> str:
        """Execute a trade."""
        return order_id

    trade = StructuredTool.from_function(_trade, name="execute_trade")
    assert descriptor_from_object(read_portfolio) == ToolDescriptor(
        name="read_portfolio", description="Read a portfolio."
    )
    assert descriptor_from_object(trade) == ToolDescriptor(
        name="execute_trade", description="Execute a trade."
    )


def test_agno_agent_with_function_plain_function_and_toolkit():
    @agno_tool
    def get_stock_price(symbol: str) -> str:
        """Return the price of a stock symbol."""
        return symbol

    def plain_lookup(query: str) -> str:
        """Look something up."""
        return query

    class FinanceTools(Toolkit):
        def __init__(self) -> None:
            super().__init__(name="finance_tools", tools=[self.read_portfolio, self.execute_trade])

        def read_portfolio(self, portfolio_id: str) -> str:
            """Read a portfolio."""
            return portfolio_id

        def execute_trade(self, order_id: str) -> str:
            """Execute a trade."""
            return order_id

    agent = Agent(name="finance-agent", tools=[get_stock_price, plain_lookup, FinanceTools()])
    tools, errors = normalize_items([agent])
    assert errors == []
    assert [t.name for t in tools] == [
        "get_stock_price",
        "plain_lookup",
        "read_portfolio",
        "execute_trade",
    ]
    assert tools[0].description == "Return the price of a stock symbol."


def test_openai_agents_sdk_function_tool_and_agent():
    @function_tool
    def get_stock_price(symbol: str) -> str:
        """Return the price of a stock symbol."""
        return symbol

    tools, errors = normalize_items([OpenAIAgent(name="finance-agent", tools=[get_stock_price])])
    assert errors == []
    assert [(t.name, t.description) for t in tools] == [
        ("get_stock_price", "Return the price of a stock symbol.")
    ]


def test_pydantic_ai_tool_toolset_and_agent():
    def lookup_price(symbol: str) -> str:
        """Look up a price."""
        return symbol

    def place_order(order_id: str) -> str:
        """Place an order."""
        return order_id

    def search_news(query: str) -> str:
        """Search the news."""
        return query

    assert descriptor_from_object(PydanticTool(lookup_price)).name == "lookup_price"
    toolset_tools, _ = normalize_items(
        # The stubs want a RunContext parameter, but plain functions work at runtime.
        [FunctionToolset([lookup_price, place_order])]  # ty: ignore[invalid-argument-type]
    )
    assert [t.name for t in toolset_tools] == ["lookup_price", "place_order"]

    # Plain functions without a RunContext parameter work at runtime but not in the type stubs.
    agent = PydanticAgent(  # ty: ignore[no-matching-overload]
        "test",
        tools=[lookup_price, place_order],
        toolsets=[FunctionToolset([search_news])],  # ty: ignore[invalid-argument-type]
    )
    tools, errors = normalize_items([agent])
    assert errors == []
    assert [t.name for t in tools] == ["lookup_price", "place_order", "search_news"]


def test_langgraph_tool_node_is_opened():
    tools, errors = normalize_items([ToolNode([read_portfolio, execute_trade])])
    assert errors == []
    assert [t.name for t in tools] == ["read_portfolio", "execute_trade"]


def test_langchain_toolkit_is_opened():
    class FinanceToolkit(BaseToolkit):
        def get_tools(self) -> list[BaseTool]:
            return [read_portfolio, execute_trade]

    tools, errors = normalize_items([FinanceToolkit()])
    assert errors == []
    assert [t.name for t in tools] == ["read_portfolio", "execute_trade"]


def test_tool_objects_are_not_mistaken_for_containers():
    @agno_tool
    def lookup(query: str) -> str:
        """Look something up."""
        return query

    assert tool_container_contents(read_portfolio) is None
    assert tool_container_contents(lookup) is None
    assert tool_container_contents({"name": "a", "tools": []}) is None


def test_nested_containers_have_a_depth_limit():
    class Box:
        def __init__(self, inner: object) -> None:
            self.tools = [inner]

    five: object = {"name": "deep"}
    for _ in range(5):
        five = Box(five)
    assert [t.name for t in normalize_items([five])[0]] == ["deep"]

    six = Box(five)
    tools, errors = normalize_items([six])
    assert tools == []
    assert errors == ["item 0.0.0.0.0.0: tool containers are nested more than 5 levels deep"]


def test_get_tools_that_needs_arguments_is_not_called():
    class NeedsContext:
        name = "context_tool"

        def get_tools(self, session: object) -> list[object]:
            raise AssertionError("must not be called")

    assert tool_container_contents(NeedsContext()) is None
    assert [t.name for t in normalize_items([NeedsContext()])[0]] == ["context_tool"]


def test_failing_get_tools_is_reported():
    class Broken:
        def get_tools(self) -> list[object]:
            raise RuntimeError("no tools today")

    tools, errors = normalize_items([Broken()])
    assert tools == []
    assert errors == ["item 0: reading its tools raised RuntimeError: no tools today"]


def test_plain_function_uses_the_first_docstring_line():
    def get_stock_price(symbol: str) -> str:
        """Return the price of a stock symbol.

        More detail that is not used.
        """
        return symbol

    assert descriptor_from_object(get_stock_price) == ToolDescriptor(
        name="get_stock_price", description="Return the price of a stock symbol."
    )


def test_lambda_is_rejected():
    with pytest.raises(NormalizeError, match="cannot recognize a tool"):
        descriptor_from_object(lambda: None)


def test_unrecognized_value():
    with pytest.raises(NormalizeError, match=r"builtins\.int"):
        descriptor_from_object(42)


def test_invalid_name_is_rejected():
    with pytest.raises(NormalizeError, match="invalid tool name"):
        descriptor_from_dict({"name": " padded"})


def test_normalize_items_reports_the_index_of_bad_items():
    tools, errors = normalize_items([{"name": "a"}, 5, {"name": "b"}])
    assert [t.name for t in tools] == ["a", "b"]
    assert errors == ["item 1: cannot recognize a tool in a value of type builtins.int"]


def test_dedupe_keeps_the_first_and_warns():
    tools, warnings = dedupe([ToolDescriptor(name="a"), ToolDescriptor(name="a")], "json:t.json")
    assert tools == (ToolDescriptor(name="a"),)
    assert warnings == ("json:t.json: duplicate tool name 'a' ignored",)


def test_truncate_collapses_whitespace_and_limits_length():
    assert truncate("a\n  b\tc") == "a b c"
    long = truncate("x" * 500)
    assert len(long) == 300
    assert long.endswith("...")


SOURCE = SourceRef(kind="json", label="json:t.json")


def test_a_raising_name_is_reported_per_item():
    class Bad:
        @property
        def name(self) -> str:
            raise RuntimeError("boom")

    tools, errors = normalize_items([Bad(), {"name": "good"}])
    assert [t.name for t in tools] == ["good"]
    assert errors == ["item 0: reading the tool raised RuntimeError: boom"]


def test_async_get_tools_is_not_called():
    class AsyncToolkit:
        async def get_tools(self) -> list[object]:
            return []

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        tools, errors = normalize_items([AsyncToolkit()])
    assert tools == []
    assert errors == [
        "item 0: async get_tools() is not supported; point lockwalk at the tool list instead"
    ]


def test_get_tools_returning_a_string_is_an_error():
    class Odd:
        def get_tools(self) -> str:
            return "abc"

    tools, errors = normalize_items([Odd()])
    assert tools == []
    assert len(errors) == 1
    assert "get_tools() returned builtins.str" in errors[0]


def test_get_tools_returning_a_dict_uses_its_values():
    class Mapped:
        def get_tools(self) -> dict[str, object]:
            return {"a": {"name": "a"}, "b": {"name": "b"}}

    tools, errors = normalize_items([Mapped()])
    assert errors == []
    assert [t.name for t in tools] == ["a", "b"]


def test_a_class_is_not_a_tool():
    class FakeTool:
        name = "x"

    tools, errors = normalize_items([FakeTool])
    assert tools == []
    assert len(errors) == 1
    assert "is a class, not a tool" in errors[0]


def test_a_self_referencing_container_is_reported_once():
    class Box:
        def __init__(self) -> None:
            self.tools: list[object] = []

    box = Box()
    box.tools = [box, box, box, box]
    tools, errors = normalize_items([box])
    assert tools == []
    assert errors == ["item 0.0: tool container contains itself"]


def test_finish_with_one_error_keeps_tools_and_the_exact_text():
    result = finish(SOURCE, [ToolDescriptor(name="a")], ["item 1: bad"], ["agent-1"])
    assert result.ok is False
    assert result.tools == (ToolDescriptor(name="a"),)
    assert result.error == "item 1: bad"
    assert result.agents == ("agent-1",)


def test_finish_with_many_errors_shows_the_count_after_truncation():
    result = finish(SOURCE, [], ["x" * 200, "y" * 200, "z"], [])
    assert result.error is not None
    assert result.error.startswith("3 problems: ")
    assert len(result.error) == 300


def test_failed_truncates_and_passes_agents_through():
    result = failed(SOURCE, "m" * 500, agents=["a"])
    assert result.ok is False
    assert result.error is not None
    assert len(result.error) == 300
    assert result.agents == ("a",)


def test_truncate_leaves_exactly_the_limit_unchanged():
    assert truncate("x" * 300) == "x" * 300


def test_dedupe_mentions_a_differing_description():
    _, warnings_ = dedupe(
        [ToolDescriptor(name="a", description="one"), ToolDescriptor(name="a", description="two")],
        "json:t.json",
    )
    assert len(warnings_) == 1
    assert "description differs" in warnings_[0]
