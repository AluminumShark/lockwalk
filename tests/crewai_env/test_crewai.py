"""CrewAI tools, tested in their own environment.

CrewAI pins openai<3 and mcp 1.x, so it cannot be installed next to the dev group.
Run these tests with:

    UV_PROJECT_ENVIRONMENT=.venv-crewai uv run --no-default-groups --group crewai \
        pytest tests/crewai_env

In the normal dev environment CrewAI is missing and this module is skipped.
"""

from lockwalk_crewai_env import importorskip_crewai, otel_sdk_disabled  # noqa: F401

from lockwalk.inventory.normalize import normalize_items

importorskip_crewai("crewai.tools")


def test_crewai_tools_and_agent():
    from crewai import Agent
    from crewai.tools import BaseTool, tool

    @tool("Read portfolio")
    def read_portfolio(portfolio_id: str) -> str:
        """Read a portfolio."""
        return portfolio_id

    class TradeTool(BaseTool):
        name: str = "execute_trade"
        description: str = "Execute a trade."

        def _run(self, order_id: str) -> str:
            return order_id

    agent = Agent(
        role="analyst",
        goal="Manage a portfolio",
        backstory="Demo agent for lockwalk tests",
        tools=[read_portfolio, TradeTool()],
        llm="gpt-4o-mini",
    )
    tools, errors = normalize_items([agent])
    assert errors == []
    assert [(t.name, t.description) for t in tools] == [
        ("Read portfolio", "Read a portfolio."),
        ("execute_trade", "Execute a trade."),
    ]


def test_crewai_tool_info_and_direct_call():
    from crewai.tools import BaseTool, tool

    from lockwalk.harness.direct import call, tool_info

    calls: list[str] = []

    @tool("Read portfolio")
    def read_portfolio(portfolio_id: str) -> str:
        """Read a portfolio."""
        calls.append(portfolio_id)
        return portfolio_id

    class TradeTool(BaseTool):
        name: str = "execute_trade"
        description: str = "Execute a trade."

        def _run(self, order_id: str) -> str:
            if order_id == "deny":
                raise PermissionError("denied")
            calls.append(order_id)
            return order_id

    info = tool_info("Read portfolio", read_portfolio)
    assert info.kind == "crewai"
    assert info.callable
    assert info.input_schema is not None
    assert "portfolio_id" in info.input_schema["properties"]
    assert call(read_portfolio, {"portfolio_id": "p-1"}).exception is None
    trade = TradeTool()
    assert tool_info("execute_trade", trade).kind == "crewai"
    assert call(trade, {"order_id": "o-1"}).exception is None
    assert calls == ["p-1", "o-1"]
    # BaseTool.run is expected to let what _run raises through; the call reports it.
    assert call(trade, {"order_id": "deny"}).exception == "PermissionError"
