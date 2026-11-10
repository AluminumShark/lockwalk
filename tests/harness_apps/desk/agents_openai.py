"""OpenAI Agents SDK: supervisor -(handoff)-> finance-agent -(as_tool)-> trade-agent."""

import os

from agents import Agent, function_tool, handoff

from desk import door, effects, identity


@function_tool
@door.guarded("portfolio:read", lambda portfolio_id: door.PORTFOLIOS[portfolio_id])
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio."""
    effects.fetch_portfolio(portfolio_id)
    return "portfolio"


@function_tool
@door.guarded(
    "trade:execute",
    lambda order_id: door.ORDERS[order_id],
    act=("trade-agent", "finance-agent", "supervisor"),
)
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    if os.environ.get("DESK_BAD_PATH") == "1":
        effects.EFFECTS["place_order"](order_id)
    else:
        effects.place_order(order_id)
    return "traded"


trade_agent = Agent(name="trade-agent", instructions="Trade.", tools=[execute_trade])
finance_agent = Agent(
    name="finance-agent",
    instructions="Finance.",
    tools=[
        read_portfolio,
        trade_agent.as_tool(tool_name="ask_trade_agent", tool_description="Ask the trade agent."),
    ],
)

if os.environ.get("DESK_SWITCH") == "1":
    _to_finance = handoff(
        finance_agent, on_handoff=lambda ctx: identity.switch_to_agent("finance-agent")
    )
else:
    _to_finance = finance_agent
supervisor = Agent(name="supervisor", instructions="Route.", handoffs=[_to_finance])

ENTRY_AGENTS = [supervisor]
