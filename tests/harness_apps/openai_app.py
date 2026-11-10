"""OpenAI Agents SDK app for the fake-framework tests: supervisor, finance-agent, trade-agent."""

import contextvars

from agents import Agent, function_tool

IDENT: contextvars.ContextVar[str] = contextvars.ContextVar("ident", default="NONE")
CALLS: list[tuple[str, str]] = []


@function_tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    CALLS.append((order_id, IDENT.get()))
    return "traded " + order_id


trade_agent = Agent(name="trade-agent", instructions="trade", tools=[execute_trade])
finance_agent = Agent(
    name="finance-agent",
    instructions="finance",
    tools=[trade_agent.as_tool(tool_name="ask_trade_agent", tool_description="ask trade")],
)
supervisor = Agent(name="supervisor", instructions="route", handoffs=[finance_agent])

# Not passed to Found in the tests: the handoff target lockwalk did not discover.
ghost_agent = Agent(name="ghost", instructions="ghost")
ghost_supervisor = Agent(name="ghost-supervisor", instructions="route", handoffs=[ghost_agent])
