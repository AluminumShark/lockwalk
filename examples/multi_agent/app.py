"""A small multi-agent trading desk, built from real framework objects.

Importing this module constructs the agents and does nothing else: no model is called,
no network connection is opened, and no API key is needed.

lockwalk reads these objects for `discover`, `coverage`, and `lockwalk test` without
`[harness]`; none of those calls a tool. With `[harness]` (see examples/iam_cedar), lockwalk
may call these tools in `lockwalk test`, in a worker subprocess, but only after it has
replaced the side effects in demo_trading.py with counters. Each tool asks the demo door
(demo_door.py) first, and the door asks the IAM. Outside lockwalk the side effects raise, so a
tool never really acts.

Two switches break the demo on purpose, so you can watch lockwalk catch them:

- LOCKWALK_DEMO_BYPASS=<tool name>: that tool skips the door.
- LOCKWALK_DEMO_OWN_IDENTITY=finance-agent: the handoff from supervisor to finance-agent
  switches to finance-agent's own identity, so the user is lost.

Agents (the ids match registry.yaml):

- supervisor (OpenAI Agents SDK): the entry agent for analysts and traders. It hands off
  to finance-agent.
- trade-desk (OpenAI Agents SDK): the entry agent for traders only. It hands off to
  trade-agent.
- finance-agent (OpenAI Agents SDK): reads portfolios, uses trade-agent as a tool
  (as_tool), and asks pricing-agent for quotes inside its get_quote tool.
- trade-agent (OpenAI Agents SDK): executes trades with its own identity, asks the remote
  market-oracle to confirm prices inside its confirm_price tool, and hands back to
  finance-agent, which closes a cycle.
- pricing-agent (Pydantic AI): quotes stock prices.
- market-oracle: a remote agent run by the exchange. It is not in this file; only
  registry.yaml knows it.

lockwalk discovers handoffs and as_tool() from the objects. It cannot see a call that a
tool function makes to another agent, so registry.yaml declares those two routes with
`calls`: finance-agent -> pricing-agent and trade-agent -> market-oracle.
"""

import os

import demo_door
import demo_trading
from agents import Agent, function_tool, handoff
from pydantic_ai import Agent as PydanticAgent

# ---- pricing-agent (Pydantic AI) ----


# No model is set: the agent is never run. name= is the id lockwalk shows in the graph.
pricing_agent = PydanticAgent(name="pricing-agent", instructions="Quote stock prices.")


@pricing_agent.tool_plain
@demo_door.guarded("market:read", lambda symbol: demo_trading.SYMBOLS[symbol])
def get_stock_price(symbol: str) -> str:
    """Return the price of a stock symbol (demo)."""
    # pricing-agent is on_behalf_of: lockwalk sets the user plus the delegation chain as the
    # current identity, and the door asks with that identity as it is.
    demo_trading.quote(symbol)
    return "price"


# ---- trade-agent (OpenAI Agents SDK) ----


# trade-agent's tools run with its own service identity (delegation_mode: agent).
@function_tool
@demo_door.guarded(
    "trade:execute",
    lambda order_id: demo_trading.ORDERS[order_id],
    as_agent=demo_trading.TRADE_AGENT,
)
def execute_trade(order_id: str) -> str:
    """Execute a trade order (demo)."""
    demo_trading.place_order(order_id)
    return "traded"


@function_tool
@demo_door.guarded(
    "market:confirm",
    lambda symbol: demo_trading.SYMBOLS[symbol],
    as_agent=demo_trading.TRADE_AGENT,
)
def confirm_price(symbol: str) -> str:
    """Ask the exchange's market-oracle agent to confirm a price (demo).

    A real app would send an A2A request to market-oracle here. lockwalk cannot see a
    call made inside a tool, so registry.yaml declares it: trade-agent calls market-oracle.
    """
    demo_trading.confirm(symbol)
    return "confirmed"


trade_agent = Agent(
    name="trade-agent",
    instructions="Execute the trade orders you are given.",
    tools=[execute_trade, confirm_price],
)


# ---- finance-agent (OpenAI Agents SDK) ----


@function_tool
@demo_door.guarded("portfolio:read", lambda portfolio_id: demo_trading.PORTFOLIOS[portfolio_id])
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio (demo)."""
    demo_trading.fetch_portfolio(portfolio_id)
    return "portfolio"


@function_tool
async def get_quote(symbol: str) -> str:
    """Ask the pricing agent for a quote.

    lockwalk cannot see this call to pricing-agent, so registry.yaml declares it:
    finance-agent calls pricing-agent. lockwalk does not call this tool: it has no side
    effect to replace, and calling it would run pricing-agent.
    """
    result = await pricing_agent.run(f"Quote {symbol}")
    return result.output


finance_agent = Agent(
    name="finance-agent",
    instructions="Manage the user's portfolio.",
    tools=[
        read_portfolio,
        get_quote,
        trade_agent.as_tool(
            tool_name="ask_trade_agent",
            tool_description="Ask the trade agent to execute an order.",
        ),
    ],
)

# The cycle: after a trade, trade-agent hands the conversation back to finance-agent.
trade_agent.handoffs = [finance_agent]


# ---- entry agents (OpenAI Agents SDK) ----


# LOCKWALK_DEMO_OWN_IDENTITY=finance-agent: the handoff replaces the user with
# finance-agent's own identity. lockwalk's identity check reports it as MISMATCH.
if os.environ.get("LOCKWALK_DEMO_OWN_IDENTITY") == "finance-agent":
    _to_finance = handoff(
        finance_agent, on_handoff=lambda ctx: demo_door.switch_to_agent("finance-agent")
    )
else:
    _to_finance = finance_agent

supervisor = Agent(
    name="supervisor",
    instructions="Route the user to the right agent.",
    handoffs=[_to_finance],
)

trade_desk = Agent(
    name="trade-desk",
    instructions="Take trade orders from traders.",
    handoffs=[trade_agent],
)

# What .lockwalk.toml points lockwalk at: one target per framework, so both OpenAI entry
# agents are in one list. A target per entry agent (app:supervisor, app:trade_desk) works
# too: lockwalk merges the identical tools that both walks report.
OPENAI_ENTRY_AGENTS = [supervisor, trade_desk]
