"""Pydantic AI: quote-agent (no model; lockwalk's fake model drives it)."""

from pydantic_ai import Agent

from desk import door, effects

quote_agent = Agent(name="quote-agent", instructions="Quote prices.")


@quote_agent.tool_plain
@door.guarded("market:read", lambda symbol: door.SYMBOLS[symbol])
def get_stock_price(symbol: str) -> str:
    """Return the price of a symbol."""
    effects.get_price(symbol)
    return "100"


ENTRY = quote_agent
