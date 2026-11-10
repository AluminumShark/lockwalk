"""Pydantic AI app for the fake-framework tests."""

import contextvars

from pydantic_ai import Agent

IDENT: contextvars.ContextVar[str] = contextvars.ContextVar("ident", default="NONE")
CALLS: list[tuple[str, str]] = []

pricing = Agent(name="pricing-agent", instructions="quote")


@pricing.tool_plain
def get_stock_price(symbol: str) -> str:
    CALLS.append((symbol, IDENT.get()))
    return "100"


finance = Agent(name="finance-agent", instructions="finance")


@finance.tool_plain
async def ask_pricing(symbol: str) -> str:
    result = await pricing.run("quote " + symbol)
    return result.output


structured = Agent(name="structured-agent", instructions="structured", output_type=int)


@structured.tool_plain(name="get_stock_price")
def structured_price(symbol: str) -> str:
    CALLS.append((symbol, IDENT.get()))
    return "100"
