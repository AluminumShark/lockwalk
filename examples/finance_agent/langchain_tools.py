"""The finance demo tools written with LangChain's @tool decorator.

lockwalk can collect them straight from the code. From the repository root:

    lockwalk discover --python examples.finance_agent.langchain_tools:FINANCE_TOOLS

The tools are stubs and are never called.
"""

from langchain_core.tools import tool


@tool
def get_stock_price(symbol: str) -> str:
    """Return the price of a stock symbol (demo stub)."""
    raise RuntimeError("demo stub; lockwalk never calls tools")


@tool
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio (demo stub)."""
    raise RuntimeError("demo stub; lockwalk never calls tools")


@tool
def execute_trade(order_id: str) -> str:
    """Execute a trade order (demo stub)."""
    raise RuntimeError("demo stub; lockwalk never calls tools")


FINANCE_TOOLS = [get_stock_price, read_portfolio, execute_trade]
