"""The trading desk's side effects, and the small in-memory tables the door reads.

The tables match fixtures.yaml: the same type, id, and properties. A real app would read
them from its database.

Every side effect raises if it really runs. lockwalk replaces them with counters before it
calls a tool, so in a lockwalk test they never run. Run outside lockwalk, they say so.
"""

PORTFOLIOS = {
    "p-alice": {"type": "portfolio", "id": "p-alice", "properties": {"owner": "alice"}},
    "p-bob": {"type": "portfolio", "id": "p-bob", "properties": {"owner": "bob"}},
}
ORDERS = {
    "o-bob-1": {"type": "order", "id": "o-bob-1", "properties": {"account_owner": "bob"}},
    "o-alice-1": {"type": "order", "id": "o-alice-1", "properties": {"account_owner": "alice"}},
}
SYMBOLS = {"2330.TW": {"type": "stock_symbol", "id": "2330.TW"}}

# trade-agent calls its tools with its own service identity (delegation_mode: agent).
TRADE_AGENT = {
    "type": "agent",
    "id": "trade-agent",
    "properties": {"roles": ["service_agent"], "service_account": "svc-trade"},
}


def fetch_portfolio(portfolio_id: str) -> str:
    raise RuntimeError("demo: this would read a real portfolio")


def place_order(order_id: str) -> str:
    raise RuntimeError("demo: this would place a real trade order")


def quote(symbol: str) -> str:
    raise RuntimeError("demo: this would fetch a real market price")


def confirm(symbol: str) -> str:
    raise RuntimeError("demo: this would ask the exchange to confirm a price")
