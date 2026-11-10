"""The real side effects. Each raises, so a missed replacement fails loudly."""

from collections.abc import Callable


def fetch_portfolio(portfolio_id: str) -> str:
    raise RuntimeError("real side effect ran")


def place_order(order_id: str) -> str:
    raise RuntimeError("real side effect ran")


def get_price(symbol: str) -> str:
    raise RuntimeError("real side effect ran")


def fetch_report(report_id: str) -> str:
    raise RuntimeError("real side effect ran")


# A reference the harness reference scan cannot see (used by DESK_BAD_PATH).
EFFECTS: dict[str, Callable[[str], str]] = {"place_order": place_order}
