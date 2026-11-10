"""Hooks for `lockwalk test` with [harness]: how lockwalk reaches the demo door.

lockwalk loads this file in a worker subprocess. It tells lockwalk how the app learns who is
calling (set_identity), which functions do the real work (SIDE_EFFECTS, replaced by counters
before any tool runs), and which function is the door (DOOR, only recorded).
"""

import sys
from pathlib import Path

import iam_bridge

# The app lives in ../multi_agent and imports demo_door and demo_trading by plain name.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "multi_agent"))

import demo_door

# The door asks Cedar. Without this line it fails closed.
demo_door.set_decider(iam_bridge.decide)

set_identity = demo_door.as_identity

SIDE_EFFECTS = {
    "read_portfolio": "demo_trading.fetch_portfolio",
    "execute_trade": "demo_trading.place_order",
    "get_stock_price": "demo_trading.quote",
    "confirm_price": "demo_trading.confirm",
}

DOOR = "demo_door.check"


def read_door_call(args, kwargs, result):
    """The door was called as check(subject, action, resource); an exception means deny."""
    return {"subject": args[0], "decision": result is True}
