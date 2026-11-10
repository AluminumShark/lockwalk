"""Hooks for the desk app: identity, side effects, and the door."""

from desk import identity

set_identity = identity.as_identity

SIDE_EFFECTS = {
    "read_portfolio": "desk.effects.fetch_portfolio",
    "execute_trade": "desk.effects.place_order",
    "get_stock_price": "desk.effects.get_price",
    "read_report": "desk.effects.fetch_report",
}

DOOR = "desk.door.check"


def read_door_call(args, kwargs, result):
    return {"subject": args[0], "decision": result is True}
