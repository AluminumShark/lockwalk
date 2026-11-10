"""The door: every tool asks the IAM before its body runs."""

import functools
import os
from collections.abc import Callable
from typing import Any

from desk import iam
from desk.identity import current

PORTFOLIOS = {
    "p-alice": {"type": "portfolio", "id": "p-alice", "properties": {"owner": "alice"}},
    "p-bob": {"type": "portfolio", "id": "p-bob", "properties": {"owner": "bob"}},
}
ORDERS = {
    "o-alice-1": {"type": "order", "id": "o-alice-1", "properties": {"account_owner": "alice"}},
    "o-bob-1": {"type": "order", "id": "o-bob-1", "properties": {"account_owner": "bob"}},
}
SYMBOLS = {"2330.TW": {"type": "stock_symbol", "id": "2330.TW"}}
REPORTS = {"r-q3": {"type": "report", "id": "r-q3"}}


def check(subject: dict[str, Any] | None, action: str, resource: dict[str, Any]) -> bool:
    if subject is None:
        return False
    return iam.decide(subject, {"name": action}, resource, {})


def with_act(subject: dict[str, Any] | None, chain: tuple[str, ...]) -> dict[str, Any] | None:
    """Add the delegation chain (outermost agent first) as properties.act, as RFC 8693 does."""
    if subject is None or not chain:
        return subject
    act: dict[str, Any] | None = None
    for agent_id in reversed(chain):
        act = (
            {"type": "agent", "id": agent_id}
            if act is None
            else {
                "type": "agent",
                "id": agent_id,
                "act": act,
            }
        )
    properties = {**(subject.get("properties") or {}), "act": act}
    return {**subject, "properties": properties}


def guarded(
    action: str, resource_of: Callable[..., dict[str, Any]], act: tuple[str, ...] = ()
) -> Callable[..., Any]:
    """Decorator: ask the door first. DESK_BYPASS=<tool name> skips it for that tool.

    `act` is the delegation chain the app puts on the identity (on_behalf_of tools).
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = getattr(fn, "__name__", "")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            asked = os.environ.get("DESK_BYPASS") != name
            if asked and not check(with_act(current(), act), action, resource_of(*args, **kwargs)):
                raise PermissionError("the door denied this call")
            return fn(*args, **kwargs)

        return wrapper

    return decorate
