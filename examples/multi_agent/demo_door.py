"""A small door for the demo: every guarded tool asks the IAM before its body runs.

This is example code, not part of lockwalk. Your app has its own door; lockwalk only needs
to know its name (DOOR in the hooks file) and how to read a call (read_door_call).

The IAM is plugged in with set_decider(). The hooks file in examples/iam_cedar sets it to
the Cedar bridge. With no decider the door fails closed: check() raises.
"""

import contextlib
import functools
import os
from collections.abc import Callable, Generator
from contextvars import ContextVar
from typing import Any

Decider = Callable[[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]], bool]

_decider: Decider | None = None
# The holder is mutable on purpose: a switch made inside a handoff survives context copies.
_HOLDER: ContextVar[dict[str, Any] | None] = ContextVar("demo_identity", default=None)


def set_decider(fn: Decider | None) -> None:
    """Plug in the IAM: fn(subject, action, resource, context) -> bool."""
    global _decider
    _decider = fn


@contextlib.contextmanager
def as_identity(subject: dict[str, Any]) -> Generator[None]:
    """Run one request as `subject` (a fresh holder, restored afterwards)."""
    token = _HOLDER.set({"subject": subject})
    try:
        yield
    finally:
        _HOLDER.reset(token)


def current() -> dict[str, Any] | None:
    holder = _HOLDER.get()
    return holder["subject"] if holder is not None else None


def switch_to_agent(agent_id: str) -> None:
    """Replace the identity in place: the demo bug behind LOCKWALK_DEMO_OWN_IDENTITY."""
    holder = _HOLDER.get()
    if holder is not None:
        holder["subject"] = {"type": "agent", "id": agent_id, "properties": {}}


def check(subject: dict[str, Any] | None, action: str, resource: dict[str, Any]) -> bool:
    """Ask the IAM. Fails closed: no decider or no identity is an error or a deny."""
    if _decider is None:
        raise RuntimeError("the door has no IAM: call demo_door.set_decider(...) first")
    if subject is None:
        return False
    return bool(_decider(subject, {"name": action}, resource, {}))


def guarded(
    action: str,
    resource_of: Callable[..., dict[str, Any]],
    as_agent: dict[str, Any] | None = None,
) -> Callable[..., Any]:
    """Decorator: ask the door first, raise PermissionError on deny.

    `as_agent` is the tool's own service identity, for tools that run as an agent
    (delegation_mode: agent). LOCKWALK_DEMO_BYPASS=<tool name> skips the door for that tool.
    """

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = getattr(fn, "__name__", "")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if os.environ.get("LOCKWALK_DEMO_BYPASS") != name:
                subject = as_agent if as_agent is not None else current()
                # Fail closed: a resource that cannot be built (for example an unknown id)
                # is a deny, and the tool body never runs. The raw lookup error stays hidden.
                try:
                    resource = resource_of(*args, **kwargs)
                except Exception:
                    raise PermissionError("the door denied this call: unknown resource") from None
                if not check(subject, action, resource):
                    raise PermissionError("the door denied this call")
            return fn(*args, **kwargs)

        return wrapper

    return decorate
