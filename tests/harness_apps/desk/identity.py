"""Who the current request acts as. The holder is mutable, so a switch survives context copies."""

import contextlib
from collections.abc import Generator
from contextvars import ContextVar
from typing import Any

_HOLDER: ContextVar[dict[str, Any] | None] = ContextVar("desk_identity", default=None)


@contextlib.contextmanager
def as_identity(subject: dict[str, Any]) -> Generator[None]:
    """Install a fresh holder for the duration of one request."""
    token = _HOLDER.set({"subject": subject})
    try:
        yield
    finally:
        _HOLDER.reset(token)


def current() -> dict[str, Any] | None:
    holder = _HOLDER.get()
    return holder["subject"] if holder is not None else None


def switch_to_agent(agent_id: str) -> None:
    """Replace the identity in place (the bug DESK_SWITCH models: the user is lost)."""
    holder = _HOLDER.get()
    if holder is not None:
        holder["subject"] = {"type": "agent", "id": agent_id, "properties": {}}
