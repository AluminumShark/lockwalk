"""The desk policy. `lockwalk test` asks it, and the door asks it too."""

from typing import Any


def _props(entity: dict[str, Any]) -> dict[str, Any]:
    return entity.get("properties") or {}


def decide(
    subject: dict[str, Any],
    action: dict[str, Any],
    resource: dict[str, Any],
    context: dict[str, Any],
) -> bool:
    name = action["name"]
    is_user = subject.get("type") == "user"
    if name == "market:read":
        return True
    if name == "report:read":
        return is_user
    if name == "portfolio:read":
        return is_user and _props(resource).get("owner") == subject["id"]
    if name == "trade:execute":
        return (
            is_user
            and "trader" in (_props(subject).get("roles") or [])
            and _props(resource).get("account_owner") == subject["id"]
        )
    return False
