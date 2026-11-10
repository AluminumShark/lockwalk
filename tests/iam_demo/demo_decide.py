"""The multi-agent demo policy in plain Python: the reference the IAM examples must match.

It has one deliberate hole, which lockwalk test must find: trade-agent's own service
identity may execute trades on any account.
"""

MARKET = {"market:read", "market:quote", "market:confirm"}


def _allowed(subject: dict, action: dict, resource: dict, *, broken: bool) -> bool:
    name = action["name"]
    attrs = resource.get("properties", {})
    if name == "agent:invoke":
        return True
    if subject["type"] == "agent":
        if name in MARKET:
            return True
        return subject["id"] == "trade-agent" and name == "trade:execute"  # the hole
    roles = set(subject.get("properties", {}).get("roles", []))
    if name in MARKET:
        return bool(roles & {"analyst", "trader"})
    if name == "portfolio:read":
        if broken:  # the "broken rule" switch: the owner check is gone
            return bool(roles & {"analyst", "trader"})
        return attrs.get("owner") == subject["id"]
    if name == "trade:execute":
        return "trader" in roles and attrs.get("account_owner") == subject["id"]
    return False


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    return _allowed(subject, action, resource, broken=False)


def decide_broken(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    return _allowed(subject, action, resource, broken=True)
