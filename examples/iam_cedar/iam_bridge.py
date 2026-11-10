"""Ask Cedar, locally, through lockwalk's decide() adapter.

lockwalk calls decide(subject, action, resource, context) with AuthZEN 1.0 fields. This
bridge turns them into a Cedar request and asks the cedarpy engine, using plain Cedar
policy text. An AuthZEN type with no entry in TYPES raises ValueError, and so does any
error Cedar reports while it evaluates the request. lockwalk shows both as ERROR, never
as a PASS: cedarpy itself does not raise, it answers "deny" and lists the errors.
"""

import json
from functools import cache
from pathlib import Path

import cedarpy

HERE = Path(__file__).resolve().parent

# AuthZEN type -> Cedar entity type. Add a row here when your spec uses another type.
TYPES = {
    "user": "User",
    "agent": "Agent",
    "portfolio": "Portfolio",
    "order": "Order",
    "stock_symbol": "StockSymbol",
}


def _cedar_type(authzen_type: str) -> str:
    try:
        return TYPES[authzen_type]
    except KeyError:
        raise ValueError(f"no Cedar type for {authzen_type!r}; add it to TYPES") from None


def _uid(entity: dict) -> dict:
    return {"type": _cedar_type(entity["type"]), "id": entity["id"]}


def _ref(uid: dict) -> str:
    # ensure_ascii=False: Cedar rejects the Unicode escapes that json.dumps writes by default.
    return f"{uid['type']}::{json.dumps(uid['id'], ensure_ascii=False)}"


def _attrs(entity: dict, *, principal: bool) -> dict:
    # AuthZEN properties become Cedar entity attributes. The delegation chain ("act")
    # stays out of the entity: these policies do not use it.
    attrs = {key: value for key, value in entity.get("properties", {}).items() if key != "act"}
    if principal:
        # A principal without roles is denied by the policy, not turned into a Cedar error
        # (reading a missing attribute is an evaluation error).
        attrs.setdefault("roles", [])
    # "name" is the AuthZEN id on purpose, so it comes last and wins over a property "name".
    return {**attrs, "name": entity["id"]}


@cache
def _policy_set(policy_file: str) -> cedarpy.PolicySet:
    """Parse each policy file once."""
    return cedarpy.PolicySet.from_str((HERE / policy_file).read_text(encoding="utf-8"))


def _decide(policy_file: str, subject: dict, action: dict, resource: dict) -> bool:
    principal, target = _uid(subject), _uid(resource)
    entities = [{"uid": principal, "attrs": _attrs(subject, principal=True), "parents": []}]
    if target != principal:  # Cedar rejects two entities with the same uid
        entities.append({"uid": target, "attrs": _attrs(resource, principal=False), "parents": []})
    request = {
        "principal": _ref(principal),
        "action": f"Action::{json.dumps(action['name'], ensure_ascii=False)}",
        "resource": _ref(target),
        "context": {},  # unused: these policies do not read the AuthZEN context
    }
    result = cedarpy.is_authorized(request, _policy_set(policy_file), entities)
    errors = [str(error) for error in result.diagnostics.errors]
    if errors:
        raise ValueError("cedar: " + "; ".join(errors))
    return bool(result.allowed)


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    return _decide("policies.cedar", subject, action, resource)


def decide_broken(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    return _decide("policies-broken.cedar", subject, action, resource)
