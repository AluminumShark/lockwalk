"""decide() for Casbin (pycasbin), run locally with an ABAC model.

Point lockwalk at it with `--policy python:examples/recipes/casbin/decide.py:decide`, or in
.lockwalk.toml:

    [policy]
    adapter = "python"
    target = "decide.py:decide"

You provide `model.conf` and `policy.csv` (the ones next to this file reproduce the
trading-desk demo). Install the engine with `pip install casbin`; it is imported lazily, so
importing this module never needs it. Environment:

    CASBIN_MODEL     path to the model; default model.conf next to this file
    CASBIN_POLICY    path to the policy; default policy.csv next to this file

The request is (sub, act, obj). `sub` and `obj` are plain objects with the attributes the
policy reads: type, id, and every AuthZEN property, so a condition can say r_sub.roles or
r_obj.owner. ATTRIBUTE_DEFAULTS lists the attributes the demo conditions read; a missing one
is None (or [] for roles), so a policy denies instead of failing. Add your own names there.

decide() returns a real bool. It raises when Casbin cannot evaluate a request, for example
a condition that reads an attribute nobody defined.
"""

import os
from functools import cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

HERE = Path(__file__).resolve().parent

# Attributes the demo policy reads. A property of the same name overrides the default.
ATTRIBUTE_DEFAULTS: dict[str, Any] = {"roles": (), "owner": None, "account_owner": None}


def _entity(entity: dict) -> SimpleNamespace:
    for key in ("type", "id"):
        if not isinstance(entity.get(key), str) or not entity[key]:
            raise ValueError(f"casbin: the entity {key} must be a non-empty string")
    attributes = {**ATTRIBUTE_DEFAULTS, **entity.get("properties", {})}
    attributes["roles"] = list(attributes["roles"] or ())
    # type and id come last: a property cannot change who the entity is.
    return SimpleNamespace(**{**attributes, "type": entity["type"], "id": entity["id"]})


@cache
def _enforcer(model: str, policy: str) -> Any:
    import casbin  # imported here so this module loads without the package

    return casbin.Enforcer(model, policy)


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    model = os.environ.get("CASBIN_MODEL", str(HERE / "model.conf"))
    policy = os.environ.get("CASBIN_POLICY", str(HERE / "policy.csv"))
    allowed = _enforcer(model, policy).enforce(_entity(subject), action["name"], _entity(resource))
    if not isinstance(allowed, bool):
        raise RuntimeError(f"casbin: enforce returned {type(allowed).__name__}, not a bool")
    return allowed
