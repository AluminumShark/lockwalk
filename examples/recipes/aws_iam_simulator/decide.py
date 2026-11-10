"""decide() for the AWS IAM policy simulator.

API used: the boto3 "iam" client, operation SimulatePrincipalPolicy (IAM API version
2010-05-08). Request fields: PolicySourceArn, ActionNames, ResourceArns. Response:
EvaluationResults=[{EvalActionName, EvalResourceName, EvalDecision, ...}], where EvalDecision
is "allowed", "explicitDeny", or "implicitDeny".

The simulator returns one EvaluationResult per action. Its EvalDecision is the most
restrictive decision across the resources asked about; per-resource decisions are in
ResourceSpecificResults. This recipe sends one action and one resource, so the two agree.

What it answers: whether the IAM identity policies (and boundaries, SCPs the simulator
covers) of one principal allow one action on one resource ARN. It does NOT know about
application-level rules such as "a trader may only touch their own orders".

Where the inputs come from:
  principal ARN  subject["properties"]["arn"]    (an IAM user or role ARN)
  action         action["name"], used as the IAM action, for example "s3:GetObject"
  resource ARN   resource["properties"]["arn"]
A missing ARN raises ValueError. The AuthZEN context is NOT sent (no ContextEntries). If a
policy has a Condition on a context key, the simulator answers implicitDeny and lists the
missing keys in ResourceSpecificResults[].MissingContextValues (or, for a resource of "*",
in EvaluationResult.MissingContextValues). That implicitDeny is an unknown, not a deny, so
when either list is non-empty the recipe raises ValueError with the number of keys (never
the key names, which can reveal policy details), whatever the decision. Any EvalDecision other
than the three above, a missing result, or more than one result raises. Credentials and
region come from the normal boto3 chain. The client is built once per worker. This recipe
is tested with fake responses only.
"""

import functools
from typing import Any


@functools.cache
def _client() -> Any:
    import boto3  # ty: ignore[import-not-found]  # lazy; the SDK is not a dependency

    return boto3.client("iam")


def _arn(entity: dict, what: str) -> str:
    arn = (entity.get("properties") or {}).get("arn")
    if not isinstance(arn, str) or not arn:
        raise ValueError(f"{what} has no properties.arn")
    return arn


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    response = _client().simulate_principal_policy(
        PolicySourceArn=_arn(subject, "subject"),
        ActionNames=[action["name"]],
        ResourceArns=[_arn(resource, "resource")],
    )
    results = response.get("EvaluationResults")
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError("simulate_principal_policy did not return exactly one result")
    missing = len(results[0].get("MissingContextValues") or [])
    for specific in results[0].get("ResourceSpecificResults") or []:
        missing += len(specific.get("MissingContextValues") or [])
    if missing:
        raise ValueError(
            f"the simulation needs context values that the recipe does not send: {missing} keys"
        )
    decision = results[0].get("EvalDecision")
    if decision == "allowed":
        return True
    if decision in ("explicitDeny", "implicitDeny"):
        return False
    raise ValueError(f"unknown EvalDecision {decision!r}")
