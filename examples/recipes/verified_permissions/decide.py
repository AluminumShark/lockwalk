"""decide() and decide_many() for Amazon Verified Permissions.

API used: the boto3 "verifiedpermissions" client, operations IsAuthorized and
BatchIsAuthorized (service API version 2021-12-01), as documented by AWS.

Request fields: policyStoreId, principal {entityType, entityId}, action {actionType,
actionId}, resource {entityType, entityId}, context {contextMap: {name: {string | long |
boolean: value}}}. BatchIsAuthorized takes requests=[...] with 1 to 30 items. Responses:
IsAuthorized gives decision "ALLOW" or "DENY"; BatchIsAuthorized gives results=[{request,
decision, ...}].
AWS documents that results come back in request order, so the echoed "request" is not
compared (the AWS example echoes ids with different casing).

Batch constraint: within one BatchIsAuthorized call, either the principal or the resource
must be the same in every request, or AWS rejects the call with a ValidationException.
decide_many groups the queries by identical principal (entityType plus entityId), splits
each group into calls of at most 30, and puts the answers back in the original order.

Environment:
  AVP_POLICY_STORE_ID  required, the policy store id
  AVP_NAMESPACE        optional Cedar namespace, for example "TradingDesk"; it is put in
                       front of every entity type and of "Action"

Edit TYPES to map an AuthZEN type to your Cedar entity type. A type that is not listed
raises ValueError, and so does any decision other than ALLOW or DENY. Only scalar context
values (string, int, bool) are supported; anything else raises. Ints outside the int64
range are rejected by AWS.

AWS credentials and region come from the normal boto3 chain. Nothing is logged.
The client is built once per worker.
This recipe is tested with fake responses only.
"""

import functools
import os
from typing import Any

# AuthZEN type -> Cedar entity type (without the namespace).
TYPES = {
    "user": "User",
    "agent": "Agent",
    "portfolio": "Portfolio",
    "order": "Order",
}

BATCH_LIMIT = 30  # BatchIsAuthorized accepts at most 30 requests


@functools.cache
def _client() -> Any:
    import boto3  # ty: ignore[import-not-found]  # lazy; the SDK is not a dependency

    return boto3.client("verifiedpermissions")


def _qualify(name: str) -> str:
    namespace = os.environ.get("AVP_NAMESPACE", "")
    return f"{namespace}::{name}" if namespace else name


def _entity(entity: dict) -> dict:
    try:
        entity_type = TYPES[entity["type"]]
    except KeyError:
        raise ValueError(f"no Cedar type for {entity['type']!r}; add it to TYPES") from None
    return {"entityType": _qualify(entity_type), "entityId": entity["id"]}


def _context(context: dict) -> dict | None:
    if not context:
        return None
    cmap: dict[str, dict] = {}
    for key, value in context.items():
        if isinstance(value, bool):
            cmap[key] = {"boolean": value}
        elif isinstance(value, int):
            cmap[key] = {"long": value}
        elif isinstance(value, str):
            cmap[key] = {"string": value}
        else:
            raise ValueError(f"context value for {key!r} is not a string, int, or bool")
    return {"contextMap": cmap}


def _request(query: dict) -> dict:
    request = {
        "principal": _entity(query["subject"]),
        "action": {"actionType": _qualify("Action"), "actionId": query["action"]["name"]},
        "resource": _entity(query["resource"]),
    }
    context = _context(query.get("context") or {})
    if context is not None:
        request["context"] = context
    return request


def _store_id() -> str:
    store = os.environ.get("AVP_POLICY_STORE_ID")
    if not store:
        raise RuntimeError("AVP_POLICY_STORE_ID is not set")
    return store


def _to_bool(decision: object) -> bool:
    # A per-result "errors" array does not invalidate the decision: Cedar skips the policies
    # that errored and decides from the rest, so only the decision field is read.
    if decision == "ALLOW":
        return True
    if decision == "DENY":
        return False
    raise ValueError(f"unknown Verified Permissions decision {decision!r}")


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    query = {"subject": subject, "action": action, "resource": resource, "context": context}
    response = _client().is_authorized(policyStoreId=_store_id(), **_request(query))
    return _to_bool(response.get("decision"))


def decide_many(queries: list[dict]) -> list[bool]:
    store = _store_id()
    requests = [_request(query) for query in queries]
    client = _client()
    # One call may only mix requests that share a principal, so group by principal first.
    groups: dict[tuple[str, str], list[int]] = {}
    for index, request in enumerate(requests):
        principal = request["principal"]
        groups.setdefault((principal["entityType"], principal["entityId"]), []).append(index)
    answers: list[bool | None] = [None] * len(requests)
    for indexes in groups.values():
        for start in range(0, len(indexes), BATCH_LIMIT):
            part = indexes[start : start + BATCH_LIMIT]
            chunk = [requests[i] for i in part]
            response = client.batch_is_authorized(policyStoreId=store, requests=chunk)
            results = response.get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                got = len(results) if isinstance(results, list) else type(results).__name__
                raise ValueError(f"batch_is_authorized returned {got} results for {len(chunk)}")
            for index, result in zip(part, results, strict=True):
                answers[index] = _to_bool(result.get("decision"))
    final: list[bool] = []
    for answer in answers:
        if answer is None:
            raise ValueError("batch_is_authorized left a query without an answer")
        final.append(answer)
    return final
