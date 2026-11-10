"""decide() for GCP Policy Troubleshooter.

API used: google-cloud-policy-troubleshooter, module google.cloud.policytroubleshooter_v1,
IamCheckerClient.troubleshoot_iam_policy (API v1). Request: access_tuple {principal,
full_resource_name, permission}. Response: access, an AccessState enum with values
GRANTED, NOT_GRANTED, UNKNOWN_CONDITIONAL, UNKNOWN_INFO_DENIED (numbers 1 to 4; 0 is
unspecified).
Not verified against a live service (assumption, check it): the client accepts a plain
dict as the request, as proto-plus clients normally do.

LIMIT: v1 answers from allow policies only. Its types have no IAM deny policy and no
Principal Access Boundary. If you use deny policies or Principal Access Boundaries, a
GRANTED answer may be wrong (too permissive). Use the IAM v3 troubleshooter instead.

Where the inputs come from:
  principal           subject["properties"]["principal"], the account email, for example
                      "a@example.com" (no "user:" prefix in v1)
  permission          action["name"], for example "storage.objects.get"
  full resource name  resource["properties"]["full_resource_name"], for example
                      "//cloudresourcemanager.googleapis.com/projects/my-project"
A missing property raises ValueError. GRANTED is True and NOT_GRANTED is False. The two
UNKNOWN states (a condition that cannot be evaluated, or missing permission to look) and
anything else raise: they are never turned into allow or deny. The AuthZEN context is not
sent. Credentials come from Application Default Credentials. The client is built once per
worker. This recipe is tested with fake responses only.
"""

import functools
from typing import Any

_BY_NUMBER = {1: "GRANTED", 2: "NOT_GRANTED", 3: "UNKNOWN_CONDITIONAL", 4: "UNKNOWN_INFO_DENIED"}


@functools.cache
def _client() -> Any:
    from google.cloud import policytroubleshooter_v1  # ty: ignore[import-not-found]  # lazy

    return policytroubleshooter_v1.IamCheckerClient()


def _prop(entity: dict, key: str, what: str) -> str:
    value = (entity.get("properties") or {}).get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} has no properties.{key}")
    return value


def _state(access: object) -> str:
    name = getattr(access, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(access, int) and not isinstance(access, bool):
        return _BY_NUMBER.get(access, f"UNKNOWN_NUMBER_{access}")
    # A plain string (or anything else) is not a documented response type: fail closed.
    return f"UNSUPPORTED_TYPE_{type(access).__name__}"


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    request = {
        "access_tuple": {
            "principal": _prop(subject, "principal", "subject"),
            "full_resource_name": _prop(resource, "full_resource_name", "resource"),
            "permission": action["name"],
        }
    }
    state = _state(_client().troubleshoot_iam_policy(request=request).access)
    if state == "GRANTED":
        return True
    if state == "NOT_GRANTED":
        return False
    raise ValueError(f"Policy Troubleshooter could not decide: {state}")
