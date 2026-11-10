"""decide() for Open Policy Agent (OPA), asked over its REST API.

Point lockwalk at it with `--policy python:examples/recipes/opa/decide.py:decide`, or in
.lockwalk.toml:

    [policy]
    adapter = "python"
    target = "decide.py:decide"

You provide a running OPA server with a policy that defines `data.lockwalk.allow` (see
policy.rego and docker-compose.yml). Environment:

    OPA_URL        base URL of the server; default http://127.0.0.1:8181
    OPA_TIMEOUT    seconds per request; default 5

The input document is {subject, action, resource, context}, the AuthZEN 1.0 fields as
lockwalk gives them. decide() returns a real bool, and raises when OPA does not answer a
plain true or false (an HTTP error, a missing `result`, or a result that is not a bool).

The timeout limits each socket operation (connect, send, each read), not the whole
request. A server that answers slowly byte by byte can take longer in total. A redirect
(3xx) is never followed: it raises.
"""

import json
import os
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8181"
DEFAULT_TIMEOUT = 5.0
MAX_BODY = 1_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would resend the request, and its token, to another host."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _timeout() -> float:
    raw = os.environ.get("OPA_TIMEOUT", "")
    try:
        value = float(raw) if raw else DEFAULT_TIMEOUT
    except ValueError:
        raise ValueError("OPA_TIMEOUT must be a number of seconds") from None
    if not 0 < value <= 300:
        raise ValueError("OPA_TIMEOUT must be between 0 and 300 seconds")
    return value


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    base = os.environ.get("OPA_URL", DEFAULT_URL).rstrip("/")
    body = json.dumps(
        {"input": {"subject": subject, "action": action, "resource": resource, "context": context}}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base}/v1/data/lockwalk/allow",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=_timeout()) as reply:
            raw = reply.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"opa: HTTP {error.code}") from None
    except OSError as error:  # URLError is an OSError
        raise RuntimeError(f"opa: cannot reach the server: {type(error).__name__}") from None
    if len(raw) > MAX_BODY:
        raise RuntimeError("opa: the answer is too large")
    try:
        document = json.loads(raw)
    except ValueError:
        raise RuntimeError("opa: the answer is not JSON") from None
    if not isinstance(document, dict) or "result" not in document:
        raise RuntimeError("opa: no `result` in the answer; is data.lockwalk.allow defined?")
    result = document["result"]
    if not isinstance(result, bool):
        raise RuntimeError(f"opa: `result` is {type(result).__name__}, not a bool")
    return result
