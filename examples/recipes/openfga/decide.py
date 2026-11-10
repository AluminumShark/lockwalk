"""decide() for OpenFGA, asked over its Check API.

Point lockwalk at it with `--policy python:examples/recipes/openfga/decide.py:decide`, or in
.lockwalk.toml:

    [policy]
    adapter = "python"
    target = "decide.py:decide"

You provide a running OpenFGA server, a store, and an authorization model whose types and
relations match your lockwalk spec. This recipe does not write the model or any tuples.
Environment:

    OPENFGA_URL        base URL; default http://127.0.0.1:8080
    OPENFGA_STORE      store id (required)
    OPENFGA_MODEL_ID   authorization model id (optional; the store's latest model otherwise)
    OPENFGA_API_TOKEN  bearer token for a server that needs one (optional)
    OPENFGA_TIMEOUT    seconds per request; default 5

The Check tuple is built from the AuthZEN fields:

    user      "{subject.type}:{subject.id}"        for example user:alice
    relation  the action name, see RELATIONS below
    object    "{resource.type}:{resource.id}"      for example portfolio:p-alice

OpenFGA relation names cannot contain ":", so the default relation for the action
"portfolio:read" is "portfolio_read". Add a row to RELATIONS when your model uses another
name. Ids that contain ":", "#", "@", "*" or whitespace would change the meaning of the tuple, so
decide() raises on them. The AuthZEN context is not sent.

decide() returns a real bool, and raises on an HTTP error or an answer without a boolean
`allowed`. The token is never put in an error message.

The timeout limits each socket operation (connect, send, each read), not the whole
request. A server that answers slowly byte by byte can take longer in total. A redirect
(3xx) is never followed: it raises.
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT = 5.0
MAX_BODY = 1_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would resend the request, and its token, to another host."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)

# action name -> relation. An action with no row here becomes its name with ":" turned
# into "_".
RELATIONS: dict[str, str] = {}

_BAD_PART = re.compile(r"[:#@*\s]")
_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]+")


def _timeout() -> float:
    raw = os.environ.get("OPENFGA_TIMEOUT", "")
    try:
        value = float(raw) if raw else DEFAULT_TIMEOUT
    except ValueError:
        raise ValueError("OPENFGA_TIMEOUT must be a number of seconds") from None
    if not 0 < value <= 300:
        raise ValueError("OPENFGA_TIMEOUT must be between 0 and 300 seconds")
    return value


def _part(kind: str, value: object) -> str:
    if not isinstance(value, str) or not value or _BAD_PART.search(value):
        raise ValueError(
            f"openfga: {kind} must be a non-empty string without ':', '#', '@', '*' or spaces"
        )
    return value


def _object(entity: dict) -> str:
    return f"{_part('type', entity['type'])}:{_part('id', entity['id'])}"


def tuple_key(subject: dict, action: dict, resource: dict) -> dict[str, str]:
    name = action["name"]
    relation = RELATIONS.get(name) or name.replace(":", "_")
    return {
        "user": _object(subject),
        "relation": _part("relation", relation),
        "object": _object(resource),
    }


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    store = os.environ.get("OPENFGA_STORE", "")
    if not store:
        raise ValueError("openfga: set OPENFGA_STORE to the store id")
    base = os.environ.get("OPENFGA_URL", DEFAULT_URL).rstrip("/")
    payload: dict[str, object] = {"tuple_key": tuple_key(subject, action, resource)}
    model_id = os.environ.get("OPENFGA_MODEL_ID", "")
    if model_id:
        payload["authorization_model_id"] = model_id
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("OPENFGA_API_TOKEN", "")
    if token:
        if not _TOKEN.fullmatch(token):
            raise ValueError("openfga: OPENFGA_API_TOKEN is not a valid bearer token")
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{base}/stores/{urllib.parse.quote(store, safe='')}/check",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=_timeout()) as reply:
            raw = reply.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"openfga: HTTP {error.code}") from None
    except OSError as error:  # URLError is an OSError
        raise RuntimeError(f"openfga: cannot reach the server: {type(error).__name__}") from None
    except ValueError:  # http.client puts the offending header value in its message
        raise RuntimeError("openfga: the request could not be sent") from None
    if len(raw) > MAX_BODY:
        raise RuntimeError("openfga: the answer is too large")
    try:
        document = json.loads(raw)
    except ValueError:
        raise RuntimeError("openfga: the answer is not JSON") from None
    allowed = document.get("allowed") if isinstance(document, dict) else None
    if not isinstance(allowed, bool):
        raise RuntimeError("openfga: no boolean `allowed` in the answer")
    return allowed
