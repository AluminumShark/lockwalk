"""decide() for Keycloak Authorization Services, asked with a UMA ticket request.

Point lockwalk at a copy of this file with `--policy python:keycloak_decide.py:decide`, or in
.lockwalk.toml:

    [policy]
    adapter = "python"
    target = "keycloak_decide.py:decide"

What you provide:

  * A Keycloak realm with a client that has Authorization Services enabled, and its
    resources, scopes and permissions.
  * subject_token(), below. Keycloak decides for the holder of an access token, so lockwalk's
    test identities (alice, bob) need a token each. How you get one (a test user's password
    grant, token exchange, a service account) is your choice and your risk, and this recipe
    does not guess it. Replace the function in your copy.

Environment:

    KEYCLOAK_URL        base URL; default http://127.0.0.1:8080
    KEYCLOAK_REALM      realm name (required)
    KEYCLOAK_CLIENT_ID  the resource server client, sent as `audience` (required)
    KEYCLOAK_TIMEOUT    seconds per request; default 5

The request is POST {KEYCLOAK_URL}/realms/{realm}/protocol/openid-connect/token with the form
grant_type=urn:ietf:params:oauth:grant-type:uma-ticket, audience, response_mode=decision and
permission="{resource.id}#{action.name}", and the subject's token as a bearer token. See
permission() to change how the resource and the scope are named. A 200 answer with
`result: true` is an allow. A 403 `access_denied` is a deny. Anything else raises. The AuthZEN
context is not sent. Tokens never appear in error messages.

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
UMA_TICKET = "urn:ietf:params:oauth:grant-type:uma-ticket"

_TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]+")
_PERMISSION_PART = re.compile(r"[^#,\s]+")
_REALM = re.compile(r"[A-Za-z0-9._~-]+")


def subject_token(subject: dict) -> str:
    """Return an access token for this AuthZEN subject. Replace this in your copy."""
    raise NotImplementedError(
        "keycloak: write subject_token(subject) so that it returns an access token for "
        f"the test identity {subject.get('id')!r}"
    )


def permission(resource: dict, action: dict) -> str:
    """The UMA permission string: a Keycloak resource (name or id) and a scope."""
    parts = (resource["id"], action["name"])
    for part in parts:
        if not isinstance(part, str) or not _PERMISSION_PART.fullmatch(part):
            raise ValueError(
                "keycloak: the resource id and the action name must be non-empty strings "
                "without '#', ',' or whitespace"
            )
    return f"{parts[0]}#{parts[1]}"


def _timeout() -> float:
    raw = os.environ.get("KEYCLOAK_TIMEOUT", "")
    try:
        value = float(raw) if raw else DEFAULT_TIMEOUT
    except ValueError:
        raise ValueError("KEYCLOAK_TIMEOUT must be a number of seconds") from None
    if not 0 < value <= 300:
        raise ValueError("KEYCLOAK_TIMEOUT must be between 0 and 300 seconds")
    return value


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"keycloak: set {name}")
    return value


def decide(subject: dict, action: dict, resource: dict, context: dict) -> bool:
    realm = _required("KEYCLOAK_REALM")
    if not _REALM.fullmatch(realm):
        raise ValueError("keycloak: KEYCLOAK_REALM has characters a realm name cannot have")
    audience = _required("KEYCLOAK_CLIENT_ID")
    token = subject_token(subject)
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise ValueError("keycloak: subject_token() must return a token string (not shown here)")
    base = os.environ.get("KEYCLOAK_URL", DEFAULT_URL).rstrip("/")
    form = urllib.parse.urlencode(
        {
            "grant_type": UMA_TICKET,
            "audience": audience,
            "response_mode": "decision",
            "permission": permission(resource, action),
        }
    )
    request = urllib.request.Request(
        f"{base}/realms/{realm}/protocol/openid-connect/token",
        data=form.encode("ascii"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=_timeout()) as reply:
            raw = reply.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        if error.code == 403:
            try:
                denied = _is_access_denied(error.read(MAX_BODY))
            except OSError as read_error:  # includes TimeoutError
                raise RuntimeError(
                    f"keycloak: cannot read the answer: {type(read_error).__name__}"
                ) from None
            if denied:
                return False
        raise RuntimeError(f"keycloak: HTTP {error.code}") from None
    except OSError as error:  # URLError is an OSError
        raise RuntimeError(f"keycloak: cannot reach the server: {type(error).__name__}") from None
    except ValueError:  # http.client puts the offending header value in its message
        raise RuntimeError("keycloak: the request could not be sent") from None
    if len(raw) > MAX_BODY:
        raise RuntimeError("keycloak: the answer is too large")
    try:
        document = json.loads(raw)
    except ValueError:
        raise RuntimeError("keycloak: the answer is not JSON") from None
    result = document.get("result") if isinstance(document, dict) else None
    if result is not True:
        # A 200 answer in decision mode carries result: true. Do not guess at anything else.
        raise RuntimeError("keycloak: a 200 answer without `result: true`")
    return True


def _is_access_denied(raw: bytes) -> bool:
    try:
        document = json.loads(raw)
    except ValueError:
        return False
    return isinstance(document, dict) and document.get("error") == "access_denied"
