"""The Keycloak recipe (examples/recipes/keycloak), against a fake server on 127.0.0.1.

The fake token endpoint checks the request shape (path, form fields, bearer token) and
answers like Keycloak in decision mode. No real Keycloak runs.
"""

import importlib.util
import json
import threading
import urllib.error
import urllib.parse
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from lockwalk_net_helpers import free_port

RECIPE = Path(__file__).resolve().parents[1] / "examples" / "recipes" / "keycloak"


def _load():
    spec = importlib.util.spec_from_file_location("recipe_keycloak_decide", RECIPE / "decide.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recipe = _load()

USER = {"type": "user", "id": "alice"}
ACTION = {"name": "read"}
RESOURCE = {"type": "portfolio", "id": "p-alice"}
TOKEN = "eyJhbGciOi.payload.sig-nature"


class FakeKeycloak:
    """Records (path, form, headers) and answers with a fixed (status, body, delay)."""

    def __init__(self, status=200, body=None, delay=0.0):
        self.reply = (status, {"result": True} if body is None else body, delay)
        self.requests = []
        self.headers = {}  # extra response headers, for example Location
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode("ascii"))
                headers = {key.lower(): value for key, value in self.headers.items()}
                outer.requests.append((self.path, form, headers))
                status, body, delay = outer.reply
                if delay:
                    threading.Event().wait(delay)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                try:
                    self.send_response(status)
                    for name, value in outer.headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass  # the client gave up (a timeout test)

            def log_message(self, format, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_REALM", "demo")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "trading-api")
    monkeypatch.setattr(recipe, "subject_token", lambda subject: TOKEN)


def test_the_uma_ticket_request_has_the_documented_shape(monkeypatch):
    with FakeKeycloak() as server:
        monkeypatch.setenv("KEYCLOAK_URL", server.url + "/")
        assert recipe.decide(USER, ACTION, RESOURCE, {"x": 1}) is True
    ((path, form, headers),) = server.requests
    assert path == "/realms/demo/protocol/openid-connect/token"
    assert form == {
        "grant_type": ["urn:ietf:params:oauth:grant-type:uma-ticket"],
        "audience": ["trading-api"],
        "response_mode": ["decision"],
        "permission": ["p-alice#read"],
    }
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert headers["content-type"] == "application/x-www-form-urlencoded"


def test_the_token_comes_from_the_subject(monkeypatch):
    seen = []
    monkeypatch.setattr(recipe, "subject_token", lambda subject: seen.append(subject) or TOKEN)
    with FakeKeycloak() as server:
        monkeypatch.setenv("KEYCLOAK_URL", server.url)
        recipe.decide(USER, ACTION, RESOURCE, {})
    assert seen == [USER]


def test_a_403_access_denied_is_a_deny(monkeypatch):
    body = {"error": "access_denied", "error_description": "not_authorized"}
    with FakeKeycloak(403, body) as server:
        monkeypatch.setenv("KEYCLOAK_URL", server.url)
        assert recipe.decide(USER, ACTION, RESOURCE, {}) is False


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (403, {"error": "invalid_scope"}),
        (403, b"<html>"),
        (401, {"error": "invalid_token"}),
        (500, {"error": "server_error"}),
        (200, {"result": False}),
        (200, {"result": 1}),
        (200, {}),
        (200, b"nope"),
    ],
)
def test_anything_else_raises(monkeypatch, status, body):
    with FakeKeycloak(status, body) as server:
        monkeypatch.setenv("KEYCLOAK_URL", server.url)
        with pytest.raises(RuntimeError, match=r"^keycloak: ") as caught:
            recipe.decide(USER, ACTION, RESOURCE, {})
    assert TOKEN not in str(caught.value)


def test_the_default_subject_token_function_says_what_to_write(monkeypatch):
    monkeypatch.undo()  # drop the autouse fake of subject_token
    monkeypatch.setenv("KEYCLOAK_REALM", "demo")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "trading-api")
    fresh = _load()
    with pytest.raises(NotImplementedError, match="subject_token"):
        fresh.decide(USER, ACTION, RESOURCE, {})


@pytest.mark.parametrize("token", ["", "a b", "x\r\nInjected: 1", None, 5])
def test_a_malformed_token_raises_without_showing_it(monkeypatch, token):
    monkeypatch.setattr(recipe, "subject_token", lambda subject: token)
    with pytest.raises(ValueError, match="token string") as caught:
        recipe.decide(USER, ACTION, RESOURCE, {})
    assert "Injected" not in str(caught.value)


@pytest.mark.parametrize("name", ["KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID"])
def test_a_missing_setting_raises(monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(ValueError, match=name):
        recipe.decide(USER, ACTION, RESOURCE, {})


def test_a_realm_with_a_slash_raises(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_REALM", "demo/../master")
    with pytest.raises(ValueError, match="realm"):
        recipe.decide(USER, ACTION, RESOURCE, {})


def test_an_unreachable_server_raises_without_the_token(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_URL", f"http://127.0.0.1:{free_port()}")
    with pytest.raises(RuntimeError, match="cannot reach") as caught:
        recipe.decide(USER, ACTION, RESOURCE, {})
    assert TOKEN not in str(caught.value)


def test_a_slow_server_times_out(monkeypatch):
    with FakeKeycloak(delay=2.0) as server:
        monkeypatch.setenv("KEYCLOAK_URL", server.url)
        monkeypatch.setenv("KEYCLOAK_TIMEOUT", "0.2")
        with pytest.raises(RuntimeError, match="cannot reach"):
            recipe.decide(USER, ACTION, RESOURCE, {})


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed_and_the_token_stays(monkeypatch, status):
    with FakeKeycloak() as elsewhere, FakeKeycloak(status, b"") as front:
        front.headers["Location"] = elsewhere.url + "/realms/demo/protocol/openid-connect/token"
        monkeypatch.setenv("KEYCLOAK_URL", front.url)
        with pytest.raises(RuntimeError, match=f"HTTP {status}") as caught:
            recipe.decide(USER, ACTION, RESOURCE, {})
    assert elsewhere.requests == []
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize(
    ("resource_id", "action_name"),
    [
        ("p#1", "read"),
        ("p,1", "read"),
        ("", "read"),
        ("p 1", "read"),
        ("p-1", "a,b"),
        ("p-1", "a#b"),
        ("p-1", ""),
    ],
)
def test_a_permission_part_that_changes_the_request_raises(resource_id, action_name):
    resource = {"type": "portfolio", "id": resource_id}
    with pytest.raises(ValueError, match="without '#'"):
        recipe.decide(USER, {"name": action_name}, resource, {})


def test_a_slow_403_body_raises_a_clean_error(monkeypatch):
    class Slow(urllib.error.HTTPError):
        def read(self, n=-1):
            raise TimeoutError("timed out")

    def refuse(request, timeout):
        raise Slow("http://x", 403, "Forbidden", Message(), None)

    monkeypatch.setattr(recipe._OPENER, "open", refuse)
    with pytest.raises(RuntimeError, match="cannot read the answer: TimeoutError"):
        recipe.decide(USER, ACTION, RESOURCE, {})
