"""The OpenFGA recipe (examples/recipes/openfga), against a fake server on 127.0.0.1.

The fake checks the request shape (path, tuple, headers) and answers. No real OpenFGA runs.
"""

import importlib.util
from pathlib import Path

import pytest
from lockwalk_authzen_server import FakePdp
from lockwalk_net_helpers import free_port

RECIPE = Path(__file__).resolve().parents[1] / "examples" / "recipes" / "openfga"


def _load():
    spec = importlib.util.spec_from_file_location("recipe_openfga_decide", RECIPE / "decide.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recipe = _load()

USER = {"type": "user", "id": "alice", "properties": {"roles": ["analyst"]}}
ACTION = {"name": "portfolio:read"}
PORTFOLIO = {"type": "portfolio", "id": "p-alice"}


def _answer(payload):
    return lambda path, body, headers: (200, payload, 0.0)


def test_the_check_request_has_the_documented_shape(monkeypatch):
    with FakePdp(_answer({"allowed": True})) as server:
        monkeypatch.setenv("OPENFGA_URL", server.url + "/")
        monkeypatch.setenv("OPENFGA_STORE", "01ABC")
        assert recipe.decide(USER, ACTION, PORTFOLIO, {"x": 1}) is True
    ((path, body, headers),) = server.requests
    assert path == "/stores/01ABC/check"
    assert body == {
        "tuple_key": {
            "user": "user:alice",
            "relation": "portfolio_read",
            "object": "portfolio:p-alice",
        }
    }
    assert headers["content-type"] == "application/json"
    assert "authorization" not in headers


def test_model_id_and_token_are_sent_when_set(monkeypatch):
    with FakePdp(_answer({"allowed": False})) as server:
        monkeypatch.setenv("OPENFGA_URL", server.url)
        monkeypatch.setenv("OPENFGA_STORE", "01ABC")
        monkeypatch.setenv("OPENFGA_MODEL_ID", "01MODEL")
        monkeypatch.setenv("OPENFGA_API_TOKEN", "t0ken")
        assert recipe.decide(USER, ACTION, PORTFOLIO, {}) is False
    ((_, body, headers),) = server.requests
    assert body["authorization_model_id"] == "01MODEL"
    assert headers["authorization"] == "Bearer t0ken"


def test_a_relations_row_overrides_the_default(monkeypatch):
    monkeypatch.setitem(recipe.RELATIONS, "portfolio:read", "viewer")
    key = recipe.tuple_key(USER, ACTION, PORTFOLIO)
    assert key["relation"] == "viewer"


def test_the_store_id_is_url_quoted(monkeypatch):
    with FakePdp(_answer({"allowed": True})) as server:
        monkeypatch.setenv("OPENFGA_URL", server.url)
        monkeypatch.setenv("OPENFGA_STORE", "a/b c")
        recipe.decide(USER, ACTION, PORTFOLIO, {})
    assert server.requests[0][0] == "/stores/a%2Fb%20c/check"


def test_a_missing_store_raises(monkeypatch):
    monkeypatch.delenv("OPENFGA_STORE", raising=False)
    with pytest.raises(ValueError, match="OPENFGA_STORE"):
        recipe.decide(USER, ACTION, PORTFOLIO, {})


@pytest.mark.parametrize("bad", ["al:ice", "al#ice", "al@ice", "al*ice", "*", "al ice", ""])
def test_an_id_that_would_change_the_tuple_raises(monkeypatch, bad):
    monkeypatch.setenv("OPENFGA_STORE", "01ABC")
    with pytest.raises(ValueError, match="without"):
        recipe.decide({"type": "user", "id": bad}, ACTION, PORTFOLIO, {})
    with pytest.raises(ValueError, match="without"):
        recipe.decide(USER, ACTION, {"type": "portfolio", "id": bad}, {})


@pytest.mark.parametrize(
    "payload", [{}, {"allowed": 1}, {"allowed": "true"}, {"allowed": None}, []]
)
def test_an_answer_without_a_real_bool_raises(monkeypatch, payload):
    with FakePdp(_answer(payload)) as server:
        monkeypatch.setenv("OPENFGA_URL", server.url)
        monkeypatch.setenv("OPENFGA_STORE", "01ABC")
        with pytest.raises(RuntimeError, match="allowed"):
            recipe.decide(USER, ACTION, PORTFOLIO, {})


def test_an_http_error_raises_without_the_token(monkeypatch):
    with FakePdp(lambda path, body, headers: (401, {"code": "unauthenticated"}, 0.0)) as server:
        monkeypatch.setenv("OPENFGA_URL", server.url)
        monkeypatch.setenv("OPENFGA_STORE", "01ABC")
        monkeypatch.setenv("OPENFGA_API_TOKEN", "t0ken")
        with pytest.raises(RuntimeError, match="HTTP 401") as caught:
            recipe.decide(USER, ACTION, PORTFOLIO, {})
    assert "t0ken" not in str(caught.value)


def test_an_unreachable_server_raises(monkeypatch):
    monkeypatch.setenv("OPENFGA_URL", f"http://127.0.0.1:{free_port()}")
    monkeypatch.setenv("OPENFGA_STORE", "01ABC")
    monkeypatch.setenv("OPENFGA_API_TOKEN", "t0ken")
    with pytest.raises(RuntimeError, match="cannot reach") as caught:
        recipe.decide(USER, ACTION, PORTFOLIO, {})
    assert "t0ken" not in str(caught.value)


def test_a_slow_server_times_out(monkeypatch):
    with FakePdp(lambda path, body, headers: (200, {"allowed": True}, 2.0)) as server:
        monkeypatch.setenv("OPENFGA_URL", server.url)
        monkeypatch.setenv("OPENFGA_STORE", "01ABC")
        monkeypatch.setenv("OPENFGA_TIMEOUT", "0.2")
        with pytest.raises(RuntimeError, match="cannot reach"):
            recipe.decide(USER, ACTION, PORTFOLIO, {})


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed_and_the_token_stays(monkeypatch, status):
    with (
        FakePdp(_answer({"allowed": True})) as elsewhere,
        FakePdp(lambda p, b, h: (status, b"", 0.0)) as front,
    ):
        front.response_headers["Location"] = elsewhere.url + "/stores/01ABC/check"
        monkeypatch.setenv("OPENFGA_URL", front.url)
        monkeypatch.setenv("OPENFGA_STORE", "01ABC")
        monkeypatch.setenv("OPENFGA_API_TOKEN", "t0ken")
        with pytest.raises(RuntimeError, match=f"HTTP {status}") as caught:
            recipe.decide(USER, ACTION, PORTFOLIO, {})
    assert elsewhere.requests == []
    assert "t0ken" not in str(caught.value)


@pytest.mark.parametrize("token", ["SECRET\n", "SE CRET", "SECRET\r\nX: 1"])
def test_a_malformed_token_raises_without_showing_it(monkeypatch, token):
    monkeypatch.setenv("OPENFGA_STORE", "01ABC")
    monkeypatch.setenv("OPENFGA_API_TOKEN", token)
    with pytest.raises(ValueError, match="not a valid bearer token") as caught:
        recipe.decide(USER, ACTION, PORTFOLIO, {})
    assert "SECRET" not in str(caught.value)


def test_a_header_value_error_from_http_client_has_no_detail(monkeypatch):
    def refuse(request, timeout):
        raise ValueError("Invalid header value b'Bearer SECRET'")

    monkeypatch.setenv("OPENFGA_STORE", "01ABC")
    monkeypatch.setattr(recipe._OPENER, "open", refuse)
    with pytest.raises(RuntimeError, match="could not be sent") as caught:
        recipe.decide(USER, ACTION, PORTFOLIO, {})
    assert "SECRET" not in str(caught.value)
