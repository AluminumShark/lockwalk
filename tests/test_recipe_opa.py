"""The OPA recipe (examples/recipes/opa).

The request shape and the failure modes run against a fake server on 127.0.0.1. The docker
tests start the real OPA image, published on 127.0.0.1 only, and run `lockwalk test
--no-harness` on the multi-agent demo with the recipe; they skip when Docker or the image
is missing. Pull the image with `docker pull openpolicyagent/opa:1.10.0`.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import time
import urllib.request
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from lockwalk_authzen_server import FakePdp
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from lockwalk_iam_expectations import (
    CASES,
    ESCALATIONS,
    case_statuses,
    escalations,
)
from lockwalk_net_helpers import free_port, wait_for_port
from typer.testing import CliRunner

from lockwalk import cli

OPA_IMAGE = "openpolicyagent/opa:1.10.0"
REPO_ROOT = Path(__file__).resolve().parents[1]
RECIPE = REPO_ROOT / "examples" / "recipes" / "opa"
CONFIG = REPO_ROOT / "examples" / "iam_cedar" / ".lockwalk.toml"

runner = CliRunner()


def _load():
    spec = importlib.util.spec_from_file_location("recipe_opa_decide", RECIPE / "decide.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recipe = _load()

USER = {"type": "user", "id": "alice", "properties": {"roles": ["analyst"]}}
ACTION = {"name": "market:read"}
SYMBOL = {"type": "stock_symbol", "id": "2330.TW"}


def _answer(result):
    def respond(path, body, headers):
        return 200, {"result": result}, 0.0

    return respond


# ---- fake server: request shape and failure modes ----------------------------------------


def test_the_request_is_a_post_of_the_input_document(monkeypatch):
    with FakePdp(_answer(True)) as server:
        monkeypatch.setenv("OPA_URL", server.url + "/")
        assert recipe.decide(USER, ACTION, SYMBOL, {"k": 1}) is True
    ((path, body, headers),) = server.requests
    assert path == "/v1/data/lockwalk/allow"
    assert body == {
        "input": {"subject": USER, "action": ACTION, "resource": SYMBOL, "context": {"k": 1}}
    }
    assert headers["content-type"] == "application/json"


@pytest.mark.parametrize("result", [True, False])
def test_the_result_is_a_real_bool(monkeypatch, result):
    with FakePdp(_answer(result)) as server:
        monkeypatch.setenv("OPA_URL", server.url)
        assert recipe.decide(USER, ACTION, SYMBOL, {}) is result


@pytest.mark.parametrize("result", [1, 0, "true", "false", None, {}, [True]])
def test_a_result_that_is_not_a_bool_raises(monkeypatch, result):
    with FakePdp(_answer(result)) as server:
        monkeypatch.setenv("OPA_URL", server.url)
        with pytest.raises(RuntimeError, match="not a bool"):
            recipe.decide(USER, ACTION, SYMBOL, {})


@pytest.mark.parametrize("payload", [{}, {"decision_id": "x"}, []])
def test_a_missing_result_raises(monkeypatch, payload):
    with FakePdp(lambda path, body, headers: (200, payload, 0.0)) as server:
        monkeypatch.setenv("OPA_URL", server.url)
        with pytest.raises(RuntimeError, match="no `result`"):
            recipe.decide(USER, ACTION, SYMBOL, {})


def test_a_non_json_answer_raises(monkeypatch):
    with FakePdp(lambda path, body, headers: (200, b"<html>", 0.0)) as server:
        monkeypatch.setenv("OPA_URL", server.url)
        with pytest.raises(RuntimeError, match="not JSON"):
            recipe.decide(USER, ACTION, SYMBOL, {})


def test_an_http_error_raises_without_the_url(monkeypatch):
    with FakePdp(lambda path, body, headers: (500, b"boom", 0.0)) as server:
        monkeypatch.setenv("OPA_URL", server.url)
        with pytest.raises(RuntimeError, match="HTTP 500") as caught:
            recipe.decide(USER, ACTION, SYMBOL, {})
    assert server.url not in str(caught.value)


def test_an_unreachable_server_raises_without_credentials(monkeypatch):
    monkeypatch.setenv("OPA_URL", f"http://user:s3cret@127.0.0.1:{free_port()}")
    with pytest.raises(RuntimeError, match="cannot reach") as caught:
        recipe.decide(USER, ACTION, SYMBOL, {})
    assert "s3cret" not in str(caught.value)


def test_a_slow_server_times_out(monkeypatch):
    with FakePdp(lambda path, body, headers: (200, {"result": True}, 2.0)) as server:
        monkeypatch.setenv("OPA_URL", server.url)
        monkeypatch.setenv("OPA_TIMEOUT", "0.2")
        with pytest.raises(RuntimeError, match="cannot reach"):
            recipe.decide(USER, ACTION, SYMBOL, {})


@pytest.mark.parametrize("value", ["abc", "0", "-1", "1000"])
def test_a_bad_timeout_setting_raises(monkeypatch, value):
    monkeypatch.setenv("OPA_TIMEOUT", value)
    with pytest.raises(ValueError, match="OPA_TIMEOUT"):
        recipe.decide(USER, ACTION, SYMBOL, {})


# ---- the real OPA image --------------------------------------------------------------------


def _docker(*args: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def _skip_reason() -> str | None:
    if shutil.which("docker") is None:
        return "docker is not installed"
    try:
        if _docker("info").returncode != 0:
            return "the docker daemon is not running"
        if _docker("image", "inspect", OPA_IMAGE).returncode != 0:
            return f"the OPA image is missing; run: docker pull {OPA_IMAGE}"
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"docker does not answer: {error}"
    return None


def _wait_healthy(port: int, name: str) -> None:
    wait_for_port(port, timeout=30.0)
    deadline = time.monotonic() + 30.0
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        running = _docker("inspect", "-f", "{{.State.Running}}", name)
        if running.returncode != 0 or running.stdout.strip() != "true":
            logs = _docker("logs", name)
            raise RuntimeError(f"OPA exited: {(logs.stdout + logs.stderr)[-500:]}")
        try:
            with urllib.request.urlopen(url, timeout=2) as reply:
                if reply.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError(f"OPA did not become healthy on port {port}")


@pytest.fixture(scope="module")
def opa_url() -> Iterator[str]:
    reason = _skip_reason()
    if reason is not None:
        pytest.skip(reason)
    name = f"lockwalk-opa-test-{uuid.uuid4().hex[:8]}"
    try:
        result = _docker(
            "run", "--rm", "-d", "--name", name,
            "-p", "127.0.0.1::8181",
            "-v", f"{RECIPE / 'policy.rego'}:/policy/policy.rego:ro",
            OPA_IMAGE, "run", "--server", "--addr=0.0.0.0:8181", "/policy/policy.rego",
        )  # fmt: skip
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {result.stderr.strip()}")
        published = _docker("port", name, "8181")
        port = int(published.stdout.splitlines()[0].rsplit(":", 1)[1])
        _wait_healthy(port, name)
        yield f"http://127.0.0.1:{port}"
    finally:
        _docker("rm", "-f", name)


@pytest.fixture(scope="module")
def default_run(opa_url: str, tmp_path_factory: pytest.TempPathFactory):
    output = tmp_path_factory.mktemp("opa")
    # The decide() worker is a subprocess; it inherits this environment.
    previous = os.environ.get("OPA_URL")
    os.environ["OPA_URL"] = opa_url
    try:
        result = runner.invoke(
            cli.app,
            [
                "test",
                "--config", str(CONFIG),
                "--no-harness",
                "--output-dir", str(output),
                "--policy", f"python:{RECIPE / 'decide.py'}:decide",
            ],
        )  # fmt: skip
    finally:
        if previous is None:
            del os.environ["OPA_URL"]
        else:
            os.environ["OPA_URL"] = previous
    path = output / "coverage.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return result, report


@pytest.mark.docker
def test_opa_matches_the_reference_on_cases_and_escalations(default_run):
    result, report = default_run
    assert result.exit_code == 1, result.stdout
    assert report is not None
    assert case_statuses(report) == CASES
    assert escalations(report) == ESCALATIONS
    assert all(control["allowed"] for control in report["controls"])
    assert report["policy_adapter"].startswith("python:")


@pytest.mark.docker
def test_opa_answers_plain_bools_for_the_demo_rules(opa_url, monkeypatch):
    monkeypatch.setenv("OPA_URL", opa_url)
    bob = {"type": "user", "id": "bob", "properties": {"roles": ["trader"]}}
    order = {"type": "order", "id": "o-1", "properties": {"account_owner": "alice"}}
    assert recipe.decide(bob, {"name": "trade:execute"}, order, {}) is False
    bot = {"type": "agent", "id": "trade-agent", "properties": {"roles": ["service_agent"]}}
    assert recipe.decide(bot, {"name": "trade:execute"}, order, {}) is True
    nobody = {"type": "user", "id": "eve"}  # no roles at all: denied, not an error
    assert recipe.decide(nobody, ACTION, SYMBOL, {}) is False


def test_the_compose_file_pins_the_image_the_tests_use():
    compose = (RECIPE / "docker-compose.yml").read_text(encoding="utf-8")
    images = [
        line.split("image:", 1)[1].strip() for line in compose.splitlines() if "image:" in line
    ]
    assert images == [OPA_IMAGE]
    assert '"127.0.0.1:8181:8181"' in compose


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed(monkeypatch, status):
    with FakePdp(_answer(True)) as elsewhere, FakePdp(lambda p, b, h: (status, b"", 0.0)) as front:
        front.response_headers["Location"] = elsewhere.url + "/v1/data/lockwalk/allow"
        monkeypatch.setenv("OPA_URL", front.url)
        with pytest.raises(RuntimeError, match=f"HTTP {status}"):
            recipe.decide(USER, ACTION, SYMBOL, {})
    assert elsewhere.requests == []
