"""MCP env and headers, ${VAR} expansion, quiet SDK logging, and optional MCP sources.

Every secret here is a unique marker. The tests assert that it never shows up in a
SourceResult, an error, a label, a warning, a snapshot, or captured terminal output.
"""

import hashlib
import importlib.util
import json
import logging
import os
import subprocess
import sys
import textwrap
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import pytest
from lockwalk_net_helpers import free_port, wait_for_port
from pydantic import TypeAdapter, ValidationError

from lockwalk.config import McpSourceConfig, load_config
from lockwalk.errors import StructuralError
from lockwalk.inventory.mcp import NOT_INSTALLED, McpSource, command_name, quiet_mcp_logging
from lockwalk.inventory.mcp_naming import ServerConfig, server_name
from lockwalk.inventory.merge import merge_inventory
from lockwalk.masking import (
    SecretValues,
    UnsetVariableError,
    expand_value,
    hide_pydantic_inputs,
)
from lockwalk.models import SourceRef, SourceResult, ToolDescriptor
from lockwalk.snapshot import SnapshotRefused, snapshot_document

SERVER = Path(__file__).resolve().parent / "fixtures_mcp_options" / "options_server.py"
SECRET = "LWSECRET" + uuid.uuid4().hex
CAPTURED = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
NEWLINE = chr(10)


def digest(value: str) -> str:
    """The description options_server.py gives env_<NAME> tools (see that file)."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def stdio_config(*server_args: str, **fields: Any) -> McpSourceConfig:
    return McpSourceConfig(command=sys.executable, args=(str(SERVER), *server_args), **fields)


def descriptions(result: SourceResult) -> dict[str, str | None]:
    return {tool.name: tool.description for tool in result.tools}


def assert_hidden(result: SourceResult, *secrets: str) -> None:
    text = NEWLINE.join([result.model_dump_json(), repr(result), str(result)])
    for secret in secrets:
        assert secret not in text


# ---- config ----


def test_env_only_applies_to_stdio_servers():
    with pytest.raises(ValidationError, match="'env' only applies to stdio servers"):
        McpSourceConfig(target="https://h/mcp", env={"A": "b"})
    assert McpSourceConfig(target="stdio://s.py", env={"A": "b"}).env == {"A": "b"}
    assert McpSourceConfig(command="node", env={"A": "b"}).env == {"A": "b"}
    assert McpSourceConfig(target="https://h/mcp", env={}).env == {}


@pytest.mark.parametrize("connect", [{"target": "stdio://s.py"}, {"command": "node"}])
def test_headers_only_apply_to_http_servers(connect):
    with pytest.raises(ValidationError, match=r"'headers' only applies to http\(s\) servers"):
        McpSourceConfig(**connect, headers={"X-Key": "v"})


def test_headers_on_http_targets():
    config = McpSourceConfig(target="http://h/mcp", headers={"Authorization": "Bearer ${T}"})
    assert config.headers == {"Authorization": "Bearer ${T}"}
    assert McpSourceConfig(target="https://h/mcp").headers == {}


@pytest.mark.parametrize("key", ["", " A", "A B", "A\tB", "bad" + chr(7)])
def test_keys_must_be_non_empty_without_whitespace(key):
    with pytest.raises(ValidationError, match="names in 'env' must be non-empty"):
        McpSourceConfig(command="node", env={key: "v"})
    with pytest.raises(ValidationError, match="names in 'headers' must be non-empty"):
        McpSourceConfig(target="https://h/mcp", headers={key: "v"})


def test_env_names_cannot_hold_an_equals_sign():
    with pytest.raises(ValidationError, match="env names must not contain '='"):
        McpSourceConfig(command="node", env={"A=B": "v"})


def test_header_names_must_be_http_tokens():
    with pytest.raises(ValidationError, match=r"'X\(Y\)' is not a valid HTTP header name"):
        McpSourceConfig(target="https://h/mcp", headers={"X(Y)": "v"})


@pytest.mark.parametrize("bad", ["pa$word", "$", "${", "${}", "${A", "${A B}", "${A=B}", "$$$"])
def test_a_bad_dollar_names_the_key_but_never_the_value(write, bad):
    path = write(
        ".lockwalk.toml",
        f"[[inventory.mcp]]\ncommand = 'node'\nenv = {{API_KEY = 'TOPSECRET{bad}'}}\n",
    )
    with pytest.raises(StructuralError) as info:
        load_config(path)
    [problem] = info.value.problems
    assert problem.startswith("inventory.mcp[0].env: ")
    assert "env 'API_KEY': a '$' must start a '${NAME}' reference or be written as '$$'" in (
        problem
    )
    assert "TOPSECRET" not in str(info.value)
    assert "TOPSECRET" not in str(info.value.__cause__)


@pytest.mark.parametrize("good", ["", "plain", "${A}", "x$$y", "${A}${B}", "${ProgramFiles(x86)}"])
def test_good_values(good):
    assert McpSourceConfig(command="node", env={"K": good}).env == {"K": good}


def test_literal_header_values_must_be_printable_ascii():
    with pytest.raises(ValidationError, match="header 'X-Key': the value must be printable ASCII"):
        McpSourceConfig(target="https://h/mcp", headers={"X-Key": "caf" + chr(0xE9)})
    with pytest.raises(ValidationError, match="header 'X-Key': the value must be printable ASCII"):
        McpSourceConfig(target="https://h/mcp", headers={"X-Key": "a" + NEWLINE + "b"})
    assert McpSourceConfig(target="https://h/mcp", headers={"X-Key": "${V}\tx"})


def test_config_errors_and_reprs_never_show_values(write):
    config = McpSourceConfig(command="node", env={"K": "TOPSECRET"})
    assert "TOPSECRET" not in repr(config)
    assert "TOPSECRET" not in str(config)
    path = write(
        ".lockwalk.toml",
        "[[inventory.mcp]]\ntarget = 'https://h/mcp'\nenv = {K = 'TOPSECRET'}\n",
    )
    with pytest.raises(StructuralError) as info:
        load_config(path)
    [problem] = info.value.problems
    assert problem == "inventory.mcp[0]: Value error, 'env' only applies to stdio servers"
    assert "TOPSECRET" not in str(info.value.__cause__)


def test_non_string_values_are_rejected_without_showing_them(write):
    path = write(
        ".lockwalk.toml",
        "[[inventory.mcp]]\ntarget = 'https://h/mcp'\nheaders = {X-Key = 987654321}\n",
    )
    with pytest.raises(StructuralError) as info:
        load_config(path)
    [problem] = info.value.problems
    assert problem.startswith("inventory.mcp[0].headers.X-Key: Input should be a valid string")
    assert "987654321" not in str(info.value.__cause__)


# ---- ${VAR} expansion ----


def test_expand_value(monkeypatch):
    monkeypatch.setenv("LW_A", "alpha")
    monkeypatch.setenv("LW_EMPTY", "")
    assert expand_value("x-${LW_A}-$$-${LW_A}") == "x-alpha-$-alpha"
    assert expand_value("plain") == "plain"
    assert expand_value("[${LW_EMPTY}]") == "[]"


def test_expansion_runs_once(monkeypatch):
    monkeypatch.setenv("LW_A", "alpha")
    monkeypatch.setenv("LW_TRICKY", "${LW_A}$$")
    assert expand_value("${LW_TRICKY}") == "${LW_A}$$"


def test_expand_value_names_a_missing_variable(monkeypatch):
    monkeypatch.delenv("LW_NOT_SET_ANYWHERE", raising=False)
    with pytest.raises(UnsetVariableError) as info:
        expand_value("x${LW_NOT_SET_ANYWHERE}")
    assert str(info.value) == "environment variable 'LW_NOT_SET_ANYWHERE' is not set"


def test_secret_values_are_hidden_in_escaped_forms():
    value = "it's" + NEWLINE + "a-" + SECRET + chr(0xE9)
    secrets = SecretValues([("env 'API_KEY'", value), ("env 'EMPTY'", "")])
    forms = [value, repr(value), repr(value.encode("utf-8")), json.dumps(value), ascii(value)]
    for form in forms:
        hidden = secrets.scrub(f"error: {form}!")
        assert SECRET not in hidden
        assert hidden.startswith("error: ")
        assert "<hidden env 'API_KEY'>" in hidden
        assert secrets.found_in(form) == "env 'API_KEY'"
    assert secrets.scrub("nothing here") == "nothing here"
    assert secrets.found_in("nothing here") is None
    assert SecretValues([]).scrub("x") == "x"


def test_hidden_text_names_the_key_but_never_the_value():
    token = "LWTOKEN" + uuid.uuid4().hex
    secrets = SecretValues([("header 'Authorization'", f"Bearer {token}"), ("env 'K'", token)])
    assert secrets.scrub(f"got Bearer {token}") == "got <hidden header 'Authorization'>"
    assert secrets.scrub(f"bad {token}") == "bad <hidden env 'K'>"
    assert secrets.found_in(f"x {token} y") == "env 'K'"


def test_hiding_takes_one_pass():
    """A key name that looks like another value is not hidden again inside a marker."""
    secrets = SecretValues([("env 'ABCDEFGH1'", "first-secret-1"), ("env 'B'", "ABCDEFGH1")])
    assert secrets.scrub("first-secret-1") == "<hidden env 'ABCDEFGH1'>"


def test_a_value_holding_a_quote_is_hidden_inside_reprs_of_either_quote_kind():
    value = "LWSEC'RET" + uuid.uuid4().hex
    secrets = SecretValues([("env 'K'", value)])
    # Text that holds both quote kinds makes repr quote with "'" and escape the value's "'".
    for text in (repr('x"y ' + value), repr(b'x"y ' + value.encode("utf-8")), repr(value)):
        assert value[-12:] in text
        assert value[-12:] not in secrets.scrub(f"bad token {text}")


def validation_error(value: object) -> ValidationError:
    try:
        TypeAdapter(dict).validate_python(value)
    except ValidationError as exc:
        return exc
    raise AssertionError("the value was valid")


@pytest.mark.parametrize("wrapped", [False, True])
def test_pydantic_input_reprs_never_reach_errors(monkeypatch, tmp_path, wrapped):
    """pydantic shortens a long input to its ends, so the value cannot be matched whole."""
    monkeypatch.setenv("LW_TEST_SOURCE", SECRET)
    error = validation_error("token=" + SECRET * 2)
    assert SECRET[:12] in str(error)  # what pydantic would show

    def fake_run(func, captured, errlog):
        # The SDK raises the ValidationError itself, or quotes it in its own message.
        raise RuntimeError(f"Failed to parse JSON response: {error}") if wrapped else error

    monkeypatch.setattr(anyio, "run", fake_run)
    config = stdio_config(env={"K": "${LW_TEST_SOURCE}"})
    result = McpSource(config, tmp_path).read()
    assert result.error
    assert SECRET[:12] not in result.error
    assert SECRET[-12:] not in result.error
    assert "dict" in result.error or "Dictionary" in result.error


def test_pydantic_inputs_are_hidden_line_by_line():
    text = NEWLINE.join(
        [
            "2 validation errors for X",
            "a  Field required [type=missing, input_value={'t': 'SECRET'}, input_type=dict]",
            "b  no input here",
            ", input_type=str before input_value=late",
        ]
    )
    assert hide_pydantic_inputs(text).split(NEWLINE) == [
        "2 validation errors for X",
        "a  Field required [type=missing, input_value=<not shown>, input_type=dict]",
        "b  no input here",
        ", input_type=str before input_value=late",
    ]


def test_hiding_pydantic_inputs_takes_linear_time():
    """A server can send 'input_value=' * N; a backtracking regex would stall for minutes."""
    start = time.perf_counter()
    assert hide_pydantic_inputs("input_value=" * 200_000) == "input_value=" * 200_000
    assert time.perf_counter() - start < 1.0


def test_scrub_takes_linear_time_on_5_mb_of_near_matches():
    token = "LWSECRET" + uuid.uuid4().hex
    quoted = "LWSEC'RET" + uuid.uuid4().hex  # several distinct forms
    secrets = SecretValues([("header 'Authorization'", token), ("env 'K'", quoted)])
    unit = token[:-1] + "#" + quoted[:-1] + "#" + token + " "
    text = unit * (5 * 1024 * 1024 // len(unit))
    start = time.perf_counter()
    hidden = secrets.scrub(text)
    found = secrets.found_in(text)
    assert time.perf_counter() - start < 5.0
    assert token not in hidden
    assert hidden.count("<hidden header 'Authorization'>") == text.count(token)
    assert found == "header 'Authorization'"


def test_values_are_hidden_before_errors_are_cut_short(monkeypatch, tmp_path):
    """Cutting first would keep the start of a secret that straddles the length limit."""
    monkeypatch.setenv("LW_TEST_SOURCE", SECRET)

    def fake_run(func, captured, errlog):
        # The secret starts before character 300, and the text runs on past it.
        raise RuntimeError("x" * 270 + SECRET + " and more" * 20)

    monkeypatch.setattr(anyio, "run", fake_run)
    result = McpSource(stdio_config(env={"K": "${LW_TEST_SOURCE}"}), tmp_path).read()
    assert result.error
    assert len(result.error) == 300
    assert SECRET[:12] not in result.error
    assert result.error.endswith("...")


def test_padded_header_values_are_rejected():
    for value in (" x", "x ", "\tx", "${T} ", " $$"):
        with pytest.raises(
            ValidationError, match="header 'X-Key': the value must not start or end with whitespace"
        ):
            McpSourceConfig(target="https://h/mcp", headers={"X-Key": value})
    assert McpSourceConfig(target="https://h/mcp", headers={"X-Key": "${A} ${B}"})


def test_padded_header_values_are_rejected_after_expansion(monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_TOKEN", "short ")
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp", headers={"X-Key": "${LW_TEST_TOKEN}"})
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error == "header 'X-Key': the value must not start or end with whitespace"


def test_short_values_are_too_common_to_hide():
    """'1' or 'info' would garble messages and drop tools such as get_info."""
    secrets = SecretValues([("env 'A'", "1"), ("env 'B'", "info"), ("env 'C'", "1234567")])
    assert not secrets
    assert secrets.scrub("get_info v1 1234567") == "get_info v1 1234567"
    pin = SecretValues([("header 'X-Pin'", "12345678")])
    assert pin.scrub("pin 12345678") == "pin <hidden header 'X-Pin'>"


def test_the_value_of_each_variable_is_hidden_on_its_own(monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_TOKEN", SECRET)
    config = McpSourceConfig(
        target="http://127.0.0.1:1/mcp", headers={"Authorization": "Bearer ${LW_TEST_TOKEN}"}
    )
    _, secrets = McpSource(config, tmp_path)._prepare()
    hidden = "<hidden header 'Authorization'>"
    assert secrets.scrub(f"bad token {SECRET}") == f"bad token {hidden}"
    assert secrets.scrub(f"got Bearer {SECRET}") == f"got {hidden}"


# ---- env reaches a stdio server ----


def test_env_reaches_a_stdio_server(monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_SOURCE", SECRET)
    monkeypatch.setenv("LW_PARENT_ONLY", "from-the-parent")
    config = stdio_config(
        *("--report-env", "LW_SECRET", "--report-env", "LW_LITERAL"),
        *("--report-env", "LW_PARENT_ONLY", "--report-env", "PATH"),
        env={"LW_SECRET": "a-${LW_TEST_SOURCE}-$$", "LW_LITERAL": "plain"},
    )
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error
    seen = descriptions(result)
    assert seen["env_LW_SECRET"] == digest(f"a-{SECRET}-$")
    assert seen["env_LW_LITERAL"] == digest("plain")
    # env is added to the minimal stdio environment; the rest of ours is not passed on.
    assert seen["env_LW_PARENT_ONLY"] == "unset"
    assert seen["env_PATH"] != "unset"
    assert result.source.label == "mcp:options-test"
    assert_hidden(result, SECRET)


def test_env_reaches_a_stdio_short_form_target(monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_SOURCE", SECRET)
    config = McpSourceConfig(
        target=f"stdio://{SERVER}",
        env={"LW_REPORT_ENV": "LW_SECRET", "LW_SECRET": "${LW_TEST_SOURCE}"},
    )
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error
    assert descriptions(result)["env_LW_SECRET"] == digest(SECRET)
    assert_hidden(result, SECRET)


def test_a_missing_variable_fails_the_source(monkeypatch, tmp_path):
    monkeypatch.delenv("LW_NOT_SET_ANYWHERE", raising=False)
    marker = tmp_path / "started.txt"
    code = f"open({str(marker)!r}, 'w').close()"
    config = McpSourceConfig(
        command=sys.executable, args=("-c", code), env={"K": "x${LW_NOT_SET_ANYWHERE}"}
    )
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.tools == ()
    assert result.error == "environment variable 'LW_NOT_SET_ANYWHERE' is not set"
    assert not result.optional
    assert not marker.exists()  # the server was never started


def test_a_missing_variable_in_a_header_fails_the_source(monkeypatch, tmp_path):
    monkeypatch.delenv("LW_NOT_SET_ANYWHERE", raising=False)
    config = McpSourceConfig(
        target="http://127.0.0.1:1/mcp", headers={"Authorization": "Bearer ${LW_NOT_SET_ANYWHERE}"}
    )
    result = McpSource(config, tmp_path).read()
    assert result.error == "environment variable 'LW_NOT_SET_ANYWHERE' is not set"


def test_header_values_must_be_printable_ascii_after_expansion(monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_TOKEN", SECRET + chr(0xE9))
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp", headers={"X-Key": "${LW_TEST_TOKEN}"})
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error == "header 'X-Key': the value must be printable ASCII"
    assert_hidden(result, SECRET)


def test_values_echoed_by_a_careless_server_are_hidden(monkeypatch, tmp_path, capfd):
    monkeypatch.setenv("LW_TEST_SOURCE", SECRET)
    config = stdio_config("--echo-env", "LW_SECRET", env={"LW_SECRET": "${LW_TEST_SOURCE}"})
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error
    assert descriptions(result)["whoami"] == "token is <hidden env 'LW_SECRET'>"
    # The server called itself echo-<secret>, so lockwalk falls back to the program name.
    assert result.source.label == "mcp:" + command_name(sys.executable)
    assert_hidden(result, SECRET)
    inventory = merge_inventory([result])
    assert SECRET not in inventory.model_dump_json()
    snapshot = snapshot_document(inventory, captured_at=CAPTURED)
    assert "token is <hidden env 'LW_SECRET'>" in json.dumps(snapshot)
    assert SECRET not in json.dumps(snapshot)
    out, err = capfd.readouterr()
    assert SECRET not in out + err


def test_a_tool_named_after_a_secret_is_left_out(monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_SOURCE", SECRET)
    config = stdio_config(
        "--echo-env", "LW_SECRET", "--leak-tool-name", env={"LW_SECRET": "${LW_TEST_SOURCE}"}
    )
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert sorted(descriptions(result)) == ["stub", "whoami"]
    assert result.error == (
        "a tool name contains the value of env 'LW_SECRET', so that tool was left out"
    )
    assert not result.optional  # it connected and listed tools, so this stays an error
    assert_hidden(result, SECRET)


def test_a_config_word_in_a_name_is_not_treated_as_a_leak(monkeypatch, tmp_path):
    """Only token-like values (16+ characters) count in names; text hides 8+."""

    def fake_run(func, captured, errlog):
        tool = {"name": "postgres_main_query", "description": "Query postgres_main"}
        return "postgres_main-server", [tool]

    monkeypatch.setattr(anyio, "run", fake_run)
    result = McpSource(stdio_config(env={"DB": "postgres_main"}), tmp_path).read()
    assert result.ok, result.error
    assert descriptions(result) == {"postgres_main_query": "Query <hidden env 'DB'>"}
    assert result.source.label == "mcp:postgres_main-server"


# ---- headers reach an HTTP server ----


@pytest.fixture(scope="module")
def header_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A local server that answers 401 unless 'Authorization: Bearer <SECRET>' is sent."""
    port = free_port()
    env = dict(os.environ, LW_EXPECTED_HEADER=f"Bearer {SECRET}")
    stderr = tmp_path_factory.mktemp("header_server") / "stderr.txt"
    with stderr.open("wb") as errors:
        process = subprocess.Popen(
            [sys.executable, str(SERVER), "--http", str(port), "--require-header", "Authorization"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=errors,
        )
    try:
        wait_for_port(port, process, stderr)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_headers_reach_an_http_server(header_server, monkeypatch, tmp_path):
    monkeypatch.setenv("LW_TEST_TOKEN", SECRET)
    config = McpSourceConfig(
        target=header_server, headers={"Authorization": "Bearer ${LW_TEST_TOKEN}"}
    )
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error
    assert [tool.name for tool in result.tools] == ["stub"]
    assert result.source.label == "mcp:options-test"
    assert_hidden(result, SECRET)


def test_the_http_server_rejects_a_missing_header(header_server, tmp_path):
    """Proves the test above can fail: without the header the server refuses."""
    result = McpSource(McpSourceConfig(target=header_server), tmp_path).read()
    assert not result.ok
    assert result.error
    assert "unauthorized: got nothing" in result.error


def test_a_header_value_echoed_in_an_error_is_hidden(header_server, tmp_path, capfd):
    wrong = "LWWRONG" + uuid.uuid4().hex
    config = McpSourceConfig(target=header_server, headers={"Authorization": f"Bearer {wrong}"})
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error
    # The server's message got through, minus the value it echoed.
    assert "unauthorized: got <hidden header 'Authorization'>" in result.error
    assert_hidden(result, wrong)
    out, err = capfd.readouterr()
    assert wrong not in out + err


# ---- quiet SDK logging ----

LOCKWALK_READ = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from lockwalk.config import McpSourceConfig
    from lockwalk.inventory.mcp import McpSource
    config = McpSourceConfig(command=sys.executable, args=(sys.argv[1], "--noise"))
    result = McpSource(config, Path.cwd()).read()
    print("ok" if result.ok else result.error)
    """
)

SDK_READ = textwrap.dedent(
    """
    import sys, tempfile
    import anyio
    from mcp import Client, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def main():
        params = StdioServerParameters(command=sys.executable, args=[sys.argv[1], "--noise"])
        with tempfile.TemporaryFile("w+", encoding="utf-8") as errlog:
            async with Client(stdio_client(params, errlog=errlog)) as client:
                await client.list_tools()
        print("ok")

    anyio.run(main)
    """
)


def run_python(code: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run code in a fresh interpreter, where no pytest log handler hides stderr output."""
    return subprocess.run(
        [sys.executable, "-c", code, str(SERVER)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        cwd=cwd,
        check=False,
    )


def test_the_sdk_prints_a_traceback_for_a_noisy_server(tmp_path):
    """Proves the next test can fail: left alone, the SDK logs a traceback to stderr."""
    done = run_python(SDK_READ, tmp_path)
    assert done.stdout.strip() == "ok", done.stderr
    assert "Traceback" in done.stderr


def test_mcp_logging_stays_quiet_while_a_source_is_read(tmp_path):
    done = run_python(LOCKWALK_READ, tmp_path)
    assert done.stdout.strip() == "ok", done.stderr
    assert "Traceback" not in done.stderr
    assert "Failed to parse" not in done.stderr


def test_quiet_logging_restores_every_level():
    names = ("mcp", "mcp.client.stdio", "client")
    loggers = [logging.getLogger(name) for name in names]
    saved = [logger.level for logger in loggers]
    try:
        loggers[0].setLevel(logging.INFO)
        loggers[1].setLevel(logging.DEBUG)
        loggers[2].setLevel(logging.NOTSET)
        with pytest.raises(RuntimeError), quiet_mcp_logging():
            for logger in loggers:
                assert logger.level == logging.CRITICAL
            assert not logging.getLogger("mcp.client.streamable_http").isEnabledFor(logging.ERROR)
            raise RuntimeError("the levels come back even after an error")
        assert [logger.level for logger in loggers] == [logging.INFO, logging.DEBUG, logging.NOTSET]
    finally:
        for logger, level in zip(loggers, saved, strict=True):
            logger.setLevel(level)


def test_a_read_leaves_the_mcp_log_level_alone(tmp_path):
    before = logging.getLogger("mcp").level
    result = McpSource(stdio_config(), tmp_path).read()
    assert result.ok, result.error
    assert logging.getLogger("mcp").level == before


# ---- optional sources ----

OPTIONAL: dict[str, Any] = {"name": "remote-tools", "agents": ("finance-agent",), "optional": True}


def refuse_to_connect(func, captured, errlog):
    """Stands in for anyio.run when a server is unreachable (the error httpx2 raises)."""
    raise ExceptionGroup("connect", [ConnectionRefusedError("All connection attempts failed")])


def test_an_unreachable_optional_source_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(anyio, "run", refuse_to_connect)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp", **OPTIONAL)
    result = McpSource(config, tmp_path).read()
    assert result.error == "ConnectionRefusedError: All connection attempts failed"
    assert not result.ok
    assert result.optional
    assert result.unavailable
    assert result.source.label == "mcp:remote-tools"
    assert result.agents == ("finance-agent",)


def test_an_optional_source_that_times_out_is_unavailable(tmp_path):
    config = McpSourceConfig(
        command=sys.executable, args=("-c", "import time; time.sleep(60)"), timeout_s=1, **OPTIONAL
    )
    result = McpSource(config, tmp_path).read()
    assert result.error == "timed out after 1s"
    assert result.unavailable


def test_an_optional_source_with_a_missing_variable_is_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("LW_NOT_SET_ANYWHERE", raising=False)
    config = stdio_config(env={"K": "${LW_NOT_SET_ANYWHERE}"}, **OPTIONAL)
    result = McpSource(config, tmp_path).read()
    assert result.error == "environment variable 'LW_NOT_SET_ANYWHERE' is not set"
    assert result.unavailable


def test_an_optional_source_without_the_mcp_extra_is_unavailable(monkeypatch, tmp_path):
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name, *args, **kwargs):
        return None if name == "mcp" else real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp", **OPTIONAL)
    result = McpSource(config, tmp_path).read()
    assert result.error == NOT_INSTALLED
    assert result.unavailable


def test_a_required_source_that_fails_is_not_optional(monkeypatch, tmp_path):
    monkeypatch.setattr(anyio, "run", refuse_to_connect)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp")
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert not result.optional
    assert not result.unavailable


def test_an_optional_source_that_listed_tools_keeps_its_errors(monkeypatch, tmp_path):
    def fake_run(func, captured, errlog):
        return "remote", [{"name": "good"}, {"name": 5}]

    monkeypatch.setattr(anyio, "run", fake_run)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp", **OPTIONAL)
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert [tool.name for tool in result.tools] == ["good"]
    assert not result.optional
    assert not result.unavailable


def test_an_optional_source_that_listed_no_tools_is_fine(monkeypatch, tmp_path):
    def fake_run(func, captured, errlog):
        return "remote", []

    monkeypatch.setattr(anyio, "run", fake_run)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp", **OPTIONAL)
    result = McpSource(config, tmp_path).read()
    assert result.ok
    assert not result.optional
    assert not result.unavailable


# ---- command labels never include args ----

BACKSLASH = "\\"


@pytest.mark.parametrize(
    ("command", "name"),
    [
        ("npx", "npx"),
        ("python", "python"),
        ("/usr/local/bin/python3.11", "python3.11"),
        # Launched as one program name, so a path with a space is written without quotes.
        (BACKSLASH.join(["C:", "Program Files", "nodejs", "npx.cmd"]), "npx"),
        ("C:/Program Files/nodejs/npx.cmd", "npx"),
        ("/opt/my tools/server.exe", "server"),
        ("python server.py --token x", "python"),
        ("C:/Program Files/a/node.exe --token=x", "Program"),
        ("C:/Program Files/a/node.exe -y", "Program"),
        ("/opt/my tools/server.exe /c", "my"),
        ("/opt/my tools/server", "my"),
        ('"C:/Program Files/nodejs/npx.cmd" --token=x', "npx"),
        ("uvx server --token=x", "uvx"),
        ("C:/Python311/python.EXE", "python"),
        ("./bin/", "bin"),
        (".exe", ".exe"),
    ],
)
def test_command_name(command, name):
    assert command_name(command) == name


@pytest.mark.parametrize(
    ("command", "name"),
    [
        # A drive-letter word, a ".com" ending, and a tab each stop the spaced-path rule, so
        # the first word is shown and the argument is not.
        ("C:/bin/node C:/u/me@secret.com", "node"),
        ("C:/bin/node\ta/ghp_NOTAREALTOKEN0000.exe", "node"),
        ("C:/bin/node\na/ghp_NOTAREALTOKEN0000.exe", "node"),
        ("C:/Program Files/tool.com", "Program"),
        # KNOWN LIMIT, kept visible on purpose. These two have the same shape as a legitimate
        # unquoted path to an executable that contains a space, so the rule cannot tell an
        # argument written inside "command" from a directory name. Writing an argument inside
        # "command" is already forbidden (it is launched as one program name). The rule does
        # not check the file system, so a label is the same on every machine. The suffix
        # test ignores case, so an upper-case ending carries the same limit.
        ("C:/bin/node a/ghp_NOTAREALTOKEN0000.exe", "ghp_NOTAREALTOKEN0000"),
        ("C:/bin/node a/ghp_NOTAREALTOKEN0000.EXE", "ghp_NOTAREALTOKEN0000"),
        ("/opt/my tools/server.exe x/ghp_NOTAREALTOKEN0000.exe", "ghp_NOTAREALTOKEN0000"),
    ],
)
def test_command_name_limits_of_the_spaced_path_rule(command, name):
    assert command_name(command) == name


@pytest.mark.parametrize("command", ["C:/Program Files/nodejs/npx.cmd", "npx"])
def test_chosen_name_is_kept_for_a_spaced_path_and_a_plain_command(command):
    config = ServerConfig(
        ("m", "T"), None, ("nodejs-tools",), (), command, ("-y", "@x/nodejs-tools")
    )
    assert server_name(config) == "nodejs-tools"


@pytest.mark.parametrize(
    "command",
    [
        "uvx mcp-server --api-key=ghp_NOTAREALTOKEN0000",
        "npx -y @mcp/server-github --token=ghp_NOTAREALTOKEN0000",
        "python server.py --token ghp_NOTAREALTOKEN0000",
        '"C:/Program Files/nodejs/npx.cmd" --token=ghp_NOTAREALTOKEN0000',
    ],
)
def test_command_line_never_reaches_label(command, tmp_path):
    label = McpSource(McpSourceConfig(command=command), tmp_path)._label(None)
    assert "NOTAREALTOKEN" not in label
    assert "--" not in label


def test_args_never_reach_labels_errors_warnings_or_snapshots(tmp_path, capfd):
    arg_secret = "LWARGSECRET" + uuid.uuid4().hex
    token = f"--token={arg_secret}"
    python = "mcp:" + command_name(sys.executable)
    # Connected, but the server's name is not valid, so the label falls back.
    unnamed = McpSource(stdio_config("--server-name", " not valid", token), tmp_path).read()
    assert unnamed.ok, unnamed.error
    assert unnamed.source.label == python
    crashed = McpSource(
        McpSourceConfig(command=sys.executable, args=("-c", "raise SystemExit(3)", token)),
        tmp_path,
    ).read()
    hanging = McpSource(
        McpSourceConfig(
            command=sys.executable, args=("-c", "import time; time.sleep(60)", token), timeout_s=1
        ),
        tmp_path,
    ).read()
    missing = McpSource(
        McpSourceConfig(command="definitely-not-a-real-command-xyz", args=(token,)), tmp_path
    ).read()
    results = [unnamed, crashed, hanging, missing]
    assert [result.ok for result in results] == [True, False, False, False]
    assert [result.source.label for result in results] == [
        python,
        python,
        python,
        "mcp:definitely-not-a-real-command-xyz",
    ]
    assert missing.error
    assert missing.error.startswith(
        "cannot start the MCP server (definitely-not-a-real-command-xyz): "
    )
    for result in results:
        assert_hidden(result, arg_secret)
    inventory = merge_inventory(results)
    # Three unnamed python sources now share a label, and the error says how to fix it.
    assert any("set a distinct 'name'" in error for error in inventory.errors)
    # Failed sources refuse the snapshot; its message names labels only. A snapshot of
    # the source that was read holds no argument either.
    with pytest.raises(SnapshotRefused) as refused:
        snapshot_document(inventory, captured_at=CAPTURED)
    text = NEWLINE.join(
        [
            inventory.model_dump_json(),
            repr(inventory),
            *inventory.errors,
            *inventory.warnings,
            str(refused.value),
            json.dumps(snapshot_document(merge_inventory([unnamed]), captured_at=CAPTURED)),
        ]
    )
    assert arg_secret not in text
    out, err = capfd.readouterr()
    assert arg_secret not in out + err


def test_label_collisions_suggest_a_name_only_where_one_can_be_set():
    def twice(kind: Any, label: str) -> list[SourceResult]:
        tool = ToolDescriptor(name="t")
        result = SourceResult(source=SourceRef(kind=kind, label=label), ok=True, tools=(tool,))
        return [result, result]

    [mcp_error] = [
        error for error in merge_inventory(twice("mcp", "mcp:npx")).errors if "label" in error
    ]
    assert mcp_error == (
        "two inventory sources share the label 'mcp:npx'; remove the duplicate, or set a "
        "distinct 'name' on one of these [[inventory.mcp]] sources"
    )
    [json_error] = [
        error for error in merge_inventory(twice("json", "json:t.json")).errors if "label" in error
    ]
    assert json_error == (
        "two inventory sources share the label 'json:t.json'; "
        "remove the duplicate or give one of them a distinct name"
    )
