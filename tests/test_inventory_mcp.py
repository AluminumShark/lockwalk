import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TextIO, cast

import anyio
import pytest
from lockwalk_net_helpers import free_port, wait_for_port

from lockwalk.config import McpSourceConfig
from lockwalk.inventory.mcp import NOT_INSTALLED, McpSource, root_cause
from lockwalk.urls import redact_url

EXPECTED = ["get_stock_price", "read_portfolio", "execute_trade", "delete_portfolio"]


@pytest.fixture
def server_script(example_dir: Path) -> Path:
    return example_dir / "mcp_server.py"


def test_stdio_lists_tools_without_calling_them(server_script, tmp_path):
    marker = tmp_path / "called.txt"
    config = McpSourceConfig(
        command=sys.executable, args=(str(server_script), "--marker", str(marker))
    )
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error
    assert result.source.label == "mcp:finance-tools"
    assert [tool.name for tool in result.tools] == EXPECTED
    assert not marker.exists()


def test_marker_does_record_a_real_call(server_script, tmp_path):
    """Proves the marker check above can fail: calling a tool does write the marker."""
    marker = tmp_path / "called.txt"

    async def call_once() -> None:
        from mcp import Client, StdioServerParameters
        from mcp.client.stdio import stdio_client

        params = StdioServerParameters(
            command=sys.executable, args=[str(server_script), "--marker", str(marker)]
        )
        with tempfile.TemporaryFile("w+", encoding="utf-8") as errlog:
            async with Client(stdio_client(params, errlog=cast(TextIO, errlog))) as client:
                with contextlib.suppress(Exception):
                    await client.call_tool("get_stock_price", {"symbol": "TSMC"})

    anyio.run(call_once)
    assert marker.read_text(encoding="utf-8") == "get_stock_price"


def test_stdio_short_form_keeps_hints(server_script, tmp_path):
    result = McpSource(McpSourceConfig(target=f"stdio://{server_script}"), tmp_path).read()
    assert result.ok, result.error
    hints = {tool.name: tool.hints for tool in result.tools}
    assert hints["delete_portfolio"] == {"destructiveHint": True}
    assert hints["get_stock_price"] == {"readOnlyHint": True}


def test_relative_stdio_target_uses_base_dir(server_script):
    config = McpSourceConfig(target=f"stdio://{server_script.name}")
    result = McpSource(config, server_script.parent).read()
    assert result.ok, result.error


def test_config_name_overrides_the_server_name(server_script, tmp_path):
    config = McpSourceConfig(name="demo", target=f"stdio://{server_script}")
    assert McpSource(config, tmp_path).read().source.label == "mcp:demo"


def test_streamable_http_target(server_script, tmp_path):
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, str(server_script), "--http", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_for_port(port)
        config = McpSourceConfig(target=f"http://127.0.0.1:{port}/mcp")
        result = McpSource(config, tmp_path).read()
    finally:
        process.terminate()
        process.wait(timeout=10)
    assert result.ok, result.error
    assert [tool.name for tool in result.tools] == EXPECTED


def test_unreachable_http_server_fails(tmp_path):
    config = McpSourceConfig(target=f"http://127.0.0.1:{free_port()}/mcp", timeout_s=5)
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.tools == ()
    assert result.error


def test_hanging_server_times_out(tmp_path):
    config = McpSourceConfig(
        command=sys.executable, args=("-c", "import time; time.sleep(60)"), timeout_s=1
    )
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error == "timed out after 1s"


def test_crashing_server_fails(tmp_path):
    config = McpSourceConfig(command=sys.executable, args=("-c", "raise SystemExit(3)"))
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error
    assert "exited or closed the connection" in result.error


def test_missing_command_fails_clearly(tmp_path):
    config = McpSourceConfig(command="definitely-not-a-real-command-xyz")
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error
    assert result.error.startswith(
        "cannot start the MCP server (definitely-not-a-real-command-xyz)"
    )


def test_short_but_sufficient_timeout_is_not_a_timeout(server_script, tmp_path):
    config = McpSourceConfig(target=f"stdio://{server_script}", timeout_s=5)
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error


def test_missing_mcp_extra_is_reported(monkeypatch, tmp_path):
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name, *args, **kwargs):
        return None if name == "mcp" else real_find_spec(name, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)
    result = McpSource(McpSourceConfig(target="http://127.0.0.1:1/mcp"), tmp_path).read()
    assert not result.ok
    assert result.error == NOT_INSTALLED


def test_root_cause_unwraps_nested_groups():
    leaf = ValueError("leaf")
    group = ExceptionGroup("outer", [ExceptionGroup("inner", [leaf])])
    assert root_cause(group) is leaf


def test_success_is_kept_when_teardown_overruns(monkeypatch, tmp_path):
    def fake_run(func, captured, errlog):
        captured.append(("finance-tools", [{"name": "a"}]))
        raise TimeoutError()

    monkeypatch.setattr(anyio, "run", fake_run)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp")
    result = McpSource(config, tmp_path).read()
    assert result.ok, result.error
    assert result.source.label == "mcp:finance-tools"
    assert [tool.name for tool in result.tools] == ["a"]


def test_timeout_without_a_completed_read_fails(monkeypatch, tmp_path):
    def fake_run(func, captured, errlog):
        raise TimeoutError()

    monkeypatch.setattr(anyio, "run", fake_run)
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp")
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error == "timed out after 10s"


def test_stdio_works_when_stderr_has_no_fileno(monkeypatch, server_script, tmp_path):
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    result = McpSource(McpSourceConfig(target=f"stdio://{server_script}"), tmp_path).read()
    assert result.ok, result.error
    assert len(result.tools) == 4


def test_server_stderr_never_reaches_the_report(tmp_path):
    code = "import sys; sys.stderr.write('boom: bad config\\n'); sys.exit(3)"
    config = McpSourceConfig(command=sys.executable, args=("-c", code))
    result = McpSource(config, tmp_path).read()
    assert not result.ok
    assert result.error
    assert "boom" not in result.error
    assert "run the server command yourself" in result.error


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://user:pw@127.0.0.1:9/mcp?api_key=X#f", "https://127.0.0.1:9/mcp"),
        ("http://host/mcp", "http://host/mcp"),
        ("http://token@host:8080/a/b?x=1", "http://host:8080/a/b"),
    ],
)
def test_redact_url(url, expected):
    assert redact_url(url) == expected


def test_credentials_in_an_mcp_url_never_reach_the_result(tmp_path):
    url = f"https://user:hunter2@127.0.0.1:{free_port()}/mcp?api_key=SECRET123"
    result = McpSource(McpSourceConfig(target=url, timeout_s=5), tmp_path).read()
    assert not result.ok
    text = f"{result.source.label}\n{result.error}"
    assert "hunter2" not in text
    assert "SECRET123" not in text
    assert result.source.label.startswith("mcp:https://127.0.0.1:")


def test_untrusted_server_name_is_ignored_when_invalid(monkeypatch, tmp_path):
    config = McpSourceConfig(target="http://127.0.0.1:1/mcp")
    source = McpSource(config, tmp_path)
    assert source._label("bad" + chr(0x1B) + "name") == "mcp:http://127.0.0.1:1/mcp"
    assert source._label("good-name") == "mcp:good-name"
