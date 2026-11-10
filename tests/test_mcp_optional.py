"""'optional' covers a server that cannot be reached, not one that answers with junk."""

import os
import sys
from pathlib import Path

import anyio
import pytest

from lockwalk.config import McpSourceConfig
from lockwalk.inventory.mcp import MAX_PAGES, McpSource
from lockwalk.inventory.merge import merge_inventory

RAW = Path(__file__).parent / "fixtures_mcp_options" / "raw_server.py"


def raw(mode: str, *extra: str, **fields) -> McpSourceConfig:
    return McpSourceConfig(
        command=sys.executable,
        args=(str(RAW), mode, *extra),
        name="partner",
        agents=("a",),
        optional=True,
        timeout_s=fields.pop("timeout_s", 20),
        **fields,
    )


def assert_error_not_warning(result):
    assert not result.ok
    assert result.tools == ()
    assert result.optional is False
    assert result.unavailable is False
    inventory = merge_inventory([result])
    assert inventory.errors and inventory.errors[0].startswith("mcp:partner: ")
    assert not any("unavailable" in w for w in inventory.warnings)


@pytest.mark.parametrize("mode", ["bad-schema", "list-error", "page2-fails"])
def test_optional_source_with_an_unusable_list_reply_is_an_error(mode, tmp_path):
    assert_error_not_warning(McpSource(raw(mode), tmp_path).read())


def test_optional_source_over_the_page_limit_is_an_error(tmp_path):
    result = McpSource(raw("endless"), tmp_path).read()
    assert_error_not_warning(result)
    assert f"more than {MAX_PAGES} pages" in (result.error or "")


def test_exactly_max_pages_is_a_success(tmp_path):
    result = McpSource(raw("pages", str(MAX_PAGES)), tmp_path).read()
    assert result.ok, result.error
    assert len(result.tools) == MAX_PAGES


def test_one_page_more_than_max_is_an_error(tmp_path):
    assert_error_not_warning(McpSource(raw("pages", str(MAX_PAGES + 1)), tmp_path).read())


def test_optional_source_that_never_connects_still_only_warns(tmp_path):
    config = McpSourceConfig(
        command=sys.executable,
        args=("-c", "raise SystemExit(3)"),
        name="partner",
        agents=("a",),
        optional=True,
    )
    result = McpSource(config, tmp_path).read()
    assert result.unavailable
    assert merge_inventory([result]).errors == ()


def test_optional_source_with_a_missing_command_still_only_warns(tmp_path):
    config = McpSourceConfig(
        command="definitely-not-a-real-command-xyz", name="partner", agents=("a",), optional=True
    )
    assert McpSource(config, tmp_path).read().unavailable


def test_optional_source_that_hangs_on_connect_still_only_warns(tmp_path):
    config = McpSourceConfig(
        command=sys.executable,
        args=("-c", "import time; time.sleep(60)"),
        name="partner",
        agents=("a",),
        optional=True,
        timeout_s=1,
    )
    assert McpSource(config, tmp_path).read().unavailable


def test_optional_source_that_times_out_listing_still_only_warns(tmp_path):
    result = McpSource(raw("list-hangs", timeout_s=2), tmp_path).read()
    assert result.unavailable
    assert result.error == "timed out after 2s"


def test_optional_source_with_unset_env_variable_still_only_warns(monkeypatch, tmp_path):
    monkeypatch.delenv("LW_NO_SUCH_VAR", raising=False)
    config = raw("pages", "1", env={"TOKEN": "${LW_NO_SUCH_VAR}"})
    assert McpSource(config, tmp_path).read().unavailable


def test_optional_source_without_the_mcp_extra_still_only_warns(monkeypatch, tmp_path):
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    assert McpSource(raw("pages", "1"), tmp_path).read().unavailable


def test_optional_source_with_a_good_list_is_unchanged(tmp_path):
    result = McpSource(raw("pages", "2"), tmp_path).read()
    assert result.ok and [t.name for t in result.tools] == ["t1", "t2"]


def test_a_finished_read_survives_a_teardown_timeout_on_an_optional_source(monkeypatch, tmp_path):
    def fake_run(func, captured, errlog):
        captured.append(("partner-srv", [{"name": "a"}]))
        raise TimeoutError()

    monkeypatch.setattr(anyio, "run", fake_run)
    result = McpSource(raw("pages", "1"), tmp_path).read()
    assert result.ok and [t.name for t in result.tools] == ["a"]


def test_a_non_optional_source_with_an_unusable_reply_is_still_an_error(tmp_path):
    config = McpSourceConfig(command=sys.executable, args=(str(RAW), "bad-schema"))
    result = McpSource(config, tmp_path).read()
    assert not result.ok and not result.unavailable and not result.optional


def test_an_unusable_reply_is_not_hidden_by_a_teardown_timeout(monkeypatch, tmp_path):
    def fake_run(func, captured, errlog):
        func.args[1].append(ValueError("tools: Input should be a valid list"))
        raise TimeoutError()

    monkeypatch.setattr(anyio, "run", fake_run)
    result = McpSource(raw("pages", "1"), tmp_path).read()
    assert_error_not_warning(result)
    assert "valid list" in (result.error or "")


def test_cli_exit_code_for_optional_sources(tmp_path):
    from test_cli_graph import run_main

    (tmp_path / "registry.yaml").write_text(
        "schema_version: '1'\nagents:\n  - id: desk\n    entry: true\n    calls: []\ntools: []\n",
        encoding="utf-8",
    )
    (tmp_path / "spec.yaml").write_text(
        "schema_version: '1'\nscenario_suite: s\ncases: []\n", encoding="utf-8"
    )

    def write(args: str) -> None:
        (tmp_path / ".lockwalk.toml").write_text(
            "[lockwalk]\nregistry = 'registry.yaml'\nspec = 'spec.yaml'\n\n"
            "[[inventory.mcp]]\nname = 'partner'\n"
            f"command = '{sys.executable}'\nargs = {args}\n"
            "optional = true\nagents = ['desk']\ntimeout_s = 30\n",
            encoding="utf-8",
        )

    write(f"['{RAW.as_posix()}', 'bad-schema']")
    bad = run_main(tmp_path, dict(os.environ), "discover")
    assert bad.returncode == 2, bad.stdout + bad.stderr
    write("['-c', 'raise SystemExit(3)']")
    down = run_main(tmp_path, dict(os.environ), "discover")
    assert down.returncode == 0, down.stdout + down.stderr
