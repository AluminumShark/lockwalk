"""A wrapper that lockwalk's own Python discovery found is a known tool for observe.

These tests run the real multi_agent example: its app.py calls
`trade_agent.as_tool(tool_name="ask_trade_agent")` and no registry declares that name.
"""

import json
import shutil
from pathlib import Path

import pytest
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from typer.testing import CliRunner

from lockwalk.cli import app

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "multi_agent"
TRACE = "e5" * 16
BASE = 1_794_105_344_000_000_000
runner = CliRunner()


def _attrs(**values: str) -> list[dict]:
    return [{"key": k.replace("__", "."), "value": {"stringValue": v}} for k, v in values.items()]


def _span(span_id: str, parent: str | None, name: str, start: int, **values: str) -> dict:
    body = {
        "traceId": TRACE,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": str(BASE + start),
        "endTimeUnixNano": str(BASE + start + 100_000),
        "attributes": _attrs(**values),
    }
    if parent:
        body["parentSpanId"] = parent
    return body


def _agent(span_id: str, parent: str | None, name: str, start: int) -> dict:
    return _span(
        span_id,
        parent,
        f"invoke_agent {name}",
        start,
        gen_ai__operation__name="invoke_agent",
        gen_ai__agent__name=name,
    )


def _tool(span_id: str, parent: str, name: str, start: int) -> dict:
    return _span(
        span_id,
        parent,
        f"execute_tool {name}",
        start,
        gen_ai__operation__name="execute_tool",
        gen_ai__tool__name=name,
    )


def wrapper_trace(path: Path, wrapper: str, caller: str = "finance-agent") -> Path:
    spans = [
        _agent("00000000000000a1", None, caller, 0),
        _tool("00000000000000b1", "00000000000000a1", wrapper, 10),
        _agent("00000000000000a2", "00000000000000b1", "trade-agent", 20),
    ]
    path.write_text(json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}))
    return path


@pytest.fixture
def example(tmp_path: Path) -> Path:
    directory = tmp_path / "multi_agent"
    shutil.copytree(EXAMPLE, directory, ignore=shutil.ignore_patterns(".lockwalk", "__pycache__"))
    return directory


def observe(directory: Path, trace: Path, *extra: str) -> dict:
    out = directory / "out"
    runner.invoke(
        app,
        [
            "observe",
            "--config",
            str(directory / ".lockwalk.toml"),
            "--traces",
            str(trace),
            "--output-dir",
            str(out),
            *extra,
        ],
    )
    return json.loads((out / "observe.json").read_text(encoding="utf-8"))


def unknown_tools(report: dict) -> list[str]:
    return [row["name"] for row in report["unknown"] if row["kind"] == "tool"]


def test_a_wrapper_found_by_discovery_is_not_unknown(example: Path) -> None:
    assert "ask_trade_agent" not in (example / "registry.yaml").read_text(encoding="utf-8")
    report = observe(example, wrapper_trace(example / "w.json", "ask_trade_agent"))
    assert unknown_tools(report) == []
    edges = {(r["from_id"], r["to_id"], r["status"]) for r in report["routes"]}
    assert ("finance-agent", "trade-agent", "ON_MAP") in edges


def test_a_wrapper_is_matched_by_name_not_by_the_edge_between_its_agents(example: Path) -> None:
    # finance-agent -> trade-agent is an agent_as_tool edge on the map, but the tool that
    # carries the call here is not the one discovery found.
    report = observe(example, wrapper_trace(example / "w.json", "rogue_exec"))
    assert unknown_tools(report) == ["rogue_exec"]
    assert report["exit_code"] == 1


def test_a_wrapper_name_that_differs_only_in_case_is_unknown(example: Path) -> None:
    report = observe(example, wrapper_trace(example / "w.json", "Ask_Trade_Agent"))
    assert unknown_tools(report) == ["Ask_Trade_Agent"]


def test_the_name_alone_decides_even_for_another_calling_agent(example: Path) -> None:
    # Known limit: matching is by tool name, so the same name below another agent is known.
    report = observe(example, wrapper_trace(example / "w.json", "ask_trade_agent", "supervisor"))
    assert unknown_tools(report) == []


def test_a_wrapper_in_the_registry_and_in_discovery_is_known(example: Path) -> None:
    registry = example / "registry.yaml"
    registry.write_text(
        registry.read_text(encoding="utf-8").rstrip("\n")
        + "\ndelegation_tools:\n  - id: ask_trade_agent\n    agent: trade-agent\n"
        "    supported_agents: [finance-agent]\n",
        encoding="utf-8",
    )
    report = observe(example, wrapper_trace(example / "w.json", "ask_trade_agent"))
    assert unknown_tools(report) == []


def save_snapshot(directory: Path) -> Path:
    path = directory / "snap.json"
    result = runner.invoke(
        app,
        ["discover", "--config", str(directory / ".lockwalk.toml"), "--save-snapshot", str(path)],
    )
    assert result.exit_code == 0, result.stdout
    return path


def replay(directory: Path, snapshot: Path, trace: Path) -> dict:
    config = directory / "replay.toml"
    config.write_text(
        '[lockwalk]\nregistry = "registry.yaml"\nspec = "security-spec.yaml"\n'
        f'fixtures = "fixtures.yaml"\n\n[[inventory.json]]\npath = "{snapshot.as_posix()}"\n',
        encoding="utf-8",
    )
    out = directory / "replay-out"
    result = runner.invoke(
        app, ["observe", "--config", str(config), "--traces", str(trace), "--output-dir", str(out)]
    )
    assert (out / "observe.json").exists(), result.output
    return json.loads((out / "observe.json").read_text(encoding="utf-8"))


def without_wrapper_names(snapshot: Path) -> None:
    """Make the snapshot look as if it was saved before wrapped_by existed."""
    document = json.loads(snapshot.read_text(encoding="utf-8"))
    removed = 0
    for source in document["sources"]:
        for edge in (source.get("graph") or {}).get("edges", []):
            removed += edge.pop("wrapped_by", None) is not None
    assert removed, "the snapshot held no wrapper name to remove"
    snapshot.write_text(json.dumps(document), encoding="utf-8")


def test_a_snapshot_saved_now_replays_like_the_live_run(example: Path) -> None:
    snapshot = save_snapshot(example)
    assert "ask_trade_agent" in snapshot.read_text(encoding="utf-8")
    trace = wrapper_trace(example / "w.json", "ask_trade_agent")
    assert unknown_tools(replay(example, snapshot, trace)) == []
    rogue = wrapper_trace(example / "r.json", "rogue_exec")
    assert unknown_tools(replay(example, snapshot, rogue)) == ["rogue_exec"]


def test_a_snapshot_without_wrapper_names_fails_closed(example: Path) -> None:
    snapshot = save_snapshot(example)
    without_wrapper_names(snapshot)
    trace = wrapper_trace(example / "w.json", "ask_trade_agent")
    assert unknown_tools(replay(example, snapshot, trace)) == ["ask_trade_agent"]


def inspect_trace(directory: Path, trace: Path) -> str:
    result = runner.invoke(
        app,
        [
            "inspect",
            "--trace",
            TRACE,
            "--config",
            str(directory / ".lockwalk.toml"),
            "--traces",
            str(trace),
        ],
    )
    assert result.exit_code == 0, result.stdout
    return result.stdout


def test_inspect_trace_agrees_with_observe_on_a_discovered_wrapper(example: Path) -> None:
    text = inspect_trace(example, wrapper_trace(example / "w.json", "ask_trade_agent"))
    assert "tool ask_trade_agent" in text
    assert "agent-as-tool wrapper" in text
    assert "UNKNOWN" not in text
    rogue = inspect_trace(example, wrapper_trace(example / "r.json", "rogue_exec"))
    assert "tool ? rogue_exec" in rogue
    assert "UNKNOWN tool (agent-as-tool wrapper)" in rogue


def test_inspect_trace_agrees_with_observe_on_a_registry_wrapper(example: Path) -> None:
    registry = example / "registry.yaml"
    registry.write_text(
        registry.read_text(encoding="utf-8").rstrip("\n")
        + "\ndelegation_tools:\n  - id: registry_only\n    agent: trade-agent\n"
        "    supported_agents: [finance-agent]\n",
        encoding="utf-8",
    )
    trace = wrapper_trace(example / "w.json", "registry_only")
    assert "UNKNOWN" not in inspect_trace(example, trace)
    assert unknown_tools(observe(example, trace)) == []
