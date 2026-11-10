"""lockwalk observe and inspect --trace, end to end through the CLI."""

import gzip
import json
import re
import shutil
from pathlib import Path

import pytest
from observe_helpers import copy_without_doors
from typer.testing import CliRunner, Result

from lockwalk.cli import app
from lockwalk.observe.results import OBSERVE_FILE_NAME

DATA = Path(__file__).resolve().parent / "observe_data"
APPS = Path(__file__).resolve().parent / "observe_apps"
runner = CliRunner()

# A content string from each fixture (prompt or tool input). None may reach any output.
CONTENT = {
    "pydantic_delegation.json": "SECRET-SYSTEM-PROMPT",
    "pydantic_handoff.json": "SECRET-SYSTEM-PROMPT",
    "openai_oi_handoff.json": "order_id",
    "openai_oi_astool.json": "do trade",
    "langgraph_oi_sub.json": "buy 5 ACME",
    "langgraph_oi_tool.json": "buy 5 ACME",
}
NO_CALL = "    calls: [trade-agent]\n"
# Without a door in the traces every call is UNGUARDED; these tests look at routes only.
UNDOORED = "fail_on_unguarded_call = []\nfail_on_untested_path = []\n"
ROUTES_ONLY = "[gate]\n" + UNDOORED


@pytest.fixture(scope="session")
def clean(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The fixtures without their door attributes.

    The fixtures carry a partial door record. The route tests run on copies
    without the door attributes, so they keep checking routes.
    """
    folder = tmp_path_factory.mktemp("clean")
    for fixture in sorted([*DATA.glob("*.json"), *DATA.glob("*.jsonl")]):
        copy_without_doors(fixture, folder)
    return folder


@pytest.fixture(scope="session")
def pydantic_trace(clean: Path) -> str:
    document = json.loads((clean / "pydantic_delegation.json").read_text("utf-8"))
    return next(
        span["traceId"]
        for resource in document["resourceSpans"]
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
    )


@pytest.fixture
def out(tmp_path: Path) -> Path:
    return tmp_path / "out"


def observe(out: Path, *args: str, config: Path | None = DATA / "observe.toml") -> Result:
    command = ["observe", "--output-dir", str(out)]
    if config is not None:
        command += ["--config", str(config)]
    return runner.invoke(app, [*command, *args])


def inspect_trace(trace: str, config: Path, *traces: str) -> Result:
    command = ["inspect", "--trace", trace, "--config", str(config)]
    for item in traces:
        command += ["--traces", item]
    return runner.invoke(app, command)


def load(out: Path) -> dict:
    return json.loads((out / OBSERVE_FILE_NAME).read_text(encoding="utf-8"))


def variant(tmp_path: Path, *, registry: str | None = None, extra: str = "") -> Path:
    """A config in tmp_path that uses the test spec, a registry variant, and extra TOML."""
    (tmp_path / "registry.yaml").write_text(
        registry if registry is not None else (DATA / "registry.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    config = tmp_path / "variant.toml"
    gate = "" if "[gate]" in extra else ROUTES_ONLY
    spec = (DATA / "security-spec.yaml").as_posix()
    config.write_text(
        f'[lockwalk]\nregistry = "registry.yaml"\nspec = "{spec}"\n{gate}{extra}', encoding="utf-8"
    )
    return config


WRAPPER_TOOLS = (
    "delegation_tools:\n  - id: ask_trade_agent\n    agent: trade-agent\n"
    "    supported_agents: [supervisor]\n"
)


def wrapper_registry() -> str:
    """The test registry plus the agent-as-tool wrapper that the *_astool fixtures use."""
    registry = (DATA / "registry.yaml").read_text(encoding="utf-8")
    assert "ask_trade_agent" not in registry
    return registry.rstrip("\n") + "\n" + WRAPPER_TOOLS


def no_handoff_registry() -> str:
    registry = (DATA / "registry.yaml").read_text(encoding="utf-8")
    assert NO_CALL in registry
    return registry.replace(NO_CALL, "")


def trace_of(report: dict) -> str:
    return report["routes"][0]["traces"][0]


def routes(report: dict) -> set[tuple[str, str, str]]:
    return {(row["from_id"], row["to_id"], row["status"]) for row in report["routes"]}


def test_pydantic_delegation_is_all_on_the_map(clean: Path, out: Path) -> None:
    result = observe(out, "--traces", str(clean / "pydantic_delegation.json"))
    assert result.exit_code == 0, result.output
    assert "Gate: PASS (exit 0)" in result.output
    assert "Report written to" in result.output
    report = load(out)
    assert report["kind"] == "observe"
    assert report["exit_code"] == 0
    assert report["totals"]["traces"] == 1
    assert {row["status"] for row in report["routes"]} == {"ON_MAP"}
    assert routes(report) >= {
        ("user", "supervisor", "ON_MAP"),
        ("supervisor", "delegate_trade", "ON_MAP"),
        ("trade-agent", "execute_trade", "ON_MAP"),
    }


def test_a_partial_door_record_is_a_read_problem(out: Path) -> None:
    result = observe(out, "--traces", str(DATA / "openai_oi_handoff.json"))
    assert result.exit_code == 2, result.output
    assert "openai_oi_handoff.json:1: door record: lockwalk.door.subject.type is missing" in (
        result.output
    )
    assert any("lockwalk.door.subject.type is missing" in e for e in load(out)["errors"])


def test_off_map_route_fails_with_a_suggestion(clean: Path, tmp_path: Path, out: Path) -> None:
    config = variant(tmp_path, registry=no_handoff_registry())
    result = observe(out, "--traces", str(clean / "openai_oi_handoff.json"), config=config)
    assert result.exit_code == 1, result.output
    assert "Routes not on the map (OFF_MAP):" in result.output
    assert "supervisor -> trade-agent (agent)" in result.output
    assert "fix: declare the call: add trade-agent to 'calls' of agent supervisor" in result.output
    assert "Gate: FAIL (exit 1) - 1 violation(s)" in result.output
    report = load(out)
    assert report["exit_code"] == 1
    off = [row for row in report["routes"] if row["status"] == "OFF_MAP"]
    assert [(row["from_id"], row["to_id"]) for row in off] == [("supervisor", "trade-agent")]
    assert off[0]["suggestion"].startswith("declare the call")
    assert report["gate"]["violations"] == [
        {
            "rule": "fail_on_off_map_route",
            "from_id": "supervisor",
            "to_id": "trade-agent",
            "kind": None,
            "name": None,
            "agent": None,
            "tool": None,
            "path": None,
            "subject": None,
        }
    ]


def test_off_map_gate_key_off_passes(clean: Path, tmp_path: Path, out: Path) -> None:
    config = variant(
        tmp_path,
        registry=no_handoff_registry(),
        extra="[gate]\nfail_on_off_map_route = false\n" + UNDOORED,
    )
    result = observe(out, "--traces", str(clean / "openai_oi_handoff.json"), config=config)
    assert result.exit_code == 0, result.output
    assert "OFF_MAP" in result.output


@pytest.mark.parametrize(
    "name",
    [
        "openai_oi_handoff.json",
        "openai_oi_astool.json",
        "langgraph_oi_sub.json",
        "langgraph_oi_tool.json",
        "langgraph_ls_sub.json",
        "langgraph_ls_tool.json",
    ],
)
def test_name_matching_fixtures_are_on_the_map(
    clean: Path, tmp_path: Path, out: Path, name: str
) -> None:
    config = variant(tmp_path, registry=wrapper_registry())
    result = observe(out, "--traces", str(clean / name), config=config)
    assert result.exit_code == 0, result.output
    report = load(out)
    assert report["unknown"] == []
    assert report["totals"]["agent_spans"] == 2
    assert report["totals"]["tool_calls"] == 1
    assert routes(report) == {
        ("user", "supervisor", "ON_MAP"),
        ("supervisor", "trade-agent", "ON_MAP"),
        ("trade-agent", "execute_trade", "ON_MAP"),
    }


@pytest.mark.parametrize(
    "name", ["openai_oi_astool.json", "langgraph_oi_tool.json", "langgraph_ls_tool.json"]
)
def test_the_wrapper_is_not_unknown(clean: Path, tmp_path: Path, out: Path, name: str) -> None:
    # ask_trade_agent is a registered delegation tool here, so it is a known wrapper.
    config = variant(tmp_path, registry=wrapper_registry())
    result = observe(out, "--traces", str(clean / name), config=config)
    assert result.exit_code == 0, result.output
    assert "ask_trade_agent" not in result.output
    assert "ask_trade_agent" not in (out / OBSERVE_FILE_NAME).read_text(encoding="utf-8")
    shown = inspect_trace(trace_of(load(out)), config, str(clean / name))
    assert shown.exit_code == 0, shown.output
    assert "tool ask_trade_agent" in shown.output
    assert "agent-as-tool wrapper" in shown.output
    assert "UNKNOWN" not in shown.output


@pytest.mark.parametrize(
    "name", ["openai_oi_astool.json", "langgraph_oi_tool.json", "langgraph_ls_tool.json"]
)
def test_the_same_wrapper_not_in_the_registry_is_unknown(clean: Path, out: Path, name: str) -> None:
    result = observe(out, "--traces", str(clean / name))
    assert result.exit_code == 1, result.output
    assert {(u["kind"], u["name"]) for u in load(out)["unknown"]} == {("tool", "ask_trade_agent")}
    assert routes(load(out)) >= {("supervisor", "trade-agent", "ON_MAP")}


def tool_span(trace: str, span: str, parent: str, name: str, start: int) -> dict:
    return {
        "traceId": trace,
        "spanId": span,
        "parentSpanId": parent,
        "name": f"execute_tool {name}",
        "startTimeUnixNano": str(1_794_105_344_000_000_000 + start),
        "endTimeUnixNano": str(1_794_105_344_000_000_000 + start + 1000),
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": name}},
        ],
    }


def rogue_trace(folder: Path) -> str:
    spans = [
        agent_span(ROGUE, "00000000000000a1", None, "supervisor", 0),
        tool_span(ROGUE, "00000000000000b1", "00000000000000a1", "rogue_exec", 10),
        agent_span(ROGUE, "00000000000000a2", "00000000000000b1", "trade-agent", 20),
        tool_span(ROGUE, "00000000000000b2", "00000000000000a2", "execute_trade", 30),
    ]
    return write_spans(folder / "rogue.json", spans)


ROGUE = "d4" * 16


def test_an_unregistered_tool_that_starts_an_agent_is_unknown(tmp_path: Path, out: Path) -> None:
    traces = rogue_trace(tmp_path)
    result = observe(out, "--traces", traces)
    assert result.exit_code == 1, result.output  # fail_on_unknown_component is on by default
    report = load(out)
    assert {(u["kind"], u["name"]) for u in report["unknown"]} == {("tool", "rogue_exec")}
    assert ("supervisor", "trade-agent", "ON_MAP") in routes(report)
    assert ("trade-agent", "execute_trade", "ON_MAP") in routes(report)
    shown = inspect_trace(ROGUE, DATA / "observe.toml", traces)
    assert "tool ? rogue_exec" in shown.output
    assert "UNKNOWN tool" in shown.output


def test_an_unregistered_wrapper_passes_when_the_unknown_gate_is_off(
    tmp_path: Path, out: Path
) -> None:
    traces = rogue_trace(tmp_path)
    config = variant(tmp_path, extra="[gate]\nfail_on_unknown_component = false\n" + UNDOORED)
    result = observe(out, "--traces", traces, config=config)
    assert result.exit_code == 0, result.output
    assert "rogue_exec" in result.output


def test_the_logfire_wrapper_is_not_unknown(clean: Path, tmp_path: Path, out: Path) -> None:
    config = variant(tmp_path, registry=wrapper_registry(), extra=LOGFIRE_RULES)
    result = observe(out, "--traces", str(clean / "openai_logfire_astool.json"), config=config)
    assert result.exit_code == 0, result.output
    assert "ask_trade_agent" not in result.output
    shown = inspect_trace(trace_of(load(out)), config, str(clean / "openai_logfire_astool.json"))
    assert "tool ask_trade_agent" in shown.output
    assert "agent-as-tool wrapper" in shown.output


LOGFIRE_RULES = """
[[observe.rules]]
kind = "agent"
name = "name"
[observe.rules.when]
"logfire.msg_template" = "Agent run: {name!r}"

[[observe.rules]]
kind = "tool"
name = "name"
[observe.rules.when]
"logfire.msg_template" = "Function: {name}"

[[observe.rules]]
kind = "handoff"
from = "from_agent"
to = "to_agent"
[observe.rules.when]
"logfire.msg_template" = "Handoff: {from_agent} \\u2192 {to_agent}"
"""


@pytest.mark.parametrize("name", ["openai_logfire_handoff.json", "openai_logfire_astool.json"])
def test_logfire_needs_its_rules(clean: Path, tmp_path: Path, out: Path, name: str) -> None:
    bare = observe(out, "--traces", str(clean / name))
    assert bare.exit_code == 2
    assert "no agent or tool spans were recognized" in bare.output.replace("\n", " ")
    config = variant(tmp_path, registry=wrapper_registry(), extra=LOGFIRE_RULES)
    result = observe(out, "--traces", str(clean / name), config=config)
    assert result.exit_code == 0, result.output
    assert routes(load(out)) == {
        ("user", "supervisor", "ON_MAP"),
        ("supervisor", "trade-agent", "ON_MAP"),
        ("trade-agent", "execute_trade", "ON_MAP"),
    }


GENERIC_RULES = """
[observe.agents]
root-1 = "supervisor"
root-2 = "trade-agent"

[[observe.rules]]
kind = "agent"
name = "span.name"
[observe.rules.when]
"span.name" = "root-1"

[[observe.rules]]
kind = "agent"
name = "span.name"
[observe.rules.when]
"span.name" = "root-2"
"""


@pytest.mark.parametrize("name", ["collector.jsonl", "jaeger_v3_search.json"])
def test_collector_and_jaeger_files(clean: Path, tmp_path: Path, out: Path, name: str) -> None:
    plain = observe(out, "--traces", str(clean / name))
    assert plain.exit_code == 2
    assert "no agent or tool spans were recognized" in plain.output.replace("\n", " ")
    config = variant(tmp_path, extra=GENERIC_RULES)
    result = observe(out, "--traces", str(clean / name), config=config)
    assert result.exit_code == 1, result.output  # root-2 as an entry agent is not on the map
    report = load(out)
    assert report["totals"]["agent_spans"] == 2
    assert routes(report) == {
        ("user", "supervisor", "ON_MAP"),
        ("user", "trade-agent", "OFF_MAP"),
    }


def test_gzip_copy_in_a_directory(clean: Path, tmp_path: Path, out: Path) -> None:
    folder = tmp_path / "traces"
    folder.mkdir()
    document = json.loads((clean / "pydantic_delegation.json").read_text(encoding="utf-8"))
    with gzip.open(folder / "pydantic.jsonl.gz", "wb") as stream:
        stream.write((json.dumps(document) + "\n").encode("utf-8"))
    result = observe(out, "--traces", str(folder))
    assert result.exit_code == 0, result.output
    assert load(out)["totals"]["traces"] == 1


UNKNOWN_REGISTRY = """schema_version: '1'
agents:
  - id: supervisor
    description: Entry agent.
    entry: true
tools:
  - id: delegate_trade
    action: trade:delegate
    risk: low
    supported_agents: [supervisor]
"""
UNKNOWN_SPEC = """schema_version: '1'
scenario_suite: unknown-test
cases:
  - id: CASE-001
    actor: alice
    role: trader
    path: [supervisor]
    tool: delegate_trade
    action: trade:delegate
    resource_fixture: order-1
    expect: allow
"""


def test_unknown_agent_name(clean: Path, tmp_path: Path, out: Path) -> None:
    # The registry lacks trade-agent and execute_trade, so the trace names are UNKNOWN.
    spec = tmp_path / "spec.yaml"
    spec.write_text(UNKNOWN_SPEC, encoding="utf-8")
    traces = ("--traces", str(clean / "pydantic_delegation.json"), "--spec", str(spec))
    config = variant(tmp_path, registry=UNKNOWN_REGISTRY)
    result = observe(out, *traces, config=config)
    assert result.exit_code == 1, result.output
    assert "Not on the map (UNKNOWN):" in result.output
    assert "agent trade-agent" in result.output
    report = load(out)
    assert ("agent", "trade-agent") in {(row["kind"], row["name"]) for row in report["unknown"]}
    assert {v["rule"] for v in report["gate"]["violations"]} == {"fail_on_unknown_component"}
    relaxed = variant(
        tmp_path,
        registry=UNKNOWN_REGISTRY,
        extra="[gate]\nfail_on_unknown_component = false\n" + UNDOORED,
    )
    result = observe(out, *traces, config=relaxed)
    assert result.exit_code == 0, result.output
    assert "Not on the map (UNKNOWN):" in result.output


def test_empty_file_is_an_error(tmp_path: Path, out: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_bytes(b"")
    result = observe(out, "--traces", str(empty))
    assert result.exit_code == 2
    assert "no traces were read" in result.output
    assert "Result: ERROR (exit 2)" in result.output
    assert load(out)["exit_code"] == 2


def test_binary_file_names_the_format_problem(tmp_path: Path, out: Path) -> None:
    binary = tmp_path / "traces.jsonl"
    binary.write_bytes(b"\x28\xb5\x2f\xfd\x00\x01\x02\xff" * 8)
    result = observe(out, "--traces", str(binary))
    assert result.exit_code == 2
    assert "format: json without compression" in result.output.replace("\n", " ")
    assert "traces.jsonl" in result.output.replace("\n", "")


def test_alias_to_a_missing_id_is_a_structural_error(
    clean: Path, tmp_path: Path, out: Path
) -> None:
    config = variant(tmp_path, extra='[observe.agents]\nghost = "nobody"\n')
    out.mkdir()
    stale = out / OBSERVE_FILE_NAME
    stale.write_text("{}", encoding="utf-8")
    result = observe(out, "--traces", str(clean / "pydantic_delegation.json"), config=config)
    assert result.exit_code == 2
    assert "nobody" in result.output
    assert not stale.exists()


def test_no_traces_given_is_a_command_line_error(out: Path) -> None:
    result = observe(out)
    assert result.exit_code == 2
    assert "observe needs --traces" in result.output.replace("\n", " ")
    assert not (out / OBSERVE_FILE_NAME).exists()


def test_missing_registry_is_a_command_line_error(clean: Path, tmp_path: Path, out: Path) -> None:
    config = tmp_path / "bare.toml"
    config.write_text("", encoding="utf-8")
    result = observe(out, "--traces", str(clean / "pydantic_delegation.json"), config=config)
    assert result.exit_code == 2
    assert "observe needs --registry" in result.output.replace("\n", " ")


def test_a_stale_report_is_removed_when_the_settings_do_not_resolve(
    tmp_path: Path, out: Path
) -> None:
    out.mkdir()
    stale = out / OBSERVE_FILE_NAME
    stale.write_text("{}", encoding="utf-8")
    missing = tmp_path / "missing.toml"
    result = runner.invoke(app, ["observe", "--output-dir", str(out), "--config", str(missing)])
    assert result.exit_code == 2
    assert not stale.exists()


@pytest.mark.parametrize("name", sorted(CONTENT))
def test_no_content_reaches_the_report_or_the_output(clean: Path, out: Path, name: str) -> None:
    marker = CONTENT[name]
    assert marker in (clean / name).read_text(encoding="utf-8")
    result = observe(out, "--traces", str(clean / name))
    # pydantic_handoff runs the agents in sequence: trade-agent starts from the user (OFF_MAP).
    assert result.exit_code in (0, 1), result.output
    assert marker not in (out / OBSERVE_FILE_NAME).read_text(encoding="utf-8")
    assert marker not in result.output
    shown = inspect_trace(trace_of(load(out)), DATA / "observe.toml", str(clean / name))
    assert shown.exit_code == 0, shown.output
    assert marker not in shown.output


def test_inspect_trace_shows_how_the_trace_was_read(clean: Path, tmp_path: Path, out: Path) -> None:
    config = variant(tmp_path, registry=no_handoff_registry())
    traces = str(clean / "openai_oi_handoff.json")
    done = observe(out, "--traces", traces, config=config)
    assert done.exit_code == 1, done.output
    trace = trace_of(load(out))
    result = inspect_trace(trace.upper(), config, traces)  # OTLP ids match in lower case
    assert result.exit_code == 0, result.output
    lines = [re.sub(r"\s+", " ", line.strip()) for line in result.output.splitlines()]
    assert lines[0] == f"lockwalk inspect - trace {trace} (complete) user: present"
    assert "agent supervisor from user: ON_MAP" in lines
    assert "agent trade-agent from supervisor: OFF_MAP" in lines
    assert "tool execute_trade used by trade-agent: ON_MAP" in lines
    assert any(re.fullmatch(r"\(\d+ other spans?\)", line) for line in lines)
    # Names of other spans are never printed.
    for hidden in ("handoff to trade-agent", "Agent workflow", "app-request", "authz-check"):
        assert hidden not in result.output


def test_inspect_trace_masks_unknown_names(clean: Path, tmp_path: Path) -> None:
    document = json.loads((clean / "pydantic_delegation.json").read_text(encoding="utf-8"))
    spans = [s for r in document["resourceSpans"] for c in r["scopeSpans"] for s in c["spans"]]
    for span in spans:
        for attribute in span["attributes"]:
            if attribute["value"].get("stringValue") == "trade-agent":
                attribute["value"]["stringValue"] = "https://user:pw@evil.example/x?k=v"
    traces = tmp_path / "t.json"
    traces.write_text(json.dumps(document), encoding="utf-8")
    result = inspect_trace(spans[0]["traceId"], DATA / "observe.toml", str(traces))
    assert result.exit_code == 0, result.output
    assert "UNKNOWN agent" in result.output
    assert "evil.example" in result.output
    assert "user:pw" not in result.output
    assert "k=v" not in result.output


def test_inspect_trace_with_a_missing_id(clean: Path) -> None:
    result = inspect_trace("f" * 32, DATA / "observe.toml", str(clean / "pydantic_delegation.json"))
    assert result.exit_code == 2
    assert "no trace" in result.output


def test_inspect_needs_exactly_one_of_case_and_trace() -> None:
    neither = runner.invoke(app, ["inspect"])
    both = runner.invoke(app, ["inspect", "--case", "CASE-001", "--trace", "abc"])
    for result in (neither, both):
        assert result.exit_code == 2
        assert "exactly one of --case" in result.output.replace("\n", " ")


def test_inspect_trace_lists_run_errors_at_the_end(
    clean: Path, pydantic_trace: str, tmp_path: Path
) -> None:
    folder = tmp_path / "traces"
    folder.mkdir()
    shutil.copy(clean / "pydantic_delegation.json", folder / "good.json")
    (folder / "bad.jsonl").write_text("{not json}\n", encoding="utf-8")
    result = inspect_trace(pydantic_trace, DATA / "observe.toml", str(folder))
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert "errors:" in lines
    assert "bad.jsonl" in "".join(lines[lines.index("errors:") + 1 :])
    assert "not json" not in result.output


def test_reader_function_run(tmp_path: Path, out: Path) -> None:
    reader = f'[observe]\nreader = "{(APPS / "reader_ok.py").as_posix()}:read"\n'
    config = variant(tmp_path, extra=reader)
    result = observe(out, config=config)
    assert result.exit_code == 0, result.output
    report = load(out)
    assert report["totals"]["traces"] == 2
    assert routes(report) >= {
        ("user", "supervisor", "ON_MAP"),
        ("supervisor", "trade-agent", "ON_MAP"),
        ("trade-agent", "execute_trade", "ON_MAP"),
    }
    # Reader ids are compared exactly (OTLP ids in lower case).
    assert inspect_trace("T1", config).exit_code == 0
    assert inspect_trace("t1", config).exit_code == 2


def agent_span(trace: str, span: str, parent: str | None, name: str, start: int) -> dict:
    found: dict = {
        "traceId": trace,
        "spanId": span,
        "name": f"invoke_agent {name}",
        "startTimeUnixNano": str(1_794_105_344_000_000_000 + start),
        "endTimeUnixNano": str(1_794_105_344_000_000_000 + start + 1000),
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}},
            {"key": "gen_ai.agent.name", "value": {"stringValue": name}},
        ],
    }
    if parent is not None:
        found["parentSpanId"] = parent
    return found


def write_spans(path: Path, spans: list[dict]) -> str:
    document = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


TRACE = "c3" * 16


def test_inspect_an_incomplete_trace(tmp_path: Path) -> None:
    spans = [agent_span(TRACE, "00000000000000a1", "00000000000000ff", "supervisor", 0)]
    traces = write_spans(tmp_path / "t.json", spans)
    result = inspect_trace(TRACE, DATA / "observe.toml", traces)
    assert result.exit_code == 0, result.output
    assert f"lockwalk inspect - trace {TRACE} (incomplete)  user: missing" in result.output
    assert "agent supervisor" in result.output
    assert "caller not known" in result.output


def test_inspect_a_merged_span(tmp_path: Path) -> None:
    spans = [
        agent_span(TRACE, "00000000000000a1", None, "supervisor", 0),
        agent_span(TRACE, "00000000000000a2", "00000000000000a1", "supervisor", 10),
    ]
    traces = write_spans(tmp_path / "t.json", spans)
    result = inspect_trace(TRACE, DATA / "observe.toml", traces)
    assert result.exit_code == 0, result.output
    assert "(same agent again: supervisor)" in result.output
    assert result.output.count("from user: ON_MAP") == 1


@pytest.mark.parametrize(
    ("spans", "message"),
    [
        (
            [
                agent_span(TRACE, "00000000000000a1", None, "supervisor", 0),
                agent_span(TRACE, "00000000000000a1", None, "supervisor", 10),
            ],
            "the trace repeats a span id",
        ),
        (
            [
                agent_span(TRACE, "00000000000000a1", "00000000000000a2", "supervisor", 0),
                agent_span(TRACE, "00000000000000a2", "00000000000000a1", "supervisor", 10),
            ],
            "form a loop",
        ),
    ],
)
def test_inspect_an_errored_trace_shows_the_error_once(
    tmp_path: Path, spans: list[dict], message: str
) -> None:
    traces = write_spans(tmp_path / "t.json", spans)
    result = inspect_trace(TRACE, DATA / "observe.toml", traces)
    assert result.exit_code == 0, result.output
    assert "(the trace could not be walked)" in result.output
    assert result.output.count(message) == 1
    assert f"trace {TRACE}:" not in result.output  # not repeated under errors:


def test_sources_are_shown_as_given(clean: Path, tmp_path: Path, out: Path, monkeypatch) -> None:
    folder = tmp_path / "traces"
    folder.mkdir()
    shutil.copy(clean / "pydantic_delegation.json", tmp_path / "one.json")
    shutil.copy(clean / "openai_oi_handoff.json", folder / "two.json")
    shutil.copy(clean / "langgraph_oi_sub.json", folder / "three.json")
    monkeypatch.chdir(tmp_path)
    result = observe(out, "--traces", "one.json", "--traces", "traces")
    assert result.exit_code == 0, result.output
    report = load(out)
    assert report["sources"] == ["one.json", "traces (2 files)"]
    assert "Sources:      one.json, traces (2 files)" in result.output
    assert str(tmp_path) not in (out / OBSERVE_FILE_NAME).read_text(encoding="utf-8")
    sources_line = next(line for line in result.output.splitlines() if line.startswith("Sources:"))
    assert str(tmp_path) not in sources_line


def test_inspect_case_refuses_trace_only_options() -> None:
    result = runner.invoke(app, ["inspect", "--case", "CASE-001", "--traces", "x.json"])
    assert result.exit_code == 2
    assert "--case does not take --traces" in result.output.replace(chr(10), " ")


def test_a_problem_without_a_place_has_no_empty_prefix(
    clean: Path, tmp_path: Path, out: Path
) -> None:
    config = variant(tmp_path, extra="[observe]\nmax_spans = 1\n")
    result = observe(out, "--traces", str(clean / "pydantic_delegation.json"), config=config)
    assert result.exit_code == 2, result.output
    errors = load(out)["errors"]
    assert any(item.startswith("more than 1 spans") for item in errors), errors
    assert not any(item.startswith(": ") for item in errors)


def test_inspect_trace_not_found_lists_the_run_errors() -> None:
    result = inspect_trace("abc", DATA / "observe.toml", "nonexist")
    assert result.exit_code == 2
    assert "Error: no trace 'abc' in the traces: nonexist: this path does not exist" in (
        result.output
    )
    assert "x0a" not in result.output
    assert "no traces were read" not in result.output
