"""Acceptance tests for examples/multi_agent.

Most tests run the real CLI on a copy of the example. Discovery then imports app.py in a
worker subprocess and reads real OpenAI Agents SDK and Pydantic AI objects. reuse_discovery
keeps each worker result for the whole module, so a test that edits only the registry or
the spec reuses it, and a test that edits app.py gets a fresh worker. One test runs the
console entry point with fresh workers, the network blocked, and no API key. Nothing calls
a model or the network. The README shows the output these tests pin, and a test checks it.
"""

import json
import os
import runpy
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lockwalk import cli
from lockwalk.config import PythonSourceConfig
from lockwalk.inventory.python import PythonSource
from lockwalk.models import SourceResult

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "multi_agent"

runner = CliRunner()

TREE = [
    "Agent graph (entry agents: supervisor, trade-desk):",
    "  supervisor  [delegation_mode=user]",
    "    -[handoff, discovered]-> finance-agent  [delegation_mode=user]",
    "      -[calls, declared]-> pricing-agent  [delegation_mode=on_behalf_of]",
    "        -[uses_tool, discovered]-> get_stock_price  (risk=low)",
    "      -[agent_as_tool, discovered]-> trade-agent  [delegation_mode=agent]",
    "        -[calls, declared]-> finance-agent  [delegation_mode=user]  (cycle)",
    "        -[handoff, discovered]-> finance-agent  [delegation_mode=user]  (cycle)",
    "        -[calls, declared]-> market-oracle  (opaque)",
    "        -[uses_tool, discovered]-> confirm_price  (risk=medium)",
    "        -[uses_tool, discovered]-> execute_trade  (risk=critical)",
    "      -[calls, declared]-> trade-agent  [delegation_mode=agent]  (see above)",
    "      -[uses_tool, discovered]-> get_quote  (risk=low)",
    "      -[uses_tool, discovered]-> read_portfolio  (risk=high)",
    "  trade-desk  [delegation_mode=user]",
    "    -[handoff, discovered]-> trade-agent  [delegation_mode=agent]  (see above)",
]

NOTES = [
    "Graph notes:",
    "  Cycles: finance-agent -> trade-agent -> finance-agent",
    "  Opaque: market-oracle",
]

RULE_001_FAIL = "  RULE-001  FAIL          role:analyst -> tool:execute_trade"
RULE_001_PASS = "  RULE-001  PASS          role:analyst -> tool:execute_trade"
RULE_002_INCONCLUSIVE = (
    "  RULE-002  INCONCLUSIVE  agent:market-oracle -> tool:execute_trade "
    "(passes through opaque: market-oracle)"
)
RULE_002_PASS = "  RULE-002  PASS          agent:market-oracle -> tool:execute_trade"
RULE_003_PASS = "  RULE-003  PASS          agent:pricing-agent -> tool:execute_trade"

WITNESS = (
    "    supervisor -[handoff, discovered]-> finance-agent "
    "-[agent_as_tool, discovered]-> trade-agent -[uses_tool, discovered]-> execute_trade"
)
# The same route once the code no longer has it but finance-agent's calls still list it.
DECLARED_WITNESS = (
    "    supervisor -[handoff, discovered]-> finance-agent "
    "-[calls, declared]-> trade-agent -[uses_tool, discovered]-> execute_trade"
)

RULES = ["Never-reaches rules:", RULE_001_FAIL, WITNESS, RULE_002_INCONCLUSIVE, RULE_003_PASS]

IDENTITY = (
    "agent 'trade-agent' calls tools with its own identity; the IAM will not see the user. "
    "Through it, roles analyst, trader can reach 1 high-risk tool: execute_trade"
)
ROLE_GAP = (
    "role 'trader' can reach 1 high-risk tool that no case or rule covers: "
    "read_portfolio (risk=high)"
)
# .lockwalk.toml also points at pricing-agent, which is no entry agent. An entry agent
# reaches it (finance-agent calls it), so lockwalk does not warn about it.
WARNINGS = ["Warnings:", f"  - {IDENTITY}", f"  - {ROLE_GAP}"]

GATE = [
    "Gate: FAIL (exit 1)",
    "  - never_reaches: RULE-001 (FAIL)",
    "  - never_reaches: RULE-002 (INCONCLUSIVE)",
]

# The edits the README shows for each fix: the text before, and the text after.
AS_TOOL_ENTRY = """\
        trade_agent.as_tool(
            tool_name="ask_trade_agent",
            tool_description="Ask the trade agent to execute an order.",
        ),
"""
FINANCE_CALLS = "    calls: [trade-agent, pricing-agent]\n"
FINANCE_CALLS_FIXED = "    calls: [pricing-agent]\n"
ORACLE_ENTRY = """\
  - id: market-oracle
    description: The exchange's remote price oracle. lockwalk cannot see what it calls.
    remote: https://oracle.example/a2a
"""
ORACLE_ENTRY_FIXED = ORACLE_ENTRY + "    calls: []\n"

# The README's alternative to the list target in .lockwalk.toml.
PER_ENTRY_TARGETS = [
    "--python",
    "app:supervisor",
    "--python",
    "app:trade_desk",
    "--python",
    "app:pricing_agent",
]


@dataclass(frozen=True)
class Outcome:
    """discover and coverage on one copy of the example, and the report coverage wrote."""

    directory: Path
    discover_lines: list[str]
    discover_code: int
    coverage_lines: list[str]
    coverage_code: int
    report: dict


def copy_example(parent: Path) -> Path:
    directory = parent / "multi_agent"
    shutil.copytree(EXAMPLE, directory, ignore=shutil.ignore_patterns(".lockwalk", "__pycache__"))
    return directory


def run(directory: Path, command: str):
    """Run one command against a copy's own .lockwalk.toml, from any working directory."""
    return runner.invoke(cli.app, [command, "--config", str(directory / ".lockwalk.toml")])


def report_of(directory: Path) -> dict:
    return json.loads((directory / ".lockwalk" / "coverage.json").read_text(encoding="utf-8"))


def coverage_of(directory: Path) -> tuple[int, list[str]]:
    result = run(directory, "coverage")
    return result.exit_code, result.stdout.splitlines()


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, old
    path.write_text(text.replace(old, new), encoding="utf-8")


def remove_route_in_code(directory: Path) -> None:
    edit(directory / "app.py", AS_TOOL_ENTRY, "")


def remove_route_in_registry(directory: Path) -> None:
    edit(directory / "registry.yaml", FINANCE_CALLS, FINANCE_CALLS_FIXED)


def declare_oracle_calls(directory: Path) -> None:
    edit(directory / "registry.yaml", ORACLE_ENTRY, ORACLE_ENTRY_FIXED)


def assert_block(lines: list[str], block: list[str]) -> None:
    """Assert that the output has these lines in a row. A failure shows the whole output."""
    output = "\n".join(lines)
    assert block[0] in lines, f"{block[0]!r} is not in the output:\n{output}"
    start = lines.index(block[0])
    assert lines[start : start + len(block)] == block, f"the output was:\n{output}"


@pytest.fixture(scope="module", autouse=True)
def reuse_discovery() -> Iterator[None]:
    """Read each (Python source config, app.py) pair once for the whole module.

    The worker's result depends on nothing else, so the tests that edit only the registry
    or the spec reuse the results, and a test that edits app.py gets a fresh worker. The
    entry point test below runs in a subprocess, so it always starts its own real workers.
    """
    results: dict[tuple[PythonSourceConfig, bytes], SourceResult] = {}
    read = PythonSource.read

    def cached(self: PythonSource) -> SourceResult:
        key = (self._config, (self._base_dir / "app.py").read_bytes())
        if key not in results:
            results[key] = read(self)
        return results[key]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(PythonSource, "read", cached)
        yield


@pytest.fixture(scope="module")
def original(tmp_path_factory: pytest.TempPathFactory) -> Outcome:
    """The unchanged example, run once for every test that only reads its output."""
    directory = copy_example(tmp_path_factory.mktemp("original"))
    shown = run(directory, "discover")
    checked = run(directory, "coverage")
    return Outcome(
        directory=directory,
        discover_lines=shown.stdout.splitlines(),
        discover_code=shown.exit_code,
        coverage_lines=checked.stdout.splitlines(),
        coverage_code=checked.exit_code,
        report=report_of(directory),
    )


@pytest.fixture
def example(tmp_path: Path) -> Path:
    """A fresh copy of the example, for a test that edits it."""
    return copy_example(tmp_path)


# ---- 1. discover draws the whole graph ----


DEMO_MODULES = ("demo_door", "demo_trading")


def test_importing_the_app_works_without_the_network(no_network, monkeypatch, request):
    """A smoke test only: the frameworks may already be imported by other tests.

    The entry point test at the end is the real check, with fresh processes.
    """
    # app.py imports demo_door and demo_trading from its own directory, as lockwalk's
    # workers find them. The finalizer removes them again, so the test leaves no state.
    monkeypatch.syspath_prepend(str(EXAMPLE))
    request.addfinalizer(lambda: [sys.modules.pop(n, None) for n in DEMO_MODULES])
    found = runpy.run_path(str(EXAMPLE / "app.py"))
    assert [agent.name for agent in found["OPENAI_ENTRY_AGENTS"]] == ["supervisor", "trade-desk"]
    assert found["pricing_agent"].name == "pricing-agent"


def test_discover_draws_the_tree_with_kinds_and_provenance(original):
    lines = original.discover_lines
    assert original.discover_code == 0, "\n".join(lines)
    assert lines[1] == (
        "Inventory sources: registry:registry.yaml, python:app:OPENAI_ENTRY_AGENTS, "
        "python:app:pricing_agent"
    )
    assert_block(lines, TREE)
    assert_block(lines, NOTES)
    assert_block(lines, RULES)  # discover shows the rules, but has no gate
    assert f"  - {IDENTITY}" in lines
    assert lines[-1] == "Result: OK (exit 0)"


def test_every_tool_comes_from_the_framework_that_defines_it(original):
    sources = {
        line.split()[0]: line.split("sources=")[1].split("  ")[0]
        for line in original.discover_lines
        if "  sources=" in line
    }
    openai = "registry:registry.yaml, python:app:OPENAI_ENTRY_AGENTS"
    assert sources == {
        "read_portfolio": openai,
        "get_quote": openai,
        "execute_trade": openai,
        "confirm_price": openai,
        "get_stock_price": "registry:registry.yaml, python:app:pricing_agent",
    }
    assert "Inventory drift: none" in original.discover_lines


# ---- 2. coverage blocks the analyst's route to execute_trade ----


def test_coverage_fails_rule_001_with_its_witness_and_the_identity_warning(original):
    lines = original.coverage_lines
    assert original.coverage_code == 1, "\n".join(lines)
    assert_block(lines, TREE)
    assert_block(lines, RULES)
    assert_block(lines, WARNINGS)
    assert_block(lines, GATE)
    assert "Errors:" not in lines


# ---- 3. removing the route makes RULE-001 pass ----


def test_removing_the_route_makes_rule_001_pass(example):
    remove_route_in_code(example)
    code, lines = coverage_of(example)
    # finance-agent's calls still declare the route, and lockwalk trusts the declaration.
    assert code == 1, "\n".join(lines)
    assert_block(lines, [RULE_001_FAIL, DECLARED_WITNESS])

    remove_route_in_registry(example)
    code, lines = coverage_of(example)
    assert code == 1, "\n".join(lines)
    assert RULE_001_PASS in lines
    assert RULE_002_INCONCLUSIVE in lines
    assert_block(lines, ["Gate: FAIL (exit 1)", "  - never_reaches: RULE-002 (INCONCLUSIVE)", ""])
    # Traders still reach execute_trade through trade-desk.
    trader = [line for line in lines if line.startswith("  trader   execute_trade")]
    assert trader == [
        "  trader   execute_trade    critical  REACHABLE  delegation_mode=agent         "
        "covered_by=CASE-004, CASE-005"
    ]
    assert not any(line.startswith("  analyst  execute_trade") for line in lines)


# ---- 4. market-oracle: INCONCLUSIVE until its calls are declared ----


def test_the_market_oracle_rule_is_inconclusive_and_fails_the_gate(original):
    assert RULE_002_INCONCLUSIVE in original.coverage_lines
    assert "  - never_reaches: RULE-002 (INCONCLUSIVE)" in original.coverage_lines
    rule = next(row for row in original.report["rules"] if row["id"] == "RULE-002")
    assert rule["result"] == "INCONCLUSIVE"
    assert rule["opaque_reached"] == ["market-oracle"]


def test_declaring_market_oracle_calls_makes_its_rule_pass(example):
    declare_oracle_calls(example)
    code, lines = coverage_of(example)
    assert code == 1, "\n".join(lines)
    assert RULE_002_PASS in lines
    assert_block(lines, [RULE_001_FAIL, WITNESS])
    assert_block(lines, ["Gate: FAIL (exit 1)", "  - never_reaches: RULE-001 (FAIL)", ""])
    assert "  Opaque: market-oracle" not in lines

    # With both fixes the gate passes.
    remove_route_in_code(example)
    remove_route_in_registry(example)
    code, lines = coverage_of(example)
    assert code == 0, "\n".join(lines)
    assert [line for line in lines if line.startswith("  RULE-")] == [
        RULE_001_PASS,
        RULE_002_PASS,
        RULE_003_PASS,
    ]
    assert "Gate: PASS (exit 0)" in lines
    assert report_of(example)["exit_code"] == 0


# ---- a forgotten entry agent is reported ----

TRADE_DESK_ENTRY = "    entry: true\n    roles: [trader]\n"
TRADER_RULE = "  - id: RULE-009\n    role: trader\n    tool: execute_trade\n"


def test_a_top_level_target_that_is_not_marked_entry_is_reported(example):
    """Both fixes done, but trade-desk lost its entry: true. Traders now start only at
    supervisor, so RULE-009 passes without seeing the trade-desk route, and the gate
    passes. The warning and the graph note are what tell you."""
    remove_route_in_code(example)
    remove_route_in_registry(example)
    declare_oracle_calls(example)
    edit(
        example / "registry.yaml",
        "  - id: trade-desk\n    description: Front door for traders only.\n" + TRADE_DESK_ENTRY,
        "  - id: trade-desk\n    description: Front door for traders only.\n",
    )
    spec = example / "security-spec.yaml"
    spec.write_text(spec.read_text(encoding="utf-8") + TRADER_RULE, encoding="utf-8")
    code, lines = coverage_of(example)
    assert "  RULE-009  PASS          role:trader -> tool:execute_trade" in lines
    assert (
        "  - agent 'trade-desk' is a top-level discovery target but is not marked "
        "entry: true; no role starts there"
    ) in lines
    assert "  Not reachable from entry agents: market-oracle, trade-agent, trade-desk" in lines
    graph = report_of(example)["agent_graph"]
    assert graph["entry_agents"] == ["supervisor"]
    assert graph["unreachable"] == ["market-oracle", "trade-agent", "trade-desk"]
    assert code == 0, "\n".join(lines)


SUPERVISOR_ROLES = "    roles: [analyst, trader]\n"
STARTLESS_TRADER = (
    "no entry agent lists role 'trader', so lockwalk cannot tell where it starts; mark its "
    "entry agent with entry: true and add the role to its roles"
)


def test_a_rule_for_a_role_that_no_entry_agent_lists_is_inconclusive(example):
    """As above, and supervisor is for analysts only: traders start nowhere, so RULE-009
    checks nothing. That is INCONCLUSIVE, and the default gate fails it."""
    remove_route_in_code(example)
    remove_route_in_registry(example)
    declare_oracle_calls(example)
    registry = example / "registry.yaml"
    edit(
        registry,
        "  - id: trade-desk\n    description: Front door for traders only.\n" + TRADE_DESK_ENTRY,
        "  - id: trade-desk\n    description: Front door for traders only.\n",
    )
    edit(registry, SUPERVISOR_ROLES, "    roles: [analyst]\n")
    spec = example / "security-spec.yaml"
    spec.write_text(spec.read_text(encoding="utf-8") + TRADER_RULE, encoding="utf-8")
    code, lines = coverage_of(example)
    assert code == 1, "\n".join(lines)
    assert f"  RULE-009  INCONCLUSIVE  role:trader -> tool:execute_trade - {STARTLESS_TRADER}" in (
        lines
    )
    warning = (
        "  - no entry agent lists 1 role, so lockwalk cannot tell where it starts: trader; "
        "mark its entry agent with entry: true and add the role to its roles"
    )
    assert warning in lines
    assert "  - never_reaches: RULE-009 (INCONCLUSIVE)" in lines
    rule = next(row for row in report_of(example)["rules"] if row["id"] == "RULE-009")
    assert (rule["result"], rule["opaque_reached"], rule["problems"]) == (
        "INCONCLUSIVE",
        [],
        [STARTLESS_TRADER],
    )
    shown = run(example, "discover")
    assert warning in shown.stdout.splitlines()


# ---- one target per entry agent works as well as the list ----


def test_one_target_per_entry_agent_gives_the_same_graph(example, monkeypatch):
    """Both OpenAI walks report the tools of the agents they share; identical tools merge."""
    monkeypatch.chdir(example)  # command-line targets are resolved against the cwd
    discover_run = runner.invoke(cli.app, ["discover", *PER_ENTRY_TARGETS])
    lines = discover_run.stdout.splitlines()
    assert discover_run.exit_code == 0, discover_run.stdout
    assert "Errors:" not in lines
    assert_block(lines, TREE)
    both = "registry:registry.yaml, python:app:supervisor, python:app:trade_desk"
    for tool in ("read_portfolio", "get_quote", "execute_trade", "confirm_price"):
        line = next(line for line in lines if line.startswith(f"  {tool} "))
        assert f"sources={both}  " in line, line
    coverage_run = runner.invoke(cli.app, ["coverage", *PER_ENTRY_TARGETS])
    lines = coverage_run.stdout.splitlines()
    assert coverage_run.exit_code == 1, coverage_run.stdout
    assert_block(lines, RULES)
    assert_block(lines, GATE)
    assert "Errors:" not in lines


# ---- 5. coverage.json v2 ----


def test_coverage_json_has_the_graph_reachability_and_rules(original):
    report = original.report
    assert report["schema_version"] == "5"
    assert report["exit_code"] == 1
    graph = report["agent_graph"]
    assert graph["entry_agents"] == ["supervisor", "trade-desk"]
    assert graph["entry_inferred"] is False
    assert graph["cycles"] == [["finance-agent", "trade-agent", "finance-agent"]]
    assert graph["opaque"] == ["market-oracle"]
    assert graph["unreachable"] == []
    assert graph["drift"] == {
        "discovered_only_agents": [],
        "declared_only_agents": [],
        "undeclared_edges": [],
        "complete": True,
    }
    kinds = {node["id"]: node["kind"] for node in graph["nodes"]}
    assert kinds == {
        "supervisor": "agent",
        "trade-desk": "agent",
        "finance-agent": "agent",
        "trade-agent": "agent",
        "pricing-agent": "agent",
        "market-oracle": "remote_agent",
    }
    edges = {
        (edge["from_id"], edge["to_id"], edge["kind"], edge["provenance"])
        for edge in graph["edges"]
        if edge["kind"] != "uses_tool"
    }
    assert edges == {
        ("supervisor", "finance-agent", "handoff", "discovered"),
        ("trade-desk", "trade-agent", "handoff", "discovered"),
        ("finance-agent", "trade-agent", "agent_as_tool", "discovered"),
        ("finance-agent", "trade-agent", "calls", "declared"),
        ("finance-agent", "pricing-agent", "calls", "declared"),
        ("trade-agent", "finance-agent", "handoff", "discovered"),
        ("trade-agent", "finance-agent", "calls", "declared"),
        ("trade-agent", "market-oracle", "calls", "declared"),
    }
    rules = {row["id"]: row for row in report["rules"]}
    assert {rule_id: row["result"] for rule_id, row in rules.items()} == {
        "RULE-001": "FAIL",
        "RULE-002": "INCONCLUSIVE",
        "RULE-003": "PASS",
    }
    assert [(e["from_id"], e["kind"], e["to_id"]) for e in rules["RULE-001"]["witness"]] == [
        ("supervisor", "handoff", "finance-agent"),
        ("finance-agent", "agent_as_tool", "trade-agent"),
        ("trade-agent", "uses_tool", "execute_trade"),
    ]
    rows = {(row["role"], row["tool"]): row for row in report["reachability"]}
    assert len(rows) == 10  # both roles reach all five tools
    analyst_trade = rows[("analyst", "execute_trade")]
    assert analyst_trade["status"] == "REACHABLE"
    assert analyst_trade["delegation_mode"] == "agent"
    assert analyst_trade["covered_by"] == ["RULE-001"]
    assert report["gate"]["violations"] == [
        {
            "rule": "never_reaches",
            "tool": None,
            "risk": None,
            "role": None,
            "rule_id": rule_id,
            "result": result,
            "case_id": None,
            "status": None,
            "via": None,
        }
        for rule_id, result in (("RULE-001", "FAIL"), ("RULE-002", "INCONCLUSIVE"))
    ]
    assert report["cases"][2]["path"] == ["supervisor", "finance-agent", "pricing-agent"]
    assert report["cases"][2]["agent"] == "pricing-agent"


# ---- 6. ASCII only ----


def test_all_output_is_ascii(original):
    for lines in (original.discover_lines, original.coverage_lines):
        assert "\n".join(lines).isascii()
    assert (original.directory / ".lockwalk" / "coverage.json").read_bytes().isascii()


# ---- the README shows the output and the edits these tests pin ----


def test_the_readme_shows_the_real_output_and_edits():
    readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    for block in (TREE, NOTES, RULES, WARNINGS, GATE):
        assert "\n".join(block) in readme, block[0]
    for line in (DECLARED_WITNESS, RULE_001_PASS, RULE_002_PASS, "Gate: PASS (exit 0)"):
        assert f"\n{line}\n" in readme, line
    # Fix 1 and Fix 2 as the README writes them, and the text they replace.
    assert f"`{FINANCE_CALLS_FIXED.strip()}`" in readme
    assert f"```yaml\n{ORACLE_ENTRY_FIXED}```" in readme
    assert AS_TOOL_ENTRY in (EXAMPLE / "app.py").read_text(encoding="utf-8")
    registry = (EXAMPLE / "registry.yaml").read_text(encoding="utf-8")
    assert FINANCE_CALLS in registry
    assert ORACLE_ENTRY in registry
    assert ORACLE_ENTRY_FIXED not in registry
    assert f"uv run lockwalk discover {' '.join(PER_ENTRY_TARGETS)}\n" in readme


# ---- the real entry point, with the network blocked and no API key ----

# Loaded by every Python process the run starts (lockwalk and each discovery worker),
# because its directory is first on PYTHONPATH. It blocks, and records, the usual
# Python-level ways to reach the network: name lookups and outgoing connections through
# the socket module. It also records each process that loaded it.
BLOCK_NETWORK = textwrap.dedent(
    """\
    import os
    import socket
    import sys

    _LOG = os.environ["LOCKWALK_TEST_NET_LOG"]


    def _write(kind):
        # One line per record, even when an argument holds a line break.
        command = " ".join(sys.orig_argv).replace(chr(10), " ").replace(chr(13), " ")
        with open(_LOG, "a", encoding="utf-8") as log:
            log.write(kind + " " + command + chr(10))


    def _refuse(*args, **kwargs):
        _write("NETWORK")
        raise OSError("the network is blocked in this test")


    socket.socket.connect = _refuse
    socket.socket.connect_ex = _refuse
    socket.socket.sendto = _refuse
    socket.create_connection = _refuse
    socket.getaddrinfo = _refuse
    socket.gethostbyname = _refuse
    socket.gethostbyname_ex = _refuse
    socket.gethostbyaddr = _refuse
    _write("STARTED")
    """
)


def test_the_entry_point_runs_the_readme_command_without_network_or_keys(tmp_path):
    blocker = tmp_path / "block"
    blocker.mkdir()
    (blocker / "sitecustomize.py").write_text(BLOCK_NETWORK, encoding="utf-8")
    log = tmp_path / "net.log"
    env = {
        name: value
        for name, value in os.environ.items()
        if "API_KEY" not in name.upper() and not name.upper().startswith("OPENAI")
    }
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(blocker), os.environ.get("PYTHONPATH", "")) if part
    )
    env["LOCKWALK_TEST_NET_LOG"] = str(log)
    out = tmp_path / "out"
    # The README's command from the repository root, with the report kept out of the repo.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from lockwalk.cli import main; main()",
            "coverage",
            "--config",
            "examples/multi_agent/.lockwalk.toml",
            "--output-dir",
            str(out),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    assert_block(lines, RULES)
    assert_block(lines, GATE)
    assert result.stdout.isascii()
    records = log.read_text(encoding="utf-8").splitlines()
    assert not [line for line in records if line.startswith("NETWORK")], records
    # The block was active in lockwalk itself and in both discovery workers.
    started = [line for line in records if line.startswith("STARTED")]
    assert len([line for line in started if "_python_worker" in line]) == 2, records
    assert len(started) == 3, records
    assert json.loads((out / "coverage.json").read_text(encoding="utf-8"))["exit_code"] == 1
