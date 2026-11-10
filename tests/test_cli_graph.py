"""The CLI with the agent graph: discover and coverage, snapshots, and fixes without a graph."""

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lockwalk import cli, pipeline
from lockwalk.graph.build import NO_ENTRY_WARNING
from lockwalk.inventory.collect import EMPTY_INVENTORY_WARNING
from lockwalk.inventory.python import PythonSource
from lockwalk.report import to_ascii
from lockwalk.snapshot import SNAPSHOT_KEY

runner = CliRunner()

# Plain classes are enough for the shape rules, so no framework is imported.
APP = '''
def lookup(query: str) -> str:
    """Look something up."""
    raise RuntimeError("tools are never called")


class Agent:
    def __init__(self, name, tools, handoffs=()):
        self.name = name
        self.tools = list(tools)
        self.handoffs = list(handoffs)


helper = Agent("helper", [lookup])
ROOT = Agent("front", [], handoffs=[helper])
'''

# 'helper' is only known through discovery; 'front' is declared.
REGISTRY = """\
schema_version: '1'
roles: [analyst, trader]
agents:
  - id: front
    entry: true
    delegation_mode: user
tools:
  - id: lookup
    action: data:read
    risk: high
"""

CASE = """\
  - id: {id}
    actor: alice
    role: {role}
    agent: {agent}
    tool: lookup
    action: data:read
    resource_fixture: r1
    expect: deny
"""

SPEC = (
    "schema_version: '1'\nscenario_suite: graph-demo\ncases:\n"
    + CASE.format(id="CASE-001", role="analyst", agent="helper")
    + "never_reaches:\n  - id: RULE-001\n    role: trader\n    tool: lookup\n"
)

IDENTITY = (
    "agent 'helper' has no declared delegation_mode; the IAM may not see the user. "
    "Through it, roles analyst, trader can reach 1 high-risk tool: lookup"
)

DISCOVER = ["discover", "--registry", "registry.yaml", "--python", "app:ROOT"]
COVERAGE = ["coverage", "--registry", "registry.yaml", "--spec", "spec.yaml"]


@pytest.fixture
def project(tmp_path, monkeypatch) -> Path:
    """A registry, a spec, and a Python app with one discovered-only agent, in the cwd."""
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "registry.yaml").write_text(REGISTRY, encoding="utf-8")
    (tmp_path / "spec.yaml").write_text(SPEC, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def demo(tmp_path, example_dir, monkeypatch) -> Path:
    """A copy of the finance demo registry and spec in the cwd."""
    for name in ("registry.yaml", "security-spec.yaml"):
        shutil.copy(example_dir / name, tmp_path / name)
    monkeypatch.chdir(tmp_path)
    return tmp_path


# The demo registry marks both agents entry: true with calls: []. Without those two lines
# it has the shape it has without a graph, which declares neither.
DEMO_GRAPH_LINES = "    entry: true\n    calls: []\n"


@pytest.fixture
def sp1_demo(demo) -> Path:
    """The demo with the registry in its shape without a graph: no entry agent, no calls."""
    registry = demo / "registry.yaml"
    text = registry.read_text(encoding="utf-8")
    assert text.count(DEMO_GRAPH_LINES) == 2
    registry.write_text(text.replace(DEMO_GRAPH_LINES, ""), encoding="utf-8")
    return demo


def run(*args: str):
    return runner.invoke(cli.app, list(args))


def lines_of(result) -> list[str]:
    return result.stdout.splitlines()


def tool_line(result, tool: str) -> str:
    return next(line for line in lines_of(result) if line.strip().startswith(tool))


def written(path: Path) -> str:
    """The line discover prints for a snapshot (paths are shown escaped, like all output)."""
    return to_ascii(f"Snapshot written to {path}")


def report_of(directory: Path) -> dict:
    return json.loads((directory / ".lockwalk" / "coverage.json").read_text(encoding="utf-8"))


# ---- discover draws the graph ----


def test_discover_draws_the_graph_and_the_role_reachability(project):
    result = run(*DISCOVER, "--spec", "spec.yaml")
    assert result.exit_code == 0, result.stdout
    lines = lines_of(result)
    tree = lines.index("Agent graph (entry agents: front):")
    assert lines[tree + 1 : tree + 4] == [
        "  front  [delegation_mode=user]",
        "    -[handoff, discovered]-> helper",
        "      -[uses_tool, discovered]-> lookup  (risk=high)",
    ]
    reach = lines.index("Role reachability:")
    assert lines[reach + 1 : reach + 3] == [
        "  analyst  lookup  high  REACHABLE  delegation_mode=unknown  covered_by=CASE-001",
        "  trader   lookup  high  REACHABLE  delegation_mode=unknown  covered_by=RULE-001",
    ]
    assert "Result: OK (exit 0)" in lines  # RULE-001 fails, but discover has no gate
    assert result.stdout.isascii()


def test_discover_and_coverage_agree_on_covered_by(project):
    shown = run(*DISCOVER, "--spec", "spec.yaml")
    result = run(*COVERAGE, "--python", "app:ROOT")
    assert result.exit_code == 1, result.stdout
    assert "  RULE-001  FAIL          role:trader -> tool:lookup" in result.stdout
    rows = report_of(project)["reachability"]
    for row in rows:
        covered = ", ".join(row["covered_by"]) or "NONE"
        assert any(
            line.split()[:2] == [row["role"], row["tool"]] and f"covered_by={covered}" in line
            for line in lines_of(shown)
        ), row
    assert [(row["role"], row["covered_by"]) for row in rows] == [
        ("analyst", ["CASE-001"]),
        ("trader", ["RULE-001"]),
    ]


def test_discover_without_a_spec_covers_nothing(project):
    result = run(*DISCOVER)
    assert result.exit_code == 0, result.stdout
    assert (
        "  analyst  lookup  high  REACHABLE  delegation_mode=unknown  covered_by=NONE"
        in result.stdout
    )


def test_a_case_may_name_an_agent_that_only_discovery_found(project):
    """The plan is made with the same graph, so 'helper' is a known agent."""
    discovered = run(*DISCOVER, "--spec", "spec.yaml")
    assert "spec=yes" in tool_line(discovered, "lookup")
    result = run(*COVERAGE, "--python", "app:ROOT")
    assert report_of(project)["cases"][0]["status"] == "UNTESTED"
    assert result.exit_code == 1, result.stdout  # the gate fails on RULE-001, not exit 2


def test_case_roles_are_checked_against_the_registry_roles(project):
    spec = project / "spec.yaml"
    spec.write_text(SPEC.replace("role: analyst", "role: admin"), encoding="utf-8")
    assert "spec=ERROR" in tool_line(run(*DISCOVER, "--spec", "spec.yaml"), "lookup")
    result = run(*COVERAGE, "--python", "app:ROOT")
    assert result.exit_code == 2
    assert "CASE-001: role 'admin' is not in the registry roles list" in result.stdout


def test_registry_only_runs_still_build_the_graph(sp1_demo):
    result = run("discover", "--registry", "registry.yaml")
    assert result.exit_code == 0, result.stdout
    assert "Agent graph (no entry agent marked; treating all 2 agents as entries):" in (
        lines_of(result)
    )
    assert f"  - {NO_ENTRY_WARNING}" in lines_of(result)


def test_the_finance_demo_marks_its_entries_and_calls(demo):
    """Both demo agents are entries that call no agent, so nothing is guessed or opaque."""
    result = run("discover", "--registry", "registry.yaml", "--spec", "security-spec.yaml")
    assert result.exit_code == 0, result.stdout
    lines = lines_of(result)
    tree = lines.index("Agent graph (entry agents: research-agent, finance-agent):")
    assert lines[tree + 1 : tree + 7] == [
        "  research-agent",
        "    -[uses_tool, declared]-> get_stock_price  (risk=low)",
        "  finance-agent",
        "    -[uses_tool, declared]-> execute_trade  (risk=critical)",
        "    -[uses_tool, declared]-> get_stock_price  (risk=low)",
        "    -[uses_tool, declared]-> read_portfolio  (risk=high)",
    ]
    assert "(opaque)" not in result.stdout
    assert "Graph notes:" not in lines
    assert "Warnings:" not in lines


def test_never_reaches_rules_apply_to_registry_only_runs(sp1_demo):
    demo = sp1_demo
    spec = demo / "security-spec.yaml"
    spec.write_text(
        spec.read_text(encoding="utf-8")
        + "never_reaches:\n  - id: RULE-001\n    agent: research-agent\n    tool: execute_trade\n",
        encoding="utf-8",
    )
    args = ["coverage", "--registry", "registry.yaml", "--spec", "security-spec.yaml"]
    result = run(*args)
    # research-agent declares no calls, so it is opaque and the rule cannot pass.
    assert result.exit_code == 1, result.stdout
    assert "  - never_reaches: RULE-001 (INCONCLUSIVE)" in result.stdout
    registry = demo / "registry.yaml"
    registry.write_text(
        registry.read_text(encoding="utf-8").replace(
            "  - id: research-agent\n", "  - id: research-agent\n    calls: []\n"
        ),
        encoding="utf-8",
    )
    result = run(*args)
    assert result.exit_code == 0, result.stdout
    assert "  RULE-001  PASS          agent:research-agent -> tool:execute_trade" in result.stdout


def test_graph_errors_make_both_commands_exit_2(project, monkeypatch):
    real = pipeline.build_graph

    def broken(*args, **kwargs):
        graph = real(*args, **kwargs)
        return graph.model_copy(update={"errors": ("the graph is broken",)})

    monkeypatch.setattr(pipeline, "build_graph", broken)
    result = run(*DISCOVER)
    assert result.exit_code == 2, result.stdout
    lines = lines_of(result)
    assert lines.index("Errors:") < lines.index("  - the graph is broken")
    assert lines[-1] == "Result: ERROR (exit 2)"
    result = run(*COVERAGE, "--python", "app:ROOT")
    assert result.exit_code == 2, result.stdout
    assert report_of(project)["errors"] == ["the graph is broken"]


def test_graph_warnings_are_shown_by_discover(project):
    result = run(*DISCOVER)
    assert result.exit_code == 0, result.stdout
    lines = lines_of(result)
    warnings = lines.index("Warnings:")
    assert lines[warnings + 1 : warnings + 4] == [
        "  - entry agent 'front' lists no roles, so every role can use it",
        "  - agent 'helper' was discovered but is not declared in the registry; "
        "its entry, roles, and delegation_mode are unknown",
        f"  - {IDENTITY}",
    ]


def test_discover_shows_rule_results_with_the_witness(project):
    result = run(*DISCOVER, "--spec", "spec.yaml")
    assert result.exit_code == 0, result.stdout  # a FAIL rule is not a gate in discover
    lines = lines_of(result)
    rules = lines.index("Never-reaches rules:")
    assert lines[rules + 1 : rules + 3] == [
        "  RULE-001  FAIL          role:trader -> tool:lookup",
        "    front -[handoff, discovered]-> helper -[uses_tool, discovered]-> lookup",
    ]
    # The same block order as coverage: graph, reachability, rules, notes.
    assert lines.index("Role reachability:") < rules < lines.index("Graph notes:")


def test_a_rule_error_shows_in_its_line_and_discover_still_exits_0(project):
    (project / "spec.yaml").write_text(
        SPEC + "  - id: RULE-002\n    role: trader\n    tool: ghost\n", encoding="utf-8"
    )
    result = run(*DISCOVER, "--spec", "spec.yaml")
    assert result.exit_code == 0, result.stdout
    lines = lines_of(result)
    assert (
        "  RULE-002  ERROR         role:trader -> tool:ghost - tool 'ghost' is not in the inventory"
    ) in lines
    assert "Errors:" not in lines
    assert lines[-1] == "Result: OK (exit 0)"


def test_discover_shows_identity_summaries_but_not_the_gate_warnings(project):
    """Path and role-gap warnings belong to the gate, so only coverage gives them."""
    path_case = CASE.format(id="CASE-001", role="analyst", agent="helper").replace(
        "    agent: helper\n", "    path: [helper, front]\n"
    )
    (project / "spec.yaml").write_text(
        "schema_version: '1'\nscenario_suite: graph-demo\ncases:\n"
        + path_case.replace("expect: deny", "expect: allow"),
        encoding="utf-8",
    )
    shown = run(*DISCOVER, "--spec", "spec.yaml")
    assert shown.exit_code == 0, shown.stdout
    run(*COVERAGE, "--python", "app:ROOT")
    warnings = report_of(project)["warnings"]
    assert IDENTITY in warnings
    assert f"  - {IDENTITY}" in lines_of(shown)
    gate_only = [w for w in warnings if w.startswith("CASE-001: ") or "no case or rule" in w]
    assert len(gate_only) >= 2, warnings  # at least one path warning and one role gap
    for warning in gate_only:
        assert warning not in shown.stdout


# ---- discover --save-snapshot ----


def test_save_snapshot_then_read_it_back(project):
    result = run(*DISCOVER, "--save-snapshot", "snaps/s.json")
    assert result.exit_code == 0, result.stdout
    path = project / "snaps" / "s.json"
    lines = lines_of(result)
    assert lines[-2:] == ["", written(Path.cwd() / "snaps" / "s.json")]
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["lockwalk_snapshot"] == "2"
    assert [source["label"] for source in document["sources"]] == ["python:app:ROOT"]
    # The discovered graph is saved with the source.
    [saved] = document["sources"]
    assert [node["id"] for node in saved["graph"]["nodes"]] == ["front", "helper"]
    again = run("discover", "--registry", "registry.yaml", "--tools-json", "snaps/s.json")
    assert again.exit_code == 0, again.stdout
    # The saved source comes back with its own label.
    assert "sources=registry:registry.yaml, python:app:ROOT" in tool_line(again, "lookup")
    assert any(
        "json:snaps/s.json: snapshot captured at " in line and "python:app:ROOT" in line
        for line in lines_of(again)
    )


def test_a_failed_source_refuses_the_snapshot(project):
    """Leaving the failed source out could make a replay pass where this run did not."""
    result = run(*DISCOVER, "--tools-json", "missing.json", "--save-snapshot", "s.json")
    assert result.exit_code == 2
    assert lines_of(result)[-2:] == [
        "",
        to_ascii(
            f"Snapshot not written to {Path.cwd() / 's.json'}: these sources failed: "
            "json:missing.json; a snapshot cannot leave a source out, so fix them first "
            "(an MCP source that may be down can be optional = true, with agents)"
        ),
    ]
    assert "  - json:missing.json: file not found: " in result.stdout.replace(chr(92), "/")
    assert not (project / "s.json").exists()


def test_a_refused_snapshot_removes_the_older_file_at_its_path(project):
    """An older snapshot left in place could be taken for this run's, so it goes."""
    assert run(*DISCOVER, "--save-snapshot", "s.json").exit_code == 0
    assert (project / "s.json").is_file()
    result = run(*DISCOVER, "--tools-json", "missing.json", "--save-snapshot", "s.json")
    assert result.exit_code == 2
    assert lines_of(result)[-1] == to_ascii(
        f"Note: removed the older file at {Path.cwd() / 's.json'}"
    )
    assert not (project / "s.json").exists()


def test_a_refused_snapshot_leaves_a_file_that_is_not_a_snapshot(project):
    (project / "mine.yaml").write_text("tools: [a]\n", encoding="utf-8")
    result = run(*DISCOVER, "--tools-json", "missing.json", "--save-snapshot", "mine.yaml")
    assert result.exit_code == 2
    assert (project / "mine.yaml").read_text(encoding="utf-8") == "tools: [a]\n"
    assert "removed" not in result.output
    assert "is not a lockwalk snapshot" in result.output


def test_a_snapshot_is_not_written_over_a_file_that_is_not_a_snapshot(project):
    (project / "mine.yaml").write_text("tools: [a]\n", encoding="utf-8")
    result = run(*DISCOVER, "--save-snapshot", "mine.yaml")
    assert result.exit_code == 2
    assert (project / "mine.yaml").read_text(encoding="utf-8") == "tools: [a]\n"
    assert "mine.yaml" in result.output
    assert "is not a lockwalk snapshot" in result.output


def test_a_snapshot_replaces_an_older_snapshot(project):
    assert run(*DISCOVER, "--save-snapshot", "s.json").exit_code == 0
    assert run(*DISCOVER, "--save-snapshot", "s.json").exit_code == 0
    assert SNAPSHOT_KEY in (project / "s.json").read_text(encoding="utf-8")


def test_an_older_file_that_cannot_be_removed_is_reported(project, monkeypatch):
    assert run(*DISCOVER, "--save-snapshot", "s.json").exit_code == 0

    def locked(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "unlink", locked)
    result = run(*DISCOVER, "--tools-json", "missing.json", "--save-snapshot", "s.json")
    assert result.exit_code == 2  # reported, not a crash
    assert lines_of(result)[-1] == to_ascii(
        f"Note: the older file at {Path.cwd() / 's.json'} could not be removed "
        "(Permission denied); it is not this run's snapshot"
    )
    assert (project / "s.json").is_file()


def test_no_snapshot_without_the_option(project):
    run(*DISCOVER)
    assert sorted(p.name for p in project.iterdir()) == ["app.py", "registry.yaml", "spec.yaml"]


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("", "--save-snapshot: the file name must not be empty"),
        ("  ", "--save-snapshot: the file name must not be empty"),
        ("snaps", "--save-snapshot snaps: is a directory; give a file name"),
    ],
)
def test_a_bad_snapshot_path_stops_before_discovery(project, monkeypatch, value, problem):
    (project / "snaps").mkdir()

    def refuse(self):
        raise AssertionError("discovery ran")

    monkeypatch.setattr(PythonSource, "read", refuse)
    result = run(*DISCOVER, "--save-snapshot", value)
    assert result.exit_code == 2
    assert lines_of(result) == [
        "Configuration error in <command line>:",
        f"  - {problem}",
        "",
        "Result: ERROR (exit 2)",
    ]


def test_a_failed_snapshot_write_is_a_command_line_error(project, monkeypatch):
    def full_disk(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(cli, "write_snapshot", full_disk)
    result = run(*DISCOVER, "--save-snapshot", "s.json")
    assert result.exit_code == 2
    assert lines_of(result)[:2] == [
        "Configuration error in <command line>:",
        "  - --save-snapshot s.json: cannot write the file: No space left on device",
    ]
    assert "Traceback" not in result.output


def test_a_snapshot_under_a_file_is_a_command_line_error(project):
    result = run(*DISCOVER, "--save-snapshot", "app.py/s.json")
    assert result.exit_code == 2
    problem = lines_of(result)[1]
    assert problem.startswith("  - --save-snapshot app.py/s.json: cannot write the file: ")
    assert "Traceback" not in result.output


# ---- Python target format ----


def test_a_malformed_python_target_stops_before_any_worker_starts(project, monkeypatch):
    def refuse(self):
        raise AssertionError("a worker was started")

    monkeypatch.setattr(PythonSource, "read", refuse)
    result = run("discover", "--python", "no_colon_here")
    assert result.exit_code == 2
    assert lines_of(result)[:2] == [
        "Configuration error in <command line>:",
        "  - --python no_colon_here: target: Value error, "
        "target 'no_colon_here' must look like '<module>:<attribute>'",
    ]
    (project / ".lockwalk.toml").write_text(
        "[[inventory.python]]\ntarget = 'app:'\n", encoding="utf-8"
    )
    result = run("discover")
    assert result.exit_code == 2
    assert (
        "  - inventory.python[0].target: Value error, "
        "target 'app:' must look like '<module>:<attribute>'"
    ) in lines_of(result)


# ---- empty inventory ----


def test_an_empty_inventory_is_a_warning(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "empty.json").write_text("[]", encoding="utf-8")
    result = run("discover", "--tools-json", "empty.json")
    assert result.exit_code == 0, result.stdout
    assert f"  - {EMPTY_INVENTORY_WARNING}" in lines_of(result)


# ---- stale report for --config sub/.lockwalk.toml ----


@pytest.fixture
def sub_config(demo) -> Path:
    """sub/.lockwalk.toml points at the demo files in the parent directory."""
    sub = demo / "sub"
    sub.mkdir()
    config = sub / ".lockwalk.toml"
    config.write_text(
        "[lockwalk]\nregistry = '../registry.yaml'\nspec = '../security-spec.yaml'\n",
        encoding="utf-8",
    )
    return config


def test_a_bad_source_with_config_in_a_subdirectory_removes_that_report(demo, sub_config):
    report = demo / "sub" / ".lockwalk" / "coverage.json"
    assert run("coverage", "--config", "sub/.lockwalk.toml").exit_code == 0
    assert report.is_file()
    result = run("coverage", "--config", "sub/.lockwalk.toml", "--mcp", "ftp://x")
    assert result.exit_code == 2
    assert not report.exists()


def test_a_broken_config_in_a_subdirectory_removes_that_report(demo, sub_config):
    report = demo / "sub" / ".lockwalk" / "coverage.json"
    assert run("coverage", "--config", "sub/.lockwalk.toml").exit_code == 0
    sub_config.write_text("[lockwalk]\nregistyr = 'x'\n", encoding="utf-8")
    result = run("coverage", "--config", "sub/.lockwalk.toml")
    assert result.exit_code == 2
    assert "registyr" in result.stdout
    assert not report.exists()


def test_the_config_files_own_output_dir_is_cleared(demo, sub_config):
    sub_config.write_text(
        sub_config.read_text(encoding="utf-8") + "output_dir = 'out'\n", encoding="utf-8"
    )
    report = demo / "sub" / "out" / "coverage.json"
    assert run("coverage", "--config", "sub/.lockwalk.toml").exit_code == 0
    assert report.is_file()
    assert run("coverage", "--config", "sub/.lockwalk.toml", "--python", "x").exit_code == 2
    assert not report.exists()


@pytest.mark.parametrize(
    "broken",
    [
        "[[inventory.python]]\ntarget = 'x'\n",
        "[gate]\nfail_on_never_reaches_inconclusive = 'yes'\n",
    ],
)
def test_an_invalid_config_still_clears_its_own_output_dir(demo, sub_config, broken):
    text = sub_config.read_text(encoding="utf-8") + "output_dir = 'out'\n"
    sub_config.write_text(text, encoding="utf-8")
    report = demo / "sub" / "out" / "coverage.json"
    assert run("coverage", "--config", "sub/.lockwalk.toml").exit_code == 0
    assert report.is_file()
    sub_config.write_text(text + "\n" + broken, encoding="utf-8")
    result = run("coverage", "--config", "sub/.lockwalk.toml")
    assert result.exit_code == 2
    assert "Configuration error in" in result.stdout
    assert not report.exists()


def test_the_output_dir_option_still_wins(demo, sub_config):
    report = demo / "elsewhere" / "coverage.json"
    args = ["coverage", "--config", "sub/.lockwalk.toml", "--output-dir", "elsewhere"]
    assert run(*args).exit_code == 0
    assert report.is_file()
    assert run(*args, "--mcp", "ftp://x").exit_code == 2
    assert not report.exists()


# ---- secrets never reach the terminal, coverage.json, or the snapshot ----

OPTIONS_SERVER = Path(__file__).resolve().parent / "fixtures_mcp_options" / "options_server.py"


# The broken server's program: print the secret on stderr, then exit with an error.
LEAK_TO_STDERR = (
    'import os, sys; sys.stderr.write(os.environ["LW_SECRET"] + chr(10)); '
    "sys.stderr.flush(); sys.exit(3)"
)


def run_main(cwd: Path, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    """Run the real entry point, so stderr from every child process is captured too."""
    return subprocess.run(
        [sys.executable, "-c", "from lockwalk.cli import main; main()", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def test_mcp_env_and_args_never_leak(tmp_path):
    env_secret = "LWENVSECRET" + uuid.uuid4().hex
    literal_secret = "LWLITERAL" + uuid.uuid4().hex
    args_secret = "LWARGSECRET" + uuid.uuid4().hex
    (tmp_path / "registry.yaml").write_text(
        "schema_version: '1'\nagents:\n  - id: desk\n    entry: true\n    calls: []\ntools: []\n",
        encoding="utf-8",
    )
    (tmp_path / "spec.yaml").write_text(
        "schema_version: '1'\nscenario_suite: secrets\ncases: []\n", encoding="utf-8"
    )
    python = sys.executable
    (tmp_path / ".lockwalk.toml").write_text(
        "[lockwalk]\nregistry = 'registry.yaml'\nspec = 'spec.yaml'\n\n"
        # A careless server: it copies LW_SECRET into its name and a tool description.
        "[[inventory.mcp]]\n"
        f"command = '{python}'\n"
        f"args = ['{OPTIONS_SERVER}', '--echo-env', 'LW_SECRET', '--token', '{args_secret}']\n"
        f"env = {{ LW_SECRET = '${{LW_TEST_SOURCE}}', LW_LITERAL = '{literal_secret}' }}\n\n"
        # A server that writes the secret to its stderr and exits, so its failure and
        # label are shown as well, and its stderr must stay hidden. It is optional, so the
        # snapshot saves it as unavailable instead of refusing to be written.
        "[[inventory.mcp]]\n"
        "name = 'broken'\n"
        f"command = '{python}'\n"
        f"args = ['-c', '{LEAK_TO_STDERR}', '--token', '{args_secret}']\n"
        f"env = {{ LW_SECRET = '${{LW_TEST_SOURCE}}' }}\n"
        "optional = true\n"
        "agents = ['desk']\n"
        "timeout_s = 20\n",
        encoding="utf-8",
    )
    env = {**os.environ, "LW_TEST_SOURCE": env_secret}
    shown = run_main(tmp_path, env, "discover", "--save-snapshot", "snap.json")
    checked = run_main(tmp_path, env, "coverage")
    # The second server failed; it is optional, so that is a warning, not an error.
    assert shown.returncode == 0, shown.stdout + shown.stderr
    assert checked.returncode == 1, checked.stdout + checked.stderr  # undeclared tools
    snapshot = (tmp_path / "snap.json").read_text(encoding="utf-8")
    report = (tmp_path / ".lockwalk" / "coverage.json").read_text(encoding="utf-8")
    # The secret did reach the server and came back, hidden; the broken server was tried.
    assert "token is <hidden env 'LW_SECRET'>" in snapshot
    assert "Snapshot written to" in shown.stdout
    assert (
        "Note: the snapshot saves these optional sources as unavailable, because they could "
        "not be read: mcp:broken"
    ) in shown.stdout
    assert '"status": "unavailable"' in snapshot
    assert "mcp:broken (unavailable, optional)" in checked.stdout
    texts = {
        "discover stdout": shown.stdout,
        "discover stderr": shown.stderr,
        "coverage stdout": checked.stdout,
        "coverage stderr": checked.stderr,
        "coverage.json": report,
        "snapshot": snapshot,
    }
    for where, text in texts.items():
        for secret in (env_secret, literal_secret, args_secret):
            assert secret not in text, where


# ---- tools that no agent is known to use ----

# The finance demo server, with registry tools that no agent is declared to use. Without
# a holder, a rule to such a tool used to PASS while the tool is there to be called.
HOLDERLESS_REGISTRY = """\
schema_version: '1'
roles: [analyst]
agents:
  - id: finance-agent
    entry: true
    roles: [analyst]
    delegation_mode: user
    calls: []
tools:
  - {id: get_stock_price, action: market:read, risk: low, supported_agents: [finance-agent]}
  - {id: read_portfolio, action: portfolio:read, risk: high, supported_agents: [finance-agent]}
  - {id: execute_trade, action: trade:execute, risk: critical}
  - {id: delete_portfolio, action: portfolio:delete, risk: critical}
"""

HOLDERLESS_SPEC = """\
schema_version: '1'
scenario_suite: holderless
cases:
  - {id: C1, actor: a, role: analyst, agent: finance-agent, tool: read_portfolio,
     action: portfolio:read, resource_fixture: p, expect: deny}
  - {id: C2, actor: a, role: analyst, agent: finance-agent, tool: execute_trade,
     action: trade:execute, resource_fixture: p, expect: deny}
  - {id: C3, actor: a, role: analyst, agent: finance-agent, tool: delete_portfolio,
     action: portfolio:delete, resource_fixture: p, expect: deny}
never_reaches:
  - {id: RULE-001, role: analyst, tool: execute_trade}
  - {id: RULE-002, agent: finance-agent, tool: delete_portfolio}
"""

HOLDERLESS_WARNING = (
    "no agent is known to use 2 tools, so lockwalk cannot tell who reaches them: "
    "execute_trade, delete_portfolio; set 'agents' on their source or 'supported_agents' "
    "in the registry"
)


def holderless_line(rule_id: str, start: str, tool: str) -> str:
    return (
        f"  {rule_id}  INCONCLUSIVE  {start} -> tool:{tool} - no agent is known to use tool "
        f"'{tool}'; set 'agents' on its source or 'supported_agents' in the registry"
    )


@pytest.fixture
def finance_server(tmp_path, example_dir, monkeypatch) -> Path:
    """The finance demo MCP server in the cwd, with the registry and spec above."""
    shutil.copy(example_dir / "mcp_server.py", tmp_path / "mcp_server.py")
    (tmp_path / "registry.yaml").write_text(HOLDERLESS_REGISTRY, encoding="utf-8")
    (tmp_path / "spec.yaml").write_text(HOLDERLESS_SPEC, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_rules_to_tools_that_no_agent_uses_are_inconclusive(finance_server):
    result = run(*COVERAGE, "--mcp", "stdio://mcp_server.py")
    assert result.exit_code == 1, result.stdout
    lines = lines_of(result)
    assert holderless_line("RULE-001", "role:analyst", "execute_trade") in lines
    assert holderless_line("RULE-002", "agent:finance-agent", "delete_portfolio") in lines
    assert f"  - {HOLDERLESS_WARNING}" in lines
    assert "  - never_reaches: RULE-001 (INCONCLUSIVE)" in lines
    report = report_of(finance_server)
    assert [(rule["result"], rule["opaque_reached"]) for rule in report["rules"]] == [
        ("INCONCLUSIVE", []),
        ("INCONCLUSIVE", []),
    ]
    assert HOLDERLESS_WARNING in report["warnings"]
    shown = run("discover", "--registry", "registry.yaml", "--spec", "spec.yaml")
    assert shown.exit_code == 0, shown.stdout
    assert holderless_line("RULE-001", "role:analyst", "execute_trade") in lines_of(shown)
    assert f"  - {HOLDERLESS_WARNING}" in lines_of(shown)


def test_no_holderless_warning_without_rules_or_roles(finance_server):
    registry = finance_server / "registry.yaml"
    registry.write_text(
        HOLDERLESS_REGISTRY.replace("roles: [analyst]\n", "", 1).replace(
            "    roles: [analyst]\n", ""
        ),
        encoding="utf-8",
    )
    result = run("discover", "--registry", "registry.yaml", "--mcp", "stdio://mcp_server.py")
    assert result.exit_code == 0, result.stdout
    assert "no agent is known to use" not in result.stdout


def test_a_rule_has_the_same_result_live_and_from_a_snapshot(finance_server):
    """A snapshot keeps the 'agents' of its sources, so it cannot turn a FAIL into a PASS."""
    (finance_server / ".lockwalk.toml").write_text(
        '[lockwalk]\nregistry = "registry.yaml"\nspec = "spec.yaml"\n\n'
        '[[inventory.mcp]]\nname = "finance-tools"\ntarget = "stdio://mcp_server.py"\n'
        'agents = ["finance-agent"]\n',
        encoding="utf-8",
    )
    shown = run("discover", "--save-snapshot", "snap.json")
    assert shown.exit_code == 0, shown.stdout
    document = json.loads((finance_server / "snap.json").read_text(encoding="utf-8"))
    assert [source["agents"] for source in document["sources"]] == [["finance-agent"]]
    live = run("coverage")
    live_rules = [(rule["id"], rule["result"]) for rule in report_of(finance_server)["rules"]]
    replayed = run("coverage", "--tools-json", "snap.json")
    replayed_rules = [(rule["id"], rule["result"]) for rule in report_of(finance_server)["rules"]]
    assert live_rules == replayed_rules == [("RULE-001", "FAIL"), ("RULE-002", "FAIL")]
    assert (live.exit_code, replayed.exit_code) == (1, 1)


def graph_findings_of(directory: Path) -> tuple:
    """The parts of a report that a snapshot must not change."""
    report = report_of(directory)
    return (
        report["rules"],
        report["reachability"],
        report["agent_graph"]["opaque"],
        [w for w in report["warnings"] if w.startswith("no agent is known to use")],
        report["exit_code"],
    )


def test_a_snapshot_of_mixed_sources_gives_the_live_findings(finance_server):
    """The snapmix probe: ops-agent uses only the ops tools, and nobody is known to use the
    finance tools. The snapshot used to give ops-agent every tool: a false PASS."""
    (finance_server / "ops.json").write_text('[{"name": "stub"}]', encoding="utf-8")
    registry = finance_server / "registry.yaml"
    registry.write_text(
        HOLDERLESS_REGISTRY.replace(
            "    calls: []\ntools:\n",
            "    calls: []\n  - id: ops-agent\n    calls: []\ntools:\n"
            "  - {id: stub, action: ops:stub, risk: low}\n",
        ),
        encoding="utf-8",
    )
    (finance_server / ".lockwalk.toml").write_text(
        '[lockwalk]\nregistry = "registry.yaml"\nspec = "spec.yaml"\n\n'
        '[[inventory.json]]\npath = "ops.json"\nagents = ["ops-agent"]\n\n'
        '[[inventory.mcp]]\nname = "finance-tools"\ntarget = "stdio://mcp_server.py"\n',
        encoding="utf-8",
    )
    assert run("discover", "--save-snapshot", "snap.json").exit_code == 0
    run("coverage")
    live = graph_findings_of(finance_server)
    replayed = run("coverage", "--tools-json", "snap.json")
    assert graph_findings_of(finance_server) == live
    assert [(rule["id"], rule["result"]) for rule in live[0]] == [
        ("RULE-001", "INCONCLUSIVE"),
        ("RULE-002", "INCONCLUSIVE"),
    ]
    assert live[3] == [HOLDERLESS_WARNING]
    assert replayed.exit_code == 1, replayed.stdout


# ---- declaring calls does not hide unreadable tools ----

# An Agno tools factory is called only at run time, so lockwalk cannot read desk's tools.
AGNO_FACTORY_APP = '''
from agno.agent import Agent


def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    raise RuntimeError("tools are never called")


def trader_tools():
    raise RuntimeError("a tools factory is never called")


desk = Agent(name="desk", tools=trader_tools)
'''

AGNO_FACTORY_REGISTRY = """\
schema_version: '1'
roles: [analyst]
agents:
  - id: desk
    entry: true
    roles: [analyst]
    delegation_mode: user
    calls: []
  - id: back-office
    calls: []
tools:
  - {id: execute_trade, action: t:x, risk: critical, supported_agents: [back-office]}
"""

AGNO_FACTORY_SPEC = """\
schema_version: '1'
scenario_suite: agno-factory
cases:
  - {id: C1, actor: a, role: analyst, agent: desk, tool: execute_trade, action: t:x,
     resource_fixture: x, expect: deny}
never_reaches:
  - {id: RULE-001, role: analyst, tool: execute_trade}
"""


def test_declared_calls_do_not_hide_a_tools_factory(tmp_path, monkeypatch):
    """desk declares calls: [], but its tools are unknown, so the rule cannot PASS."""
    (tmp_path / "app.py").write_text(AGNO_FACTORY_APP, encoding="utf-8")
    (tmp_path / "registry.yaml").write_text(AGNO_FACTORY_REGISTRY, encoding="utf-8")
    (tmp_path / "spec.yaml").write_text(AGNO_FACTORY_SPEC, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = run(*COVERAGE, "--python", "app.py:desk")
    assert result.exit_code == 1, result.stdout
    lines = lines_of(result)
    assert (
        "  RULE-001  INCONCLUSIVE  role:analyst -> tool:execute_trade (passes through opaque: desk)"
    ) in lines
    assert (
        "  - agent 'desk' declares 'calls', but lockwalk could not read all of its tools, "
        "so it stays opaque"
    ) in lines
    [desk] = [n for n in report_of(tmp_path)["agent_graph"]["nodes"] if n["id"] == "desk"]
    assert (desk["opaque"], desk["tools_hidden"]) == (True, True)
