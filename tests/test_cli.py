import json
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest
from lockwalk_net_helpers import free_port
from typer.testing import CliRunner

from lockwalk import __version__, pipeline
from lockwalk.cli import _emit, app

runner = CliRunner()
COVERAGE = ["coverage", "--registry", "registry.yaml", "--spec", "security-spec.yaml"]

EXTRA_REGISTRY_TOOL = """\
  - id: delete_portfolio
    action: portfolio:delete
    risk: critical
    resource_type: portfolio
    supported_agents: [finance-agent]
"""

EXTRA_DENY_CASE = """\
  - id: CASE-005
    actor: alice
    role: analyst
    agent: finance-agent
    tool: delete_portfolio
    action: portfolio:delete
    resource_fixture: bob-portfolio
    expect: deny
    reason: Analysts cannot delete portfolios
"""


@pytest.fixture
def demo(tmp_path, example_dir, monkeypatch) -> Path:
    """A copy of the finance demo registry and spec in a temporary working directory."""
    for name in ("registry.yaml", "security-spec.yaml"):
        shutil.copy(example_dir / name, tmp_path / name)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(*args: str):
    return runner.invoke(app, list(args))


def append(path: Path, text: str) -> None:
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def report_of(directory: Path) -> dict:
    return json.loads((directory / ".lockwalk" / "coverage.json").read_text(encoding="utf-8"))


def test_version_option_prints_version():
    result = run("--version")
    assert result.exit_code == 0
    assert result.stdout.strip() == f"lockwalk {__version__}"


def test_version_comes_from_package_metadata():
    assert __version__ == version("lockwalk")


def test_help_lists_the_commands():
    result = run("--help")
    assert result.exit_code == 0
    assert "discover" in result.stdout
    assert "coverage" in result.stdout


def test_coverage_passes_for_a_complete_spec(demo):
    result = run(*COVERAGE)
    assert result.exit_code == 0, result.stdout
    assert "Gate: PASS (exit 0)" in result.stdout
    report = report_of(demo)
    assert report["exit_code"] == 0
    assert report["mode"] == "static"


def test_coverage_fails_for_a_tool_without_spec(demo):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    result = run(*COVERAGE, "--tools-json", "tools.json")
    assert result.exit_code == 1, result.stdout
    assert (
        "Tools without spec:                 1   "
        "(delete_portfolio, risk=unknown, source=json:tools.json)"
    ) in result.stdout
    assert "Gate: FAIL (exit 1)" in result.stdout
    assert "  - fail_on_unspecified_risk: delete_portfolio (risk=unknown)" in result.stdout
    assert report_of(demo)["exit_code"] == 1


def test_registry_tool_without_spec_fails_the_gate(demo):
    append(demo / "registry.yaml", EXTRA_REGISTRY_TOOL)
    result = run(*COVERAGE)
    assert result.exit_code == 1, result.stdout
    assert (
        "Tools without spec:                 1   "
        "(delete_portfolio, risk=critical, source=registry:registry.yaml)"
    ) in result.stdout


def test_coverage_passes_after_the_spec_and_registry_are_fixed(demo):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    append(demo / "registry.yaml", EXTRA_REGISTRY_TOOL)
    append(demo / "security-spec.yaml", EXTRA_DENY_CASE)
    result = run(*COVERAGE, "--tools-json", "tools.json")
    assert result.exit_code == 0, result.stdout


def test_misspelled_registry_field_exits_2_without_a_report(demo):
    registry = demo / "registry.yaml"
    registry.write_text(
        registry.read_text(encoding="utf-8").replace(
            "    risk: critical\n", "    risks: critical\n"
        ),
        encoding="utf-8",
    )
    result = run(*COVERAGE)
    assert result.exit_code == 2
    assert "Configuration error in" in result.stdout
    assert "tools[2].risks: Extra inputs are not permitted" in result.stdout
    assert not (demo / ".lockwalk").exists()


def test_coverage_requires_a_spec(demo):
    result = run("coverage", "--registry", "registry.yaml")
    assert result.exit_code == 2
    assert "coverage needs --spec" in result.stdout


def test_case_for_an_unknown_tool_exits_2_with_a_report(demo):
    append(
        demo / "security-spec.yaml",
        EXTRA_DENY_CASE.replace("CASE-005", "CASE-099").replace("delete_portfolio", "ghost_tool"),
    )
    result = run(*COVERAGE)
    assert result.exit_code == 2
    assert "CASE-099: tool 'ghost_tool' is not in the inventory" in result.stdout
    assert "Result: ERROR (exit 2)" in result.stdout
    assert report_of(demo)["exit_code"] == 2


def test_discover_lists_tools_and_spec_status(demo):
    (demo / "tools.json").write_text(
        '[{"name": "get_stock_price"}, {"name": "delete_portfolio"}]', encoding="utf-8"
    )
    result = run(
        "discover",
        "--registry",
        "registry.yaml",
        "--spec",
        "security-spec.yaml",
        "--tools-json",
        "tools.json",
    )
    assert result.exit_code == 0, result.stdout
    lines = result.stdout.splitlines()
    delete_line = next(line for line in lines if line.strip().startswith("delete_portfolio"))
    assert "risk=unknown" in delete_line
    assert "spec=NO" in delete_line
    price_line = next(line for line in lines if line.strip().startswith("get_stock_price"))
    assert "spec=yes" in price_line
    assert not (demo / ".lockwalk").exists()


def test_discover_with_a_failing_source_exits_2(demo):
    result = run("discover", "--registry", "registry.yaml", "--tools-json", "missing.json")
    assert result.exit_code == 2
    assert "file not found" in result.stdout


def test_discover_needs_a_source(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = run("discover")
    assert result.exit_code == 2
    assert "no inventory source" in result.stdout


def test_config_file_is_loaded_and_cli_sources_replace_it(demo):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    (demo / "empty.json").write_text("[]", encoding="utf-8")
    (demo / ".lockwalk.toml").write_text(
        "[lockwalk]\nregistry = 'registry.yaml'\nspec = 'security-spec.yaml'\n\n"
        "[[inventory.json]]\npath = 'tools.json'\n",
        encoding="utf-8",
    )
    assert run("coverage").exit_code == 1
    result = run("coverage", "--tools-json", "empty.json")
    assert result.exit_code == 0, result.stdout
    assert "replace the 1 source(s) in .lockwalk.toml" in result.stdout


def test_output_dir_option(demo):
    assert run(*COVERAGE, "--output-dir", "out").exit_code == 0
    assert (demo / "out" / "coverage.json").is_file()


def test_output_is_ascii_even_for_non_ascii_tool_names(demo):
    (demo / "tools.json").write_text('[{"name": "\u522a\u9664"}]', encoding="utf-8")
    result = run(*COVERAGE, "--tools-json", "tools.json")
    assert result.stdout.isascii()
    assert "\\u522a\\u9664" in result.stdout


def test_coverage_with_the_example_mcp_server(demo, example_dir):
    result = run(*COVERAGE, "--mcp", f"stdio://{example_dir / 'mcp_server.py'}")
    assert result.exit_code == 1, result.stdout
    assert "source=mcp:finance-tools" in result.stdout


def test_unexpected_error_exits_2_not_1(demo):
    result = run(*COVERAGE, "--output-dir", "registry.yaml")
    assert result.exit_code == 2
    assert "Error: " in result.stdout
    assert "Result: ERROR (exit 2)" in result.stdout
    assert result.stdout.isascii()


def test_a_crash_message_loses_url_credentials(demo, monkeypatch):
    """An unexpected error is shown with its message, but without URL secrets."""

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("cannot reach https://user:hunter2@db.example/x?token=SECRET123")

    monkeypatch.setattr(pipeline, "build_inventory", broken)
    result = run(*COVERAGE)
    assert result.exit_code == 2
    assert "Error: RuntimeError: cannot reach https://db.example/x" in result.stdout
    assert "RuntimeError" in result.stderr  # the traceback, redacted the same way
    for secret in ("hunter2", "SECRET123"):
        assert secret not in result.stdout
        assert secret not in result.stderr


def test_mcp_url_credentials_never_reach_the_report_or_terminal(demo):
    url = f"https://user:hunter2@127.0.0.1:{free_port()}/mcp?api_key=SECRET123"
    result = run(*COVERAGE, "--mcp", url)
    report_text = (demo / ".lockwalk" / "coverage.json").read_text(encoding="utf-8")
    for secret in ("hunter2", "SECRET123"):
        assert secret not in report_text
        assert secret not in result.output


def test_discover_marks_a_tool_whose_only_case_is_invalid_as_error(demo):
    spec = demo / "security-spec.yaml"
    text = spec.read_text(encoding="utf-8")
    old = "    agent: research-agent\n    tool: execute_trade"
    assert old in text
    spec.write_text(text.replace(old, "    agent: ghost-agent\n    tool: execute_trade"), "utf-8")
    result = run("discover", "--registry", "registry.yaml", "--spec", "security-spec.yaml")
    line = next(row for row in result.stdout.splitlines() if "execute_trade" in row)
    assert "spec=ERROR" in line


def test_structural_error_leaves_no_stale_report(demo):
    assert run(*COVERAGE).exit_code == 0
    assert (demo / ".lockwalk" / "coverage.json").exists()
    registry = demo / "registry.yaml"
    text = registry.read_text(encoding="utf-8")
    registry.write_text(text.replace("    risk: critical\n", "    risks: critical\n"), "utf-8")
    assert run(*COVERAGE).exit_code == 2
    assert not (demo / ".lockwalk" / "coverage.json").exists()


def test_a_config_file_error_also_removes_the_previous_report(demo):
    assert run(*COVERAGE).exit_code == 0
    assert (demo / ".lockwalk" / "coverage.json").is_file()
    (demo / ".lockwalk.toml").write_text("[lockwalk]\nregistyr = 'x'\n", encoding="utf-8")
    result = run(*COVERAGE)
    assert result.exit_code == 2
    assert "registyr" in result.stdout
    assert not (demo / ".lockwalk" / "coverage.json").exists()


def test_a_bad_command_line_source_also_removes_the_previous_report(demo):
    assert run(*COVERAGE, "--output-dir", "out").exit_code == 0
    assert (demo / "out" / "coverage.json").is_file()
    result = run(*COVERAGE, "--output-dir", "out", "--mcp", "ftp://x")
    assert result.exit_code == 2
    assert not (demo / "out" / "coverage.json").exists()


@pytest.mark.parametrize("command", ["discover", "coverage", "test"])
def test_command_help_shows_bracketed_names(command):
    result = run(command, "--help")
    assert result.exit_code == 0
    assert "(replaces )" not in result.stdout
    if command == "test":
        assert "[policy]" in result.stdout


def test_inspect_without_case_exits_2(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = run("inspect")
    assert result.exit_code == 2
    assert "--case" in result.output


def test_inspect_without_a_report_exits_2(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = run("inspect", "--case", "CASE-001")
    assert result.exit_code == 2
    assert "run lockwalk test first" in result.output


def test_inspect_prints_a_case_and_exits_0(demo) -> None:
    assert run(*COVERAGE).exit_code == 0
    result = run("inspect", "--case", "CASE-001")
    assert result.exit_code == 0
    assert "lockwalk inspect - CASE-001" in result.output


@pytest.mark.parametrize(
    ("line", "style"),
    [
        ("Gate: PASS (exit 0)", "[1;32m"),
        ("Result: OK (exit 0)", "[1;32m"),
        ("Gate: FAIL (exit 1)", "[1;31m"),
        ("Result: ERROR (exit 2)", "[1;31m"),
    ],
)
def test_every_verdict_line_is_styled_under_force_color(line, style, monkeypatch, capsys):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    _emit([line])
    assert style in capsys.readouterr().out


class FailingStream:
    """A text stream whose writes fail after `allow` successful ones, like a closed pipe."""

    def __init__(self, error: OSError, allow: int = 0) -> None:
        self.error = error
        self.allow = allow
        self.written: list[str | bytes] = []
        self.buffer = self  # raw bytes go through the same failing writes

    def write(self, text: str | bytes) -> int:
        if self.allow <= 0:
            raise self.error
        self.allow -= 1
        self.written.append(text)
        return len(text)

    def flush(self) -> None:
        if self.allow <= 0:
            raise self.error

    def isatty(self) -> bool:
        return False


def invoke_main(*args: str) -> int:
    """Run the real app the way the console script does, so no CliRunner swallows anything."""
    with pytest.raises(SystemExit) as stop:
        app(list(args))
    code = stop.value.code
    assert isinstance(code, int)
    return code


BROKEN_PIPE = BrokenPipeError(32, "Broken pipe")
DISK_FULL = OSError(28, "No space left on device")


@pytest.mark.parametrize("error", [BROKEN_PIPE, DISK_FULL], ids=["epipe", "enospc"])
@pytest.mark.parametrize("allow", [0, 3], ids=["first-write", "later-write"])
def test_exit_code_passes_when_stdout_closes_early(demo, monkeypatch, error, allow):
    monkeypatch.setattr(sys, "stdout", FailingStream(error, allow))
    assert invoke_main(*COVERAGE) == 0
    assert report_of(demo)["exit_code"] == 0


@pytest.mark.parametrize("allow", [0, 3], ids=["first-write", "later-write"])
def test_exit_code_fails_when_stdout_closes_early_on_a_gate_failure(demo, monkeypatch, allow):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE, allow))
    assert invoke_main(*COVERAGE, "--tools-json", "tools.json") == 1
    assert report_of(demo)["exit_code"] == 1


def test_report_is_written_even_when_stdout_is_closed(demo, monkeypatch):
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    invoke_main(*COVERAGE)
    assert (demo / ".lockwalk" / "coverage.json").is_file()


def test_exit_2_survives_closed_stdout_and_closed_stderr(demo, monkeypatch):
    (demo / "security-spec.yaml").write_text("not: [valid", encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    monkeypatch.setattr(sys, "stderr", FailingStream(BROKEN_PIPE))
    assert invoke_main(*COVERAGE) == 2


def test_crash_keeps_exit_2_when_stdout_fails_while_reporting_it(demo, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("lockwalk.cli.write_report", explode)
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    monkeypatch.setattr(sys, "stderr", FailingStream(BROKEN_PIPE))
    assert invoke_main(*COVERAGE) == 2


def test_a_render_bug_is_not_mistaken_for_a_closed_stdout(demo, monkeypatch):
    def explode(*args, **kwargs):
        raise ValueError("render bug")

    monkeypatch.setattr("lockwalk.cli.render_coverage", explode)
    assert run(*COVERAGE).exit_code == 2


def test_real_pipe_closed_before_the_run_keeps_the_gate_exit_code(demo):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    errors = (demo / "stderr.txt").open("wb")  # a file: an unread stderr pipe could fill and block
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from lockwalk.cli import main; main()",
            *COVERAGE,
            "--tools-json",
            "tools.json",
        ],
        cwd=demo,
        stdout=subprocess.PIPE,
        stderr=errors,
    )
    assert proc.stdout is not None
    proc.stdout.close()
    assert proc.wait(timeout=60) == 1
    errors.close()
    assert "Traceback" not in (demo / "stderr.txt").read_text(encoding="utf-8", errors="replace")


def test_version_and_diff_json_survive_a_closed_stdout(demo, monkeypatch):
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    assert invoke_main("--version") == 0
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    assert invoke_main(*COVERAGE) == 0
    head = str(demo / ".lockwalk" / "coverage.json")
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    assert invoke_main("diff", "--head", head, "--format", "json") == 0


DIFF_FORMATS = ["text", "json", "markdown"]
SOLE_OUTPUT_COMMANDS = ["diff-text", "diff-json", "diff-markdown", "inspect", "discover", "version"]


def sole_output_args(demo: Path, which: str) -> list[str]:
    """Arguments for a command whose stdout is its only product (it writes no file)."""
    if which.startswith("diff-"):
        head = str(demo / ".lockwalk" / "coverage.json")
        return ["diff", "--head", head, "--format", which.removeprefix("diff-")]
    if which == "inspect":
        return ["inspect", "--case", "CASE-001"]
    if which == "discover":
        return ["discover", "--registry", "registry.yaml", "--spec", "security-spec.yaml"]
    return ["--version"]


@pytest.mark.parametrize("which", SOLE_OUTPUT_COMMANDS)
def test_a_failing_stdout_is_exit_2_when_stdout_is_the_only_output(demo, monkeypatch, which):
    assert run(*COVERAGE).exit_code == 0
    args = sole_output_args(demo, which)
    monkeypatch.setattr(sys, "stdout", FailingStream(DISK_FULL))
    assert invoke_main(*args) == 2


@pytest.mark.parametrize("which", SOLE_OUTPUT_COMMANDS)
def test_a_closed_pipe_is_still_exit_0_when_stdout_is_the_only_output(demo, monkeypatch, which):
    assert run(*COVERAGE).exit_code == 0
    args = sole_output_args(demo, which)
    monkeypatch.setattr(sys, "stdout", FailingStream(BROKEN_PIPE))
    assert invoke_main(*args) == 0


def test_a_lost_diff_says_so_on_stderr(demo, monkeypatch, capsys):
    assert run(*COVERAGE).exit_code == 0
    args = sole_output_args(demo, "diff-markdown")
    monkeypatch.setattr(sys, "stdout", FailingStream(DISK_FULL))
    assert invoke_main(*args) == 2
    assert "could not write to stdout" in capsys.readouterr().err


def test_discover_with_a_snapshot_keeps_exit_0_when_the_listing_is_lost(demo, monkeypatch):
    # The snapshot file is on disk, so it is discover's product, as the report is for coverage.
    (demo / "tools.json").write_text('[{"name": "get_stock_price"}]', encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", FailingStream(DISK_FULL))
    args = [*sole_output_args(demo, "discover"), "--tools-json", "tools.json"]
    assert invoke_main(*args, "--save-snapshot", "snap.json") == 0
    assert (demo / "snap.json").is_file()


def test_coverage_with_a_full_stdout_keeps_the_gate_code(demo, monkeypatch):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    monkeypatch.setattr(sys, "stdout", FailingStream(DISK_FULL))
    assert invoke_main(*COVERAGE, "--tools-json", "tools.json") == 1


CRASH_SCRIPT = """\
import sys
import lockwalk.cli as cli

def explode(*args, **kwargs):
    raise RuntimeError("boom")

cli.write_report = explode
cli.main()
"""


@pytest.mark.parametrize(
    ("close_stdout", "close_stderr"),
    [(True, False), (False, True), (True, True)],
    ids=["stdout-closed", "stderr-closed", "both-closed"],
)
def test_real_pipes_closed_during_a_crash_still_exit_2(demo, close_stdout, close_stderr):
    # Real descriptors, not fake streams: a closed stderr pipe used to leave unflushed text
    # that failed again at interpreter exit, which turned the exit code into 120.
    out_file = (demo / "stdout.txt").open("wb")
    err_file = (demo / "stderr.txt").open("wb")  # files, so an unread pipe cannot fill and block
    proc = subprocess.Popen(
        [sys.executable, "-c", CRASH_SCRIPT, *COVERAGE],
        cwd=demo,
        stdout=subprocess.PIPE if close_stdout else out_file,
        stderr=subprocess.PIPE if close_stderr else err_file,
    )
    if close_stdout:
        assert proc.stdout is not None
        proc.stdout.close()
    if close_stderr:
        assert proc.stderr is not None
        proc.stderr.close()
    assert proc.wait(timeout=60) == 2
    out_file.close()
    err_file.close()
