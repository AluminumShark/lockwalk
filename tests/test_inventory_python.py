import time
from pathlib import Path

from lockwalk.config import PythonSourceConfig
from lockwalk.inventory.python import PythonSource
from lockwalk.models import SourceResult

PLAIN_TOOLS = '''
def get_stock_price(symbol: str) -> str:
    """Return the price of a stock symbol.

    Longer explanation that is ignored.
    """
    return "100"


def read_portfolio(portfolio_id: str) -> str:
    return "{}"


TOOLS = [get_stock_price, read_portfolio]


def build_tools():
    return TOOLS
'''


def read(
    base_dir: Path, target: str, timeout_s: float = 30.0, agents: tuple[str, ...] = ()
) -> SourceResult:
    config = PythonSourceConfig(target=target, timeout_s=timeout_s, agents=agents)
    return PythonSource(config, base_dir).read()


def test_collects_plain_functions_from_a_module(write, tmp_path):
    write("demo_tools.py", PLAIN_TOOLS)
    result = read(tmp_path, "demo_tools:TOOLS")
    assert result.ok, result.error
    assert result.source.label == "python:demo_tools:TOOLS"
    assert [(t.name, t.description) for t in result.tools] == [
        ("get_stock_price", "Return the price of a stock symbol."),
        ("read_portfolio", None),
    ]


def test_file_path_target(write, tmp_path):
    path = write("nested/demo_tools.py", PLAIN_TOOLS)
    result = read(tmp_path, f"{path}:TOOLS")
    assert result.ok, result.error
    assert len(result.tools) == 2


def test_dotted_package_target(write, tmp_path):
    write("pkg/__init__.py", "")
    write("pkg/tools.py", PLAIN_TOOLS)
    result = read(tmp_path, "pkg.tools:TOOLS")
    assert result.ok, result.error


def test_factory_call_with_parentheses(write, tmp_path):
    write("demo_tools.py", PLAIN_TOOLS)
    result = read(tmp_path, "demo_tools:build_tools()")
    assert [t.name for t in result.tools] == ["get_stock_price", "read_portfolio"]


def test_function_without_parentheses_is_itself_a_tool(write, tmp_path):
    write("demo_tools.py", PLAIN_TOOLS)
    assert [t.name for t in read(tmp_path, "demo_tools:build_tools").tools] == ["build_tools"]


def test_langchain_tools(write, tmp_path):
    write(
        "lc_tools.py",
        '''
        from langchain_core.tools import StructuredTool, tool


        @tool
        def read_portfolio(portfolio_id: str) -> str:
            """Read a portfolio."""
            return "{}"


        def _trade(order_id: str) -> str:
            """Execute a trade."""
            return "ok"


        execute_trade = StructuredTool.from_function(_trade, name="execute_trade")
        TOOLS = [read_portfolio, execute_trade]
        ''',
    )
    result = read(tmp_path, "lc_tools:TOOLS")
    assert result.ok, result.error
    assert [(t.name, t.description) for t in result.tools] == [
        ("read_portfolio", "Read a portfolio."),
        ("execute_trade", "Execute a trade."),
    ]


def test_agno_agent_target_is_opened(write, tmp_path):
    write(
        "agno_app.py",
        '''
        from agno.agent import Agent
        from agno.tools import tool


        @tool
        def get_stock_price(symbol: str) -> str:
            """Return the price of a stock symbol."""
            return "1"


        agent = Agent(name="finance-agent", tools=[get_stock_price])
        ''',
    )
    result = read(tmp_path, "agno_app:agent")
    assert result.ok, result.error
    assert [t.name for t in result.tools] == ["get_stock_price"]


def test_prints_during_import_do_not_break_the_result(write, tmp_path):
    write(
        "noisy.py",
        'import sys\nprint("hello from import")\nprint("to stderr", file=sys.stderr)\n'
        + PLAIN_TOOLS,
    )
    result = read(tmp_path, "noisy:TOOLS")
    assert result.ok, result.error


def test_exception_during_import_marks_the_source_failed(write, tmp_path):
    write("broken.py", 'raise RuntimeError("boom")\n')
    result = read(tmp_path, "broken:TOOLS")
    assert not result.ok
    assert result.error == "importing the target raised RuntimeError: boom"


def test_system_exit_during_import_is_caught(write, tmp_path):
    write("exits.py", "raise SystemExit(5)\n")
    result = read(tmp_path, "exits:TOOLS")
    assert result.error is not None
    assert "SystemExit" in result.error


def test_hanging_import_times_out(write, tmp_path):
    write("slow.py", "import time\ntime.sleep(60)\n")
    result = read(tmp_path, "slow:TOOLS", timeout_s=2)
    assert result.error == "timed out after 2s while importing the target"


def test_unrecognized_items_keep_the_recognized_tools(write, tmp_path):
    write("mixed.py", PLAIN_TOOLS + "\nMIXED = [get_stock_price, 42]\n")
    result = read(tmp_path, "mixed:MIXED")
    assert not result.ok
    assert [t.name for t in result.tools] == ["get_stock_price"]
    assert result.error == "item 1: cannot recognize a tool in a value of type builtins.int"


def test_malformed_target(tmp_path):
    # The config rejects this target (tests/test_config.py), so skip its validation to
    # check that the worker still reports the same message on its own.
    config = PythonSourceConfig.model_construct(target="no_colon_here")
    result = PythonSource(config, tmp_path).read()
    assert result.error == "target 'no_colon_here' must look like '<module>:<attribute>'"


def test_missing_attribute(write, tmp_path):
    write("demo_tools.py", PLAIN_TOOLS)
    assert read(tmp_path, "demo_tools:NOPE").error == "'demo_tools' has no attribute 'NOPE'"


def test_dict_that_is_not_a_tool_is_rejected(write, tmp_path):
    write("mapping.py", PLAIN_TOOLS + "\nBY_NAME = {'a': get_stock_price}\n")
    assert read(tmp_path, "mapping:BY_NAME").error == (
        "the target is a dict that is not a tool description; point at a list of tools instead"
    )


def test_single_tool_description_dict(write, tmp_path):
    write("one.py", "TOOL = {'name': 'lookup', 'description': 'Look something up.'}\n")
    assert [t.name for t in read(tmp_path, "one:TOOL").tools] == ["lookup"]


def test_agents_are_passed_through(write, tmp_path):
    write("demo_tools.py", PLAIN_TOOLS)
    result = read(tmp_path, "demo_tools:TOOLS", agents=("finance-agent",))
    assert result.agents == ("finance-agent",)


def test_grandchild_process_does_not_stretch_the_timeout(write, tmp_path):
    write(
        "spawner.py",
        "import subprocess, sys, time\n"
        'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])\n'
        "time.sleep(30)\n",
    )
    started = time.monotonic()
    result = read(tmp_path, "spawner:TOOLS", timeout_s=2)
    elapsed = time.monotonic() - started
    print(f"grandchild test elapsed: {elapsed:.2f}s")
    assert result.error == "timed out after 2s while importing the target"
    assert elapsed < 10


def test_input_fails_fast_because_stdin_is_closed(write, tmp_path):
    write("asks.py", "input()\n")
    started = time.monotonic()
    result = read(tmp_path, "asks:TOOLS", timeout_s=10)
    assert time.monotonic() - started < 8
    assert result.error is not None
    assert result.error.startswith("importing the target raised EOFError")


def test_non_daemon_thread_does_not_discard_the_result(write, tmp_path):
    write(
        "threaded.py",
        PLAIN_TOOLS
        + "\nimport threading, time\nthreading.Thread(target=time.sleep, args=(8,)).start()\n",
    )
    result = read(tmp_path, "threaded:TOOLS", timeout_s=4)
    assert result.ok, result.error
    assert [t.name for t in result.tools] == ["get_stock_price", "read_portfolio"]


def test_shadowing_files_in_base_dir_do_not_break_the_worker(write, tmp_path):
    write("demo_tools.py", PLAIN_TOOLS)
    write("json.py", 'raise RuntimeError("shadow")\n')
    write("lockwalk.py", 'raise RuntimeError("shadow")\n')
    assert read(tmp_path, "demo_tools:TOOLS").ok


def test_file_target_with_a_stdlib_stem(write, tmp_path):
    path = write("sub/json.py", PLAIN_TOOLS)
    result = read(tmp_path, f"{path}:TOOLS")
    assert result.ok, result.error
    assert len(result.tools) == 2


def test_non_ascii_exception_message_passes_through(write, tmp_path):
    write("unicode_fail.py", 'raise RuntimeError("\u932f\u8aa4")\n')
    result = read(tmp_path, "unicode_fail:TOOLS")
    assert result.error is not None
    assert result.error.endswith("RuntimeError: \u932f\u8aa4")


def test_no_pycache_is_written_into_the_users_tree(write, tmp_path):
    write("pkg/__init__.py", "")
    write("pkg/tools.py", PLAIN_TOOLS)
    assert read(tmp_path, "pkg.tools:TOOLS").ok
    assert not (tmp_path / "pkg" / "__pycache__").exists()


def test_worker_stderr_never_reaches_the_report(write, tmp_path):
    write(
        "leaky.py",
        """
        import os
        import sys

        sys.stderr.write("DATABASE_URL=postgres://admin:s3cr3t@db\\n")
        sys.stderr.flush()
        os._exit(3)
        """,
    )
    result = read(tmp_path, "leaky:TOOLS")
    assert not result.ok
    assert result.error
    assert "s3cr3t" not in result.error
    assert "import the target yourself" in result.error
