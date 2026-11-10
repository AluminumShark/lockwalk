"""Inventory source: tools defined in Python code.

The target module is imported in a subprocess with a timeout, so its import-time side
effects, crashes, or hangs cannot take lockwalk down or change lockwalk's global state.
"""

import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from lockwalk.config import PythonSourceConfig
from lockwalk.inventory.base import failed, finish, truncate
from lockwalk.models import GraphFragment, SourceRef, SourceResult, ToolDescriptor

WORKER_MODULE = "lockwalk.inventory._python_worker"


class PythonSource:
    def __init__(self, config: PythonSourceConfig, base_dir: Path) -> None:
        self._config = config
        self._base_dir = base_dir
        self._ref = SourceRef(kind="python", label=f"python:{config.target}")

    def read(self) -> SourceResult:
        agents = self._config.agents
        timeout = self._config.timeout_s
        # A lingering grandchild may still hold a file open on Windows, so ignore cleanup errors.
        with tempfile.TemporaryDirectory(prefix="lockwalk-", ignore_cleanup_errors=True) as tmp:
            output = Path(tmp) / "result.json"
            stderr_path = Path(tmp) / "stderr.txt"
            # -P keeps the working directory off sys.path while the worker imports its own deps.
            command = [sys.executable, "-P", "-m", WORKER_MODULE, self._config.target, str(output)]
            env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
            try:
                with stderr_path.open("wb") as stderr_file:
                    process = subprocess.Popen(
                        command,
                        cwd=self._base_dir,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=stderr_file,
                        start_new_session=sys.platform != "win32",
                    )
                    try:
                        returncode = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        _kill_tree(process)
                        return failed(
                            self._ref,
                            f"timed out after {timeout:g}s while importing the target",
                            agents=agents,
                        )
            except OSError as exc:
                return failed(self._ref, f"cannot start the Python worker: {exc}", agents=agents)
            if not output.is_file():
                # The worker's stderr stays out of the report: it can hold secrets such as
                # connection strings. It only keeps the user's output off lockwalk's terminal.
                return failed(
                    self._ref,
                    f"the Python worker exited with code {returncode}; "
                    "import the target yourself to see its error output",
                    agents=agents,
                )
            try:
                payload = json.loads(output.read_text(encoding="utf-8"))
                if "fatal" in payload:
                    return failed(self._ref, str(payload["fatal"]), agents=agents)
                tools = [ToolDescriptor.model_validate(item) for item in payload["tools"]]
                errors = [str(error) for error in payload["errors"]]
                graph_data = payload.get("graph")
                fragment = (
                    GraphFragment()
                    if graph_data is None
                    else GraphFragment.model_validate(graph_data)
                )
                graph_warnings = payload.get("graph_warnings", [])
                if not isinstance(graph_warnings, list):
                    raise TypeError("graph_warnings must be a list")
            except (ValueError, TypeError, KeyError):
                return failed(
                    self._ref, "the Python worker wrote an unreadable result", agents=agents
                )
        result = finish(self._ref, tools, errors, agents)
        warnings = (*result.warnings, *(truncate(str(item)) for item in graph_warnings))
        return result.model_copy(update={"graph": fragment, "warnings": warnings})


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    """Kill the worker and every process it started, then reap it on a best-effort basis."""
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(process.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=5)
