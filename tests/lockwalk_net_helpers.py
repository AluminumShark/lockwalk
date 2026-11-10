"""Helpers for tests that start a server on 127.0.0.1, shared by the MCP tests.

pyproject.toml puts tests/ on sys.path (pytest's pythonpath setting), so test modules
import this module by name in every pytest import mode. (conftest.py cannot be imported
that way under --import-mode=importlib.)
"""

import socket
import subprocess
import time
from pathlib import Path


def free_port() -> int:
    """A TCP port on 127.0.0.1 that nothing listened on a moment ago."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(
    port: int,
    process: "subprocess.Popen[bytes] | None" = None,
    stderr: Path | None = None,
    timeout: float = 15.0,
) -> None:
    """Wait until something listens on 127.0.0.1:port.

    With process, stop early if it exits first. With stderr, the error includes the text
    of that file (the server's stderr), to show why it did not start.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"server exited with {process.returncode}:\n{_read(stderr)}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"server did not open port {port}:\n{_read(stderr)}")


def _read(stderr: Path | None) -> str:
    if stderr is None:
        return ""
    return stderr.read_text(encoding="utf-8", errors="replace")
