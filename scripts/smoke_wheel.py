"""Install the built wheel in a clean environment and run the real CLI.

Usage: python scripts/smoke_wheel.py DIST_DIR
The wheel is also installed with its mcp and otel extras, and what they provide is imported.
Needs uv and access to the package index. Exits 1 and says which step failed.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

REGISTRY = """\
schema_version: '1'
agents:
  - id: smoke-agent
    entry: true
tools:
  - id: smoke_delete
    action: smoke:delete
    risk: critical
    supported_agents: [smoke-agent]
"""
INSTALL_TIMEOUT = 600
CLI_TIMEOUT = 120
SPEC = """\
schema_version: '1'
scenario_suite: smoke-v1
cases: []
"""


EXTRAS = "mcp,otel"
# The imports the two extras exist for, as lockwalk's own lazy imports make them.
EXTRAS_IMPORT = """\
import anyio
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from opentelemetry import trace
"""


class SmokeError(Exception):
    """A step of the smoke test failed."""


def _clean_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PYTHON", "UV_PROJECT_ENVIRONMENT"):
        env.pop(name, None)
    return env


def _run(
    step: str,
    command: Sequence[str | Path],
    cwd: Path,
    expect: int = 0,
    timeout: int = CLI_TIMEOUT,
) -> str:
    print(f"[{step}] {' '.join(str(part) for part in command)}", flush=True)
    try:
        done = subprocess.run(
            [str(part) for part in command],
            cwd=cwd,
            env=_clean_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SmokeError(f"{step}: timed out after {timeout} s") from None
    except OSError as error:
        raise SmokeError(f"{step}: cannot start the command ({error})") from error
    output = done.stdout + done.stderr
    if done.returncode != expect:
        raise SmokeError(f"{step}: exit code {done.returncode}, expected {expect}\n{output}")
    return output


def _wheel_version(wheel: Path) -> str:
    match = re.match(r"^lockwalk-([^-]+)-", wheel.name)
    if match is None:
        raise SmokeError(f"find wheel: {wheel.name} is not a lockwalk wheel name")
    return match.group(1)


def _check_extras(python: Path, wheel: Path, work: Path) -> None:
    """Install the wheel with its extras and import what each extra is for."""
    _run(
        f"install extras [{EXTRAS}]",
        ["uv", "pip", "install", "--python", python, f"{wheel}[{EXTRAS}]"],
        work,
        timeout=INSTALL_TIMEOUT,
    )
    _run("import extras (mcp, opentelemetry)", [python, "-I", "-c", EXTRAS_IMPORT], work)


def smoke(dist: Path) -> None:
    if shutil.which("uv") is None:
        raise SmokeError("find uv: the uv command is not on PATH")
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise SmokeError(f"find wheel: expected one wheel in {dist}, found {len(wheels)}")
    wheel = wheels[0].resolve()
    version = _wheel_version(wheel)
    with tempfile.TemporaryDirectory(prefix="lockwalk-smoke-", ignore_cleanup_errors=True) as name:
        work = Path(name).resolve()
        env_dir = work / "env"
        scripts = env_dir / ("Scripts" if os.name == "nt" else "bin")
        suffix = ".exe" if os.name == "nt" else ""
        python = scripts / f"python{suffix}"
        exe = scripts / f"lockwalk{suffix}"

        _run(
            "create environment",
            ["uv", "venv", "--python", sys.executable, env_dir],
            work,
            timeout=INSTALL_TIMEOUT,
        )
        _run(
            "install wheel",
            ["uv", "pip", "install", "--python", python, wheel],
            work,
            timeout=INSTALL_TIMEOUT,
        )

        (work / "registry.yaml").write_text(REGISTRY, encoding="utf-8")
        (work / "security-spec.yaml").write_text(SPEC, encoding="utf-8")

        shown = _run("version", [exe, "--version"], work)
        if shown.split()[-1:] != [version]:
            raise SmokeError(
                f"version: expected {version!r} at the end of the output, got {shown!r}"
            )

        covered = _run(
            "coverage gate",
            [
                exe,
                "coverage",
                "--registry",
                "registry.yaml",
                "--spec",
                "security-spec.yaml",
                "--output-dir",
                "out",
            ],
            work,
            expect=1,
        )
        if "smoke_delete" not in covered:
            raise SmokeError(f"coverage gate: tool name missing from the output\n{covered}")
        if not (work / "out" / "coverage.json").is_file():
            raise SmokeError(f"coverage gate: out/coverage.json was not written\n{covered}")

        text = _run("diff text", [exe, "diff", "--head", "out/coverage.json"], work)
        if "smoke_delete" not in text:
            raise SmokeError(f"diff text: tool name missing from the output\n{text}")

        markdown = _run(
            "diff markdown",
            [exe, "diff", "--head", "out/coverage.json", "--format", "markdown"],
            work,
        )
        if not markdown.startswith("<!-- lockwalk-diff -->"):
            raise SmokeError(f"diff markdown: output does not start with the marker\n{markdown}")

        where = _run(
            "import location",
            [python, "-I", "-c", "import lockwalk; print(lockwalk.__file__)"],
            work,
        ).strip()
        if work not in Path(where).resolve().parents:
            raise SmokeError(
                f"import location: lockwalk was imported from {where}, not from the environment"
            )
        print(f"imported from {where}")

        _check_extras(python, wheel, work)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python scripts/smoke_wheel.py DIST_DIR", file=sys.stderr)
        return 2
    try:
        smoke(Path(args[0]))
    except SmokeError as error:
        print(f"SMOKE FAILED at {error}", file=sys.stderr)
        return 1
    print("OK: the installed wheel works")
    return 0


if __name__ == "__main__":
    sys.exit(main())
