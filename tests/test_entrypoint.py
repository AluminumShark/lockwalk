"""Run the real console entry point, because CliRunner maps uncaught exceptions to exit 1."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ARGS = ["coverage", "--registry", "registry.yaml", "--spec", "security-spec.yaml"]


@pytest.fixture
def demo(tmp_path, example_dir) -> Path:
    for name in ("registry.yaml", "security-spec.yaml"):
        shutil.copy(example_dir / name, tmp_path / name)
    return tmp_path


def run_main(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", "from lockwalk.cli import main; main()", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )


def test_complete_spec_exits_0(demo):
    assert run_main(demo, *ARGS).returncode == 0


def test_gate_failure_exits_1(demo):
    (demo / "tools.json").write_text('[{"name": "delete_portfolio"}]', encoding="utf-8")
    assert run_main(demo, *ARGS, "--tools-json", "tools.json").returncode == 1


def test_deeply_nested_registry_exits_2(demo):
    (demo / "registry.yaml").write_text("a: " + "[" * 5000 + "\n", encoding="utf-8")
    assert run_main(demo, *ARGS).returncode == 2


def test_typo_in_registry_exits_2(demo):
    text = (demo / "registry.yaml").read_text(encoding="utf-8")
    (demo / "registry.yaml").write_text(
        text.replace("    risk: critical\n", "    risks: critical\n"), encoding="utf-8"
    )
    assert run_main(demo, *ARGS).returncode == 2
