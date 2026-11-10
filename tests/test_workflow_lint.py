"""Run actionlint over every workflow file, when it is installed."""

import shutil
import subprocess

import pytest
from workflow_helpers import REPO_ROOT, WORKFLOWS

FILES = [
    *sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]),
    REPO_ROOT / "examples" / "ci" / "github-actions.yml",
]


@pytest.mark.parametrize("path", FILES, ids=lambda path: path.name)
def test_actionlint_accepts_the_workflow(path):
    exe = shutil.which("actionlint")
    if exe is None:
        pytest.skip("actionlint is not on PATH")
    done = subprocess.run(
        [exe, str(path)], capture_output=True, text=True, check=False, timeout=120
    )
    assert done.returncode == 0, done.stdout + done.stderr
