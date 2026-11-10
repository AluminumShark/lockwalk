"""Helpers for tests that read GitHub Actions workflows."""

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
# owner/repo@<40 hex> # vX.Y.Z
# A local `./` action or a `docker://` image does not match, so it fails the pin test. That is
# the safe direction: add an exception on purpose if one is ever needed.
PINNED = re.compile(r"uses:\s*[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s*v\d")


def load_workflow(path: Path) -> dict[Any, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) reads the bare key `on` as the boolean True.
    raw = workflow.get("on", workflow.get(True))
    assert isinstance(raw, dict)
    return raw


def steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return list(job["steps"])


def uses_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if re.match(r"\s*(-\s*)?uses:", line)
    ]
