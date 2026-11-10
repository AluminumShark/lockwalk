"""CONTRIBUTING.md shows the same test commands that CI runs."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_contributing_runs_the_same_commands_as_ci() -> None:
    guide = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for command in (
        'pytest -q -rs -m "not docker"',
        "pytest -q -rs -m docker --ignore=tests/crewai_env",
        "--no-default-groups --group crewai pytest -q tests/crewai_env",
        "ruff check",
        "ruff format --check",
        "ty check",
    ):
        assert command in ci, command
        assert command in guide, command


def test_security_policy_names_the_private_reporting_route() -> None:
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Report a vulnerability" in policy
    assert "https://github.com/AluminumShark/lockwalk/security" in policy
