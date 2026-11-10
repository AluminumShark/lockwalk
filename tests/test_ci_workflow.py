"""The project's own CI workflow keeps the properties that matter, since it cannot run locally."""

import importlib.util
import itertools
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from workflow_helpers import (
    PINNED,
    REPO_ROOT,
    WORKFLOWS,
    load_workflow,
    steps,
    triggers,
    uses_lines,
)

CI = WORKFLOWS / "ci.yml"
TESTS = REPO_ROOT / "tests"
UV_VERSION = "0.13.7"


@pytest.fixture(scope="module")
def workflow() -> dict[Any, Any]:
    return load_workflow(CI)


def _runs(job: dict[str, Any]) -> list[str]:
    return [str(step["run"]) for step in steps(job) if "run" in step]


def _all_runs(workflow: dict[Any, Any]) -> str:
    return "\n".join(run for job in workflow["jobs"].values() for run in _runs(job))


def _constant(filename: str, name: str) -> str:
    text = (TESTS / filename).read_text(encoding="utf-8")
    match = re.search(rf'^{name} = "([^"]+)"', text, re.M)
    assert match, f"{name} not found in {filename}"
    return match.group(1)


def _combinations(matrix: dict[str, Any]) -> set[tuple[str, str]]:
    """The (os, python) pairs a job matrix expands to, following the GitHub rules."""
    axes = {key: value for key, value in matrix.items() if key not in ("include", "exclude")}
    names = sorted(axes)
    product = itertools.product(*(axes[n] for n in names))
    found = [dict(zip(names, values, strict=True)) for values in product]
    for removed in matrix.get("exclude", []):
        found = [c for c in found if not all(c.get(k) == v for k, v in removed.items())]
    for added in matrix.get("include", []):
        # An entry that matches an existing combination only adds fields to it. These
        # entries name both axes, so they are either already present or a new combination.
        if not any(all(c.get(k) == v for k, v in added.items() if k in axes) for c in found):
            found.append({k: v for k, v in added.items() if k in axes})
    return {(c["os"], c["python"]) for c in found}


def test_triggers_and_permissions(workflow):
    assert set(triggers(workflow)) == {"push", "pull_request", "workflow_dispatch"}
    assert triggers(workflow)["push"]["branches"] == ["main"]
    assert workflow["permissions"] == {"contents": "read"}
    assert "cancel-in-progress" in workflow["concurrency"]


def test_jobs(workflow):
    assert set(workflow["jobs"]) == {"lint", "test", "docker", "crewai", "package"}


def test_every_action_is_pinned_to_a_commit():
    lines = uses_lines(CI)
    assert lines
    for line in lines:
        assert PINNED.search(line), line


def test_checkouts_keep_no_credentials(workflow):
    seen = 0
    for job in workflow["jobs"].values():
        for step in steps(job):
            if "actions/checkout" in step.get("uses", ""):
                seen += 1
                assert step["with"]["persist-credentials"] is False
    assert seen == len(workflow["jobs"])


def test_every_setup_uv_pins_the_uv_version(workflow):
    seen = 0
    for job in workflow["jobs"].values():
        for step in steps(job):
            if "astral-sh/setup-uv" in step.get("uses", ""):
                seen += 1
                assert step["with"]["version"] == UV_VERSION
    assert seen == len(workflow["jobs"])


def test_each_job_stands_alone(workflow):
    # Jobs run in any order, or in parallel: none waits for another, and each one gets its own
    # checkout and uv.
    for name, job in workflow["jobs"].items():
        assert "needs" not in job, name
        used = [step.get("uses", "") for step in steps(job)]
        assert any("actions/checkout" in u for u in used), name
        assert any("astral-sh/setup-uv" in u for u in used), name
        assert "actions/download-artifact" not in " ".join(used), name


def test_matrix(workflow):
    matrix = workflow["jobs"]["test"]["strategy"]
    assert matrix["fail-fast"] is False
    expected = {("ubuntu-latest", v) for v in ("3.11", "3.12", "3.13", "3.14")}
    expected |= {(os, v) for os in ("windows-latest", "macos-latest") for v in ("3.11", "3.14")}
    assert _combinations(matrix["matrix"]) == expected
    # Python versions are strings: a bare 3.10 would be read as the number 3.1.
    assert all(isinstance(v, str) for v in matrix["matrix"]["python"])
    job = workflow["jobs"]["test"]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["env"]["UV_PYTHON"] == "${{ matrix.python }}"


def test_matrix_helper_follows_the_github_rules():
    matrix = {
        "os": ["a", "b"],
        "python": ["1", "2"],
        "include": [{"os": "a", "python": "3"}, {"os": "a", "python": "1"}],
        "exclude": [{"os": "b", "python": "1"}],
    }
    assert _combinations(matrix) == {("a", "1"), ("a", "2"), ("a", "3"), ("b", "2")}


def test_matrix_skips_docker(workflow):
    pytest_lines = [r for r in _runs(workflow["jobs"]["test"]) if "pytest" in r]
    assert len(pytest_lines) == 1
    assert '-m "not docker"' in pytest_lines[0]


def test_matrix_commands_run_in_powershell(workflow):
    # `run:` uses PowerShell on Windows, so the matrix steps keep to plain `uv` commands:
    # no `&&`, `$VAR`, `export`, or `shell:` override.
    for step in steps(workflow["jobs"]["test"]):
        assert "shell" not in step
        run = str(step.get("run", ""))
        for bash_only in ("&&", "||", "$", "export ", "\\\n"):
            assert bash_only not in run, run


def test_matrix_installs_from_the_lock_file(workflow):
    assert any("uv sync --locked" in r for r in _runs(workflow["jobs"]["test"]))


def test_no_write_permissions(workflow):
    def values(node: Any) -> list[Any]:
        return [workflow["permissions"], *(j.get("permissions", {}) for j in node.values())]

    for permissions in values(workflow["jobs"]):
        entries = permissions.values() if isinstance(permissions, dict) else [permissions]
        assert all(v == "read" for v in entries), permissions
    assert "id-token" not in CI.read_text(encoding="utf-8")


def test_pull_request_target_is_not_used(workflow):
    assert "pull_request_target" not in triggers(workflow)
    assert "pull_request_target" not in CI.read_text(encoding="utf-8")


def test_docker_job_pulls_what_the_tests_use(workflow):
    images = {
        _constant("test_iam_cerbos.py", "CERBOS_IMAGE"),
        _constant("test_recipe_opa.py", "OPA_IMAGE"),
        _constant("test_observe_collector_docker.py", "IMAGE"),
    }
    runs = _runs(workflow["jobs"]["docker"])
    pulled = {
        match.group(1)
        for run in runs
        for match in re.finditer(r"^\s*docker pull (\S+)\s*$", run, re.M)
    }
    assert pulled == images
    # The pulls come before any test run.
    first_test = next(i for i, r in enumerate(runs) if "pytest" in r)
    last_pull = max(i for i, r in enumerate(runs) if "docker pull" in r)
    assert last_pull < first_test
    assert any("pytest" in r and "-m docker" in r for r in runs)


def test_docker_job_fails_on_a_skipped_docker_test(workflow):
    runs = _runs(workflow["jobs"]["docker"])
    pytest_at = next(i for i, r in enumerate(runs) if "-m docker" in r)
    assert "--junitxml=docker.xml" in runs[pytest_at]
    # The CrewAI tests skip at collection without CrewAI, which the check would count as a skip.
    assert "--ignore=tests/crewai_env" in runs[pytest_at]
    check_at = next(i for i, r in enumerate(runs) if "scripts/check_no_skips.py docker.xml" in r)
    assert check_at > pytest_at
    # The check step must run only when the earlier steps worked, so it has no `if: always()`.
    check_step = next(s for s in steps(workflow["jobs"]["docker"]) if "check_no_skips" in str(s))
    assert "if" not in check_step


def _load_check_no_skips():
    path = REPO_ROOT / "scripts" / "check_no_skips.py"
    spec = importlib.util.spec_from_file_location("check_no_skips", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report(tmp_path, cases):
    body = "".join(cases)
    path = tmp_path / "r.xml"
    path.write_text(
        f'<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="{len(cases)}">'
        f"{body}</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


PASSED = '<testcase classname="t.a" name="ok"/>'
SKIPPED = '<testcase classname="t.a" name="no"><skipped message="image missing"/></testcase>'
FAILED = '<testcase classname="t.a" name="bad"><failure message="x"/></testcase>'


def test_check_no_skips_accepts_only_passed_tests(tmp_path, capsys):
    script = _load_check_no_skips()
    assert script.main([str(_report(tmp_path, [PASSED, PASSED]))]) == 0


def test_check_no_skips_rejects_a_skip_an_empty_run_and_a_bad_file(tmp_path, capsys):
    script = _load_check_no_skips()
    assert script.main([str(_report(tmp_path, [PASSED, SKIPPED]))]) == 1
    assert "skipped: t.a::no" in capsys.readouterr().err
    assert script.main([str(_report(tmp_path, []))]) == 1
    assert "no tests ran" in capsys.readouterr().err
    assert script.main([str(tmp_path / "missing.xml")]) == 1
    (tmp_path / "bad.xml").write_text("<testsuites>", encoding="utf-8")
    assert script.main([str(tmp_path / "bad.xml")]) == 1
    assert script.main([]) == 2


ERRORED = '<testcase classname="t.a" name="boom"><error message="x"/></testcase>'


def _suite_report(tmp_path, attrs, cases=(PASSED,)):
    path = tmp_path / "s.xml"
    path.write_text(
        f'<?xml version="1.0"?><testsuites><testsuite name="pytest" {attrs}>'
        f"{''.join(cases)}</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_check_no_skips_rejects_a_failure_and_an_error(tmp_path, capsys):
    script = _load_check_no_skips()
    assert script.main([str(_report(tmp_path, [PASSED, FAILED]))]) == 1
    assert "failed: t.a::bad" in capsys.readouterr().err
    assert script.main([str(_report(tmp_path, [PASSED, ERRORED]))]) == 1
    assert "error: t.a::boom" in capsys.readouterr().err


@pytest.mark.parametrize(
    "attrs",
    ['skipped="5"', 'errors="1"', 'failures="2"', 'tests="1" errors="1" failures="0" skipped="0"'],
)
def test_check_no_skips_reads_the_suite_counts(tmp_path, capsys, attrs):
    # A collection error can leave a report with a passing test case and only a count.
    script = _load_check_no_skips()
    assert script.main([str(_suite_report(tmp_path, attrs))]) == 1
    assert "suite" in capsys.readouterr().err


def test_check_no_skips_rejects_a_collection_error_with_no_test_case(tmp_path, capsys):
    script = _load_check_no_skips()
    assert script.main([str(_suite_report(tmp_path, 'tests="0" errors="1"', cases=()))]) == 1
    err = capsys.readouterr().err
    assert "no tests ran" in err
    assert "errors" in err


def test_check_no_skips_accepts_zero_counts(tmp_path):
    script = _load_check_no_skips()
    attrs = 'tests="1" errors="0" failures="0" skipped="0"'
    assert script.main([str(_suite_report(tmp_path, attrs))]) == 0


def test_check_no_skips_rejects_a_count_that_is_not_a_number(tmp_path, capsys):
    script = _load_check_no_skips()
    assert script.main([str(_suite_report(tmp_path, 'errors="many"'))]) == 1
    assert "errors" in capsys.readouterr().err


# Files that mention docker but have no docker test of their own.
MENTION_ONLY = {Path(__file__).name, "test_ci_example.py"}
USES_DOCKER = re.compile(r"""["']docker["']|subprocess[^\n]*docker|shutil\.which\(["']docker""")


def test_every_docker_test_file_carries_the_marker():
    # `pytest -m docker` only selects marked tests, so a file that runs docker without the
    # marker would never run in CI.
    for path in TESTS.glob("test_*.py"):
        text = path.read_text(encoding="utf-8")
        if path.name not in MENTION_ONLY and USES_DOCKER.search(text):
            assert "pytest.mark.docker" in text, path.name


def test_cancel_in_progress_is_for_pull_requests_only(workflow):
    assert "pull_request" in str(workflow["concurrency"]["cancel-in-progress"])


def test_crewai_cache_is_separate(workflow):
    uv = next(s for s in steps(workflow["jobs"]["crewai"]) if "setup-uv" in s.get("uses", ""))
    assert uv["with"]["cache-suffix"] == "crewai"


def test_dependabot_updates_actions():
    config = yaml.safe_load((REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert config["version"] == 2
    assert [u["package-ecosystem"] for u in config["updates"]] == ["github-actions"]
    update = config["updates"][0]
    assert update["directory"] == "/"
    assert update["schedule"]["interval"] == "weekly"
    assert update["cooldown"]["default-days"] >= 1


def test_crewai_job(workflow):
    job = workflow["jobs"]["crewai"]
    assert job["env"]["UV_PROJECT_ENVIRONMENT"] == ".venv-crewai"
    major, minor = (int(part) for part in str(job["env"]["UV_PYTHON"]).split("."))
    assert (major, minor) < (3, 14)
    runs = "\n".join(_runs(job))
    assert "--group crewai" in runs
    assert "--no-default-groups" in runs
    assert "tests/crewai_env" in runs
    assert "uv run" in runs and "pytest" in runs


def test_package_job(workflow):
    job = workflow["jobs"]["package"]
    runs = "\n".join(_runs(job))
    assert "uv build" in runs
    assert re.search(r"python3 scripts/check_package\.py dist\b", runs)
    assert re.search(r"python3 scripts/smoke_wheel\.py dist\b", runs)
    assert re.search(r"uvx twine==\d+\.\d+\.\d+ check dist/\*", runs)
    order = [runs.index(x) for x in ("uv build", "check_package", "smoke_wheel", "twine")]
    assert order == sorted(order)


def test_lint_job(workflow):
    runs = "\n".join(_runs(workflow["jobs"]["lint"]))
    assert "uv run ruff check" in runs
    assert "uv run ruff format --check" in runs
    assert "uv run ty check" in runs
    assert re.search(r"uvx --from actionlint-py==\d+\.\d+\.\d+\.\d+ actionlint\b", runs)


def test_jobs_have_timeouts(workflow):
    for name, job in workflow["jobs"].items():
        assert isinstance(job["timeout-minutes"], int), name


def test_scripts_exist(workflow):
    paths = set(re.findall(r"scripts/[\w./-]+\.py", _all_runs(workflow)))
    assert paths
    for path in paths:
        assert (REPO_ROOT / path).is_file(), path
