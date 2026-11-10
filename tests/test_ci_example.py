"""The GitHub Actions example parses, and every lockwalk flag it uses really exists."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from lockwalk.cli import app
from lockwalk.diff_markdown import MARKER

CERBOS_TEST = Path(__file__).resolve().parent / "test_iam_cerbos.py"
CI_DIR = Path(__file__).resolve().parent.parent / "examples" / "ci"
WORKFLOW = CI_DIR / "github-actions.yml"


@pytest.fixture(scope="module")
def workflow() -> dict[Any, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) reads the bare key `on` as the boolean True.
    raw = workflow.get("on", workflow.get(True))
    assert isinstance(raw, dict)
    return raw


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return list(job["steps"])


def _lockwalk_commands(workflow: dict[Any, Any]) -> list[list[str]]:
    found: list[list[str]] = []
    for job in workflow["jobs"].values():
        for step in _steps(job):
            for line in str(step.get("run", "")).splitlines():
                try:
                    words = shlex.split(line, comments=True)
                except ValueError:
                    # A line that is only part of a multi-line quoted string cannot be
                    # split on its own; it holds no lockwalk command.
                    continue
                if "lockwalk" in words:
                    found.append(words[words.index("lockwalk") + 1 :])
    return found


def test_triggers(workflow: dict[Any, Any]) -> None:
    triggers = _triggers(workflow)
    assert {"pull_request", "schedule", "workflow_dispatch"} <= set(triggers)
    assert len(triggers["schedule"][0]["cron"].split()) == 5
    assert workflow["permissions"] == {"contents": "read"}


def test_jobs_and_conditions(workflow: dict[Any, Any]) -> None:
    jobs = workflow["jobs"]
    assert set(jobs) == {"coverage", "comment", "test"}
    assert "pull_request" in str(jobs["coverage"]["if"])
    assert "pull_request" in str(jobs["comment"]["if"])
    assert "pull_request" in str(jobs["test"]["if"])
    assert "!=" in str(jobs["test"]["if"])


def test_each_job_runs_its_command(workflow: dict[Any, Any]) -> None:
    for name in ("coverage", "test"):
        runs = [str(s.get("run", "")) for s in _steps(workflow["jobs"][name])]
        assert any(re.search(rf"lockwalk {name}\b.*--summary", r) for r in runs), name
    # The target branch is checked in the same mode, so the two reports can be compared.
    lines = [
        line
        for s in _steps(workflow["jobs"]["coverage"])
        for line in str(s.get("run", "")).splitlines()
    ]
    assert sum(bool(re.search(r"lockwalk coverage\b.*--summary", line)) for line in lines) == 2


def test_uv_setup_and_locked_sync(workflow: dict[Any, Any]) -> None:
    for job in (workflow["jobs"]["coverage"], workflow["jobs"]["test"]):
        uses = [str(s.get("uses", "")) for s in _steps(job)]
        pinned = [u for u in uses if u.startswith("astral-sh/setup-uv@")]
        assert pinned
        assert all(re.fullmatch(r"astral-sh/setup-uv@v\d+", u) for u in pinned)
        assert any("uv sync --locked" in str(s.get("run", "")) for s in _steps(job))


def test_artifact_upload(workflow: dict[Any, Any]) -> None:
    for name in ("coverage", "test"):
        uploads = [
            s
            for s in _steps(workflow["jobs"][name])
            if str(s.get("uses", "")).startswith("actions/upload-artifact@")
        ]
        assert uploads
        paths = str(uploads[0]["with"]["path"]).split()
        if name == "test":
            # `lockwalk inspect --case` needs the evidence file next to the report.
            assert paths == [".lockwalk/coverage.json", ".lockwalk/evidence.jsonl"]
        else:
            assert {"comment.md", ".lockwalk-head/coverage.json"} <= set(paths)
        # upload-artifact skips hidden files (.lockwalk/) unless told otherwise.
        assert uploads[0]["with"]["include-hidden-files"] is True
        assert uploads[0]["with"]["if-no-files-found"] == "warn"
        # The report matters most when the gate failed.
        assert "!cancelled()" in str(uploads[0]["if"])


def test_pull_request_jobs_keep_write_access_away_from_pr_code(workflow: dict[Any, Any]) -> None:
    jobs = workflow["jobs"]
    assert jobs["coverage"].get("permissions", workflow["permissions"]) == {"contents": "read"}
    checkout = next(s for s in _steps(jobs["coverage"]) if "actions/checkout" in s.get("uses", ""))
    assert checkout["with"]["persist-credentials"] is False
    # The target branch worktree needs the full history.
    assert checkout["with"]["fetch-depth"] == 0
    assert jobs["comment"]["permissions"] == {"pull-requests": "write"}
    assert not any("actions/checkout" in s.get("uses", "") for s in _steps(jobs["comment"]))
    condition = str(jobs["comment"]["if"])
    assert "github.repository" in condition
    assert "full_name" in condition
    # It still runs when the gate failed, which is when the comment matters most.
    assert jobs["comment"]["needs"] == "coverage"
    assert "!cancelled()" in condition


def test_never_uses_pull_request_target(workflow: dict[Any, Any]) -> None:
    # A comment in the file may warn against it; only a real trigger or condition counts.
    assert "pull_request_target" not in _triggers(workflow)
    for job in workflow["jobs"].values():
        assert "pull_request_target" not in str(job.get("if", ""))
        for step in _steps(job):
            assert "pull_request_target" not in str(step.get("if", ""))


def test_summary_and_exit_code(workflow: dict[Any, Any]) -> None:
    steps = _steps(workflow["jobs"]["coverage"])
    summary = next(i for i, s in enumerate(steps) if "$GITHUB_STEP_SUMMARY" in str(s.get("run")))
    assert "comment.md" in steps[summary]["run"]
    assert "!cancelled()" in str(steps[summary]["if"])
    upload = next(
        i for i, s in enumerate(steps) if str(s.get("uses", "")).startswith("actions/upload-art")
    )
    assert "!cancelled()" in str(steps[upload]["if"])
    # The head run records its exit code even when lockwalk fails.
    head = next(s for s in steps if s.get("id") == "head")
    assert "set +e" in head["run"]
    assert "$GITHUB_OUTPUT" in head["run"]
    # The last step fails the job with that code. It has no `if`, so a cancelled run is not
    # reported as a success, and the code goes through env rather than into the script.
    last = steps[-1]
    assert summary < upload < len(steps) - 1
    assert "if" not in last
    assert "exit" in last["run"]
    assert "CODE" in last["run"]
    assert "steps.head.outputs.code" in last["env"]["CODE"]


def test_base_step_is_best_effort_and_uses_the_pr_lockwalk(workflow: dict[Any, Any]) -> None:
    steps = _steps(workflow["jobs"]["coverage"])
    base = next(s for s in steps if "git worktree add" in str(s.get("run")))
    assert base["continue-on-error"] is True
    run = base["run"]
    assert run.index("git worktree add") < run.index("cd ")
    assert "uv run --project" in run
    assert "--output-dir" in run


def test_base_is_the_first_parent_of_the_merge_commit(workflow: dict[Any, Any]) -> None:
    # The pull request was merged onto this commit. The target branch's current tip may have
    # moved since, and would show other people's changes as this pull request's.
    steps = _steps(workflow["jobs"]["coverage"])
    base = next(s for s in steps if "git worktree add" in str(s.get("run")))
    add = next(line for line in base["run"].splitlines() if "git worktree add" in line)
    assert add.split()[-1] == "HEAD^1"
    checkout = next(s for s in steps if "actions/checkout" in s.get("uses", ""))
    assert checkout["with"]["fetch-depth"] == 0
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "GITHUB_BASE_REF" not in text
    assert "origin/" not in text


def test_comment_job_skips_dependabot_pull_requests(workflow: dict[Any, Any]) -> None:
    condition = str(workflow["jobs"]["comment"]["if"])
    assert "github.event.pull_request.user.login != 'dependabot[bot]'" in condition


def test_comment_lookup_does_not_pipe_into_head(workflow: dict[Any, Any]) -> None:
    steps = _steps(workflow["jobs"]["comment"])
    script = "\n".join(str(s.get("run", "")) for s in steps)
    # `head` can exit early and kill `gh` with SIGPIPE, which fails the step under pipefail.
    assert not re.search(r"\|\s*head\b", script)
    assert "| sed -n 1p" in script


def test_comment_only_updates_its_own(workflow: dict[Any, Any]) -> None:
    steps = _steps(workflow["jobs"]["comment"])
    script = "\n".join(str(s.get("run", "")) for s in steps)
    assert "github-actions[bot]" in script
    assert MARKER in script
    # Values from the event go through env, not into the script text.
    assert "${{" not in script


def test_cerbos_service_is_commented_out(workflow: dict[Any, Any]) -> None:
    assert "services" not in workflow["jobs"]["test"]
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "# services:" in text
    assert "ghcr.io/cerbos/cerbos" in text


def test_one_run_per_pull_request(workflow: dict[Any, Any]) -> None:
    # Two quick pushes must not post two comments or let an older run overwrite a newer one.
    concurrency = workflow["concurrency"]
    assert "github.event.pull_request.number" in concurrency["group"]
    assert "github.ref" in concurrency["group"]
    assert "pull_request" in str(concurrency["cancel-in-progress"])


def test_comment_job_survives_a_missing_artifact(workflow: dict[Any, Any]) -> None:
    steps = _steps(workflow["jobs"]["comment"])
    download = next(s for s in steps if "download-artifact" in s.get("uses", ""))
    assert download["continue-on-error"] is True
    post = next(s for s in steps if "gh api" in str(s.get("run", "")))
    run = post["run"]
    # The check for a missing file comes first and ends the step without an error.
    assert run.index("comment.md ]") < run.index("gh api")
    assert "exit 0" in run[: run.index("gh api")]


def test_every_flag_exists(workflow: dict[Any, Any]) -> None:
    runner = CliRunner()
    commands = _lockwalk_commands(workflow)
    assert commands
    for words in commands:
        sub = words[0]
        help_text = runner.invoke(app, [sub, "--help"]).output
        for word in words[1:]:
            if word.startswith("--"):
                assert word.split("=")[0] in help_text, (sub, word)
    # `--base` sits in a bash array in the workflow, so the loop above cannot see it.
    assert next(c[:3] for c in commands if c[0] == "diff") == [
        "diff",
        "--head",
        ".lockwalk-head/coverage.json",
    ]
    diff_help = runner.invoke(app, ["diff", "--help"]).output
    for flag in ("--base", "--head", "--format"):
        assert flag in diff_help
    compare = next(s for s in _steps(workflow["jobs"]["coverage"]) if s.get("name") == "Compare")
    assert "--base" in compare["run"]


def test_readme_content() -> None:
    text = (CI_DIR / "README.md").read_text(encoding="utf-8")
    for needle in (
        "github-actions.yml",
        "lockwalk coverage",
        "lockwalk test",
        "--waivers",
        "lockwalk diff",
        "The pull request comment",
    ):
        assert needle in text
    for row in (
        "| 0 | pass | green |",
        "| 1 | findings, or the gate failed | red |",
        "| 2 | the test itself is broken",
    ):
        assert row in text
    assert 'adapter = "authzen"' in text
    assert 'roles_property = "cerbos.roles"' in text
    assert "uv add --dev" in text
    assert "git+" not in text
    assert "docker run -d --name cerbos" in text
    assert "healthcheck" in text


def test_cerbos_image_matches_the_iam_test() -> None:
    # Read the constant as text; importing another test module would run its setup.
    match = re.search(r'^CERBOS_IMAGE = "([^"]+)"', CERBOS_TEST.read_text("utf-8"), re.M)
    assert match
    expected = match.group(1)
    for name in ("github-actions.yml", "README.md"):
        text = (CI_DIR / name).read_text(encoding="utf-8")
        images = set(re.findall(r"ghcr\.io/cerbos/cerbos:[\w.\-]+", text))
        assert images == {expected}, name


def test_compare_fallback_keeps_the_marker_and_the_reason(workflow: dict[Any, Any]) -> None:
    compare = next(s for s in _steps(workflow["jobs"]["coverage"]) if s.get("name") == "Compare")
    run = str(compare["run"])
    # Without the marker, the next run would post a second comment.
    assert MARKER in run
    # The error from lockwalk diff is printed before the fallback replaces comment.md.
    assert run.index("cat comment.md >&2") < run.index("could not compare")
