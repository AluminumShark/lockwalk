"""Pin the security and ordering rules of the release workflow."""

import re
from typing import Any

import pytest
from workflow_helpers import PINNED, REPO_ROOT, WORKFLOWS, load_workflow, steps, triggers

PATH = WORKFLOWS / "release.yml"
PUBLISH_ACTION = "pypa/gh-action-pypi-publish@"


@pytest.fixture(scope="module")
def workflow() -> dict[Any, Any]:
    return load_workflow(PATH)


@pytest.fixture(scope="module")
def text() -> str:
    return PATH.read_text(encoding="utf-8")


def _uses(job: dict[str, Any], prefix: str) -> list[dict[str, Any]]:
    return [s for s in steps(job) if str(s.get("uses", "")).startswith(prefix)]


def _runs(job: dict[str, Any]) -> list[str]:
    return [str(s["run"]) for s in steps(job) if "run" in s]


def test_only_version_tag_pushes_trigger_it(workflow):
    assert triggers(workflow) == {"push": {"tags": ["v*"]}}


def test_workflow_permissions_are_read_only(workflow):
    assert workflow["permissions"] == {"contents": "read"}


def test_jobs_are_exactly_build_and_the_two_publishers(workflow):
    assert list(workflow["jobs"]) == ["build", "publish-testpypi", "publish-pypi"]


def test_every_action_is_pinned(text):
    lines = [line.strip() for line in text.splitlines() if re.match(r"\s*(-\s*)?uses:", line)]
    assert lines
    for line in lines:
        assert PINNED.search(line), line


def test_setup_uv_pins_the_uv_version(workflow):
    found = 0
    for job in workflow["jobs"].values():
        for step in _uses(job, "astral-sh/setup-uv@"):
            found += 1
            assert step["with"]["version"] == "0.13.7"
    assert found >= 1


def test_build_job_has_no_token_permission(workflow):
    job = workflow["jobs"]["build"]
    assert "id-token" not in (job.get("permissions") or {})
    assert "environment" not in job


def test_build_checks_out_without_credentials(workflow):
    checkouts = _uses(workflow["jobs"]["build"], "actions/checkout@")
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["persist-credentials"] is False
    # Full history, so origin/main exists for the ancestor check.
    assert checkouts[0]["with"]["fetch-depth"] == 0


def _index(job, predicate):
    found = [i for i, s in enumerate(steps(job)) if predicate(s)]
    assert len(found) == 1
    return found[0]


def test_tagged_commit_must_be_on_main_before_anything_is_built(workflow):
    job = workflow["jobs"]["build"]
    check = _index(
        job,
        lambda s: s.get("run") == 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
    )
    checkout = _index(job, lambda s: str(s.get("uses", "")).startswith("actions/checkout@"))
    build = _index(job, lambda s: s.get("run") == "uv build")
    upload = _index(job, lambda s: str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert checkout < check < build < upload


def test_twine_check_runs_after_the_upload_and_still_fails_the_job(workflow):
    job = workflow["jobs"]["build"]
    upload = _index(job, lambda s: str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    twine = _index(job, lambda s: "twine check" in str(s.get("run", "")))
    assert upload < twine
    assert not steps(job)[twine].get("continue-on-error")


def test_build_builds_checks_and_uploads(workflow):
    job = workflow["jobs"]["build"]
    runs = _runs(job)
    joined = "\n".join(runs)
    assert "uv build" in runs
    assert (
        'scripts/check_package.py dist --tag "$GITHUB_REF_NAME" --changelog CHANGELOG.md' in joined
    )
    assert "scripts/smoke_wheel.py dist" in joined
    assert "uvx --from twine==7.0.0 twine check" in joined


def test_tag_check_runs_before_the_upload(workflow):
    job = workflow["jobs"]["build"]
    order = [i for i, s in enumerate(steps(job)) if "check_package.py" in str(s.get("run", ""))]
    upload = [
        i
        for i, s in enumerate(steps(job))
        if str(s.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    build = [i for i, s in enumerate(steps(job)) if s.get("run") == "uv build"]
    assert len(order) == len(upload) == len(build) == 1
    assert build[0] < order[0] < upload[0]
    # Only the build job can upload an artifact, so a failed check blocks every publisher.
    for name in ("publish-testpypi", "publish-pypi"):
        assert not _uses(workflow["jobs"][name], "actions/upload-artifact@")


def test_only_the_packages_are_uploaded_not_other_files_in_dist(workflow):
    (upload,) = _uses(workflow["jobs"]["build"], "actions/upload-artifact@")
    assert upload["with"]["name"] == "dist"
    paths = str(upload["with"]["path"]).split()
    assert sorted(paths) == ["dist/*.tar.gz", "dist/*.whl"]
    assert upload["with"]["if-no-files-found"] == "error"


@pytest.mark.parametrize("name", ["publish-testpypi", "publish-pypi"])
def test_publish_jobs_only_download_and_publish(workflow, name):
    job = workflow["jobs"][name]
    assert job["permissions"] == {"id-token": "write"}
    assert job["environment"] == name.removeprefix("publish-")
    assert not _uses(job, "actions/checkout@")
    assert not _runs(job)
    kinds = [str(s["uses"]).split("@")[0] for s in steps(job)]
    assert kinds == ["actions/download-artifact", "pypa/gh-action-pypi-publish"]
    (download,) = _uses(job, "actions/download-artifact@")
    assert download["with"] == {"name": "dist", "path": "dist/"}


def test_testpypi_job_follows_build_and_uses_the_test_index(workflow):
    job = workflow["jobs"]["publish-testpypi"]
    assert job["needs"] == "build"
    (publish,) = _uses(job, PUBLISH_ACTION)
    assert publish["with"]["repository-url"] == "https://test.pypi.org/legacy/"


def test_testpypi_tolerates_a_version_it_already_has(workflow):
    # A re-run after a partial failure must not be blocked by the earlier upload.
    (publish,) = _uses(workflow["jobs"]["publish-testpypi"], PUBLISH_ACTION)
    assert publish["with"]["skip-existing"] is True


def test_pypi_job_follows_testpypi_and_uses_the_default_index(workflow):
    job = workflow["jobs"]["publish-pypi"]
    assert job["needs"] == "publish-testpypi"
    (publish,) = _uses(job, PUBLISH_ACTION)
    assert "with" not in publish or "repository-url" not in publish["with"]


def test_pypi_never_skips_existing_files(workflow, text):
    (publish,) = _uses(workflow["jobs"]["publish-pypi"], PUBLISH_ACTION)
    assert "skip-existing" not in (publish.get("with") or {})
    assert text.count("skip-existing") == 1


def test_no_stored_credentials(text):
    for word in ("password", "api-token", "secrets."):
        assert word not in text, word


def test_no_event_value_inside_a_script(workflow):
    for job in workflow["jobs"].values():
        for script in _runs(job):
            assert "${{" not in script, script


def test_scripts_named_in_the_workflow_exist(text):
    names = set(re.findall(r"scripts/[\w.]+\.py", text))
    assert names
    for name in names:
        assert (REPO_ROOT / name).is_file(), name
    assert (REPO_ROOT / "CHANGELOG.md").is_file()
