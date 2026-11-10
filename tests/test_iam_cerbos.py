"""lockwalk test on examples/iam_cerbos: a real Cerbos PDP must match the reference policy.

Two Cerbos containers run in Docker, published on 127.0.0.1 only: the correct policies and
the broken ones. Discovery imports examples/multi_agent/app.py in a worker subprocess;
reuse_discovery shares its result between the runs. Nothing calls a model.

The docker tests skip when Docker or the image is missing. Pull the image with
`docker pull ghcr.io/cerbos/cerbos:0.57.0`. The pinning test runs everywhere.
"""

import json
import shutil
import subprocess
import time
import urllib.request
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from lockwalk_discovery_cache import reuse_discovery  # noqa: F401
from lockwalk_iam_expectations import (
    BROKEN_CASES,
    CASES,
    DENY_ONLY_CASES,
    ESCALATIONS,
    case_statuses,
    escalations,
)
from lockwalk_net_helpers import wait_for_port
from typer.testing import CliRunner

from lockwalk import cli
from lockwalk.config import PolicyConfig
from lockwalk.models import Verdict
from lockwalk.policy.authzen import AuthZenAdapter
from lockwalk.policy.base import Entity, Query, QueryAction

CERBOS_IMAGE = "ghcr.io/cerbos/cerbos:0.57.0"
REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "iam_cerbos"
CONFIG = EXAMPLE / ".lockwalk.toml"

runner = CliRunner()


def _docker(*args: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
    )


def _skip_reason() -> str | None:
    if shutil.which("docker") is None:
        return "docker is not installed"
    try:
        if _docker("info").returncode != 0:
            return "the docker daemon is not running"
        if _docker("image", "inspect", CERBOS_IMAGE).returncode != 0:
            return f"the Cerbos image is missing; run: docker pull {CERBOS_IMAGE}"
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"docker does not answer: {error}"
    return None


def _start(name: str, policies: Path) -> None:
    """Start one Cerbos container, published on a free 127.0.0.1 port chosen by Docker."""
    result = _docker(
        "run",
        "--rm",
        "-d",
        "--name",
        name,
        "-p",
        "127.0.0.1::3592",
        "-v",
        f"{policies}:/policies:ro",
        "-v",
        f"{EXAMPLE / 'cerbos' / 'conf.yaml'}:/conf.yaml:ro",
        CERBOS_IMAGE,
        "server",
        "--config=/conf.yaml",
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker run failed: {result.stderr.strip()}")


def _host_port(name: str) -> int:
    result = _docker("port", name, "3592")
    if result.returncode != 0:
        raise RuntimeError(f"docker port failed: {result.stderr.strip()}")
    # One line per binding, like "127.0.0.1:49153"; the first is the IPv4 one.
    return int(result.stdout.splitlines()[0].rsplit(":", 1)[1])


def _wait_healthy(port: int, name: str) -> None:
    wait_for_port(port, timeout=30.0)
    deadline = time.monotonic() + 30.0
    url = f"http://127.0.0.1:{port}/_cerbos/health"
    while time.monotonic() < deadline:
        running = _docker("inspect", "-f", "{{.State.Running}}", name)
        if running.returncode != 0 or running.stdout.strip() != "true":
            logs = _docker("logs", name)
            raise RuntimeError(f"Cerbos exited: {(logs.stdout + logs.stderr)[-500:]}")
        try:
            with urllib.request.urlopen(url, timeout=2) as reply:
                if json.loads(reply.read()).get("status") == "SERVING":
                    return
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    logs = _docker("logs", name)
    raise TimeoutError(f"Cerbos did not become healthy on port {port}: {logs.stdout[-500:]}")


@dataclass(frozen=True)
class Pdps:
    good: str
    broken: str


@pytest.fixture(scope="module")
def pdps() -> Iterator[Pdps]:
    reason = _skip_reason()
    if reason is not None:
        pytest.skip(reason)
    names: list[str] = []
    try:
        for directory in ("policies", "policies-broken"):
            name = f"lockwalk-cerbos-test-{uuid.uuid4().hex[:8]}"
            names.append(name)  # before docker run, so a timeout cannot leak the container
            _start(name, EXAMPLE / "cerbos" / directory)
        ports = [_host_port(name) for name in names]
        for name, port in zip(names, ports, strict=True):
            _wait_healthy(port, name)
        yield Pdps(
            good=f"authzen:http://127.0.0.1:{ports[0]}",
            broken=f"authzen:http://127.0.0.1:{ports[1]}",
        )
    finally:
        for name in names:
            _docker("rm", "-f", name)


@dataclass(frozen=True)
class Run:
    code: int
    stdout: str
    report: dict | None


def run_cli(output: Path, *args: str | Path) -> Run:
    arguments = ["test", "--config", str(CONFIG), "--output-dir", str(output), *map(str, args)]
    result = runner.invoke(cli.app, arguments)
    path = output / "coverage.json"
    report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    return Run(result.exit_code, result.stdout, report)


@pytest.fixture(scope="module")
def default_run(pdps: Pdps, tmp_path_factory: pytest.TempPathFactory) -> Run:
    return run_cli(tmp_path_factory.mktemp("default"), "--policy", pdps.good)


@pytest.fixture(scope="module")
def broken_run(pdps: Pdps, tmp_path_factory: pytest.TempPathFactory) -> Run:
    return run_cli(tmp_path_factory.mktemp("broken"), "--policy", pdps.broken)


@pytest.fixture(scope="module")
def deny_only_run(pdps: Pdps, tmp_path_factory: pytest.TempPathFactory) -> Run:
    spec = REPO_ROOT / "examples" / "multi_agent" / "deny-only-spec.yaml"
    return run_cli(tmp_path_factory.mktemp("deny_only"), "--policy", pdps.good, "--spec", spec)


@pytest.mark.docker
def test_cerbos_matches_the_reference_on_cases_and_escalations(default_run):
    assert default_run.code == 1, default_run.stdout
    report = default_run.report
    assert report is not None
    assert case_statuses(report) == CASES
    assert escalations(report) == ESCALATIONS
    assert all(control["allowed"] for control in report["controls"])
    assert report["policy_adapter"].startswith("authzen:")


@pytest.mark.docker
def test_the_batch_endpoint_is_used(default_run):
    report = default_run.report
    assert report is not None
    assert isinstance(report["warnings"], list)
    # This text is the adapter's current wording in src/lockwalk/policy/authzen.py.
    fallback = "the PDP has no AuthZEN batch endpoint"
    assert fallback not in default_run.stdout
    assert not any(fallback in str(warning) for warning in report["warnings"])
    assert report["policy_adapter"].startswith("authzen:")
    assert all(control["allowed"] for control in report["controls"])


@pytest.mark.docker
def test_a_broken_cerbos_policy_fails_the_deny_case(broken_run):
    assert broken_run.code == 1, broken_run.stdout
    assert broken_run.report is not None
    assert case_statuses(broken_run.report) == BROKEN_CASES


@pytest.mark.docker
def test_deny_only_cases_are_inconclusive_under_cerbos(deny_only_run):
    assert deny_only_run.code == 1, deny_only_run.stdout
    assert deny_only_run.report is not None
    assert case_statuses(deny_only_run.report) == DENY_ONLY_CASES


@pytest.mark.docker
def test_one_batch_with_one_subject_id_and_different_roles_is_answered_per_query(pdps):
    """Cerbos builds one principal per subject id in a batch; the adapter must split."""
    url = pdps.good.removeprefix("authzen:")
    adapter = AuthZenAdapter(PolicyConfig(adapter="authzen", url=url))
    order = Entity(type="order", id="o-1", properties={"account_owner": "alice"})
    action = QueryAction(name="trade:execute")

    def query(roles: list[str]) -> Query:
        subject = Entity(type="user", id="alice", properties={"cerbos.roles": roles})
        return Query(subject=subject, action=action, resource=order)

    try:
        decisions = adapter.decide([query(["trader"]), query(["analyst"]), query(["trader"])])
        reversed_order = adapter.decide([query(["analyst"]), query(["trader"])])
    finally:
        adapter.close()
    assert [d.verdict for d in decisions] == [Verdict.ALLOW, Verdict.DENY, Verdict.ALLOW]
    assert [d.verdict for d in reversed_order] == [Verdict.DENY, Verdict.ALLOW]


def test_the_compose_file_pins_the_image_the_tests_use():
    compose = (EXAMPLE / "docker-compose.yml").read_text(encoding="utf-8")
    images = [
        line.split("image:", 1)[1].strip() for line in compose.splitlines() if "image:" in line
    ]
    assert images == [CERBOS_IMAGE, CERBOS_IMAGE]
