"""A real OpenTelemetry Collector writes the trace file that lockwalk observe reads.

Skipped unless docker works and the pinned image is already present (the test never pulls).
The container listens on 127.0.0.1 only and is always removed.
"""

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest
from lockwalk_net_helpers import free_port
from typer.testing import CliRunner, Result

from lockwalk.cli import app
from lockwalk.config import ObserveConfig
from lockwalk.observe.otlp import read_otlp
from lockwalk.observe.spans import Limits, allowlist

IMAGE = "otel/opentelemetry-collector-contrib:0.165.0"
DATA = Path(__file__).resolve().parent / "observe_data"
runner = CliRunner()


def _docker_has_image() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        done = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        not _docker_has_image(),
        reason=f"docker is not available or {IMAGE} is not present locally",
    ),
]

CONFIG = """receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file:
    path: /out/traces.jsonl
{extra}service:
  telemetry:
    metrics:
      level: none
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [file]
"""


def _attr(key: str, value: str) -> dict:
    return {"key": key, "value": {"stringValue": value}}


def _span(trace: str, span: str, parent: str | None, name: str, start: int, *attrs: dict) -> dict:
    found: dict = {
        "traceId": trace,
        "spanId": span,
        "name": name,
        "kind": 1,
        "startTimeUnixNano": str(1_794_105_344_000_000_000 + start),
        "endTimeUnixNano": str(1_794_105_344_000_000_000 + start + 1000),
        "attributes": list(attrs),
    }
    if parent is not None:
        found["parentSpanId"] = parent
    return found


def _agent(name: str) -> tuple[dict, dict]:
    return _attr("gen_ai.operation.name", "invoke_agent"), _attr("gen_ai.agent.name", name)


def _tool(name: str) -> tuple[dict, dict]:
    return _attr("gen_ai.operation.name", "execute_tool"), _attr("gen_ai.tool.name", name)


def payload() -> dict:
    """Two traces: supervisor -> trade-agent -> execute_trade, and supervisor -> delegate_trade."""
    one, two = "a1" * 16, "b2" * 16
    spans = [
        _span(one, "0000000000000001", None, "invoke_agent supervisor", 0, *_agent("supervisor")),
        _span(
            one, "0000000000000002", "0000000000000001", "invoke_agent trade-agent", 10,
            *_agent("trade-agent"),
        ),
        _span(
            one, "0000000000000003", "0000000000000002", "execute_tool execute_trade", 20,
            *_tool("execute_trade"), _attr("gen_ai.tool.call.arguments", "SECRET-ARGS"),
        ),
        _span(two, "0000000000000011", None, "invoke_agent supervisor", 100, *_agent("supervisor")),
        _span(
            two, "0000000000000012", "0000000000000011", "execute_tool delegate_trade", 110,
            *_tool("delegate_trade"),
        ),
    ]  # fmt: skip
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": [_attr("service.name", "docker-test")]},
                "scopeSpans": [{"scope": {"name": "lockwalk.test"}, "spans": spans}],
            }
        ]
    }


def _run_collector(tmp_path: Path, extra: str) -> Path:
    """Start the Collector, send the payload, stop it, and return the output directory."""
    out = tmp_path / "out"
    out.mkdir()
    # The image runs as its own user (uid 10001): let the container write here, and on POSIX
    # run it as the host user so the exported file is readable afterwards.
    out.chmod(0o777)
    config = tmp_path / "collector.yaml"
    config.write_text(CONFIG.format(extra=extra), encoding="utf-8")
    port = free_port()
    name = f"lockwalk-test-{uuid.uuid4().hex[:8]}"
    user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    command = [
        "docker", "run", "-d", "--name", name, *user,
        "-p", f"127.0.0.1:{port}:4318",
        "-v", f"{config.as_posix()}:/etc/otelcol/config.yaml:ro",
        "-v", f"{out.as_posix()}:/out",
        IMAGE, "--config", "/etc/otelcol/config.yaml",
    ]  # fmt: skip
    try:
        started = subprocess.run(command, capture_output=True, timeout=60, check=False)
        assert started.returncode == 0, started.stderr.decode(errors="replace")
        _post(port, json.dumps(payload()).encode("utf-8"))
        written = out / "traces.jsonl"
        deadline = time.monotonic() + 30
        while not (written.exists() and written.stat().st_size > 0):
            assert time.monotonic() < deadline, "the Collector wrote no file within 30 s"
            time.sleep(0.25)
        stopped = subprocess.run(
            ["docker", "stop", name], capture_output=True, timeout=60, check=False
        )
        assert stopped.returncode == 0, (
            f"docker stop failed: {stopped.stderr.decode(errors='replace')}"
        )
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60, check=False)
    return out


def _observe(report_dir: Path, written: Path) -> Result:
    command = [
        "observe",
        "--config",
        str(DATA / "observe.toml"),
        "--output-dir",
        str(report_dir),
        "--traces",
        str(written),
    ]
    return runner.invoke(app, command)


def _post(port: int, body: bytes) -> None:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/traces",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    deadline = time.monotonic() + 30
    while True:
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


def test_collector_json_file_is_read_and_observed(tmp_path: Path) -> None:
    out = _run_collector(tmp_path, "    format: json\n")
    written = out / "traces.jsonl"
    assert written.is_file()
    text = written.read_text(encoding="utf-8")
    first = json.loads(text.splitlines()[0])
    spans = [s for r in first["resourceSpans"] for c in r["scopeSpans"] for s in c["spans"]]
    assert all(s["traceId"] == s["traceId"].lower() for s in spans)
    assert all(isinstance(s["kind"], int) for s in spans)
    roots = [s for s in spans if s["name"] == "invoke_agent supervisor"]
    assert roots and all("parentSpanId" not in s for s in roots)  # absent, not empty

    read = read_otlp(
        [written],
        keys=allowlist(ObserveConfig()),
        limits=Limits(max_spans=1000, max_line_bytes=1 << 20, max_total_bytes=1 << 24),
    )
    assert read.problems == ()
    assert len(read.raw) == 5
    assert {s.trace_id for s in read.raw} == {"a1" * 16, "b2" * 16}

    report_dir = tmp_path / "report"
    result = _observe(report_dir, written)
    assert result.exit_code == 0, result.output
    report = json.loads((report_dir / "observe.json").read_text(encoding="utf-8"))
    assert report["totals"]["traces"] == 2
    assert {(r["from_id"], r["to_id"], r["status"]) for r in report["routes"]} == {
        ("user", "supervisor", "ON_MAP"),
        ("supervisor", "trade-agent", "ON_MAP"),
        ("trade-agent", "execute_trade", "ON_MAP"),
        ("supervisor", "delegate_trade", "ON_MAP"),
    }
    assert "SECRET-ARGS" not in result.output
    assert "SECRET-ARGS" not in (report_dir / "observe.json").read_text(encoding="utf-8")


def test_collector_zstd_file_gives_the_binary_format_error(tmp_path: Path) -> None:
    out = _run_collector(tmp_path, "    compression: zstd\n")
    written = out / "traces.jsonl"
    assert written.is_file()
    report_dir = tmp_path / "report"
    result = _observe(report_dir, written)
    assert result.exit_code == 2
    assert "format: json without compression" in result.output.replace("\n", " ")
