"""Door and effect rules, end to end through the CLI.

One generic app trace with an approval span (a person's decision, no subject) and an
execute_tool span. Nothing here names a real framework. The traces come from a private
OpenTelemetry SDK provider (the fixture of test_observe_e2e_doors).
"""

import json
from pathlib import Path
from typing import Any

import pytest
from observe_helpers import (
    Sdk,
    make_config,
    observe,
    only_guard,
    otlp_json_from_sdk_spans,
    rules,
    runner,
)
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from lockwalk.cli import app

RULES = """\
[[observe.rules]]
kind = "door"
when = { "gen_ai.operation.name" = "approval", "app.granted" = true }
decision = "allow"
tool_call_id = "gen_ai.tool.call.id"

[[observe.rules]]
kind = "door"
when = { "gen_ai.operation.name" = "approval", "app.granted" = false }
decision = "deny"
tool_call_id = "gen_ai.tool.call.id"

[[observe.rules]]
kind = "effect"
when = { "app.outcome" = "completed" }
"""
NO_SUBJECT_WARNING = (
    "1 door records have no subject (for example a person's approval); "
    "they count for guard checks only"
)


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> Sdk:
    """A private SDK provider (as in test_observe_e2e_doors); the global one is never set."""
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    sdk = TracerProvider()
    exporter = InMemorySpanExporter()
    sdk.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "get_tracer", lambda name, *a, **k: sdk.get_tracer(name))
    return Sdk(sdk, exporter)


def write_sdk_trace(tmp_path: Path, sdk: Sdk) -> Path:
    path = tmp_path / "sdk.json"
    path.write_text(json.dumps(otlp_json_from_sdk_spans(sdk.finished())), encoding="utf-8")
    return path


def run_app(sdk: Any, *, granted: bool, outcome: str, call: str = "call-1") -> None:
    """supervisor -> trade-agent -> (approval, execute_trade) with generic attributes."""
    tracer = sdk.get_tracer("app")
    root = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "supervisor"}
    with tracer.start_as_current_span(
        "invoke_agent supervisor", attributes={**root, "user.id": "alice"}
    ):
        agent = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "trade-agent"}
        with tracer.start_as_current_span("invoke_agent trade-agent", attributes=agent):
            approval = {
                "gen_ai.operation.name": "approval",
                "app.granted": granted,
                "gen_ai.tool.call.id": call,
            }
            with tracer.start_as_current_span("approval", attributes=approval):
                pass
            tool = {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "execute_trade",
                "gen_ai.tool.call.id": call,
                "app.outcome": outcome,
            }
            with tracer.start_as_current_span("execute_tool execute_trade", attributes=tool):
                pass


def test_granted_and_completed_is_guarded(provider: Sdk, tmp_path: Path) -> None:
    run_app(provider, granted=True, outcome="completed")
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider), extra=RULES)
    assert only_guard(report) == {"GUARDED": 1}
    assert report["identities"] == []
    assert NO_SUBJECT_WARNING in report["warnings"]
    assert result.exit_code == 0, result.output
    assert rules(report) == []


def test_denied_and_blocked_is_denied_unverified(provider: Sdk, tmp_path: Path) -> None:
    run_app(provider, granted=False, outcome="blocked")
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider), extra=RULES)
    assert result.exit_code == 0, result.output
    assert only_guard(report) == {"DENIED_UNVERIFIED": 1}


def test_denied_and_blocked_beside_a_granted_trace_is_denied(provider: Sdk, tmp_path: Path) -> None:
    run_app(provider, granted=True, outcome="completed", call="call-1")
    run_app(provider, granted=False, outcome="blocked", call="call-2")
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider), extra=RULES)
    assert result.exit_code == 0, result.output
    assert only_guard(report) == {"GUARDED": 1, "DENIED": 1}


def test_denied_and_completed_is_a_bypass(provider: Sdk, tmp_path: Path) -> None:
    run_app(provider, granted=False, outcome="completed")
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider), extra=RULES)
    assert only_guard(report) == {"BYPASS": 1}
    assert "bypass" in rules(report)
    assert result.exit_code == 1, result.output


def test_inspect_shows_the_decision_only_line(provider: Sdk, tmp_path: Path) -> None:
    run_app(provider, granted=False, outcome="blocked")
    path = write_sdk_trace(tmp_path, provider)
    trace_id = json.loads(path.read_text(encoding="utf-8"))["resourceSpans"][0]["scopeSpans"][0][
        "spans"
    ][0]["traceId"]
    config = make_config(tmp_path, RULES)
    result = runner.invoke(
        app, ["inspect", "--trace", trace_id, "--config", str(config), "--traces", str(path)]
    )
    assert result.exit_code == 0, result.output
    assert "door: deny (decision only, no subject) (linked by tool call id)" in result.output
    assert "alice" not in result.output


def test_without_the_rules_the_call_is_unguarded(provider: Sdk, tmp_path: Path) -> None:
    run_app(provider, granted=True, outcome="completed")
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert only_guard(report) == {"UNGUARDED": 1}
    assert not any("no subject" in w for w in report["warnings"])
    assert result.exit_code == 1, result.output
