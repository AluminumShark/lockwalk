"""lockwalk observe with door records, end to end through the CLI.

Traces come from the real OpenTelemetry SDK (record_authz / record_effect on a private
provider), from corrected copies of the openai_oi_handoff.json fixture, and from small
hand-built OTLP documents. Nothing calls a model or the network.
"""

import json
import re
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from observe_helpers import (
    DATA,
    Sdk,
    copy_without_doors,
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

from lockwalk import waivers
from lockwalk.cli import app
from lockwalk.models import IdentityCheckRow, IdentityObservation, IdentityResult
from lockwalk.observe.checks import TEST_DIFFERS_NOTE
from lockwalk.observe.results import OBSERVE_FILE_NAME
from lockwalk.record import record_authz, record_effect
from lockwalk.report import write_report
from lockwalk.waivers import COVERAGE_OR_TEST_ONLY_NOTE

FIXTURE = DATA / "openai_oi_handoff.json"
AGENT_SUBJECT = {"type": "agent", "id": "trade-agent"}
USER_SUBJECT = {"type": "user", "id": "alice"}
ORDER_ID = "order-4711"  # a resource id; it must never reach a trace file or an output


def only_identity(report: dict) -> dict:
    (row,) = report["identities"]
    return row


# ---- a round trip through the OpenTelemetry SDK ----


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch):
    """A private SDK provider and the spans it finished.

    tests/crewai_env used to set OTEL_SDK_DISABLED at collection time; the variable is removed
    here before the provider is built, so the result never depends on test order. The global
    provider is never set (the API allows that only once).
    """
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    sdk = TracerProvider()
    exporter = InMemorySpanExporter()
    sdk.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "get_tracer", lambda name, *a, **k: sdk.get_tracer(name))
    return Sdk(sdk, exporter)


def run_app(
    sdk: Any,
    *,
    subject: dict[str, Any] = AGENT_SUBJECT,
    decision: str = "allow",
    effect: bool = True,
    door: bool = True,
) -> None:
    """One request: supervisor -> trade-agent -> execute_trade, with the door's records."""
    tracer = sdk.get_tracer("app")
    root = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "supervisor"}
    with tracer.start_as_current_span(
        "invoke_agent supervisor", attributes={**root, "user.id": "alice"}
    ):
        agent = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "trade-agent"}
        with tracer.start_as_current_span("invoke_agent trade-agent", attributes=agent):
            call = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "execute_trade"}
            with tracer.start_as_current_span("execute_tool execute_trade", attributes=call):
                if door:
                    record_authz(
                        subject=subject,
                        action="trade:execute",
                        decision=decision,
                        resource={"type": "order", "id": ORDER_ID},
                    )
                if effect:
                    record_effect()


def write_sdk_trace(tmp_path: Path, sdk: Any) -> Path:
    path = tmp_path / "sdk.json"
    path.write_text(json.dumps(otlp_json_from_sdk_spans(sdk.finished())), encoding="utf-8")
    return path


def test_sdk_round_trip_match(provider, tmp_path: Path) -> None:
    run_app(provider)
    path = write_sdk_trace(tmp_path, provider)
    assert ORDER_ID not in path.read_text(encoding="utf-8")  # the helpers never write it
    result, report = observe(tmp_path, path)
    assert result.exit_code == 0, result.output
    assert report["totals"]["door_records"] == 1
    assert report["totals"]["records_without_call"] == 0
    row = only_identity(report)
    assert (row["result"], row["mode"], row["tool"]) == ("MATCH", "agent", "execute_trade")
    assert only_guard(report) == {"GUARDED": 1}
    assert [p["status"] for p in report["paths"]] == ["TESTED"]
    assert ORDER_ID not in result.output and "alice" not in result.output


def test_sdk_round_trip_mismatch(provider, tmp_path: Path) -> None:
    run_app(provider, subject=USER_SUBJECT)  # trade-agent's mode is agent, not user
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert result.exit_code == 1, result.output
    row = only_identity(report)
    assert (row["result"], row["expected"], row["observed"]) == (
        "MISMATCH",
        "agent:trade-agent",
        "the trace's user",
    )
    assert rules(report) == ["fail_on_identity_mismatch"]
    assert "alice" not in result.output and "alice" not in json.dumps(report)


def test_sdk_round_trip_bypass(provider, tmp_path: Path) -> None:
    run_app(provider, decision="deny", effect=True)
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert result.exit_code == 1, result.output
    assert only_guard(report) == {"BYPASS": 1}
    assert rules(report) == ["bypass"]


def test_sdk_round_trip_denied_and_stopped(provider, tmp_path: Path) -> None:
    run_app(provider, decision="deny", effect=False)
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert result.exit_code == 0, result.output  # nothing proves the denial held
    assert only_guard(report) == {"DENIED_UNVERIFIED": 1}


def test_sdk_round_trip_denied_while_effects_are_recorded_elsewhere(
    provider, tmp_path: Path
) -> None:
    run_app(provider)  # a normal call, with an effect marker
    run_app(provider, decision="deny", effect=False)  # a denied call that stopped
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert result.exit_code == 0, result.output
    assert only_guard(report) == {"GUARDED": 1, "DENIED": 1}  # markers are in use, so DENIED


def test_sdk_round_trip_unguarded(provider, tmp_path: Path) -> None:
    run_app(provider, door=False)  # the effect marker is there; the door record is not
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert result.exit_code == 1, result.output
    assert only_guard(report) == {"UNGUARDED": 1}
    assert report["guards"][0]["effect_without_record"] == 1
    assert rules(report) == ["fail_on_unguarded_call"]


def test_sdk_sub_agent_record_beside_its_own_tool_span_is_linked_by_time(
    provider, tmp_path: Path
) -> None:
    # The sub-agent's tool span is started but is not the current span (LangChain style), so
    # the record sits in a sibling span and only time can link it. The call above the agent
    # (delegate_trade) must not take it, and the sub-agent's own call (execute_trade) must.
    tracer = provider.get_tracer("app")
    agent = {"gen_ai.operation.name": "invoke_agent"}
    tool = {"gen_ai.operation.name": "execute_tool"}
    root = {**agent, "gen_ai.agent.name": "supervisor", "user.id": "alice"}
    with tracer.start_as_current_span("invoke_agent supervisor", attributes=root):
        delegate = {**tool, "gen_ai.tool.name": "delegate_trade"}
        with tracer.start_as_current_span("execute_tool delegate_trade", attributes=delegate):
            sub = {**agent, "gen_ai.agent.name": "trade-agent"}
            with tracer.start_as_current_span("invoke_agent trade-agent", attributes=sub):
                call = tracer.start_span(
                    "execute_tool execute_trade",
                    attributes={**tool, "gen_ai.tool.name": "execute_trade"},
                )
                time.sleep(0.01)
                with tracer.start_as_current_span("authz"):
                    record_authz(subject=AGENT_SUBJECT, action="trade:execute", decision="allow")
                    time.sleep(0.01)
                time.sleep(0.01)
                call.end()
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    assert result.exit_code == 0, result.output
    counts = {(row["agent"], row["tool"]): row for row in report["guards"]}
    assert counts[("supervisor", "delegate_trade")]["counts"] == {"UNGUARDED": 1}
    assert counts[("trade-agent", "execute_trade")]["counts"] == {"GUARDED": 1}
    assert counts[("trade-agent", "execute_trade")]["by_time"] == 1
    assert report["totals"]["records_by_time"] == 1
    assert report["totals"]["records_without_call"] == 0


def test_the_otel_sdk_is_not_disabled_for_this_test(provider) -> None:
    # A no-op provider would hand out spans that never finish; this guards the fixture itself.
    run_app(provider)
    assert len(provider.finished()) == 5


# ---- corrected copies of the openai_oi_handoff.json fixture ----


def fixture_variant(
    tmp_path: Path, *, set_: dict[str, Any] | None = None, drop: tuple[str, ...] = (), name="v"
) -> Path:
    """The fixture with its partial door record edited (the span that has the decision)."""
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    hits = [
        span
        for resource in document["resourceSpans"]
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
        if any(a["key"] == "lockwalk.door.decision" for a in span["attributes"])
    ]
    assert len(hits) == 1
    attributes = [a for a in hits[0]["attributes"] if a["key"] not in drop]
    for key, value in (set_ or {}).items():
        attributes = [a for a in attributes if a["key"] != key]
        any_value = {"boolValue": value} if isinstance(value, bool) else {"stringValue": value}
        attributes.append({"key": key, "value": any_value})
    hits[0]["attributes"] = attributes
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


AGENT_RECORD = {
    "lockwalk.door.subject.type": "agent",
    "lockwalk.door.subject.id": "trade-agent",
}
USER_RECORD = {"lockwalk.door.subject.type": "user", "lockwalk.door.subject.id": "alice"}


def test_the_fixtures_partial_record_is_a_read_problem(tmp_path: Path) -> None:
    result, report = observe(tmp_path, FIXTURE)
    assert result.exit_code == 2, result.output
    assert "openai_oi_handoff.json:1: door record: lockwalk.door.subject.type is missing" in (
        result.output
    )
    assert any("lockwalk.door.subject.type is missing" in e for e in report["errors"])


def test_corrected_fixture_match(tmp_path: Path) -> None:
    result, report = observe(tmp_path, fixture_variant(tmp_path, set_=AGENT_RECORD))
    assert result.exit_code == 0, result.output
    assert only_identity(report)["result"] == "MATCH"
    assert only_guard(report) == {"GUARDED": 1}
    assert report["errors"] == []


def test_corrected_fixture_mismatch(tmp_path: Path) -> None:
    result, report = observe(tmp_path, fixture_variant(tmp_path, set_=USER_RECORD))
    assert result.exit_code == 1, result.output
    assert only_identity(report)["result"] == "MISMATCH"
    assert rules(report) == ["fail_on_identity_mismatch"]
    assert "alice" not in result.output


def test_mismatch_can_be_switched_off(tmp_path: Path) -> None:
    path = fixture_variant(tmp_path, set_=USER_RECORD)
    result, report = observe(tmp_path, path, extra="[gate]\nfail_on_identity_mismatch = false\n")
    assert result.exit_code == 0, result.output
    assert only_identity(report)["result"] == "MISMATCH"


def test_corrected_fixture_bypass(tmp_path: Path) -> None:
    changes = {**AGENT_RECORD, "lockwalk.door.decision": "deny", "lockwalk.effect": True}
    result, report = observe(tmp_path, fixture_variant(tmp_path, set_=changes))
    assert result.exit_code == 1, result.output
    assert only_guard(report) == {"BYPASS": 1}
    assert rules(report) == ["bypass"]


def test_bypass_ignores_the_gate_keys(tmp_path: Path) -> None:
    changes = {**AGENT_RECORD, "lockwalk.door.decision": "deny", "lockwalk.effect": True}
    gate = "[gate]\nfail_on_unguarded_call = []\nfail_on_inconclusive_observation = false\n"
    result, report = observe(tmp_path, fixture_variant(tmp_path, set_=changes), extra=gate)
    assert result.exit_code == 1 and rules(report) == ["bypass"]


def test_corrected_fixture_denied_unverified(tmp_path: Path) -> None:
    changes = {**AGENT_RECORD, "lockwalk.door.decision": "deny"}
    result, report = observe(tmp_path, fixture_variant(tmp_path, set_=changes))
    assert result.exit_code == 0, result.output
    assert only_guard(report) == {"DENIED_UNVERIFIED": 1}
    assert "DENIED_UNVERIFIED" in result.output


def test_corrected_fixture_unguarded(tmp_path: Path) -> None:
    copy_without_doors(FIXTURE, tmp_path)
    result, report = observe(tmp_path, tmp_path / FIXTURE.name)
    assert result.exit_code == 1, result.output
    assert only_guard(report) == {"UNGUARDED": 1}
    assert report["identities"] == []
    assert rules(report) == ["fail_on_unguarded_call"]


def test_unguarded_for_a_low_risk_tool_is_shown_not_blocked(tmp_path: Path) -> None:
    copy_without_doors(FIXTURE, tmp_path)
    gate = "[gate]\nfail_on_unguarded_call = ['critical']\n"
    result, report = observe(tmp_path, tmp_path / FIXTURE.name, extra=gate)
    assert result.exit_code == 0, result.output
    assert only_guard(report) == {"UNGUARDED": 1}


def test_a_bad_record_value_is_a_read_problem(tmp_path: Path) -> None:
    path = fixture_variant(tmp_path, set_={**AGENT_RECORD, "lockwalk.door.decision": "maybe"})
    result, report = observe(tmp_path, path)
    assert result.exit_code == 2, result.output
    assert report["guards"] == [] or "GUARDED" not in only_guard(report)  # never "has a record"
    assert any("decision" in e for e in report["errors"])


# ---- hand-built traces: links by time, ambiguity, warnings ----

T0 = 1_794_105_344_000_000_000
MS = 1_000_000


def attr(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    return {"key": key, "value": {"stringValue": value}}


def span(
    sid: int, parent: int | None, name: str, start: int, end: int, **attrs: Any
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "traceId": "ab" * 16,
        "spanId": f"{sid:016x}",
        "name": name,
        "kind": 1,
        "startTimeUnixNano": str(T0 + start * MS),
        "endTimeUnixNano": str(T0 + end * MS),
        "attributes": [attr(k.replace("__", "."), v) for k, v in attrs.items()],
    }
    if parent is not None:
        item["parentSpanId"] = f"{parent:016x}"
    return item


def agent(sid: int, parent: int | None, name: str, start: int, end: int, **attrs: Any) -> dict:
    return span(
        sid,
        parent,
        f"invoke_agent {name}",
        start,
        end,
        gen_ai__operation__name="invoke_agent",
        gen_ai__agent__name=name,
        **attrs,
    )


def tool(sid: int, parent: int | None, name: str, start: int, end: int, **attrs: Any) -> dict:
    return span(
        sid,
        parent,
        f"execute_tool {name}",
        start,
        end,
        gen_ai__operation__name="execute_tool",
        gen_ai__tool__name=name,
        **attrs,
    )


def door(
    sid: int, parent: int | None, start: int, end: int, decision="allow", **extra: Any
) -> dict:
    return span(
        sid,
        parent,
        "lockwalk.door",
        start,
        end,
        lockwalk__door__decision=decision,
        lockwalk__door__subject__type="agent",
        lockwalk__door__subject__id="trade-agent",
        lockwalk__door__action="trade:execute",
        **extra,
    )


def write_trace(tmp_path: Path, spans: list[dict], name: str = "hand.json") -> Path:
    document = {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def base_spans() -> list[dict]:
    return [
        agent(1, None, "supervisor", 0, 100, user__id="alice"),
        agent(2, 1, "trade-agent", 1, 99),
    ]


def test_a_record_beside_the_tool_call_is_linked_by_time(tmp_path: Path) -> None:
    # The LangChain shape: the guard runs in its own span next to the tool span, not below it.
    spans = [*base_spans(), tool(3, 2, "execute_trade", 10, 30), door(4, 2, 12, 13)]
    result, report = observe(tmp_path, write_trace(tmp_path, spans))
    assert result.exit_code == 0, result.output
    assert report["totals"]["records_by_time"] == 1
    assert report["totals"]["records_without_call"] == 0
    assert only_guard(report) == {"GUARDED": 1}
    assert report["guards"][0]["by_time"] == 1
    assert only_identity(report)["result"] == "MATCH"


def test_two_overlapping_calls_make_the_record_ambiguous(tmp_path: Path) -> None:
    spans = [
        *base_spans(),
        tool(3, 2, "execute_trade", 10, 30),
        tool(4, 2, "execute_trade", 15, 35),
        door(5, 2, 20, 21),
    ]
    result, report = observe(tmp_path, write_trace(tmp_path, spans))
    assert result.exit_code == 1, result.output
    assert report["totals"]["records_without_call"] == 1
    assert only_guard(report) == {"INCONCLUSIVE": 2}
    row = only_identity(report)
    # Both candidates are the same agent on the same path, so the identity can still be
    # judged; only the tool is unknown.
    assert (row["result"], row["tool"]) == ("MATCH", None)
    assert rules(report) == ["fail_on_inconclusive_observation"]


def test_ambiguity_can_be_accepted_by_a_gate_key(tmp_path: Path) -> None:
    spans = [
        *base_spans(),
        tool(3, 2, "execute_trade", 10, 30),
        tool(4, 2, "execute_trade", 15, 35),
        door(5, 2, 20, 21),
    ]
    gate = "[gate]\nfail_on_inconclusive_observation = false\n"
    result, report = observe(tmp_path, write_trace(tmp_path, spans), extra=gate)
    assert result.exit_code == 0, result.output
    assert only_guard(report) == {"INCONCLUSIVE": 2}


def test_a_record_that_covers_tool_calls_warns_once(tmp_path: Path) -> None:
    # The record sits on the agent span, which has a tool call below it. It is never
    # time-linked; the effect marker on the same span is not tied to the call either.
    spans = [
        agent(1, None, "supervisor", 0, 100, user__id="alice"),
        agent(
            2,
            1,
            "trade-agent",
            1,
            99,
            lockwalk__door__decision="allow",
            lockwalk__door__subject__type="agent",
            lockwalk__door__subject__id="trade-agent",
            lockwalk__door__action="trade:execute",
            lockwalk__effect=True,
        ),
        tool(3, 2, "execute_trade", 10, 30),
    ]
    result, report = observe(tmp_path, write_trace(tmp_path, spans))
    covers = [w for w in report["warnings"] if "sit on spans that contain tool calls" in w]
    assert covers == [
        "1 door records sit on spans that contain tool calls; "
        "record them with lockwalk.record.record_authz or a span of their own. "
        "1 effect markers sit on spans that contain tool calls, "
        "so they are not tied to a tool call"
    ]
    assert report["totals"]["records_without_call"] == 1
    assert only_guard(report) == {"UNGUARDED": 1}  # a record that covers calls guards none
    assert result.exit_code == 1


def test_the_covers_tools_warning_is_one_line_for_many_records(tmp_path: Path) -> None:
    def covering(sid: int, parent: int, name: str, start: int) -> list[dict]:
        record = {
            "lockwalk__door__decision": "allow",
            "lockwalk__door__subject__type": "agent",
            "lockwalk__door__subject__id": "trade-agent",
            "lockwalk__door__action": "trade:execute",
        }
        return [
            agent(sid, parent, name, start, start + 10, **record),
            tool(sid + 1, sid, "execute_trade", start + 1, start + 5),
        ]

    spans = [
        agent(1, None, "supervisor", 0, 100, user__id="alice"),
        *covering(2, 1, "trade-agent", 1),
        *covering(4, 1, "trade-agent", 20),
    ]
    _, report = observe(tmp_path, write_trace(tmp_path, spans))
    covers = [w for w in report["warnings"] if "sit on spans that contain tool calls" in w]
    assert covers == [
        "2 door records sit on spans that contain tool calls; "
        "record them with lockwalk.record.record_authz or a span of their own"
    ]


def test_two_user_ids_warn_with_a_count_and_never_an_id(tmp_path: Path) -> None:
    spans = [
        agent(1, None, "supervisor", 0, 100, user__id="alice-secret"),
        agent(2, 1, "trade-agent", 1, 99, user__id="bob-secret"),
        tool(3, 2, "execute_trade", 10, 30),
        door(4, 3, 11, 12),
    ]
    result, report = observe(tmp_path, write_trace(tmp_path, spans))
    assert (
        "1 door records saw two different user ids; the nearest one was used"
        in (report["warnings"])
    )
    blob = result.output + json.dumps(report)
    assert "alice-secret" not in blob and "bob-secret" not in blob


def test_a_record_with_no_known_calling_agent_is_counted_in_a_warning(tmp_path: Path) -> None:
    spans = [tool(1, None, "execute_trade", 10, 30), door(2, 1, 11, 12)]  # no agent above
    gate = "[gate]\nfail_on_unknown_component = false\n"
    result, report = observe(tmp_path, write_trace(tmp_path, spans), extra=gate)
    assert report["identities"] == []  # no row without a calling agent
    assert any(
        w.startswith("1 door records have no known calling agent") for w in report["warnings"]
    )
    assert report["totals"]["door_records"] == 1
    assert result.exit_code == 0, result.output


# ---- untested paths ----


def test_a_path_with_a_case_is_tested_and_one_without_is_not(tmp_path: Path) -> None:
    spans = [
        agent(1, None, "supervisor", 0, 100, user__id="alice"),
        tool(2, 1, "delegate_trade", 5, 8),
        agent(3, 1, "trade-agent", 10, 90),
        tool(4, 3, "execute_trade", 20, 30),
        door(5, 4, 21, 22),
    ]
    path = write_trace(tmp_path, spans)
    result, report = observe(tmp_path, path)
    statuses = {(tuple(p["path"]), p["tool"]): p["status"] for p in report["paths"]}
    assert statuses == {
        (("supervisor",), "delegate_trade"): "UNTESTED",
        (("supervisor", "trade-agent"), "execute_trade"): "TESTED",
    }
    # delegate_trade is low risk: not blocking by default, so the run passes.
    assert result.exit_code == 0, result.output
    gate = "[gate]\nfail_on_untested_path = ['low', 'high']\n"
    blocked, report = observe(tmp_path, path, extra=gate)
    assert blocked.exit_code == 1
    assert rules(report) == ["fail_on_untested_path"]
    assert "Real paths no case tests (UNTESTED)" in blocked.output


def test_the_same_tool_on_another_path_is_tested_other_path(tmp_path: Path) -> None:
    spans = [
        agent(1, None, "trade-agent", 0, 100, user__id="alice"),  # entered directly
        tool(2, 1, "execute_trade", 20, 30),
        door(3, 2, 21, 22),
    ]
    gate = "[gate]\nfail_on_off_map_route = false\nfail_on_untested_path = ['high']\n"
    result, report = observe(tmp_path, write_trace(tmp_path, spans), extra=gate)
    assert [p["status"] for p in report["paths"]] == ["TESTED_OTHER_PATH"]
    assert result.exit_code == 0, result.output  # another path is shown, not blocked


# ---- waivers, summary, side by side, inspect ----


TODAY = date(2026, 11, 8)


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(waivers, "today", lambda: TODAY)


def waivers_file(tmp_path: Path, match: str, days: int = 30) -> Path:
    expires = waivers.today() + timedelta(days=days)
    path = tmp_path / "waivers-observe.yaml"
    path.write_text(
        "schema_version: '1'\n"
        "waivers:\n"
        "  - id: W-1\n"
        f"    match: {match}\n"
        "    reason: tracked in a ticket\n"
        "    owner: owner@example.com\n"
        f"    expires: {expires.isoformat()}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def unguarded(tmp_path: Path) -> Path:
    folder = tmp_path / "plain"
    folder.mkdir()
    return copy_without_doors(FIXTURE, folder)


def test_a_waiver_makes_the_run_pass(tmp_path: Path, unguarded: Path) -> None:
    waivers = waivers_file(tmp_path, "{unguarded: {agent: trade-agent, tool: execute_trade}}")
    result, report = observe(tmp_path, unguarded, args=("--waivers", str(waivers)))
    assert result.exit_code == 0, result.output
    assert report["gate"]["violations"] == []
    assert report["gate"]["waived"][0]["waiver_id"] == "W-1"
    assert report["guards"][0]["waived_by"] == "W-1"
    assert "[waived: W-1]" in result.output


def test_a_waiver_for_a_coverage_finding_is_silent_here(tmp_path: Path, unguarded: Path) -> None:
    waivers = waivers_file(tmp_path, "{rule: RULE-001}")
    result, report = observe(tmp_path, unguarded, args=("--waivers", str(waivers)))
    assert result.exit_code == 1  # the unguarded call still blocks
    assert any(row["note"] == COVERAGE_OR_TEST_ONLY_NOTE for row in report["waivers"])


def test_a_waiver_file_with_a_wrong_date_is_a_configuration_error(
    tmp_path: Path, unguarded: Path
) -> None:
    waivers = waivers_file(
        tmp_path, "{unguarded: {agent: trade-agent, tool: execute_trade}}", days=400
    )
    result, report = observe(tmp_path, unguarded, args=("--waivers", str(waivers)))
    assert result.exit_code == 2
    assert not report  # no traces were read and no report was written


def test_summary_shows_the_blocking_finding(tmp_path: Path, unguarded: Path) -> None:
    result, _ = observe(tmp_path, unguarded, args=("--summary",))
    assert result.exit_code == 1
    lines = result.output.splitlines()
    assert "Blocking (1):" in lines
    assert "  - UNGUARDED: trade-agent / execute_trade" in lines
    assert not any(line.startswith("Sources:") for line in lines)


def write_test_report(tmp_path: Path, make_report, result=IdentityResult.MATCH) -> None:
    check = IdentityCheckRow(
        case_id="CASE-001",
        path=("supervisor", "trade-agent"),
        tool="execute_trade",
        result=result,
        observations=(
            IdentityObservation(
                mode="direct",
                expected={"type": "agent"},
                observed=({"type": "agent"},),
                result=result,
            ),
        ),
    )
    report = make_report().model_copy(update={"mode": "test", "identity_checks": (check,)})
    stamp = {"generated_at": datetime(2026, 1, 1, tzinfo=UTC), "version": "0.1.0"}
    write_report(report, tmp_path, **stamp)


def test_the_last_test_run_is_shown_beside_the_real_identity(tmp_path: Path, make_report) -> None:
    write_test_report(tmp_path, make_report)  # tmp_path/coverage.json
    path = fixture_variant(tmp_path, set_=USER_RECORD)
    result, report = observe(tmp_path, path, extra='[observe]\ntest_report = "coverage.json"\n')
    row = only_identity(report)
    assert row["result"] == "MISMATCH"
    assert row["test_results"] == ["CASE-001 direct: MATCH"]
    assert TEST_DIFFERS_NOTE in row["notes"]
    assert "CASE-001 direct: MATCH" in result.output


def test_a_missing_test_report_is_silent_and_a_bad_one_warns(tmp_path: Path) -> None:
    path = fixture_variant(tmp_path, set_=AGENT_RECORD)
    _, report = observe(tmp_path, path, extra='[observe]\ntest_report = "coverage.json"\n')
    assert not any("test report" in w for w in report["warnings"])
    (tmp_path / "coverage.json").write_text("{not json", encoding="utf-8")
    _, report = observe(tmp_path, path, extra='[observe]\ntest_report = "coverage.json"\n')
    assert any(w.startswith("the test report cannot be used") for w in report["warnings"])


def test_inspect_trace_shows_the_door_lines(tmp_path: Path) -> None:
    path = fixture_variant(tmp_path, set_={**AGENT_RECORD, "lockwalk.effect": True})
    config = make_config(tmp_path)
    trace_id = "bd43c2c928e8d4dc245da1b7f9e9b7b7"
    result = runner.invoke(
        app, ["inspect", "--trace", trace_id, "--config", str(config), "--traces", str(path)]
    )
    assert result.exit_code == 0, result.output
    assert "door: allow for agent:trade-agent (linked by ancestry)" in result.output
    assert "effect marker (linked by ancestry)" in result.output
    assert "alice" not in result.output


def test_inspect_case_shows_real_traffic_from_observe_json(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    out = tmp_path / "out"
    covered = runner.invoke(app, ["coverage", "--config", str(config), "--output-dir", str(out)])
    assert (out / "coverage.json").exists(), covered.output
    path = fixture_variant(tmp_path, set_=AGENT_RECORD)
    seen = runner.invoke(
        app, ["observe", "--config", str(config), "--output-dir", str(out), "--traces", str(path)]
    )
    assert seen.exit_code == 0, seen.output
    result = runner.invoke(
        app, ["inspect", "--case", "CASE-001", "--config", str(config), "--output-dir", str(out)]
    )
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("  real traffic (observe"))
    traffic = lines[start + 1 : start + 4]
    assert traffic == [
        "    identity (agent): MATCH 1, expected agent:trade-agent, saw agent:trade-agent",
        "    door: GUARDED 1",
        "    path: TESTED 1",
    ]


def test_inspect_case_without_observe_json_has_no_traffic_section(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    out = tmp_path / "out"
    runner.invoke(app, ["coverage", "--config", str(config), "--output-dir", str(out)])
    result = runner.invoke(
        app, ["inspect", "--case", "CASE-001", "--config", str(config), "--output-dir", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "real traffic" not in result.output


# ---- hygiene ----


def test_no_resource_id_or_user_id_in_any_file(provider, tmp_path: Path) -> None:
    run_app(provider, subject=USER_SUBJECT)
    result, report = observe(tmp_path, write_sdk_trace(tmp_path, provider))
    out = tmp_path / "out"
    text = result.output + (out / OBSERVE_FILE_NAME).read_text(encoding="utf-8")
    assert not re.search(r"alice|" + ORDER_ID, text)
    assert report["errors"] == []


def test_one_clock_for_loading_and_applying(tmp_path: Path, unguarded: Path, monkeypatch) -> None:
    waivers_path = waivers_file(tmp_path, "{unguarded: {agent: trade-agent, tool: execute_trade}}")
    calls: list[int] = []

    def clock() -> date:
        calls.append(1)
        return TODAY

    monkeypatch.setattr(waivers, "today", clock)
    result, _ = observe(tmp_path, unguarded, args=("--waivers", str(waivers_path)))
    assert result.exit_code == 0, result.output
    assert len(calls) == 1  # read once and used for both load and apply


def test_a_waiver_after_its_date_is_expired(tmp_path: Path, unguarded: Path, monkeypatch) -> None:
    waivers_path = waivers_file(tmp_path, "{unguarded: {agent: trade-agent, tool: execute_trade}}")
    # Loading uses the same date, so the file is read with "today" = TODAY ...
    real = {"now": TODAY}
    monkeypatch.setattr(waivers, "today", lambda: real["now"])
    ok, _ = observe(tmp_path, unguarded, args=("--waivers", str(waivers_path)))
    assert ok.exit_code == 0
    # ... and a later day expires it (30 days + 1, still inside the 90 day load limit).
    real["now"] = TODAY + timedelta(days=31)
    late, report = observe(tmp_path, unguarded, args=("--waivers", str(waivers_path)))
    assert late.exit_code == 1, late.output
    assert any(row["status"] == "expired" for row in report["waivers"])


def test_inspect_trace_ignores_a_bad_waivers_file(tmp_path: Path) -> None:
    path = fixture_variant(tmp_path, set_=AGENT_RECORD)
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: [valid", encoding="utf-8")
    config = make_config(tmp_path, f'waivers = "{bad.as_posix()}"' + chr(10))
    result = runner.invoke(
        app,
        [
            "inspect",
            "--trace",
            "bd43c2c928e8d4dc245da1b7f9e9b7b7",
            "--config",
            str(config),
            "--traces",
            str(path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "execute_trade" in result.output


def test_calls_with_record_counts_calls_not_records(tmp_path: Path) -> None:
    # Two records on one tool call and none on the second: one call has a record.
    spans = [
        *base_spans(),
        tool(3, 2, "execute_trade", 10, 30),
        door(4, 3, 12, 13),
        door(5, 3, 14, 15),
        tool(6, 2, "execute_trade", 40, 60),
    ]
    result, report = observe(tmp_path, write_trace(tmp_path, spans))
    assert result.exit_code in (0, 1), result.output
    totals = report["totals"]
    assert (totals["tool_calls"], totals["door_records"]) == (2, 2)
    assert totals["calls_with_record"] == 1
    assert totals["records_without_call"] == 0
    assert (
        "Door records: 2 (1 tool call(s) have one; 0 not tied to a tool call, 0 linked by time)"
        in (result.output)
    )


def test_raw_spans_are_dropped_after_recognition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lockwalk.observe import pipeline

    seen: list[tuple[int, int]] = []
    real = pipeline.observe_totals

    def spy(read, views, spans, counts=None):
        seen.append((len(read.raw), len(spans)))
        return real(read, views, spans, counts)

    monkeypatch.setattr(pipeline, "observe_totals", spy)
    spans = [*base_spans(), tool(3, 2, "execute_trade", 10, 30), door(4, 3, 12, 13)]
    result, report = observe(tmp_path, write_trace(tmp_path, spans))
    assert result.exit_code in (0, 1), result.output
    assert seen and seen[0][0] == 0 and seen[0][1] > 0
    assert report["totals"]["spans"] == seen[0][1]
