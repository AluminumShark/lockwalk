import json
import subprocess
import sys
from typing import Any

import pytest
from observe_helpers import loose_raw_spans_from_document, otlp_json_from_sdk_spans
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from lockwalk import record
from lockwalk.observe import keys
from lockwalk.observe.door import MAX_ACT_BYTES, MAX_DOOR_TEXT

SUBJECT = {"type": "user", "id": "alice"}
CHAIN_SUBJECT = {
    "type": "agent",
    "id": "a1",
    "properties": {
        "role": "admin",
        "act": {"type": "agent", "id": "a2", "act": {"type": "user", "id": "alice", "x": 1}},
    },
}


@pytest.fixture
def exporter(monkeypatch):
    # A private provider; the global one is never set (the API allows that only once).
    # tests/crewai_env sets OTEL_SDK_DISABLED=true at collection time, which would make this
    # provider hand out no-op spans in a full run.
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    provider = TracerProvider()
    mem = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(mem))
    monkeypatch.setattr(trace, "get_tracer", lambda name, *a, **k: provider.get_tracer(name))
    return mem


def test_text_limit_matches_observe():
    assert record._MAX_TEXT == MAX_DOOR_TEXT


def test_act_limit_matches_observe():
    assert record._MAX_ACT_JSON == MAX_ACT_BYTES


def _long_chain(count: int, size: int) -> dict[str, Any]:
    act = None
    for _ in range(count):
        act = {"type": "t" * size, "id": "i" * size, "act": act}
    assert act is not None
    return act


@pytest.mark.parametrize(
    "field",
    ["subject.type", "subject.id", "action", "resource.type", "tool_call_id", "act.type", "act.id"],
)
def test_length_limit_per_field(field, exporter):
    def kwargs(size: int) -> dict[str, Any]:
        text = "x" * size
        args: dict[str, Any] = {
            "subject": dict[str, Any](SUBJECT),
            "action": "a",
            "decision": "allow",
        }
        if field == "subject.type":
            args["subject"]["type"] = text
        elif field == "subject.id":
            args["subject"]["id"] = text
        elif field == "action":
            args["action"] = text
        elif field == "resource.type":
            args["resource"] = {"type": text}
        elif field == "tool_call_id":
            args["tool_call_id"] = text
        else:
            args["subject"]["act"] = {"type": "u", "id": "v", field.split(".")[1]: text}
        return args

    record.record_authz(**kwargs(512))
    assert len(exporter.get_finished_spans()) == 1
    with pytest.raises(ValueError) as caught:
        record.record_authz(**kwargs(513))
    expected = "act link." + field[4:] if field.startswith("act.") else field
    assert expected in str(caught.value)
    assert "xxxx" not in str(caught.value)


def test_act_json_over_limit_raises(exporter):
    subject = {**SUBJECT, "act": _long_chain(64, 512)}
    with pytest.raises(ValueError, match="act chain"):
        record.record_authz(subject=subject, action="a", decision="allow")
    assert not exporter.get_finished_spans()
    # A long but allowed chain still passes.
    record.record_authz(
        subject={**SUBJECT, "act": _long_chain(64, 100)}, action="a", decision="allow"
    )
    assert len(exporter.get_finished_spans()) == 1


def test_constants_match_keys():
    assert record._DECISION == keys.DOOR_DECISION
    assert record._SUBJECT_TYPE == keys.DOOR_SUBJECT_TYPE
    assert record._SUBJECT_ID == keys.DOOR_SUBJECT_ID
    assert record._ACT == keys.DOOR_ACT
    assert record._ACTION == keys.DOOR_ACTION
    assert record._RESOURCE_TYPE == keys.DOOR_RESOURCE_TYPE
    assert record._TOOL_CALL_ID == keys.DOOR_TOOL_CALL_ID
    assert record._EFFECT == keys.EFFECT


def test_import_loads_nothing_else(tmp_path):
    code = (
        "import sys\n"
        "before = set(sys.modules)\n"
        "import lockwalk.record\n"
        "new = set(sys.modules) - before\n"
        "bad = [m for m in new if m.startswith(('pydantic', 'typer', 'opentelemetry')) "
        "or (m.startswith('lockwalk') and m not in ('lockwalk', 'lockwalk.record'))]\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=tmp_path
    )
    assert done.returncode == 0, done.stderr


def test_authz_minimal(exporter):
    record.record_authz(subject=SUBJECT, action="trade:execute", decision="allow")
    (span,) = exporter.get_finished_spans()
    assert span.name == "lockwalk.door"
    assert dict(span.attributes) == {
        "lockwalk.door.decision": "allow",
        "lockwalk.door.subject.type": "user",
        "lockwalk.door.subject.id": "alice",
        "lockwalk.door.action": "trade:execute",
    }


def test_authz_full_with_act_chain(exporter):
    record.record_authz(
        subject=CHAIN_SUBJECT,
        action="a:b",
        decision="deny",
        resource={"type": "order", "id": "o-1", "properties": {"x": 1}},
        tool_call_id="call_1",
    )
    (span,) = exporter.get_finished_spans()
    attrs = dict(span.attributes)
    assert attrs["lockwalk.door.act"] == (
        '{"type":"agent","id":"a2","act":{"type":"user","id":"alice"}}'
    )
    assert set(attrs) == {
        "lockwalk.door.decision",
        "lockwalk.door.subject.type",
        "lockwalk.door.subject.id",
        "lockwalk.door.act",
        "lockwalk.door.action",
        "lockwalk.door.resource.type",
        "lockwalk.door.tool_call_id",
    }
    assert attrs["lockwalk.door.resource.type"] == "order"
    assert attrs["lockwalk.door.tool_call_id"] == "call_1"
    text = json.dumps(attrs)
    assert "admin" not in text and "o-1" not in text


def test_direct_act(exporter):
    subject = {"type": "agent", "id": "a1", "act": {"type": "user", "id": "u"}}
    record.record_authz(subject=subject, action="a", decision="error")
    (span,) = exporter.get_finished_spans()
    assert span.attributes["lockwalk.door.act"] == '{"type":"user","id":"u"}'


def _chain_of(count: int) -> Any:
    act = None
    for i in range(count):
        act = {"type": "agent", "id": f"a{i}", "act": act}
    return act


def test_act_of_64_links_is_kept(exporter):
    record.record_authz(subject={**SUBJECT, "act": _chain_of(64)}, action="a", decision="allow")
    (span,) = exporter.get_finished_spans()
    node, depth = json.loads(span.attributes["lockwalk.door.act"]), 0
    while node:
        depth += 1
        node = node.get("act")
    assert depth == 64


def test_act_over_64_links_raises(exporter):
    with pytest.raises(ValueError, match="act has more than 64 links"):
        record.record_authz(subject={**SUBJECT, "act": _chain_of(65)}, action="a", decision="allow")
    assert exporter.get_finished_spans() == ()


def test_a_cyclic_act_raises(exporter):
    loop: dict[str, Any] = {"type": "agent", "id": "a"}
    loop["act"] = loop
    with pytest.raises(ValueError, match="act has more than 64 links"):
        record.record_authz(subject={**SUBJECT, "act": loop}, action="a", decision="allow")


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"decision": "maybe"}, ValueError),
        ({"subject": "alice"}, TypeError),
        ({"subject": {"type": "user"}}, TypeError),
        ({"subject": {"type": "", "id": "x"}}, ValueError),
        ({"subject": {"type": "user", "id": 5}}, TypeError),
        ({"subject": {"type": "user", "id": "x", "act": {"type": "a"}}}, TypeError),
        ({"action": ""}, ValueError),
        ({"action": 3}, TypeError),
        ({"resource": "order"}, TypeError),
        ({"resource": {"type": 3}}, TypeError),
        ({"tool_call_id": 3}, TypeError),
        ({"tool_call_id": ""}, ValueError),
        ({"resource": {"type": ""}}, ValueError),
        ({"subject": {"type": "user", "id": "x", "act": "x"}}, TypeError),
        ({"subject": {"type": "user", "id": "x", "act": 5}}, TypeError),
    ],
)
def test_validation(kwargs, error):
    args: dict[str, Any] = {"subject": SUBJECT, "action": "a", "decision": "allow", **kwargs}
    with pytest.raises(error):
        record.record_authz(**args)


def test_effect(exporter):
    record.record_effect()
    (span,) = exporter.get_finished_spans()
    assert span.name == "lockwalk.effect"
    assert dict(span.attributes) == {"lockwalk.effect": True}


def test_child_of_current_span(exporter):
    tracer = trace.get_tracer("t")
    with tracer.start_as_current_span("tool"):
        record.record_authz(subject=SUBJECT, action="a", decision="allow")
        record.record_effect()
    spans = {s.name: s for s in exporter.get_finished_spans()}
    tool_id = spans["tool"].context.span_id
    assert spans["lockwalk.door"].parent.span_id == tool_id
    assert spans["lockwalk.effect"].parent.span_id == tool_id


def test_noop_with_default_provider():
    record.record_authz(subject=SUBJECT, action="a", decision="allow")
    record.record_effect()


def test_noop_without_opentelemetry(monkeypatch):
    monkeypatch.setattr(record, "_otel_missing", False)  # restored after the test
    monkeypatch.setitem(sys.modules, "opentelemetry", None)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", None)
    record.record_authz(subject=SUBJECT, action="a", decision="allow")
    record.record_effect()
    with pytest.raises(ValueError):
        record.record_authz(subject=SUBJECT, action="a", decision="nope")


def test_round_trip_through_otlp_json(exporter):
    record.record_authz(subject=CHAIN_SUBJECT, action="a:b", decision="allow", tool_call_id="c1")
    record.record_effect()
    document = otlp_json_from_sdk_spans(exporter.get_finished_spans())
    spans = {s.name: s for s in loose_raw_spans_from_document(json.loads(json.dumps(document)))}
    door = spans["lockwalk.door"]
    assert door.attributes["lockwalk.door.decision"] == "allow"
    assert door.attributes["lockwalk.door.subject.id"] == "a1"
    act = door.attributes["lockwalk.door.act"]
    assert isinstance(act, str) and json.loads(act)["id"] == "a2"
    assert door.attributes["lockwalk.door.tool_call_id"] == "c1"
    assert door.start_ns is not None and door.end_ns is not None
    assert door.end_ns >= door.start_ns
    assert spans["lockwalk.effect"].attributes["lockwalk.effect"] is True


@pytest.mark.parametrize(
    "field",
    ["subject.type", "subject.id", "action", "resource.type", "tool_call_id", "act.id"],
)
def test_lone_surrogate_message_has_no_value(field):
    bad = "secret" + chr(0xD800) + "tail"
    subject: dict[str, Any] = {"type": "user", "id": "x"}
    args: dict[str, Any] = {"subject": subject, "action": "a", "decision": "allow"}
    if field == "subject.type":
        args["subject"]["type"] = bad
    elif field == "subject.id":
        args["subject"]["id"] = bad
    elif field == "action":
        args["action"] = bad
    elif field == "resource.type":
        args["resource"] = {"type": bad}
    elif field == "tool_call_id":
        args["tool_call_id"] = bad
    else:
        args["subject"]["act"] = {"type": "u", "id": bad}
    with pytest.raises(ValueError) as caught:
        record.record_authz(**args)
    message = str(caught.value)
    assert chr(0xD800) not in message and "secret" not in message and "tail" not in message
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


def test_act_limit_counts_utf8_bytes(exporter):
    # 64 links of 512 four-byte characters: about 34 thousand characters, 132 thousand bytes.
    emoji = chr(0x1F600)
    chain: dict[str, Any] = {"type": "t", "id": emoji * 512}
    node = chain
    for _ in range(63):
        node["act"] = {"type": "t", "id": emoji * 512}
        node = node["act"]
    with pytest.raises(ValueError, match="act chain"):
        record.record_authz(subject={**SUBJECT, "act": chain}, action="a", decision="allow")
    assert not exporter.get_finished_spans()


def test_missing_otel_is_remembered(monkeypatch):
    monkeypatch.setattr(record, "_otel_missing", False)
    monkeypatch.setitem(sys.modules, "opentelemetry", None)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", None)
    record.record_effect()
    assert record._otel_missing is True
