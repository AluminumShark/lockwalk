"""Door records, effect markers and users read from span attributes."""

import json
from dataclasses import replace

import pytest
from observe_helpers import loose_raw_spans
from test_observe_conventions import raw

from lockwalk.config import ObserveConfig
from lockwalk.observe.conventions import recognize
from lockwalk.observe.door import DoorKeys, DoorRecord, read_door, read_effect, read_user
from lockwalk.observe.spans import ScalarValue

KEYS = DoorKeys.from_config(ObserveConfig())
SECRET = "s3cr3t-value-XYZ"
BASE: dict[str, ScalarValue] = {
    "lockwalk.door.decision": "allow",
    "lockwalk.door.subject.type": "user",
    "lockwalk.door.subject.id": "u-1",
    "lockwalk.door.action": "trade:execute",
}


def door(**changes: object) -> DoorRecord | str | None:
    attributes = {**BASE, **changes}
    return read_door({k: v for k, v in attributes.items() if v is not None}, KEYS)


def act(*ids: str) -> str:
    value: dict[str, object] | None = None
    for item in reversed(ids):
        value = {"type": "agent", "id": item, **({"act": value} if value else {})}
    return json.dumps(value)


def test_no_door_key_is_none() -> None:
    assert read_door({}, KEYS) is None
    assert read_door({"gen_ai.tool.name": "x"}, KEYS) is None


def test_full_record() -> None:
    record = door(
        **{
            "lockwalk.door.resource.type": "account",
            "lockwalk.door.tool_call_id": "call-1",
            "lockwalk.door.act": act("a", "b"),
        }
    )
    assert record == DoorRecord(
        "allow",
        "user",
        "u-1",
        (("agent", "a"), ("agent", "b")),
        "trade:execute",
        "account",
        "call-1",
    )


def test_minimal_record_and_decisions() -> None:
    record = door()
    assert isinstance(record, DoorRecord) and record.act == () and record.resource_type is None
    for decision in ("deny", "error"):
        assert isinstance(door(**{"lockwalk.door.decision": decision}), DoorRecord)


@pytest.mark.parametrize("key", list(BASE))
def test_each_required_key_is_required(key: str) -> None:
    attributes = {k: v for k, v in BASE.items() if k != key}
    attributes["lockwalk.door.resource.type"] = "account"
    message = read_door(attributes, KEYS)
    assert isinstance(message, str) and key in message and "missing" in message


@pytest.mark.parametrize("key", list(BASE))
@pytest.mark.parametrize("bad", ["", 5, True, "x" * 513])
def test_required_values_are_checked(key: str, bad: object) -> None:
    message = door(**{key: bad})
    assert isinstance(message, str) and key in message


def test_wrong_decision_names_the_key_not_the_value() -> None:
    message = door(**{"lockwalk.door.decision": SECRET})
    assert isinstance(message, str) and "lockwalk.door.decision" in message
    assert SECRET not in message


@pytest.mark.parametrize("key", ["lockwalk.door.resource.type", "lockwalk.door.tool_call_id"])
def test_optional_strings_are_checked(key: str) -> None:
    for bad in ("", 3, "y" * 513):
        message = door(**{key: bad})
        assert isinstance(message, str) and key in message
    assert isinstance(door(**{key: "y" * 512}), DoorRecord)


def test_long_strings_at_the_limit_pass() -> None:
    assert isinstance(door(**{"lockwalk.door.subject.id": "x" * 512}), DoorRecord)


def test_act_malformed_variants() -> None:
    key = "lockwalk.door.act"
    nested = json.dumps({"type": "a", "id": "b", "act": {"type": "c", "id": SECRET, "act": 7}})
    cases: list[object] = [
        "not json",
        "[]",
        "5",
        "null",
        '"x"',
        "{}",
        '{"type": "a"}',
        '{"type": "a", "id": ""}',
        json.dumps({"type": "a", "id": 3}),
        json.dumps({"type": "a", "id": "z" * 513}),
        '{"type": "a", "id": "b", "type": "c"}',
        '{"type": "a", "id": "b", "act": {"type": "c", "id": "d", "id": "e"}}',
        nested,
        act(*["x"] * 65),
        "[" * 100_000,
        "x" * (64 * 1024 + 1),
        7,
        True,
    ]
    for bad in cases:
        message = door(**{key: bad})
        assert isinstance(message, str), bad
        assert key in message and SECRET not in message


def test_act_depth_limit() -> None:
    ok = door(**{"lockwalk.door.act": act(*["x"] * 64)})
    assert isinstance(ok, DoorRecord) and len(ok.act) == 64
    assert isinstance(door(**{"lockwalk.door.act": act(*["x"] * 65)}), str)


def test_repr_hides_the_subject_id() -> None:
    assert SECRET not in repr(door(**{"lockwalk.door.subject.id": SECRET}))


def test_mapping_replaces_the_default_key() -> None:
    config = ObserveConfig(attributes={"lockwalk.door.decision": "authz.result"})
    keys = DoorKeys.from_config(config)
    attributes = {**BASE, "authz.result": "deny"}
    record = read_door(attributes, keys)
    assert isinstance(record, DoorRecord) and record.decision == "deny"
    del attributes["authz.result"]
    message = read_door(attributes, keys)
    assert isinstance(message, str) and "authz.result" in message


def test_effect_values() -> None:
    assert read_effect({}, KEYS) is False
    assert read_effect({"lockwalk.effect": False}, KEYS) is False
    assert read_effect({"lockwalk.effect": True}, KEYS) is True
    for bad in ("true", 1, 0, 1.0, ""):
        message = read_effect({"lockwalk.effect": bad}, KEYS)
        assert isinstance(message, str) and "lockwalk.effect" in message


def test_user_fallback_and_mapping() -> None:
    assert read_user({}, KEYS) is None
    assert read_user({"enduser.id": "e"}, KEYS) == "e"
    assert read_user({"user.id": "u", "enduser.id": "e"}, KEYS) == "u"
    assert read_user({"user.id": "", "enduser.id": "e"}, KEYS) == "e"
    assert read_user({"user.id": 5, "enduser.id": "e"}, KEYS) == "e"
    assert read_user({"user.id": 5}, KEYS) is None
    mapped = DoorKeys.from_config(ObserveConfig(attributes={"user.id": "app.user"}))
    assert read_user({"app.user": "m", "user.id": "u"}, mapped) == "m"
    assert read_user({"user.id": "u"}, mapped) is None
    assert read_user({"user.id": "u", "enduser.id": "e"}, mapped) == "e"


def test_openai_handoff_fixture_has_a_partial_record() -> None:
    result = recognize(
        loose_raw_spans("openai_oi_handoff.json"),
        rules=[],
        agent_names=frozenset(),
        door_keys=KEYS,
    )
    assert len(result.problems) == 1
    problem = result.problems[0]
    assert "lockwalk.door.subject.type is missing" in problem.message
    assert problem.where
    assert all(s.door is None for s in result.spans)
    assert any(s.kind == "tool" for s in result.spans)


def test_corrected_fixture_gives_a_full_record() -> None:
    fixed = []
    for span in loose_raw_spans("openai_oi_handoff.json"):
        if "lockwalk.door.decision" in span.attributes:
            attributes = {
                **span.attributes,
                "lockwalk.door.subject.type": "user",
                "lockwalk.door.subject.id": "u-1",
            }
            span = replace(span, attributes=attributes)
        fixed.append(span)
    result = recognize(fixed, rules=[], agent_names=frozenset(), door_keys=KEYS)
    assert result.problems == []
    (record,) = [s.door for s in result.spans if s.door is not None]
    assert record.decision == "allow" and record.action == "trade:execute"


def test_recognize_adds_fields_and_problems_keep_the_span() -> None:
    tool = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "execute_trade"}
    good = raw(
        "t",
        {
            **tool,
            "gen_ai.tool.call.id": "call-9",
            "lockwalk.effect": True,
            "enduser.id": "u-1",
            **BASE,
        },
        span_id="0000000000000001",
    )
    bad = raw(
        "t",
        {**tool, "lockwalk.door.decision": SECRET, "lockwalk.effect": SECRET},
        span_id="0000000000000002",
    )
    result = recognize([good, bad], rules=[], agent_names=frozenset(), door_keys=KEYS)
    first, second = result.spans
    assert first.tool_call_id == "call-9" and first.effect and first.user_id == "u-1"
    assert first.door is not None and first.door.subject_id == "u-1"
    assert second.kind == "tool" and second.door is None and not second.effect
    assert len(result.problems) == 2
    assert all(p.where == "t.json:3" and SECRET not in p.message for p in result.problems)


def test_tool_call_id_only_for_tool_spans() -> None:
    other = raw("x", {"gen_ai.tool.call.id": "c"})
    result = recognize([other], rules=[], agent_names=frozenset(), door_keys=KEYS)
    assert result.spans[0].tool_call_id is None


def test_top_level_null_act_is_a_problem_but_nested_null_ends_the_chain() -> None:
    message = door(**{"lockwalk.door.act": "null"})
    assert isinstance(message, str) and "lockwalk.door.act" in message
    assert "must be an object" in message
    record = door(**{"lockwalk.door.act": '{"type": "a", "id": "b", "act": null}'})
    assert isinstance(record, DoorRecord) and record.act == (("a", "b"),)


def test_user_ids_are_bounded_and_malformed_ones_fall_back() -> None:
    assert read_user({"user.id": "x" * 513, "enduser.id": "e"}, KEYS) == "e"
    assert read_user({"user.id": "x" * 513}, KEYS) is None
    assert read_user({"user.id": "x" * 512}, KEYS) == "x" * 512
    assert read_user({"user.id": "", "enduser.id": "y" * 600}, KEYS) is None
    mapped = DoorKeys.from_config(ObserveConfig(attributes={"user.id": "app.user"}))
    assert read_user({"app.user": "z" * 513, "enduser.id": "e"}, mapped) == "e"


def test_malformed_tool_call_id_is_absent() -> None:
    tool: dict[str, ScalarValue] = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "t",
    }
    for bad in ("", "c" * 513, 5, True):
        result = recognize(
            [raw("t", {**tool, "gen_ai.tool.call.id": bad})],
            rules=[],
            agent_names=frozenset(),
            door_keys=KEYS,
        )
        assert result.spans[0].kind == "tool" and result.spans[0].tool_call_id is None
        assert result.problems == []
    good = recognize(
        [raw("t", {**tool, "gen_ai.tool.call.id": "c" * 512})],
        rules=[],
        agent_names=frozenset(),
        door_keys=KEYS,
    )
    assert good.spans[0].tool_call_id == "c" * 512
