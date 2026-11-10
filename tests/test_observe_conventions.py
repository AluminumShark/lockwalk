"""Recognition of agent, tool and handoff spans."""

import time
from collections import Counter
from collections.abc import Iterable, Sequence

from observe_helpers import loose_raw_spans

from lockwalk.config import ObserveConfig, ObserveRule
from lockwalk.observe.conventions import recognize
from lockwalk.observe.door import DoorKeys, decision_only
from lockwalk.observe.spans import RawSpan, ScalarValue, Span

NAMES = frozenset({"supervisor", "trade-agent"})
KEYS = DoorKeys.from_config(ObserveConfig())


def recognize_spans(
    raw_spans: Iterable[RawSpan], *, rules: Sequence[ObserveRule], agent_names: frozenset[str]
) -> list[Span]:
    result = recognize(raw_spans, rules=rules, agent_names=agent_names, door_keys=KEYS)
    return result.spans


def raw(
    name: str = "s",
    attributes: dict[str, ScalarValue] | None = None,
    *,
    span_id: str = "0000000000000001",
) -> RawSpan:
    return RawSpan(
        trace_id="a" * 32,
        span_id=span_id,
        parent_id="0000000000000009",
        name=name,
        start_ns=5,
        end_ns=9,
        attributes=attributes or {},
        where="t.json:3",
    )


def one(
    span: RawSpan,
    rules: list[ObserveRule] | None = None,
    names: frozenset[str] = frozenset(),
) -> Span:
    (out,) = recognize_spans([span], rules=rules or [], agent_names=names)
    return out


def seen(
    fixture: str, rules: list[ObserveRule] | None = None, names: frozenset[str] = NAMES
) -> Counter[tuple[str, str | None]]:
    spans = recognize_spans(loose_raw_spans(fixture), rules=rules or [], agent_names=names)
    return Counter((s.kind, s.name) for s in spans if s.kind != "other")


def rule(**kwargs: object) -> ObserveRule:
    return ObserveRule.model_validate(kwargs)


def test_pydantic_delegation() -> None:
    assert seen("pydantic_delegation.json") == Counter(
        {
            ("agent", "supervisor"): 1,
            ("agent", "trade-agent"): 1,
            ("tool", "delegate_trade"): 1,
            ("tool", "execute_trade"): 1,
        }
    )


def test_openai_oi_handoff() -> None:
    spans = recognize_spans(
        loose_raw_spans("openai_oi_handoff.json"), rules=[], agent_names=frozenset()
    )
    assert Counter((s.kind, s.name) for s in spans if s.kind != "other") == Counter(
        {("agent", "supervisor"): 1, ("agent", "trade-agent"): 1, ("tool", "execute_trade"): 1}
    )
    callers = {s.name: s.caller for s in spans if s.kind == "agent"}
    assert callers == {"supervisor": None, "trade-agent": "supervisor"}
    # the nameless handoff TOOL and the nameless AGENT 'Agent workflow'
    assert sum(s.unnamed_marker for s in spans if s.kind == "other") == 2
    assert sum(1 for s in spans if s.kind == "other") == 8


def test_openai_oi_astool_wrapper_is_a_tool() -> None:
    assert seen("openai_oi_astool.json", names=frozenset()) == Counter(
        {
            ("agent", "supervisor"): 1,
            ("agent", "trade-agent"): 1,
            ("tool", "ask_trade_agent"): 1,
            ("tool", "execute_trade"): 1,
        }
    )


def test_langgraph_oi_sub_by_name() -> None:
    spans = recognize_spans(loose_raw_spans("langgraph_oi_sub.json"), rules=[], agent_names=NAMES)
    assert Counter((s.kind, s.name) for s in spans if s.kind != "other") == Counter(
        {("agent", "supervisor"): 1, ("agent", "trade-agent"): 2, ("tool", "execute_trade"): 1}
    )
    # the two inner ReAct 'agent' nodes: AGENT marker without a name
    assert sum(s.unnamed_marker for s in spans) == 2


def test_langgraph_oi_sub_without_names_finds_only_the_tool() -> None:
    assert seen("langgraph_oi_sub.json", names=frozenset()) == Counter(
        {("tool", "execute_trade"): 1}
    )


def test_langgraph_ls_tool() -> None:
    assert seen("langgraph_ls_tool.json") == Counter(
        {
            ("agent", "supervisor"): 1,
            ("agent", "trade-agent"): 1,
            ("tool", "ask_trade_agent"): 1,
            ("tool", "execute_trade"): 1,
        }
    )


ARROW = chr(0x2192)  # the arrow in the Logfire handoff template; keeps this file ASCII
LOGFIRE_RULES = [
    rule(kind="agent", when={"logfire.msg_template": "Agent run: {name!r}"}, name="name"),
    rule(kind="tool", when={"logfire.msg_template": "Function: {name}"}, name="name"),
    rule(
        kind="handoff",
        when={"logfire.msg_template": "Handoff: {from_agent} " + ARROW + " {to_agent}"},
        **{"from": "from_agent", "to": "to_agent"},
    ),
]


def test_logfire_with_rules() -> None:
    spans = recognize_spans(
        loose_raw_spans("openai_logfire_handoff.json"), rules=LOGFIRE_RULES, agent_names=frozenset()
    )
    assert Counter((s.kind, s.name) for s in spans if s.kind != "other") == Counter(
        {
            ("agent", "supervisor"): 1,
            ("agent", "trade-agent"): 1,
            ("tool", "execute_trade"): 1,
            ("handoff", None): 1,
        }
    )
    handoff = next(s for s in spans if s.kind == "handoff")
    assert (handoff.handoff_from, handoff.handoff_to) == ("supervisor", "trade-agent")


def test_logfire_without_rules_finds_nothing() -> None:
    assert seen("openai_logfire_handoff.json", names=frozenset()) == Counter()


def test_logfire_astool_wrapper_is_a_function_tool() -> None:
    spans = recognize_spans(
        loose_raw_spans("openai_logfire_astool.json"), rules=LOGFIRE_RULES, agent_names=frozenset()
    )
    assert Counter(s.name for s in spans if s.kind == "tool") == Counter(
        {"ask_trade_agent": 1, "execute_trade": 1}
    )
    assert Counter(s.name for s in spans if s.kind == "agent") == Counter(
        {"supervisor": 1, "trade-agent": 1}
    )


LANGFUSE_RULES = [
    rule(kind="agent", when={"langfuse.observation.type": "agent"}, name="span.name"),
    rule(kind="tool", when={"langfuse.observation.type": "tool"}, name="span.name"),
]


def test_langfuse_rules() -> None:
    out = recognize_spans(
        [
            raw("supervisor", {"langfuse.observation.type": "agent"}, span_id="01"),
            raw("execute_trade", {"langfuse.observation.type": "tool"}, span_id="02"),
            raw("gen", {"langfuse.observation.type": "generation"}, span_id="03"),
        ],
        rules=LANGFUSE_RULES,
        agent_names=frozenset(),
    )
    assert [(s.kind, s.name) for s in out] == [
        ("agent", "supervisor"),
        ("tool", "execute_trade"),
        ("other", None),
    ]
    assert out[2].unnamed_marker is False


def test_ids_times_and_where_are_copied() -> None:
    span = one(raw("x", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "a"}))
    assert span == Span(
        trace_id="a" * 32,
        span_id="0000000000000001",
        parent_id="0000000000000009",
        kind="agent",
        name="a",
        start_ns=5,
        end_ns=9,
        where="t.json:3",
    )


def test_tool_first() -> None:
    attributes: dict[str, ScalarValue] = {
        "openinference.span.kind": "AGENT",
        "tool.name": "ask_trade_agent",
        "agent.name": "x",
    }
    span = one(raw("w", attributes))
    assert (span.kind, span.name) == ("tool", "ask_trade_agent")


def test_tool_beats_handoff_beats_agent() -> None:
    attrs: dict[str, ScalarValue] = {"k": "v", "t": "tool", "a": "agent", "f": "from", "to_": "to"}
    rules = [
        rule(kind="agent", when={"k": "v"}, name="a"),
        rule(kind="handoff", when={"k": "v"}, **{"from": "f", "to": "to_"}),
    ]
    assert one(raw("n", attrs), rules).kind == "handoff"
    rules.append(rule(kind="tool", when={"k": "v"}, name="t"))
    span = one(raw("n", attrs), rules)
    assert (span.kind, span.name) == ("tool", "tool")


def test_handoff_needs_both_ends() -> None:
    rules = [rule(kind="handoff", when={"k": "v"}, **{"from": "f", "to": "t"})]
    span = one(raw("n", {"k": "v", "f": "a"}), rules)
    assert span.kind == "other"
    assert span.unnamed_marker is True  # a rule matched but gave no names


def test_first_matching_rule_decides_the_name() -> None:
    rules = [
        rule(kind="agent", when={"k": "v"}, name="missing"),
        rule(kind="agent", when={"k": "v"}, name="n2"),
    ]
    span = one(raw("x", {"k": "v", "n2": "bob"}), rules)
    # the first matching rule's name source is absent, so the second rule is not consulted
    assert span.kind == "other"
    assert span.unnamed_marker is True


def test_rule_all_conditions_and_empty_string_value() -> None:
    rules = [rule(kind="agent", when={"a": "1", "b": ""}, name="span.name")]
    out = recognize_spans(
        [
            raw("x", {"a": "1", "b": ""}),
            raw("y", {"a": "1", "b": "z"}, span_id="02"),
            raw("z", {"a": "1"}, span_id="03"),
        ],
        rules=rules,
        agent_names=frozenset(),
    )
    assert [s.kind for s in out] == ["agent", "other", "other"]


def test_span_name_condition() -> None:
    rules = [rule(kind="tool", when={"span.name": "run it", "k": "v"}, name="k")]
    out = recognize_spans(
        [raw("run it", {"k": "v"}), raw("other", {"k": "v"}, span_id="02")],
        rules=rules,
        agent_names=frozenset(),
    )
    assert [(s.kind, s.name) for s in out] == [("tool", "v"), ("other", None)]


def test_non_string_values_are_absent() -> None:
    span = one(raw("x", {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": 7}))
    assert span.kind == "other"
    assert span.unnamed_marker is True
    assert one(raw("x", {"gen_ai.tool.name": ""})).kind == "other"


def test_agent_id_when_invoke_agent() -> None:
    span = one(raw("x", {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.id": "id-1"}))
    assert (span.kind, span.name) == ("agent", "id-1")


def test_agent_name_without_invoke_agent_is_not_an_agent() -> None:
    span = one(raw("chat", {"gen_ai.operation.name": "chat", "gen_ai.agent.name": "supervisor"}))
    assert span.kind == "other"
    assert span.unnamed_marker is False


def test_span_name_in_agent_names_gets_caller() -> None:
    span = one(raw("trade-agent", {"graph.node.parent_id": "supervisor"}), names=NAMES)
    assert (span.kind, span.name, span.caller) == ("agent", "trade-agent", "supervisor")


def test_linear_time() -> None:
    rules = [rule(kind="agent", when={f"k{i}": "v", "x": "y"}, name="span.name") for i in range(50)]
    spans = [raw("n", {"x": "y", "k49": "v"}, span_id=f"{i:016x}") for i in range(200_000)]
    start = time.monotonic()
    out = recognize_spans(spans, rules=rules, agent_names=NAMES)
    assert time.monotonic() - start < 30
    assert len(out) == 200_000
    assert out[0].kind == "agent"


def exec_tool_attrs(**extra: ScalarValue) -> dict[str, ScalarValue]:
    return {"gen_ai.operation.name": "execute_tool", **extra}


def test_execute_tool_with_owner_agent_name_is_a_tool() -> None:
    span = one(raw("t", exec_tool_attrs(**{"gen_ai.tool.name": "x", "gen_ai.agent.name": "a"})))
    assert (span.kind, span.name) == ("tool", "x")


def test_invoke_agent_with_stray_tool_name_is_an_agent() -> None:
    span = one(
        raw(
            "i",
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": "a",
                "gen_ai.tool.name": "x",
            },
        )
    )
    assert (span.kind, span.name) == ("agent", "a")


def test_oi_agent_with_only_agent_name_is_an_agent() -> None:
    span = one(raw("n", {"openinference.span.kind": "AGENT", "agent.name": "a"}))
    assert (span.kind, span.name) == ("agent", "a")


def test_oi_tool_without_tool_name_never_becomes_an_agent() -> None:
    attrs: dict[str, ScalarValue] = {"openinference.span.kind": "TOOL", "agent.name": "a"}
    span = one(raw("n", attrs))
    assert span.kind == "other" and span.unnamed_marker is True
    # even when its span name is a known agent id
    span = one(raw("trade-agent", attrs), names=NAMES)
    assert span.kind == "other" and span.unnamed_marker is True


def test_execute_tool_without_name_never_matches_agent_names() -> None:
    span = one(raw("trade-agent", exec_tool_attrs()), names=NAMES)
    assert span.kind == "other" and span.unnamed_marker is True


def test_tool_span_named_like_an_agent_is_a_tool() -> None:
    by_rule = one(
        raw("trade-agent", {"k": "v", "t": "wrap"}),
        [rule(kind="tool", when={"k": "v"}, name="t")],
        NAMES,
    )
    assert (by_rule.kind, by_rule.name) == ("tool", "wrap")
    by_attr = one(raw("trade-agent", exec_tool_attrs(**{"gen_ai.tool.name": "wrap"})), names=NAMES)
    assert (by_attr.kind, by_attr.name) == ("tool", "wrap")


def test_tool_rule_without_name_beats_agent_rule() -> None:
    rules = [
        rule(kind="tool", when={"k": "v"}, name="missing"),
        rule(kind="agent", when={"k": "v"}, name="a"),
    ]
    span = one(raw("x", {"k": "v", "a": "bob"}), rules)
    assert span.kind == "other" and span.unnamed_marker is True


def test_handoff_rule_on_invoke_agent_span() -> None:
    rules = [rule(kind="handoff", when={"k": "v"}, **{"from": "f", "to": "t"})]
    base: dict[str, ScalarValue] = {
        "gen_ai.operation.name": "invoke_agent",
        "gen_ai.agent.name": "a",
        "k": "v",
    }
    assert one(raw("x", {**base, "f": "p", "t": "q"}), rules).kind == "handoff"
    span = one(raw("x", {**base, "f": "p"}), rules)
    assert (span.kind, span.name) == ("agent", "a")


def test_empty_agent_name_falls_back_to_agent_id() -> None:
    span = one(
        raw(
            "x",
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": "",
                "gen_ai.agent.id": "id-2",
            },
        )
    )
    assert (span.kind, span.name) == ("agent", "id-2")


def test_empty_span_name_never_matches_agent_names() -> None:
    assert one(raw(""), names=frozenset({""})).kind == "other"


# ---- typed when values, door rules and effect rules ----


def test_typed_when_compares_exact_types() -> None:
    bool_rule = [rule(kind="tool", when={"app.ok": True}, name="tool.name")]
    assert one(raw("s", {"app.ok": True, "tool.name": "t"}), bool_rule).kind == "tool"
    assert one(raw("s", {"app.ok": "true", "tool.name": "t"}), bool_rule).kind == "other"
    assert one(raw("s", {"app.ok": 1, "tool.name": "t"}), bool_rule).kind == "other"
    int_rule = [rule(kind="tool", when={"n": 1}, name="tool.name")]
    assert one(raw("s", {"n": 1, "tool.name": "t"}), int_rule).kind == "tool"
    assert one(raw("s", {"n": True, "tool.name": "t"}), int_rule).kind == "other"
    assert one(raw("s", {"n": 1.0, "tool.name": "t"}), int_rule).kind == "other"


APPROVAL: dict[str, ScalarValue] = {
    "gen_ai.operation.name": "approval",
    "app.granted": False,
    "gen_ai.tool.call.id": "c1",
}


def door_rule(**extra: object) -> ObserveRule:
    fields: dict[str, object] = {
        "kind": "door",
        "when": {"gen_ai.operation.name": "approval", "app.granted": False},
        "decision": "deny",
        "tool_call_id": "gen_ai.tool.call.id",
    }
    return rule(**{**fields, **extra})


def test_door_rule_makes_a_decision_only_record() -> None:
    span = one(raw("a", dict(APPROVAL)), [door_rule()])
    assert span.door == decision_only("deny", "c1")
    assert span.kind == "other"


def test_door_rule_without_a_usable_call_id_still_makes_a_record() -> None:
    without_source = one(raw("a", dict(APPROVAL)), [door_rule(tool_call_id=None)])
    assert without_source.door == decision_only("deny", None)
    for value in (None, ""):
        attributes = {**APPROVAL, "gen_ai.tool.call.id": value}
        attributes = {k: v for k, v in attributes.items() if v is not None}
        span = one(raw("a", attributes), [door_rule()])
        assert span.door == decision_only("deny", None)


def test_first_matching_door_rule_wins() -> None:
    rules_ = [door_rule(decision="allow"), door_rule(decision="deny")]
    assert one(raw("a", dict(APPROVAL)), rules_).door == decision_only("allow", "c1")


def test_a_valid_own_door_record_beats_a_door_rule() -> None:
    own = {
        **APPROVAL,
        "lockwalk.door.decision": "allow",
        "lockwalk.door.subject.type": "agent",
        "lockwalk.door.subject.id": "trade-agent",
        "lockwalk.door.action": "trade:execute",
    }
    door = one(raw("a", own), [door_rule()]).door
    assert door is not None
    assert (door.decision, door.subject_id, door.action) == (
        "allow",
        "trade-agent",
        "trade:execute",
    )


def test_a_malformed_own_door_record_is_not_replaced_by_a_rule() -> None:
    attributes: dict[str, ScalarValue] = {**APPROVAL, "lockwalk.door.decision": "deny"}
    result = recognize(
        [raw("a", attributes)], rules=[door_rule()], agent_names=frozenset(), door_keys=KEYS
    )
    (span,) = result.spans
    assert span.door is None
    assert len(result.problems) == 1


def test_effect_rule_sets_the_marker() -> None:
    effect = [rule(kind="effect", when={"app.outcome": "completed"})]
    assert one(raw("e", {"app.outcome": "completed"}), effect).effect is True
    assert one(raw("e", {"app.outcome": "blocked"}), effect).effect is False


def test_own_effect_marker_beats_an_effect_rule() -> None:
    effect = [rule(kind="effect", when={"app.outcome": "completed"})]
    span = one(raw("e", {"app.outcome": "completed", "lockwalk.effect": False}), effect)
    assert span.effect is False
    bad = recognize(
        [raw("e", {"app.outcome": "completed", "lockwalk.effect": "yes"})],
        rules=effect,
        agent_names=frozenset(),
        door_keys=KEYS,
    )
    assert bad.spans[0].effect is False
    assert len(bad.problems) == 1


def test_door_rule_on_a_tool_span_keeps_the_tool_call_id() -> None:
    attributes: dict[str, ScalarValue] = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "t",
        "gen_ai.tool.call.id": "c9",
        "app.outcome": "blocked",
    }
    rules_ = [rule(kind="door", when={"app.outcome": "blocked"}, decision="deny")]
    span = one(raw("t", attributes), rules_)
    assert (span.kind, span.name, span.tool_call_id) == ("tool", "t", "c9")
    assert span.door == decision_only("deny", None)


def test_linear_time_with_door_and_effect_rules() -> None:
    rules_ = [
        rule(kind="door", when={f"k{i}": "v", "x": "y"}, decision="deny") for i in range(50)
    ] + [rule(kind="effect", when={f"e{i}": "v", "x": "y"}) for i in range(50)]
    spans = [raw("n", {"x": "y", "k49": "v"}, span_id=f"{i:016x}") for i in range(5000)]
    start = time.monotonic()
    out = recognize_spans(spans, rules=rules_, agent_names=NAMES)
    assert time.monotonic() - start < 30
    assert len(out) == 5000
    assert out[0].door == decision_only("deny", None)


# ---- rules and [observe.attributes] mappings ----


def mapped_keys() -> DoorKeys:
    config = ObserveConfig.model_validate(
        {"attributes": {"lockwalk.door.decision": "app.decision", "lockwalk.effect": "app.fx"}}
    )
    return DoorKeys.from_config(config)


def recognize_mapped(span: RawSpan, rules_: list[ObserveRule]):
    return recognize([span], rules=rules_, agent_names=frozenset(), door_keys=mapped_keys())


def test_mapped_own_door_key_beats_a_door_rule() -> None:
    rules_ = [door_rule(decision="allow", when={"x": "y"})]
    # An incomplete own record under the mapped key is a read problem, never the rule's record.
    result = recognize_mapped(raw("a", {"x": "y", "app.decision": "deny"}), rules_)
    assert result.spans[0].door is None
    assert len(result.problems) == 1
    # A span with only the default key (mapped away) has no door key, so the rule applies.
    result = recognize_mapped(raw("a", {"x": "y", "lockwalk.door.decision": "deny"}), rules_)
    assert result.spans[0].door == decision_only("allow", None)
    assert result.problems == []


def test_mapped_effect_key_and_effect_rule() -> None:
    effect = [rule(kind="effect", when={"app.outcome": "completed"})]
    base: dict[str, ScalarValue] = {"app.outcome": "completed"}
    own_false = recognize_mapped(raw("e", {**base, "app.fx": False}), effect)
    assert own_false.spans[0].effect is False
    # The default key is mapped away: read_effect ignores it, so the rule applies.
    default_only = recognize_mapped(raw("e", {**base, "lockwalk.effect": False}), effect)
    assert default_only.spans[0].effect is True
    assert default_only.problems == []
    bad = recognize_mapped(raw("e", {**base, "app.fx": "yes"}), effect)
    assert bad.spans[0].effect is False
    assert len(bad.problems) == 1


def test_door_rule_with_an_unusable_call_id_source_keeps_the_record() -> None:
    for value in ("x" * 513, 7):
        attributes: dict[str, ScalarValue] = {**APPROVAL, "gen_ai.tool.call.id": value}
        assert one(raw("a", attributes), [door_rule()]).door == decision_only("deny", None)
