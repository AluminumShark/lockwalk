"""Recognize agent, tool and handoff spans.

A RawSpan becomes a Span. The order is fixed: the user's rules, then the OTel GenAI and
OpenInference attributes, then name matching against the agent names the map knows. A tool
is decided before a handoff, and a handoff before an agent, so an agent-as-tool wrapper that
OpenInference marks as AGENT is still a tool. Door and effect rules only fill in what a span
does not say itself. One pass, linear in spans x rules x conditions.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from lockwalk.config import DoorDecision, ObserveRule
from lockwalk.observe.door import (
    DoorKeys,
    check_text,
    decision_only,
    read_door,
    read_effect,
    read_user,
)
from lockwalk.observe.keys import (
    GEN_AI_AGENT_ID,
    GEN_AI_AGENT_NAME,
    GEN_AI_OPERATION,
    GEN_AI_TOOL_CALL_ID,
    GEN_AI_TOOL_NAME,
    OI_AGENT_NAME,
    OI_KIND,
    OI_PARENT,
    OI_TOOL_NAME,
    SPAN_NAME,
)
from lockwalk.observe.spans import RawSpan, ReadProblem, Span, SpanKind

_OPERATION_TOOL = "execute_tool"
_OPERATION_AGENT = "invoke_agent"
_OI_TOOL = "TOOL"
_OI_AGENT = "AGENT"


@dataclass(frozen=True, slots=True)
class _Rule:
    conditions: tuple[tuple[str, str | bool | int], ...]
    name: str | None
    from_: str | None
    to: str | None
    decision: DoorDecision | None
    tool_call_id: str | None


@dataclass(frozen=True, slots=True)
class _Rules:
    """The rules of each kind, each list in the user's order."""

    agents: list[_Rule]
    tools: list[_Rule]
    handoffs: list[_Rule]
    doors: list[_Rule]
    effects: list[_Rule]


def _compile(rules: Sequence[ObserveRule]) -> _Rules:
    out = _Rules(agents=[], tools=[], handoffs=[], doors=[], effects=[])
    buckets = {
        "agent": out.agents,
        "tool": out.tools,
        "handoff": out.handoffs,
        "door": out.doors,
        "effect": out.effects,
    }
    for rule in rules:
        compiled = _Rule(
            tuple(rule.when.items()),
            rule.name,
            rule.from_,
            rule.to,
            rule.decision,
            rule.tool_call_id,
        )
        buckets[rule.kind].append(compiled)
    return out


def _same(actual: object, expected: str | bool | int) -> bool:
    # bool is a subclass of int, so compare the exact types: true never equals 1 or "true".
    return type(actual) is type(expected) and actual == expected


def _value(span: RawSpan, source: str | None) -> str | None:
    """The span name for 'span.name', else a non-empty string attribute; else absent.

    Other attribute types (int, bool, float) count as absent, and rules compare string
    attribute values only.
    """
    if source is None:
        return None
    if source == SPAN_NAME:
        return span.name or None
    value = span.attributes.get(source)
    return value if isinstance(value, str) and value else None


def _matches(span: RawSpan, rule: _Rule) -> bool:
    for key, expected in rule.conditions:
        actual = span.name if key == SPAN_NAME else span.attributes.get(key)
        if not _same(actual, expected):
            return False
    return True


def _first_match(span: RawSpan, rules: Sequence[_Rule]) -> _Rule | None:
    for rule in rules:
        if _matches(span, rule):
            return rule
    return None


def _span(
    raw: RawSpan,
    kind: SpanKind,
    *,
    name: str | None = None,
    caller: str | None = None,
    handoff_from: str | None = None,
    handoff_to: str | None = None,
    unnamed_marker: bool = False,
) -> Span:
    return Span(
        trace_id=raw.trace_id,
        span_id=raw.span_id,
        parent_id=raw.parent_id,
        kind=kind,
        name=name,
        caller=caller,
        handoff_from=handoff_from,
        handoff_to=handoff_to,
        start_ns=raw.start_ns,
        end_ns=raw.end_ns,
        unnamed_marker=unnamed_marker,
        where=raw.where,
    )


def _tool_name(
    span: RawSpan, rule: _Rule | None, operation: str | None, oi_kind: str | None
) -> str | None:
    name = _value(span, rule.name) if rule is not None else None
    # gen_ai.tool.name is read only for execute_tool: other spans may carry an owner's name.
    if name is None and operation == _OPERATION_TOOL:
        name = _value(span, GEN_AI_TOOL_NAME)
    # OpenInference marks some tools (agent-as-tool wrappers) as AGENT, so read tool.name for both.
    if name is None and oi_kind in (_OI_TOOL, _OI_AGENT):
        name = _value(span, OI_TOOL_NAME)
    return name


def _agent_name(
    span: RawSpan,
    rule: _Rule | None,
    operation: str | None,
    oi_kind: str | None,
    agent_names: frozenset[str],
) -> str | None:
    name = _value(span, rule.name) if rule is not None else None
    # gen_ai.agent.name is read only for invoke_agent: chat and tool spans carry the owner's name.
    if name is None and operation == _OPERATION_AGENT:
        name = _value(span, GEN_AI_AGENT_NAME) or _value(span, GEN_AI_AGENT_ID)
    if name is None and oi_kind == _OI_AGENT:
        name = _value(span, OI_AGENT_NAME)
    if name is None and span.name and span.name in agent_names:
        name = span.name
    return name


def _recognize_one(
    span: RawSpan,
    rules: _Rules,
    agent_names: frozenset[str],
) -> Span:
    agent_rules, tool_rules, handoff_rules = rules.agents, rules.tools, rules.handoffs
    operation = _value(span, GEN_AI_OPERATION)
    oi_kind = _value(span, OI_KIND)

    # Order: tool, then handoff, then agent. An agent-as-tool wrapper is marked as an agent by
    # some instrumentations but is a tool call, not an agent visit.
    tool_rule = _first_match(span, tool_rules)
    tool_name = _tool_name(span, tool_rule, operation, oi_kind)
    if tool_name is not None:
        return _span(span, "tool", name=tool_name)

    handoff_rule = _first_match(span, handoff_rules)
    if handoff_rule is not None:
        source = _value(span, handoff_rule.from_)
        target = _value(span, handoff_rule.to)
        if source is not None and target is not None:
            return _span(span, "handoff", handoff_from=source, handoff_to=target)

    # A span marked as a tool but without a tool name never becomes an agent by name.
    if tool_rule is not None or operation == _OPERATION_TOOL or oi_kind == _OI_TOOL:
        return _span(span, "other", unnamed_marker=True)

    agent_rule = _first_match(span, agent_rules)
    agent_name = _agent_name(span, agent_rule, operation, oi_kind, agent_names)
    if agent_name is not None:
        return _span(span, "agent", name=agent_name, caller=_value(span, OI_PARENT))

    marked = (
        handoff_rule is not None
        or agent_rule is not None
        or operation == _OPERATION_AGENT
        or oi_kind == _OI_AGENT
    )
    return _span(span, "other", unnamed_marker=marked)


@dataclass(frozen=True)
class Recognized:
    spans: list[Span]
    problems: list[ReadProblem]


def _with_door_data(
    raw: RawSpan, span: Span, keys: DoorKeys, problems: list[ReadProblem], rules: _Rules
) -> Span:
    """Add the door record, effect marker, user and tool call id; a bad one is a problem.

    The span's own data always wins: a door rule never touches a span that has any door key,
    and an effect rule never touches a span that has the effect key.
    """
    attributes = raw.attributes
    door = read_door(attributes, keys)
    if isinstance(door, str):
        problems.append(ReadProblem(raw.where, door))
        door = None
    elif door is None:
        # No door key on the span: a door rule may make a decision-only record.
        door_rule = _first_match(raw, rules.doors)
        # Config guarantees a decision on door rules; the check only narrows the type for ty.
        if door_rule is not None and door_rule.decision is not None:
            source = door_rule.tool_call_id
            call = check_text(attributes.get(source)) if source else None
            door = decision_only(door_rule.decision, call)
    effect = read_effect(attributes, keys)
    if isinstance(effect, str):
        problems.append(ReadProblem(raw.where, effect))
        effect = False
    elif keys.effect not in attributes and any(_matches(raw, rule) for rule in rules.effects):
        effect = True
    user_id = read_user(attributes, keys)
    # A malformed tool call id (not a string, empty, over the limit) counts as absent.
    call_id = check_text(attributes.get(GEN_AI_TOOL_CALL_ID)) if span.kind == "tool" else None
    if door is None and not effect and user_id is None and call_id is None:
        return span
    return replace(span, door=door, effect=effect, user_id=user_id, tool_call_id=call_id)


def recognize(
    raw: Iterable[RawSpan],
    *,
    rules: Sequence[ObserveRule],
    agent_names: frozenset[str],
    door_keys: DoorKeys,
) -> Recognized:
    compiled = _compile(rules)
    problems: list[ReadProblem] = []
    spans: list[Span] = []
    for item in raw:
        span = _recognize_one(item, compiled, agent_names)
        spans.append(_with_door_data(item, span, door_keys, problems, compiled))
    return Recognized(spans, problems)
