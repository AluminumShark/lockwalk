"""Attribute names lockwalk observe reads from trace spans.

Nothing else of a span's attributes is ever kept. This module imports
nothing, so config.py can use it.
"""

GEN_AI_OPERATION = "gen_ai.operation.name"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_AGENT_ID = "gen_ai.agent.id"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
OI_KIND = "openinference.span.kind"
OI_AGENT_NAME = "agent.name"
OI_TOOL_NAME = "tool.name"
OI_PARENT = "graph.node.parent_id"
USER_ID = "user.id"
ENDUSER_ID = "enduser.id"
DOOR_DECISION = "lockwalk.door.decision"
DOOR_SUBJECT_TYPE = "lockwalk.door.subject.type"
DOOR_SUBJECT_ID = "lockwalk.door.subject.id"
DOOR_ACT = "lockwalk.door.act"
DOOR_ACTION = "lockwalk.door.action"
DOOR_RESOURCE_TYPE = "lockwalk.door.resource.type"
DOOR_TOOL_CALL_ID = "lockwalk.door.tool_call_id"
EFFECT = "lockwalk.effect"

# The special source name in [[observe.rules]]: the span's own name, not an attribute.
SPAN_NAME = "span.name"

DOOR_KEYS = frozenset(
    {
        DOOR_DECISION,
        DOOR_SUBJECT_TYPE,
        DOOR_SUBJECT_ID,
        DOOR_ACT,
        DOOR_ACTION,
        DOOR_RESOURCE_TYPE,
        DOOR_TOOL_CALL_ID,
    }
)
# What [observe.attributes] may map: the door record, the effect marker, the user.
MAPPABLE_KEYS = DOOR_KEYS | {EFFECT, USER_ID}
BUILTIN_KEYS = frozenset(
    {
        GEN_AI_OPERATION,
        GEN_AI_AGENT_NAME,
        GEN_AI_AGENT_ID,
        GEN_AI_TOOL_NAME,
        GEN_AI_TOOL_CALL_ID,
        OI_KIND,
        OI_AGENT_NAME,
        OI_TOOL_NAME,
        OI_PARENT,
        ENDUSER_ID,
    }
    | MAPPABLE_KEYS
)
