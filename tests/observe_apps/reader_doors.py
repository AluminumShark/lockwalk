"""A reader that returns authorization records, an effect marker and a user."""


def read(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "other", "user_id": "u-1"}
    yield {
        "trace_id": "T",
        "span_id": "B",
        "parent_id": "A",
        "kind": "tool",
        "name": "execute_trade",
        "tool_call_id": "call-1",
        "effect": True,
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-01-01T00:00:01Z",
        "authz": [
            {
                "decision": "allow",
                "subject": {"type": "user", "id": "u-1", "act": {"type": "agent", "id": "bot"}},
                "action": "trade:execute",
                "resource_type": "account",
                "tool_call_id": "call-1",
            },
            {
                "decision": "deny",
                "subject": {"type": "agent", "id": "bot"},
                "action": "trade:execute",
            },
        ],
    }
