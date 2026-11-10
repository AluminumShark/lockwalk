"""A reader that returns a small, valid trace."""


def read(paths):
    yield {"trace_id": "T1", "span_id": "A", "kind": "other"}
    yield {
        "trace_id": "T1",
        "span_id": "B",
        "parent_id": "A",
        "kind": "agent",
        "name": "supervisor",
        "start": "2026-01-01T00:00:00.000001+00:00",
        "end": "2026-01-01T00:00:01+00:00",
    }
    yield {
        "trace_id": "T1",
        "span_id": "C",
        "parent_id": "B",
        "kind": "agent",
        "name": "trade-agent",
        "caller": "supervisor",
    }
    yield {
        "trace_id": "T1",
        "span_id": "D",
        "parent_id": "C",
        "kind": "tool",
        "name": "execute_trade",
    }
    yield {
        "trace_id": "T2",
        "span_id": "E",
        "kind": "handoff",
        "from": "supervisor",
        "to": "trade-agent",
        "user_id": "u-1",
        "effect": True,
    }
