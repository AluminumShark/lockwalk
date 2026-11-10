"""Readers that return things the worker or the parent must refuse."""


def read_non_dict(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "other"}
    yield "not a dict"


def read_set(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "other", "extra": {1, 2}}


def read_invalid(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "agent"}  # no name
    yield {"trace_id": "T", "span_id": "B", "kind": "other", "secret": "hunter2"}  # extra key
    yield {"trace_id": "T", "span_id": "C", "kind": "tool", "name": "ok"}
    yield {"trace_id": "T", "span_id": "D", "kind": "handoff", "from": "a"}  # no 'to'
    yield {"trace_id": "T", "span_id": "E", "kind": "other", "start": "2026-01-01T00:00:00"}


def read_not_iterable(paths):
    return 42
