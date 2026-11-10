"""Readers that yield many or wide records."""


def read(paths):
    for number in range(int(paths[0])):
        yield {"trace_id": "T", "span_id": f"S{number}", "kind": "other"}


def read_invalid(paths):
    for number in range(int(paths[0])):
        yield {"trace_id": "T", "span_id": f"S{number}", "kind": "agent"}


def read_wide(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "other"}
    yield {"trace_id": "T", "span_id": "B", "kind": "other", "authz": [{"k": "v" * 400}]}
