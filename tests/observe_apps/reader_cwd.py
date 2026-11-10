"""Readers that show their working directory and the paths they were given."""


def read(paths):
    with open("data.txt", encoding="utf-8") as handle:
        name = handle.read().strip()
    yield {"trace_id": "T", "span_id": "A", "kind": "tool", "name": name}


def read_paths(paths):
    for number, path in enumerate(paths):
        yield {"trace_id": "T", "span_id": f"S{number}", "kind": "tool", "name": path}


NOT_CALLABLE = 5
