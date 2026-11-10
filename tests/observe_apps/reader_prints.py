"""A reader that prints to stdout and stderr."""

import sys


def read(paths):
    print("hello from the reader")
    print("an error line", file=sys.stderr)
    sys.stdout.flush()
    yield {"trace_id": "T", "span_id": "A", "kind": "tool", "name": "printed"}
