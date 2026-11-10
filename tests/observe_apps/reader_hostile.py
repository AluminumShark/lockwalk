"""Readers that misbehave while their records are encoded, run, or cleaned up."""

import subprocess
import sys
from pathlib import Path


class BrokenItems(dict):
    def items(self):
        raise RuntimeError("items failed")


class EndlessItems(dict):
    def __init__(self):
        super().__init__(a=1)

    def items(self):
        number = 0
        while True:
            number += 1
            yield f"k{number}", "v" * 100


class Opaque:
    pass


def read_broken_items(paths):
    yield BrokenItems(a=1)


def read_object_value(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "other", "x": Opaque()}


def read_endless_item(paths):
    yield EndlessItems()


def read_infinite(paths):
    """Never ends; the finally block leaves a marker so the test sees the generator closed."""
    number = 0
    try:
        while True:
            number += 1
            yield {"trace_id": "T", "span_id": f"S{number}", "kind": "other"}
    finally:
        Path(paths[0]).write_text("closed", encoding="utf-8")


async def read_infinite_async(paths):
    number = 0
    try:
        while True:
            number += 1
            yield {"trace_id": "T", "span_id": f"S{number}", "kind": "other"}
    finally:
        Path(paths[0]).write_text("closed", encoding="utf-8")


def read_leaves_child(paths):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    Path(paths[0]).write_text(str(child.pid), encoding="utf-8")
    yield {"trace_id": "T", "span_id": "A", "kind": "other"}


def read_ids(paths):
    yield {"trace_id": "Tr", "span_id": "Ab", "kind": "other"}
    yield {"trace_id": "Tr", "span_id": "ab", "kind": "other"}
    yield {"trace_id": "tr", "span_id": "x", "kind": "other"}


def read_epoch(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "other", "start": 1767225600}
