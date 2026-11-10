"""Async readers: an async generator, and a coroutine that returns a list."""


async def read(paths):
    yield {"trace_id": "T", "span_id": "A", "kind": "agent", "name": "async-agent"}
    yield {"trace_id": "T", "span_id": "B", "parent_id": "A", "kind": "tool", "name": "t"}


async def read_list(paths):
    return [{"trace_id": "T", "span_id": "A", "kind": "tool", "name": "listed"}]
