"""Subprocess side of the observe reader function.

Run as: python -P -m lockwalk.observe._reader_worker <request.json> <output-dir>

The user's function gets the trace paths and returns (or yields) one dict per span. Each
dict is written to <output-dir>/records.jsonl as one JSON line, with limits checked while
writing. <output-dir>/result.json is written last and atomically. stdout and stderr go
nowhere the parent reads: the user's code may print anything. The parent validates every
record; this process only checks that each item is a dict that serializes.
"""

import asyncio
import contextlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

from lockwalk.inventory._python_worker import resolve
from lockwalk.inventory.normalize import describe_error


class _Stop(Exception):
    """A limit was reached; `reason` is the value for result.json's `stopped`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _Sink:
    """Writes accepted items to the records file and enforces the three limits."""

    def __init__(self, handle: Any, max_records: int, max_line: int, max_total: int) -> None:
        self.count = 0
        self._handle = handle
        self._max_records = max_records
        self._max_line = max_line
        self._max_total = max_total
        self._total = 0

    def add(self, item: object) -> None:
        position = self.count + 1
        if self.count >= self._max_records:
            raise _Stop("too_many")
        if not isinstance(item, dict):
            raise TypeError(f"record {position} is a {type(item).__name__}, not a dict")
        size = 1  # the newline
        chunks: list[bytes] = []
        try:
            # Encode piece by piece and stop at the limit: a huge or endless item must not
            # be built in memory first.
            for piece in _ENCODER.iterencode(item):
                data = piece.encode("utf-8")
                size += len(data)
                if size - 1 > self._max_line or self._total + size > self._max_total:
                    raise _Stop("too_large")
                chunks.append(data)
        except _Stop:
            raise
        except Exception as exc:  # user objects may raise anything while being encoded
            raise TypeError(
                f"record {position} cannot be written as JSON ({type(exc).__name__})"
            ) from None
        chunks.append(b"\n")
        self._handle.write(b"".join(chunks))
        self._total += size
        self.count += 1


_ENCODER = json.JSONEncoder(ensure_ascii=False, allow_nan=False)


def _close(value: Any) -> None:
    """Close the user's generator now, so its finally blocks run before result.json is
    written (otherwise they would run at garbage collection, after the parent moved on)."""
    close = getattr(value, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):
            close()


def _feed(value: Any, sink: _Sink) -> None:
    if isinstance(value, dict | str | bytes) or not hasattr(value, "__iter__"):
        raise TypeError(f"the reader returned a {type(value).__name__}, not an iterable of dicts")
    try:
        for item in value:
            sink.add(item)
    finally:
        _close(value)


async def _drain(value: Any, sink: _Sink) -> None:
    """Finish an awaitable, then feed the sink from what it gave (sync or async iterable)."""
    if inspect.isawaitable(value):
        value = await value
    if hasattr(value, "__aiter__"):
        try:
            async for item in value:
                sink.add(item)
        finally:
            aclose = getattr(value, "aclose", None)  # same reason as _close
            if callable(aclose):
                with contextlib.suppress(Exception):
                    await aclose()
    else:
        _feed(value, sink)


MAX_ERROR_CHARS = 2000  # keeps result.json far below the parent's size cap


def run(request: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Run the reader; the result is what goes into result.json."""
    stopped: str | None = None
    error: str | None = None
    count = 0
    sink: _Sink | None = None
    try:
        with open(out_dir / "records.jsonl", "wb") as handle:
            sink = _Sink(
                handle,
                request["max_records"],
                request["max_line_bytes"],
                request["max_total_bytes"],
            )
            try:
                sys.path.insert(0, os.getcwd())
                function = resolve(request["target"])
                if not callable(function):
                    raise TypeError("the reader target is not callable")
                value = function(list(request["paths"]))
                if inspect.isawaitable(value) or hasattr(value, "__aiter__"):
                    asyncio.run(_drain(value, sink))
                else:
                    _feed(value, sink)
            except _Stop as stop:
                stopped = stop.reason
            except BaseException as exc:  # user code may raise anything, even SystemExit
                error = describe_error(exc)[:MAX_ERROR_CHARS]
            count = sink.count
    except OSError as exc:  # for example a full disk
        error = f"cannot write the records file ({type(exc).__name__})"
        count = sink.count if sink else 0
    return {"count": count, "stopped": stopped, "error": error}


def main(argv: list[str]) -> int:
    request_path, out_dir = Path(argv[1]), Path(argv[2])
    request = json.loads(request_path.read_text(encoding="utf-8"))
    result = run(request, out_dir)
    temp = out_dir / "result.json.tmp"
    temp.write_text(json.dumps(result), encoding="utf-8")
    os.replace(temp, out_dir / "result.json")
    return 0


if __name__ == "__main__":
    with contextlib.suppress(BrokenPipeError):
        sys.exit(main(sys.argv))
