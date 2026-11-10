"""Read OTLP JSON trace files into RawSpans.

Accepted: the OTel Collector file exporter (one JSON document per line), a single OTLP/JSON
document, and Jaeger's `{"result": ...}` wrapper; each may be gzip-compressed. Only
allowlisted attributes are kept. Every limit is checked while reading, files are read
line by line, and no message quotes input content.
"""

import codecs
import gzip
import json
import os
import re
import stat
import zlib
from collections.abc import Generator, Iterator, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lockwalk.jsonvalues import reject_duplicate_keys
from lockwalk.observe.spans import MIB, Limits, RawSpan, ReadProblem, ReadResult, ScalarValue

SUFFIXES = (".json", ".jsonl", ".json.gz", ".jsonl.gz")
MAX_PROBLEMS = 100
MAX_BLANK_LINES = 1000
_CHUNK = 64 * 1024
_MAX_DIGITS = 20
_BOM = b"\xef\xbb\xbf"
_TRACE_ID = re.compile(r"[0-9a-fA-F]{32}")
_SPAN_ID = re.compile(r"[0-9a-fA-F]{16}")
_DIGITS = re.compile(r"[0-9]{1,20}")
_INT = re.compile(r"-?[0-9]{1,20}")
_DOUBLE_WORDS = {"NaN": float("nan"), "Infinity": float("inf"), "-Infinity": float("-inf")}
_NOT_OTLP = "this is not an OTLP JSON document"
_BINARY = (
    "this is not OTLP JSON. The OTel Collector's file exporter with compression: zstd or "
    "format: proto writes a binary format; use format: json without compression"
)


class _Bad(Exception):
    """One span or document that cannot be used. The message never quotes the input."""


@dataclass(frozen=True, slots=True)
class _Doc:
    line: int
    data: bytes | None = None
    problem: str | None = None  # set: nothing usable at this line
    fatal: bool = False  # set: stop reading this file


class _Budget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.spans = 0
        self.bytes = 0
        self.truncated = False
        self.problems: list[ReadProblem] = []
        self.overflow = 0

    def problem(self, where: str, message: str, *, force: bool = False) -> None:
        if force or len(self.problems) < MAX_PROBLEMS:
            self.problems.append(ReadProblem(where, message))
        else:
            self.overflow += 1

    def add_bytes(self, count: int) -> bool:
        """Count bytes read; False (and truncated) once the total limit is passed."""
        self.bytes += count
        if self.bytes > self.limits.max_total_bytes:
            self.truncate(
                f"more than {_mib(self.limits.max_total_bytes)} MiB of trace data; "
                "raise [observe] max_total_mb or read fewer files"
            )
            return False
        return True

    def add_span(self) -> bool:
        if self.spans >= self.limits.max_spans:
            self.truncate(
                f"more than {self.limits.max_spans} spans; "
                "raise [observe] max_spans or read fewer files"
            )
            return False
        self.spans += 1
        return True

    def truncate(self, message: str) -> None:
        if not self.truncated:
            self.truncated = True
            self.problem("", message, force=True)


def _mib(size: int) -> str:
    return f"{size / MIB:g}"


def read_otlp(
    paths: Sequence[Path],
    *,
    keys: frozenset[str],
    limits: Limits,
    only_trace: str | None = None,
    labels: Sequence[str] | None = None,
) -> ReadResult:
    """Read OTLP JSON files. labels (one per path) is how a source is named in the report
    and in messages; it defaults to the path. Paths are only used to open files."""
    if labels is not None and len(labels) != len(paths):
        raise ValueError("labels must have one entry per path")
    budget = _Budget(limits)
    raw: list[RawSpan] = []
    sources: list[str] = []
    warnings: list[str] = []
    wanted = only_trace.lower() if only_trace is not None else None
    for index, path in enumerate(paths):
        label = labels[index] if labels is not None else str(path)
        files = _files(path, label, budget, warnings, sources)
        for file in files:
            if budget.truncated:
                break
            _read_file(file, keys, wanted, budget, raw)
        if budget.truncated:
            break
    if budget.overflow:
        budget.problems.append(ReadProblem("", f"... and {budget.overflow} more problems"))
    return ReadResult(
        raw=tuple(raw),
        sources=tuple(sources),
        problems=tuple(budget.problems),
        warnings=tuple(warnings),
        truncated=budget.truncated,
    )


def _files(
    path: Path, label: str, budget: _Budget, warnings: list[str], sources: list[str]
) -> list[Path]:
    try:
        if path.is_dir():
            entries = sorted(path.iterdir(), key=lambda p: p.name)
        elif path.exists():
            sources.append(label)
            if not path.name.lower().endswith(SUFFIXES):
                budget.problem(label, "this is not a .json, .jsonl, .json.gz or .jsonl.gz file")
                return []
            return [path]
        else:
            budget.problem(label, "this path does not exist")
            return []
    except OSError:
        budget.problem(label, "this path could not be read")
        return []
    files: list[Path] = []
    skipped = 0
    folders = 0
    try:
        for entry in entries:
            if entry.is_dir():
                folders += 1
                continue
            if entry.name.lower().endswith(SUFFIXES):
                files.append(entry)
            else:
                skipped += 1
    except OSError:
        budget.problem(label, "this path could not be read")
        return []
    sources.append(f"{label} ({len(files)} file{'' if len(files) == 1 else 's'})")
    if skipped:
        warnings.append(
            f"{label}: {skipped} file(s) skipped (not .json, .jsonl, .json.gz or .jsonl.gz)"
        )
    if folders:
        # A count only: folder names are external data (a user or tenant id may be one).
        warnings.append(f"{label}: {folders} sub-folder(s) skipped (the scan does not descend)")
    return files


def _read_file(
    file: Path, keys: frozenset[str], only_trace: str | None, budget: _Budget, raw: list[RawSpan]
) -> None:
    jsonl = file.name.lower().endswith((".jsonl", ".jsonl.gz"))
    with closing(_documents(file, jsonl, budget)) as docs:
        _read_docs(docs, file, keys, only_trace, budget, raw)


def _read_docs(
    docs: Iterator[_Doc],
    file: Path,
    keys: frozenset[str],
    only_trace: str | None,
    budget: _Budget,
    raw: list[RawSpan],
) -> None:
    for doc in docs:
        where = f"{file.name}:{doc.line}" if doc.line else file.name
        if doc.problem is not None:
            budget.problem(where, doc.problem)
            if doc.fatal:
                return
            continue
        assert doc.data is not None
        line_reported = False
        try:
            document = json.loads(doc.data, object_pairs_hook=reject_duplicate_keys)
        except (ValueError, RecursionError):
            budget.problem(where, "this is not valid JSON, or repeats a key")
            continue
        try:
            for item in _spans(document, where, keys, only_trace):
                if isinstance(item, _Bad):
                    if not line_reported:
                        line_reported = True
                        budget.problem(where, str(item))
                    continue
                if not budget.add_span():
                    return
                raw.append(item)
        except _Bad as bad:
            if not line_reported:
                budget.problem(where, str(bad))
        if budget.truncated:
            return


def _documents(file: Path, jsonl: bool, budget: _Budget) -> Generator[_Doc]:
    limit = budget.limits.max_line_bytes
    opener = gzip.open if file.name.lower().endswith(".gz") else open
    try:
        if not _is_regular(file):
            yield _Doc(0, problem="this is not a regular file", fatal=True)
            return
        with opener(file, "rb") as stream:
            first = True
            line = 0
            blanks = 0
            while True:
                data = stream.readline(limit + 2) if jsonl else stream.read(limit + 1)
                if not data:
                    return
                line += 1
                if not budget.add_bytes(len(data)):
                    return
                if first and data.startswith(_BOM):
                    data = data[len(_BOM) :]
                if jsonl and not data.strip():
                    blanks += 1
                    if blanks > MAX_BLANK_LINES:
                        yield _Doc(
                            0,
                            problem=f"more than {MAX_BLANK_LINES} blank lines in a row",
                            fatal=True,
                        )
                        return
                    continue
                blanks = 0
                if first:
                    if not data.lstrip().startswith(b"{"):
                        text = _BINARY if _looks_binary(data) else _NOT_OTLP
                        yield _Doc(line, problem=text, fatal=True)
                        return
                    first = False
                if not jsonl:
                    if len(data) > limit:
                        yield _Doc(
                            line,
                            problem=f"this file is larger than {_mib(limit)} MiB "
                            "([observe] max_line_mb)",
                            fatal=True,
                        )
                        return
                    yield _Doc(line, data=data)
                    return
                if len(data.rstrip(b"\r\n")) > limit:
                    yield _Doc(
                        line,
                        problem=f"this line is longer than {_mib(limit)} MiB "
                        "([observe] max_line_mb)",
                    )
                    if not _skip_rest(stream, data, budget):
                        return
                    continue
                yield _Doc(line, data=data)
    except (OSError, EOFError, zlib.error):
        yield _Doc(0, problem="this file could not be read", fatal=True)


def _is_regular(file: Path) -> bool:
    """False for a FIFO, device or socket: opening one could block or read without end."""
    return stat.S_ISREG(os.stat(file).st_mode)


def _looks_binary(head: bytes) -> bool:
    """A NUL byte, or bytes that are not UTF-8 (a cut at the end of head is not counted)."""
    if b"\x00" in head:
        return True
    try:
        codecs.getincrementaldecoder("utf-8")().decode(head[:4096], final=False)
    except UnicodeDecodeError:
        return True
    return False


def _skip_rest(stream: Any, last: bytes, budget: _Budget) -> bool:
    """Read on in bounded chunks to the end of a too-long line. False when the budget ends."""
    while not last.endswith(b"\n"):
        last = stream.readline(_CHUNK)
        if not last:
            return True
        if not budget.add_bytes(len(last)):
            return False
    return True


def _spans(
    document: Any, where: str, keys: frozenset[str], only_trace: str | None
) -> Iterator[RawSpan | _Bad]:
    if isinstance(document, dict) and len(document) == 1 and "result" in document:
        document = document["result"]
    if not isinstance(document, dict) or not isinstance(document.get("resourceSpans"), list):
        raise _Bad("this is not an OTLP document (no resourceSpans list)")
    for resource in document["resourceSpans"]:
        if not isinstance(resource, dict):
            raise _Bad("a resourceSpans entry is not an object")
        scopes = resource.get("scopeSpans")
        if scopes is None:
            if "instrumentationLibrarySpans" in resource:
                raise _Bad("old OTLP format (instrumentationLibrarySpans) is not supported")
            continue
        if not isinstance(scopes, list):
            raise _Bad("scopeSpans is not a list")
        for scope in scopes:
            if not isinstance(scope, dict):
                raise _Bad("a scopeSpans entry is not an object")
            spans = scope.get("spans")
            if spans is None:
                continue
            if not isinstance(spans, list):
                raise _Bad("spans is not a list")
            for span in spans:
                try:
                    made = _span(span, where, keys, only_trace)
                except _Bad as bad:
                    yield bad
                    continue
                if made is not None:
                    yield made


def _span(span: Any, where: str, keys: frozenset[str], only_trace: str | None) -> RawSpan | None:
    if not isinstance(span, dict):
        raise _Bad("a span is not an object")
    trace_id = _hex(span.get("traceId"), _TRACE_ID, "traceId")
    if only_trace is not None and trace_id != only_trace:
        return None
    span_id = _hex(span.get("spanId"), _SPAN_ID, "spanId")
    parent = span.get("parentSpanId")
    parent_id = None if parent in (None, "") else _hex(parent, _SPAN_ID, "parentSpanId")
    name = span.get("name", "")
    if not isinstance(name, str):
        raise _Bad("name is not a string")
    return RawSpan(
        trace_id=trace_id,
        span_id=span_id,
        parent_id=parent_id,
        name=name,
        start_ns=_time(span.get("startTimeUnixNano"), "startTimeUnixNano"),
        end_ns=_time(span.get("endTimeUnixNano"), "endTimeUnixNano"),
        attributes=_attributes(span.get("attributes"), keys),
        where=where,
    )


def _hex(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value) or not int(value, 16):
        raise _Bad(f"{label} is missing or is not a valid non-zero hex id")
    return value.lower()


def _time(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**20:
        return value
    if isinstance(value, str) and _DIGITS.fullmatch(value):
        return int(value)
    raise _Bad(f"{label} is not a non-negative integer")


def _attributes(items: Any, keys: frozenset[str]) -> dict[str, ScalarValue]:
    if items is None:
        return {}
    if not isinstance(items, list):
        raise _Bad("attributes is not a list")
    result: dict[str, ScalarValue] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            raise _Bad("an attribute is not an object with a string key")
        key = item["key"]
        if key not in keys:
            continue
        value = item.get("value")
        if not isinstance(value, dict):
            raise _Bad("an attribute value is not an object")
        scalar = _scalar(value)
        if scalar is not None:
            result[key] = scalar
    return result


def _scalar(value: dict[str, Any]) -> ScalarValue | None:
    """The scalar of an AnyValue, or None for arrays, lists, bytes, and empty values."""
    if "stringValue" in value:
        text = value["stringValue"]
        if isinstance(text, str):
            return text
    elif "boolValue" in value:
        flag = value["boolValue"]
        if isinstance(flag, bool):
            return flag
    elif "intValue" in value:
        number = value["intValue"]
        if isinstance(number, int) and not isinstance(number, bool):
            return number
        if isinstance(number, str) and _INT.fullmatch(number):
            return int(number)
    elif "doubleValue" in value:
        real = value["doubleValue"]
        if isinstance(real, int | float) and not isinstance(real, bool):
            try:
                return float(real)
            except OverflowError:
                raise _Bad("an allowlisted attribute has a number that is too large") from None
        if isinstance(real, str) and real in _DOUBLE_WORDS:
            return _DOUBLE_WORDS[real]
    else:
        return None
    raise _Bad("an allowlisted attribute has a malformed value")
