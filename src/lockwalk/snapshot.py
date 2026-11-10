"""Offline inventory snapshots: what every discovery source of one run gave, saved as JSON.

A snapshot can be read back later with the JSON source (--tools-json FILE), for example
when the MCP servers it came from cannot be reached. It reads back as the sources it saved,
one each (see inventory/jsonfile.py), and the rule is: for the same registry and spec, a
replay gives the same rule results, role x tool rows, opaque nodes, and hidden tools as the
live run it was saved from. So each saved source keeps everything the agent graph uses:

- its label, kind, and `optional` flag;
- its `agents`, so they reach only this source's tools;
- its tools (name, description, hints);
- the agent graph it discovered (a Python source's GraphFragment: nodes with their opaque
  and tools_hidden flags, and edges), so an agent whose tools could not be read stays
  opaque;
- whether it could be read: an optional source that could not be read is saved as
  "unavailable" and replays as the same opaque mcp_server node.

A source that failed (and is not an unavailable optional one) cannot be replayed honestly,
so no snapshot is written at all: write_snapshot raises SnapshotRefused.

The graph's agent_as_tool edges also keep the names of the wrapper tools discovery read
(`wrapped_by`), which observe uses to know a wrapper. A snapshot saved before that field
existed lacks the names, and a replay then reports such a wrapper as unknown (it fails
closed).

A snapshot never holds MCP env or header values, URLs beyond the already-redacted labels and
remote_url fields (the same values coverage.json shows), errors, or warnings. It may be out
of date by the time it is read.

Version "2". A version "1" file does not hold the agent graph or unread sources, so it is
rejected with a request to save the snapshot again, never read in a way that could give a
false PASS.
"""

import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, NamedTuple, TypeGuard

from pydantic import ValidationError

from lockwalk.errors import format_validation_error
from lockwalk.models import GraphFragment, Inventory, SourceKind, SourceResult, check_name
from lockwalk.output_files import TIMESTAMP_FORMAT, utc_timestamp, write_text_atomic

SNAPSHOT_VERSION = "2"
# A JSON object with this key is a snapshot, whatever else it holds.
SNAPSHOT_KEY = "lockwalk_snapshot"
_TIMESTAMP_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_KINDS: tuple[SourceKind, ...] = ("mcp", "python", "json")
# Every key of a document and of one saved source; any other key is rejected.
_DOCUMENT_KEYS = frozenset({SNAPSHOT_KEY, "captured_at", "sources"})
_SOURCE_KEYS = frozenset({"label", "kind", "status", "optional", "agents", "tools", "graph"})
SourceStatus = Literal["ok", "unavailable"]


class SnapshotRefused(ValueError):
    """The snapshot was not written: some source failed, and leaving it out could make a
    replay pass where the live run did not."""


class SnapshotSource(NamedTuple):
    """One source of a snapshot document, before its tools are validated."""

    label: str
    kind: SourceKind
    status: SourceStatus
    optional: bool
    agents: tuple[str, ...]
    tools: list[Any]  # raw tool items; always empty for an unavailable source
    graph: GraphFragment | None  # the agent graph the source discovered, if any


def failed_sources(inventory: Inventory) -> list[str]:
    """Labels of the discovery sources that a snapshot cannot save: failed, not unavailable."""
    return [
        result.source.label
        for result in inventory.sources
        if result.source.kind != "registry" and not result.ok and not result.unavailable
    ]


def parse_snapshot(data: Mapping[str, Any]) -> tuple[str, list[SnapshotSource]]:
    """Return captured_at and every source of a snapshot document.

    Raise ValueError with a readable message for another version or a bad shape.
    """
    version = data[SNAPSHOT_KEY]
    if version == "1":
        raise ValueError(
            "snapshot version '1' holds neither the agent graph nor the sources that could "
            "not be read, so it cannot be replayed safely; save the snapshot again"
        )
    if version != SNAPSHOT_VERSION:
        raise ValueError(f"unsupported snapshot version {version!r}")
    _no_unknown_keys(data, _DOCUMENT_KEYS, "invalid snapshot")
    captured_at = data.get("captured_at")
    if not _is_timestamp(captured_at):
        raise ValueError("invalid snapshot: captured_at must look like 2026-01-01T00:00:00Z")
    sources = data.get("sources")
    if not isinstance(sources, list):
        raise ValueError("invalid snapshot: 'sources' must be a list")
    return captured_at, [_source(source, index) for index, source in enumerate(sources)]


def _source(source: object, index: int) -> SnapshotSource:
    where = f"invalid snapshot: sources[{index}]"
    if not isinstance(source, dict):
        raise ValueError(f"{where} must be an object")
    _no_unknown_keys(source, _SOURCE_KEYS, where)
    label = source.get("label")
    kind = source.get("kind")
    status = source.get("status")
    optional = source.get("optional")
    items = source.get("tools")
    if not isinstance(label, str) or not isinstance(items, list):
        raise ValueError(f"{where} must have a string 'label' and a 'tools' list")
    if kind not in _KINDS:
        raise ValueError(f"{where}.kind must be one of: {', '.join(_KINDS)}")
    # The kind decides how duplicate tools merge (Python sources may share identical ones),
    # so it must be the kind the label names.
    if not label.startswith(f"{kind}:"):
        raise ValueError(f"{where}.label must start with '{kind}:', the kind of the source")
    if status not in ("ok", "unavailable"):
        raise ValueError(f"{where}.status must be 'ok' or 'unavailable'")
    if not isinstance(optional, bool):
        raise ValueError(f"{where}.optional must be true or false")
    graph = _graph(source.get("graph"), where)
    if status == "unavailable" and (not optional or items or graph is not None):
        raise ValueError(f"{where}: an unavailable source must be optional, with no tools or graph")
    return SnapshotSource(
        label=label,
        kind=kind,
        status=status,
        optional=optional,
        agents=_agents(source.get("agents"), where),
        tools=items,
        graph=graph,
    )


def _no_unknown_keys(data: Mapping[str, Any], known: frozenset[str], where: str) -> None:
    unknown = sorted(str(key) for key in data if key not in known)
    if unknown:
        raise ValueError(f"{where} has unknown keys: {', '.join(unknown)}")


def _graph(value: object, where: str) -> GraphFragment | None:
    """The saved agent graph, checked with the same model as a live Python source's."""
    if value is None:
        return None
    try:
        return GraphFragment.model_validate(value)
    except ValidationError as exc:
        problems = "; ".join(format_validation_error(exc))
        raise ValueError(f"{where}.graph: {problems}") from exc


def _agents(value: object, where: str) -> tuple[str, ...]:
    """The `agents` of one snapshot source, checked like the `agents` of a source config."""
    problem = f"{where}.agents must be a list of agent names"
    if not isinstance(value, list):
        raise ValueError(problem)
    for name in value:
        if not isinstance(name, str):
            raise ValueError(problem)
        try:
            check_name(name)
        except ValueError as exc:
            raise ValueError(f"{problem}: {name!r}: {exc}") from exc
    return tuple(value)


def _is_timestamp(value: object) -> TypeGuard[str]:
    if not isinstance(value, str) or not _TIMESTAMP_SHAPE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def _entry(result: SourceResult) -> dict[str, object]:
    unavailable = result.unavailable
    return {
        "label": result.source.label,
        "kind": result.source.kind,
        "status": "unavailable" if unavailable else "ok",
        "optional": result.optional,
        "agents": list(result.agents),
        "tools": [] if unavailable else [tool.model_dump(mode="json") for tool in result.tools],
        "graph": None
        if unavailable or result.graph is None
        else result.graph.model_dump(mode="json"),
    }


def snapshot_document(inventory: Inventory, *, captured_at: datetime) -> dict[str, object]:
    """Every discovery source (not the registry): read ones and unavailable optional ones.

    Raise SnapshotRefused when some source failed: it cannot be left out, because a replay
    without it could pass where the live run did not.
    """
    failed = failed_sources(inventory)
    if failed:
        raise SnapshotRefused(
            f"these sources failed: {', '.join(failed)}; a snapshot cannot leave a source out, "
            "so fix them first (an MCP source that may be down can be optional = true, "
            "with agents)"
        )
    return {
        SNAPSHOT_KEY: SNAPSHOT_VERSION,
        "captured_at": utc_timestamp(captured_at, name="captured_at"),
        "sources": [
            _entry(result) for result in inventory.sources if result.source.kind != "registry"
        ],
    }


def write_snapshot(inventory: Inventory, path: Path, *, captured_at: datetime) -> list[str]:
    """Write the snapshot atomically (with the same helper as report.write_report).

    Raise SnapshotRefused, and write nothing, when some source failed. Return notes, for
    example the labels of the optional sources that are saved as unavailable.
    """
    document = snapshot_document(inventory, captured_at=captured_at)
    text = json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    write_text_atomic(path, text, prefix=f".{path.name}-")
    unavailable = [result.source.label for result in inventory.sources if result.unavailable]
    if not unavailable:
        return []
    return [
        "the snapshot saves these optional sources as unavailable, because they could not "
        f"be read: {', '.join(unavailable)}"
    ]
