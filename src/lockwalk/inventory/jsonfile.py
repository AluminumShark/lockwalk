"""Inventory source: a JSON file of tool descriptions. Any language or framework can export one.

The file may also be a lockwalk snapshot (see lockwalk.snapshot). A snapshot is read back as
the sources it saved, one SourceResult each, with the label, kind, `optional` flag, tools,
`agents`, and agent graph that the source had when it was saved; an optional source that
could not be read comes back unavailable, as it was. So the agent graph uses each saved
source exactly as it used the live one: its agents reach only its own tools, an agent whose
tools were hidden stays opaque, and an `mcp:<name>` node on an agent matches the saved
`mcp:<name>` source by label, as live.

`agents` set on the JSON source apply to a plain JSON file only. A snapshot already keeps
each source's agents; extra ones would hand every saved tool to them, which can hide that no
agent is known to use a tool, so a JSON source with `agents` cannot read a snapshot.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from lockwalk.config import JsonSourceConfig
from lockwalk.errors import format_validation_error
from lockwalk.inventory.base import failed, finish, truncate
from lockwalk.inventory.normalize import normalize_items
from lockwalk.models import SourceRef, SourceResult, ToolDescriptor
from lockwalk.snapshot import SNAPSHOT_KEY, SnapshotSource, parse_snapshot

# How many source labels the snapshot warning names before it writes "...".
SHOWN_SNAPSHOT_SOURCES = 3
# The error of a replayed unavailable source. The live error text is never saved.
UNAVAILABLE_IN_SNAPSHOT = "it could not be read when the snapshot was saved"
SNAPSHOT_WITH_AGENTS = (
    "a snapshot keeps each source's agents; remove 'agents' from this [[inventory.json]]"
)


def _reject_constant(name: str) -> object:
    """Reject NaN, Infinity and -Infinity, which Python accepts but JSON does not."""
    raise ValueError(f"{name} is not valid JSON")


class JsonSource:
    def __init__(self, config: JsonSourceConfig, base_dir: Path) -> None:
        self._path = base_dir / config.path
        self._agents = config.agents
        self._ref = SourceRef(kind="json", label=f"json:{config.path}")

    def read(self) -> SourceResult:
        """The one result of a plain JSON file, or of a snapshot that saved one source.

        Raise ValueError for a snapshot of several sources: use read_all() for that.
        """
        results = self.read_all()
        if len(results) != 1:
            raise ValueError(f"{self._ref.label} holds {len(results)} sources; use read_all()")
        return results[0]

    def read_all(self) -> list[SourceResult]:
        """Every result: one for a plain JSON file, one per saved source for a snapshot.

        A file that cannot be read, or a snapshot that is not valid as a whole, gives one
        failed result labeled json:<path>. A snapshot that saved no source gives one empty
        result with that label, so its note is still shown.
        """
        try:
            text = self._path.read_text(encoding="utf-8-sig")
            data = json.loads(text, parse_constant=_reject_constant)
        except FileNotFoundError:
            return [failed(self._ref, f"file not found: {self._path}", agents=self._agents)]
        except RecursionError:
            return [failed(self._ref, "invalid JSON: nested too deeply", agents=self._agents)]
        except UnicodeDecodeError as exc:
            return [failed(self._ref, f"cannot read file: {exc}", agents=self._agents)]
        except ValueError as exc:
            # JSONDecodeError, or the ValueError raised for NaN and Infinity.
            return [failed(self._ref, f"invalid JSON: {exc}", agents=self._agents)]
        except OSError as exc:
            return [failed(self._ref, f"cannot read file: {exc}", agents=self._agents)]
        if isinstance(data, dict) and SNAPSHOT_KEY in data:
            return self._read_snapshot(data)
        items = data.get("tools") if isinstance(data, dict) else data
        if not isinstance(items, list):
            return [
                failed(
                    self._ref,
                    "expected a JSON array of tools, or an object with a 'tools' array",
                    agents=self._agents,
                )
            ]
        tools, errors = normalize_items(items)
        return [finish(self._ref, tools, errors, self._agents)]

    def _read_snapshot(self, data: Mapping[str, Any]) -> list[SourceResult]:
        if self._agents:
            return [failed(self._ref, SNAPSHOT_WITH_AGENTS)]
        try:
            captured_at, sources = parse_snapshot(data)
        except ValueError as exc:
            return [failed(self._ref, str(exc))]
        results = [self._replay(source) for source in sources]
        labels = [source.label for source in sources]
        shown = ", ".join(labels[:SHOWN_SNAPSHOT_SOURCES])
        if len(labels) > SHOWN_SNAPSHOT_SOURCES:
            shown += ", ..."
        origin = f"{len(labels)} source(s): {shown}" if labels else "0 source(s)"
        notes = [
            truncate(
                f"{self._ref.label}: snapshot captured at {captured_at} from {origin}; "
                "it may be out of date"
            )
        ]
        graphs = sum(1 for source in sources if source.graph is not None)
        if graphs:
            notes.append(
                f"{self._ref.label}: the agent graph of {graphs} source(s) comes from the "
                "snapshot, not from your code"
            )
        if not results:
            return [SourceResult(source=self._ref, ok=True, warnings=tuple(notes))]
        first = results[0]
        results[0] = first.model_copy(update={"warnings": (*notes, *first.warnings)})
        return results

    def _replay(self, source: SnapshotSource) -> SourceResult:
        """One saved source, as it was read when the snapshot was saved."""
        ref = SourceRef(kind=source.kind, label=source.label)
        agents = source.agents
        if source.status == "unavailable":
            # Not ok, optional, and without tools: unavailable, as the live source was.
            return SourceResult(
                source=ref, ok=False, optional=True, agents=agents, error=UNAVAILABLE_IN_SNAPSHOT
            )
        tools: list[ToolDescriptor] = []
        errors: list[str] = []
        for index, item in enumerate(source.tools):
            # Snapshot tools are ToolDescriptor JSON, so they are read back as exactly that.
            try:
                tools.append(ToolDescriptor.model_validate(item))
            except ValidationError as exc:
                problems = "; ".join(format_validation_error(exc))
                errors.append(f"item {index} of snapshot {self._ref.label}: {problems}")
        result = finish(ref, tools, errors, agents)
        return result.model_copy(update={"graph": source.graph, "optional": source.optional})
