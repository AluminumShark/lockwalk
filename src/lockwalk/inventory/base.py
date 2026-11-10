"""The interface every inventory source implements, plus helpers they share."""

from collections.abc import Iterable, Sequence
from typing import Protocol

from lockwalk.models import SourceRef, SourceResult, ToolDescriptor

ERROR_LIMIT = 300


class InventorySource(Protocol):
    """Something that can report which tools exist. It must never call a tool."""

    def read(self) -> SourceResult: ...


def truncate(message: str, limit: int = ERROR_LIMIT) -> str:
    """Collapse a message onto one line and cut it to at most `limit` characters."""
    message = " ".join(message.split())
    return message if len(message) <= limit else message[: limit - 3] + "..."


def dedupe(
    tools: Iterable[ToolDescriptor], label: str
) -> tuple[tuple[ToolDescriptor, ...], tuple[str, ...]]:
    """Keep the first tool for each name; warn about the rest."""
    seen: dict[str, ToolDescriptor] = {}
    warnings: list[str] = []
    for tool in tools:
        first = seen.get(tool.name)
        if first is not None:
            note = (
                " (its description differs from the first one)"
                if first.description != tool.description
                else ""
            )
            warnings.append(f"{label}: duplicate tool name {tool.name!r} ignored{note}")
        else:
            seen[tool.name] = tool
    return tuple(seen.values()), tuple(warnings)


def failed(source: SourceRef, message: str, *, agents: Sequence[str] = ()) -> SourceResult:
    """A source that produced no usable tools."""
    return SourceResult(source=source, ok=False, error=truncate(message), agents=tuple(agents))


def finish(
    source: SourceRef,
    tools: Iterable[ToolDescriptor],
    errors: Sequence[str],
    agents: Sequence[str],
) -> SourceResult:
    """Build the result of a source that ran. Any item error marks the source as failed."""
    unique, warnings = dedupe(tools, source.label)
    return SourceResult(
        source=source,
        ok=not errors,
        tools=unique,
        error=truncate(_join_errors(errors)) if errors else None,
        warnings=warnings,
        agents=tuple(agents),
    )


def _join_errors(errors: Sequence[str]) -> str:
    joined = "; ".join(errors)
    return f"{len(errors)} problems: {joined}" if len(errors) > 1 else joined
