"""Create every configured inventory source, read it, and merge the results."""

from collections.abc import Sequence
from pathlib import Path

from lockwalk.config import McpSourceConfig, PythonSourceConfig
from lockwalk.inventory.base import InventorySource
from lockwalk.inventory.jsonfile import JsonSource
from lockwalk.inventory.mcp import McpSource
from lockwalk.inventory.merge import merge_inventory
from lockwalk.inventory.python import PythonSource
from lockwalk.models import Inventory, SourceResult
from lockwalk.registry import Registry
from lockwalk.settings import SourceEntry

EMPTY_INVENTORY_WARNING = "no tools were found in any source; check the inventory targets"


def make_source(entry: SourceEntry) -> InventorySource:
    """Build the source object that matches an entry's config type."""
    config = entry.config
    if isinstance(config, McpSourceConfig):
        return McpSource(config, entry.base_dir)
    if isinstance(config, PythonSourceConfig):
        return PythonSource(config, entry.base_dir)
    return JsonSource(config, entry.base_dir)


def registry_label(registry_path: Path | None) -> str:
    """The source label of the registry, shared by the inventory and the agent graph."""
    return f"registry:{registry_path.name}" if registry_path is not None else "registry"


def build_inventory(
    entries: Sequence[SourceEntry],
    *,
    registry: Registry | None,
    registry_path: Path | None,
) -> Inventory:
    """Read every source in order and merge the results with the registry.

    When every source was read without a problem, none of them returned a tool, and the
    registry declares none either, the inventory warns: the targets are probably wrong.
    A source that failed already has its own error, so it gets no extra warning.
    """
    results: list[SourceResult] = []
    for entry in entries:
        source = make_source(entry)
        # A snapshot gives back one result per source it saved.
        results.extend(source.read_all() if isinstance(source, JsonSource) else [source.read()])
    inventory = merge_inventory(
        results, registry=registry, registry_label=registry_label(registry_path)
    )
    nothing_found = all(result.ok and not result.tools for result in results)
    if results and nothing_found and (registry is None or not registry.tools):
        inventory = inventory.model_copy(
            update={"warnings": (*inventory.warnings, EMPTY_INVENTORY_WARNING)}
        )
    return inventory
