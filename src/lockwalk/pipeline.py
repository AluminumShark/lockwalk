"""Run steps shared by `lockwalk coverage`, `lockwalk test` and `lockwalk observe`."""

from datetime import date

from lockwalk import waivers as waivers_module
from lockwalk.errors import COMMAND_LINE, StructuralError
from lockwalk.graph.build import build_graph
from lockwalk.inventory.collect import build_inventory, registry_label
from lockwalk.models import AgentGraph, CoverageReport, Inventory
from lockwalk.registry import Registry, load_registry
from lockwalk.settings import RunSettings
from lockwalk.spec_loader import SpecFile, load_spec
from lockwalk.waivers import WaiversFile, apply_waivers, load_waivers


def collect(settings: RunSettings, registry_file: Registry | None) -> tuple[Inventory, AgentGraph]:
    """Read every source, then build the agent graph from the same registry and label.

    Every run gets a graph, registry-only runs included: without a graph, analyze would
    silently skip the never_reaches rules.
    """
    inventory = build_inventory(
        settings.sources, registry=registry_file, registry_path=settings.registry
    )
    graph = build_graph(registry_file, inventory, registry_label=registry_label(settings.registry))
    return inventory, graph


def require_registry_and_spec(settings: RunSettings, command: str) -> tuple[Registry, SpecFile]:
    """Load the registry and the spec, or say which one `command` is missing."""
    if settings.registry is None or settings.spec is None:
        missing = [
            f"{command} needs --{name} (or [lockwalk].{name} in .lockwalk.toml)"
            for name, value in (("registry", settings.registry), ("spec", settings.spec))
            if value is None
        ]
        raise StructuralError(COMMAND_LINE, missing)
    return load_registry(settings.registry), load_spec(settings.spec)


def load_waivers_for(settings: RunSettings, today: date | None = None) -> WaiversFile | None:
    """Load and validate the waivers file, if one is set. Call it before reading any source.

    Pass `today` when the caller applies the waivers later with the same date.
    """
    if settings.waivers is None:
        return None
    run_date = waivers_module.today() if today is None else today
    return load_waivers(settings.waivers, settings.gate, run_date)


def finish(report: CoverageReport, waivers: WaiversFile | None) -> CoverageReport:
    """The last step of a run: apply the waivers to the final report."""
    return report if waivers is None else apply_waivers(report, waivers, waivers_module.today())
