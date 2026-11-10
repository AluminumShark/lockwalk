"""build_inventory: read every source, merge them, and warn about an empty inventory."""

from pathlib import Path

from lockwalk.config import JsonSourceConfig
from lockwalk.inventory.collect import EMPTY_INVENTORY_WARNING, build_inventory, registry_label
from lockwalk.registry import Registry
from lockwalk.settings import SourceEntry

NO_TOOLS = Registry.model_validate({"schema_version": "1", "agents": [], "tools": []})


def json_entry(tmp_path: Path, name: str, text: str | None) -> SourceEntry:
    if text is not None:
        (tmp_path / name).write_text(text, encoding="utf-8")
    return SourceEntry(config=JsonSourceConfig(path=name), base_dir=tmp_path)


def test_the_warning_text():
    assert EMPTY_INVENTORY_WARNING == (
        "no tools were found in any source; check the inventory targets"
    )


def test_every_source_empty_and_no_registry_warns_once(tmp_path):
    entries = [json_entry(tmp_path, "a.json", "[]"), json_entry(tmp_path, "b.json", "[]")]
    inventory = build_inventory(entries, registry=None, registry_path=None)
    assert inventory.errors == ()
    assert inventory.warnings == (EMPTY_INVENTORY_WARNING,)


def test_a_registry_without_tools_still_warns(tmp_path):
    entries = [json_entry(tmp_path, "a.json", "[]")]
    inventory = build_inventory(entries, registry=NO_TOOLS, registry_path=tmp_path / "r.yaml")
    assert inventory.warnings == (EMPTY_INVENTORY_WARNING,)


def test_no_warning_when_the_registry_declares_tools(tmp_path, finance_registry):
    entries = [json_entry(tmp_path, "a.json", "[]")]
    registry = Registry.model_validate(finance_registry)
    inventory = build_inventory(entries, registry=registry, registry_path=tmp_path / "r.yaml")
    assert EMPTY_INVENTORY_WARNING not in inventory.warnings


def test_no_warning_when_some_source_found_a_tool(tmp_path):
    entries = [
        json_entry(tmp_path, "a.json", "[]"),
        json_entry(tmp_path, "b.json", '[{"name": "t"}]'),
    ]
    inventory = build_inventory(entries, registry=None, registry_path=None)
    assert [tool.id for tool in inventory.tools] == ["t"]
    assert EMPTY_INVENTORY_WARNING not in inventory.warnings


def test_no_warning_when_a_source_failed(tmp_path):
    """The failure is already an error; the warning would hide why nothing was found."""
    entries = [json_entry(tmp_path, "a.json", "[]"), json_entry(tmp_path, "missing.json", None)]
    inventory = build_inventory(entries, registry=None, registry_path=None)
    assert inventory.errors
    assert EMPTY_INVENTORY_WARNING not in inventory.warnings


def test_no_warning_without_any_discovery_source():
    inventory = build_inventory([], registry=NO_TOOLS, registry_path=Path("registry.yaml"))
    assert inventory.warnings == ()


def test_registry_label():
    assert registry_label(Path("conf") / "registry.yaml") == "registry:registry.yaml"
    assert registry_label(None) == "registry"
