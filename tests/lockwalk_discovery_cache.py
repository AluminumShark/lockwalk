"""A module-scoped, autouse fixture that reads each Python source only once per module.

Discovery imports the target in a worker subprocess, which is slow. Import the fixture
into a test module (with noqa: F401) and every run in that module shares the results.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest

from lockwalk.config import PythonSourceConfig
from lockwalk.inventory.python import PythonSource
from lockwalk.inventory.targets import parse_target
from lockwalk.models import SourceResult


def _module_file(config: PythonSourceConfig, base_dir: Path) -> Path:
    """The file a Python target imports, found from the target alone."""
    module, _, _ = parse_target(config.target)
    if module.endswith(".py"):
        return base_dir / module
    return base_dir / (module.replace(".", "/") + ".py")


def _source_state(config: PythonSourceConfig, base_dir: Path) -> tuple:
    """What a worker's result depends on: the config, the directory, and its .py files."""
    directory = _module_file(config, base_dir).parent
    files = tuple(
        (entry.name, entry.stat().st_size, entry.stat().st_mtime_ns)
        for entry in sorted(directory.glob("*.py"))
    )
    return (config, base_dir, files)


@pytest.fixture(scope="module", autouse=True)
def reuse_discovery() -> Iterator[None]:
    """Read each Python source once for the whole module.

    The inputs are recorded when the source is created (its public constructor arguments),
    and the key adds the size and mtime of every .py file next to the target.
    """
    results: dict[tuple, SourceResult] = {}
    original_init = PythonSource.__init__
    original_read = PythonSource.read
    inputs: dict[int, tuple[PythonSourceConfig, Path]] = {}

    def init(self: PythonSource, config: PythonSourceConfig, base_dir: Path) -> None:
        original_init(self, config, base_dir)
        inputs[id(self)] = (config, base_dir)

    def cached(self: PythonSource) -> SourceResult:
        config, base_dir = inputs[id(self)]
        key = _source_state(config, base_dir)
        if key not in results:
            results[key] = original_read(self)
        return results[key]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(PythonSource, "__init__", init)
        patch.setattr(PythonSource, "read", cached)
        yield
