"""CrewAI test support: skip when crewai is absent, and keep OTEL_SDK_DISABLED local.

crewai may build an OpenTelemetry provider while it is imported, so the variable must be set
before the import. Setting it at module level would also run when crewai is absent (pytest
collects tests/crewai_env in every full run) and would turn every SDK provider in the other
tests into a no-op. So it is set only when crewai can be found, only around the import, and
put back afterwards. The crewai test modules import the autouse fixture below, which sets it
again for each test with monkeypatch, in case crewai reads it later. (A conftest.py in
tests/crewai_env would shadow tests/conftest.py, which other tests import by name.)
"""

import importlib.util
import os
from types import ModuleType

import pytest

VARIABLES = ("OTEL_SDK_DISABLED", "CREWAI_DISABLE_TELEMETRY")  # crewai sends telemetry


def importorskip_crewai(module: str) -> ModuleType:
    """pytest.importorskip(module) for a crewai module, without leaking the environment."""
    if importlib.util.find_spec("crewai") is None:  # does not import crewai
        pytest.skip("crewai is not installed", allow_module_level=True)
    before = {name: os.environ.get(name) for name in VARIABLES}
    os.environ.update(dict.fromkeys(VARIABLES, "true"))
    try:
        return pytest.importorskip(module)
    finally:
        for name, value in before.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.fixture(autouse=True)
def otel_sdk_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """crewai sends telemetry through OpenTelemetry; the tests stay offline. monkeypatch puts
    the variable back after each test, so the other tests keep a working SDK."""
    for name in VARIABLES:
        monkeypatch.setenv(name, "true")
