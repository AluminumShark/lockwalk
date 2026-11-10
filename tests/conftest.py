"""Shared pytest fixtures."""

import socket
import textwrap
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from lockwalk.analyzer import analyze
from lockwalk.config import GateConfig
from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import CoverageReport, SourceRef, SourceResult, ToolDescriptor
from lockwalk.planner import plan_cases
from lockwalk.registry import Registry
from lockwalk.spec_loader import SpecFile

REPO_ROOT = Path(__file__).resolve().parents[1]

FINANCE_REGISTRY = {
    "schema_version": "1",
    "agents": [{"id": "research-agent"}, {"id": "finance-agent"}],
    "tools": [
        {
            "id": "get_stock_price",
            "action": "market:read",
            "risk": "low",
            "supported_agents": ["research-agent", "finance-agent"],
        },
        {
            "id": "read_portfolio",
            "action": "portfolio:read",
            "risk": "high",
            "supported_agents": ["finance-agent"],
        },
        {
            "id": "execute_trade",
            "action": "trade:execute",
            "risk": "critical",
            "supported_agents": ["finance-agent"],
        },
    ],
}


def finance_case(
    case_id: str, agent: str, tool: str, action: str, fixture: str, expect: str
) -> dict[str, str]:
    return {
        "id": case_id,
        "actor": "alice",
        "role": "analyst",
        "agent": agent,
        "tool": tool,
        "action": action,
        "resource_fixture": fixture,
        "expect": expect,
    }


FINANCE_CASES = [
    finance_case("CASE-001", "finance-agent", "get_stock_price", "market:read", "TSMC", "allow"),
    finance_case(
        "CASE-002", "finance-agent", "read_portfolio", "portfolio:read", "alice-portfolio", "allow"
    ),
    finance_case(
        "CASE-003", "finance-agent", "read_portfolio", "portfolio:read", "bob-portfolio", "deny"
    ),
    finance_case(
        "CASE-004", "research-agent", "execute_trade", "trade:execute", "dummy-order", "deny"
    ),
]

ReportFactory = Callable[..., CoverageReport]


@pytest.fixture
def finance_registry() -> dict[str, Any]:
    return FINANCE_REGISTRY


@pytest.fixture
def finance_cases() -> list[dict[str, str]]:
    return FINANCE_CASES


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def example_dir() -> Path:
    return REPO_ROOT / "examples" / "finance_agent"


@pytest.fixture
def write(tmp_path: Path) -> Callable[[str, str], Path]:
    """Write dedented text to a file under tmp_path and return its path."""

    def _write(name: str, content: str) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def make_report() -> ReportFactory:
    """Build a CoverageReport for the finance demo (registry + an MCP source).

    extra_tools: names the MCP source reports in addition to the three declared tools.
    cases: replaces the four demo cases. extra_cases: appended to the cases.
    failed_source: label of an extra source that failed.
    """

    def _make(
        *,
        extra_tools: Sequence[str] = (),
        cases: Sequence[dict[str, Any]] | None = None,
        extra_cases: Sequence[dict[str, Any]] = (),
        gate: GateConfig | None = None,
        failed_source: str | None = None,
    ) -> CoverageReport:
        names = ("get_stock_price", "read_portfolio", "execute_trade", *extra_tools)
        discovered = [
            SourceResult(
                source=SourceRef(kind="mcp", label="mcp:finance-tools"),
                ok=True,
                tools=tuple(ToolDescriptor(name=name) for name in names),
            )
        ]
        if failed_source is not None:
            discovered.append(
                SourceResult(
                    source=SourceRef(kind="json", label=failed_source),
                    ok=False,
                    error="file not found: missing.json",
                )
            )
        inventory = merge_inventory(
            discovered,
            registry=Registry.model_validate(FINANCE_REGISTRY),
            registry_label="registry:registry.yaml",
        )
        spec = SpecFile.model_validate(
            {
                "schema_version": "1",
                "scenario_suite": "finance-demo-v1",
                "cases": [*(FINANCE_CASES if cases is None else cases), *extra_cases],
            }
        )
        return analyze(inventory, spec, plan_cases(spec, inventory), gate or GateConfig())

    return _make


# ---- shared by the discovery tests (the CrewAI ones included) ----


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if anything opens a socket or resolves a host name."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the test tried to use the network")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
