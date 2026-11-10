"""observe shared shapes: allowlist, catalog, result models, fixtures."""

from typing import Literal

import pytest
from observe_helpers import DATA, catalog, loose_raw_spans
from pydantic import ValidationError

from lockwalk.config import ObserveConfig, ObserveRule
from lockwalk.errors import StructuralError
from lockwalk.observe.catalog import build_catalog
from lockwalk.observe.keys import BUILTIN_KEYS, SPAN_NAME
from lockwalk.observe.results import (
    ObserveGate,
    ObserveReport,
    ObserveTotals,
    ObserveViolation,
    ObserveWindow,
    RouteRow,
    UnknownRow,
)
from lockwalk.observe.spans import allowlist
from lockwalk.pipeline import collect
from lockwalk.registry import load_registry
from lockwalk.settings import resolve_settings
from lockwalk.spec_loader import load_spec


def test_allowlist_has_builtins_rule_keys_and_mapped_targets() -> None:
    config = ObserveConfig(
        rules=(
            ObserveRule.model_validate(
                {"kind": "agent", "when": {"langfuse.observation.type": "agent"}, "name": SPAN_NAME}
            ),
            ObserveRule.model_validate(
                {
                    "kind": "handoff",
                    "when": {"tpl": "Handoff"},
                    "from": "from_agent",
                    "to": "to_agent",
                }
            ),
        ),
        attributes={"lockwalk.door.decision": "authz.result"},
    )
    keys = allowlist(config)
    assert keys >= BUILTIN_KEYS
    assert {"langfuse.observation.type", "tpl", "from_agent", "to_agent", "authz.result"} <= keys
    assert SPAN_NAME not in keys and "input.value" not in keys


def test_allowlist_has_door_rule_keys_and_tool_call_id_source() -> None:
    config = ObserveConfig(
        rules=(
            ObserveRule.model_validate(
                {
                    "kind": "door",
                    "when": {"app.granted": False},
                    "decision": "deny",
                    "tool_call_id": "app.call",
                }
            ),
            ObserveRule.model_validate({"kind": "effect", "when": {"app.outcome": "done"}}),
        )
    )
    keys = allowlist(config)
    assert {"app.granted", "app.call", "app.outcome"} <= keys


def test_catalog_lookups() -> None:
    known = catalog(
        agent_alias={"Trade Agent": "trade-agent"}, tool_alias={"exec": "execute_trade"}
    )
    assert known.agent_id("trade-agent") == "trade-agent"
    assert known.agent_id("Trade Agent") == "trade-agent" and known.agent_id("x") is None
    assert known.tool_id("exec") == "execute_trade"
    assert "Trade Agent" in known.agent_names


def test_route_row_rules() -> None:
    RouteRow(from_id="a", to_id="b", to_kind="agent", status="ON_MAP", count=1, traces=("t",))
    with pytest.raises(ValidationError):  # OFF_MAP needs a suggestion
        RouteRow(from_id="a", to_id="b", to_kind="agent", status="OFF_MAP", count=1, traces=("t",))
    with pytest.raises(ValidationError):  # the user does not call tools
        RouteRow(from_id="user", to_id="t", to_kind="tool", status="ON_MAP", count=1, traces=("t",))
    with pytest.raises(ValidationError):  # at most 3 examples
        RouteRow(
            from_id="a",
            to_id="b",
            to_kind="agent",
            status="ON_MAP",
            count=4,
            traces=("1", "2", "3", "4"),
        )


def test_violation_fields_match_the_rule() -> None:
    with pytest.raises(ValidationError):
        ObserveViolation(rule="fail_on_off_map_route", kind="agent", name="x")
    with pytest.raises(ValidationError):
        ObserveViolation(rule="fail_on_unknown_component", from_id="a", to_id="b")


def test_report_exit_code_must_match() -> None:
    totals = ObserveTotals(
        files=1,
        traces=1,
        spans=1,
        agent_spans=1,
        tool_calls=0,
        incomplete_traces=0,
        error_traces=0,
        unnamed_markers=0,
    )
    failing = ObserveGate(
        passed=False,
        violations=(ObserveViolation(rule="fail_on_unknown_component", kind="agent", name="x"),),
    )

    def report(
        gate: ObserveGate, errors: tuple[str, ...], exit_code: Literal[0, 1, 2]
    ) -> ObserveReport:
        return ObserveReport(
            scenario_suite="s",
            sources=(),
            totals=totals,
            window=ObserveWindow(),
            gate=gate,
            errors=errors,
            exit_code=exit_code,
        )

    report(failing, (), 1)
    with pytest.raises(ValidationError):
        report(failing, (), 0)
    with pytest.raises(ValidationError):
        report(ObserveGate(passed=True), ("e",), 1)


def _built(config: ObserveConfig):
    settings = resolve_settings(cwd=DATA, config_path=DATA / "observe.toml")
    assert settings.registry is not None and settings.spec is not None
    registry = load_registry(settings.registry)
    inventory, graph = collect(settings, registry)
    return build_catalog(inventory, graph, registry, config, load_spec(settings.spec))


def test_build_catalog_from_the_test_registry() -> None:
    built = _built(ObserveConfig(agents={"Trade Agent": "trade-agent"}))
    assert built.agents == {"supervisor", "trade-agent"}
    assert built.entry_agents == {"supervisor"}
    assert ("supervisor", "trade-agent") in built.agent_edges
    assert ("trade-agent", "execute_trade") in built.tool_edges
    assert built.agent_id("Trade Agent") == "trade-agent"
    assert {"execute_trade", "delegate_trade"} <= built.tools


def test_an_alias_to_a_missing_id_is_refused() -> None:
    with pytest.raises(StructuralError) as caught:
        _built(ObserveConfig(agents={"X": "no-such-agent"}, tools={"Y": "no-tool"}))
    assert "[observe.agents]" in str(caught.value) and "[observe.tools]" in str(caught.value)


def test_the_loose_parser_reads_every_fixture() -> None:
    for path in sorted(DATA.glob("*.json*")):
        assert loose_raw_spans(path.name), path.name


def test_an_alias_key_that_is_a_real_id_is_refused() -> None:
    cases = (
        ObserveConfig(agents={"supervisor": "trade-agent"}),  # real agent id, other target
        ObserveConfig(agents={"execute_trade": "trade-agent"}),  # real tool id
        ObserveConfig(tools={"execute_trade": "delegate_trade"}),
        ObserveConfig(tools={"supervisor": "execute_trade"}),
    )
    for config in cases:
        with pytest.raises(StructuralError, match="already a real"):
            _built(config)
    _built(ObserveConfig(agents={"supervisor": "supervisor"}))  # identity is harmless


def test_gate_passed_matches_violations() -> None:
    violation = ObserveViolation(rule="fail_on_unknown_component", kind="tool", name="x")
    with pytest.raises(ValidationError):
        ObserveGate(passed=True, violations=(violation,))
    with pytest.raises(ValidationError):
        ObserveGate(passed=False)


def test_rows_window_and_exit_code_bounds() -> None:
    with pytest.raises(ValidationError):  # at least one example trace
        RouteRow(from_id="a", to_id="b", to_kind="agent", status="ON_MAP", count=1, traces=())
    with pytest.raises(ValidationError):
        UnknownRow(kind="agent", name="x", count=1, traces=())
    ObserveWindow(first="2026-11-08T10:00:00Z", last="2026-11-08T10:00:01Z")
    with pytest.raises(ValidationError):
        ObserveWindow(first="2026-11-08 10:00:00")


def test_an_agent_named_user_is_refused() -> None:
    settings = resolve_settings(cwd=DATA, config_path=DATA / "observe.toml")
    assert settings.registry is not None and settings.spec is not None
    registry = load_registry(settings.registry)
    inventory, graph = collect(settings, registry)
    first = graph.nodes[0]
    renamed = graph.model_copy(
        update={"nodes": (first.model_copy(update={"id": "user"}), *graph.nodes[1:])}
    )
    with pytest.raises(StructuralError) as caught:
        build_catalog(inventory, renamed, registry, ObserveConfig(), load_spec(settings.spec))
    assert "an agent named 'user' clashes" in str(caught.value)
