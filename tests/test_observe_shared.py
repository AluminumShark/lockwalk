"""Shared interfaces of observe: door shapes, new Span fields, catalog modes, new result models."""

from dataclasses import FrozenInstanceError, fields
from typing import Literal

import pytest
from observe_helpers import DATA, catalog
from pydantic import ValidationError

from lockwalk.config import ObserveConfig
from lockwalk.observe.catalog import build_catalog
from lockwalk.observe.checks import LinkCounts
from lockwalk.observe.door import DoorKeys, DoorRecord, decision_only
from lockwalk.observe.links import RecordLink
from lockwalk.observe.pipeline import _link_warnings
from lockwalk.observe.results import (
    GuardRow,
    IdentityRow,
    ObserveGate,
    ObserveReport,
    ObserveTotals,
    ObserveViolation,
    ObserveWaived,
    ObserveWindow,
    PathRow,
    RouteRow,
    UnknownRow,
)
from lockwalk.observe.spans import Span, allowlist
from lockwalk.pipeline import collect
from lockwalk.registry import load_registry
from lockwalk.settings import resolve_settings
from lockwalk.spec_loader import load_spec


def _built(config: ObserveConfig, mode: str | None = None):
    settings = resolve_settings(cwd=DATA, config_path=DATA / "observe.toml")
    assert settings.registry is not None and settings.spec is not None
    registry = load_registry(settings.registry)
    inventory, graph = collect(settings, registry)
    if mode is not None:
        nodes = tuple(
            node.model_copy(update={"delegation_mode": mode}) if node.id == "trade-agent" else node
            for node in graph.nodes
        )
        graph = graph.model_copy(update={"nodes": nodes})
    return build_catalog(inventory, graph, registry, config, load_spec(settings.spec))


def test_catalog_modes_and_case_sets() -> None:
    built = _built(ObserveConfig())
    assert built.modes == {"supervisor": None, "trade-agent": None}
    assert (("supervisor", "trade-agent"), "execute_trade") in built.case_routes
    assert ("trade-agent", "execute_trade") in built.case_agents
    assert ("supervisor", "execute_trade") not in built.case_agents


def test_catalog_modes_come_from_the_graph() -> None:
    built = _built(ObserveConfig(), mode="on_behalf_of")
    assert built.modes == {"supervisor": None, "trade-agent": "on_behalf_of"}


def test_catalog_helper_defaults_are_undeclared_and_empty() -> None:
    plain = catalog()
    assert plain.modes == {}
    assert plain.case_routes == frozenset() and plain.case_agents == frozenset()
    given = catalog(modes={"supervisor": "user"}, case_agents=(("trade-agent", "execute_trade"),))
    assert given.modes["supervisor"] == "user"


def test_span_defaults_for_door_fields() -> None:
    span = Span(trace_id="a" * 32, span_id="b" * 16, parent_id=None, kind="other")
    assert span.door is None and span.effect is False
    assert span.user_id is None and span.tool_call_id is None


def test_door_keys_default_and_mapping() -> None:
    keys = DoorKeys.from_config(ObserveConfig())
    assert keys.decision == "lockwalk.door.decision" and keys.effect == "lockwalk.effect"
    assert keys.user == "user.id" and keys.enduser == "enduser.id"
    mapped = DoorKeys.from_config(
        ObserveConfig(
            attributes={
                "lockwalk.door.decision": "authz.result",
                "user.id": "app.user",
                "lockwalk.effect": "app.effect",
            }
        )
    )
    assert (mapped.decision, mapped.user, mapped.effect) == (
        "authz.result",
        "app.user",
        "app.effect",
    )
    assert mapped.action == "lockwalk.door.action" and mapped.enduser == "enduser.id"


def test_allowlist_covers_every_door_key() -> None:
    config = ObserveConfig(attributes={"lockwalk.door.decision": "authz.result"})
    keys = allowlist(config)
    door = DoorKeys.from_config(config)
    for field in fields(door):
        assert getattr(door, field.name) in keys


def _identity(**changes: object) -> IdentityRow:
    base: dict[str, object] = {
        "path": ("supervisor",),
        "tool": "execute_trade",
        "mode": "user",
        "expected": "the trace's user",
        "observed": "the trace's user",
        "result": "MATCH",
        "count": 1,
        "traces": ("t",),
    }
    return IdentityRow.model_validate(base | changes)


def _guard(**changes: object) -> GuardRow:
    base: dict[str, object] = {
        "agent": "a",
        "tool": "x",
        "tool_known": True,
        "counts": {"GUARDED": 1},
        "by_time": 0,
        "effect_without_record": 0,
    }
    return GuardRow.model_validate(base | changes)


def _path_row(**changes: object) -> PathRow:
    base: dict[str, object] = {
        "path": ("a",),
        "tool": "x",
        "incomplete": False,
        "status": "UNTESTED",
        "count": 1,
        "traces": ("t",),
    }
    return PathRow.model_validate(base | changes)


def test_identity_rows() -> None:
    assert _identity().test_results == () and _identity().waived_by is None
    for bad in (
        {"result": "MAYBE"},
        {"mode": "observed"},
        {"count": 0},
        {"traces": ()},
        {"traces": ("1", "2", "3", "4")},
    ):
        with pytest.raises(ValidationError):
            _identity(**bad)


def test_guard_rows() -> None:
    _guard(agent=None, counts={"GUARDED": 2, "BYPASS": 1}, traces=("t",))
    for bad in (
        {"counts": {"GUARDED": 0}},
        {"counts": {"NOPE": 1}},
        {"by_time": -1},
        {"effect_without_record": -1},
        {"traces": ("1", "2", "3", "4")},
    ):
        with pytest.raises(ValidationError):
            _guard(**bad)


def test_path_rows() -> None:
    _path_row()
    for bad in ({"status": "SEEN"}, {"count": 0}, {"traces": ()}):
        with pytest.raises(ValidationError):
            _path_row(**bad)


def _violation_cases() -> list[tuple[dict[str, object], bool]]:
    inconclusive = "fail_on_inconclusive_observation"
    return [
        ({"rule": "fail_on_off_map_route", "from_id": "a", "to_id": "b"}, True),
        ({"rule": "fail_on_off_map_route", "from_id": "a"}, False),
        ({"rule": "fail_on_unknown_component", "kind": "tool", "name": "x"}, True),
        ({"rule": "fail_on_unknown_component", "kind": "tool"}, False),
        ({"rule": "bypass", "tool": "t"}, True),
        ({"rule": "bypass", "tool": "t", "agent": "a"}, True),
        ({"rule": "bypass", "agent": "a"}, False),
        ({"rule": "bypass", "tool": "t", "path": ("a",)}, False),
        ({"rule": "fail_on_unguarded_call", "tool": "t", "agent": "a"}, True),
        ({"rule": "fail_on_unguarded_call"}, False),
        ({"rule": "fail_on_identity_mismatch", "path": ("a",)}, True),
        ({"rule": "fail_on_identity_mismatch", "path": ("a",), "tool": "t"}, True),
        ({"rule": "fail_on_identity_mismatch", "tool": "t"}, False),
        ({"rule": inconclusive, "subject": "identity", "path": ("a",)}, True),
        ({"rule": inconclusive, "subject": "guard", "tool": "t"}, True),
        ({"rule": inconclusive, "subject": "guard", "tool": "t", "agent": "a"}, True),
        ({"rule": inconclusive, "subject": "identity"}, False),
        ({"rule": inconclusive, "subject": "guard"}, False),
        ({"rule": inconclusive, "path": ("a",)}, False),
        ({"rule": inconclusive, "subject": "guard", "tool": "t", "path": ("a",)}, False),
        ({"rule": inconclusive, "subject": "identity", "path": ("a",), "agent": "a"}, False),
        ({"rule": "fail_on_untested_path", "path": ("a",), "tool": "t"}, True),
        ({"rule": "fail_on_untested_path", "path": ("a",)}, False),
        ({"rule": "fail_on_untested_path", "path": ("a",), "tool": "t", "agent": "a"}, False),
        ({"rule": "not_a_rule", "tool": "t"}, False),
    ]


@pytest.mark.parametrize(("given", "valid"), _violation_cases())
def test_violation_rule_table(given: dict[str, object], valid: bool) -> None:
    if valid:
        ObserveViolation.model_validate(given)
    else:
        with pytest.raises(ValidationError):
            ObserveViolation.model_validate(given)


def test_gate_waived_and_report_exit_codes_with_new_violations() -> None:
    bypass = ObserveViolation(rule="bypass", tool="execute_trade", agent="trade-agent")
    totals = ObserveTotals(
        files=1,
        traces=1,
        spans=1,
        agent_spans=1,
        tool_calls=1,
        incomplete_traces=0,
        error_traces=0,
        unnamed_markers=0,
    )
    assert (totals.door_records, totals.records_without_call, totals.records_by_time) == (0, 0, 0)

    def report(gate: ObserveGate, exit_code: Literal[0, 1, 2]) -> ObserveReport:
        return ObserveReport(
            scenario_suite="s",
            sources=(),
            totals=totals,
            window=ObserveWindow(),
            gate=gate,
            exit_code=exit_code,
        )

    failing = report(ObserveGate(passed=False, violations=(bypass,)), 1)
    assert failing.identities == () and failing.guards == () and failing.paths == ()
    assert failing.waivers == ()
    with pytest.raises(ValidationError):
        report(ObserveGate(passed=False, violations=(bypass,)), 0)
    waived = ObserveGate(passed=True, waived=(ObserveWaived(violation=bypass, waiver_id="W1"),))
    ok = report(waived, 0)
    assert ObserveReport.model_validate_json(ok.model_dump_json()) == ok
    with pytest.raises(ValidationError):
        report(waived, 1)
    route = RouteRow(
        from_id="a", to_id="b", to_kind="agent", status="ON_MAP", count=1, traces=("t",)
    )
    assert route.waived_by is None
    assert UnknownRow(kind="tool", name="x", count=1, traces=("t",)).waived_by is None


def test_guard_row_consistency_rules() -> None:
    for bad in (
        {"counts": {}},
        {"counts": {"GUARDED": 2}, "by_time": 3},
        {"counts": {"GUARDED": 1, "UNGUARDED": 1}, "effect_without_record": 2},
        {"counts": {"GUARDED": 2}, "effect_without_record": 1},
        {"counts": {"GUARDED": 1, "BYPASS": 1}},  # non-GUARDED calls need examples
    ):
        with pytest.raises(ValidationError):
            _guard(**bad)
    ok = _guard(
        counts={"GUARDED": 1, "UNGUARDED": 2}, effect_without_record=2, by_time=3, traces=("t",)
    )
    assert ok.effect_without_record == 2


def test_guard_row_counts_are_reordered_and_round_trip() -> None:
    row = _guard(
        counts={"UNGUARDED": 1, "BYPASS": 2, "GUARDED": 3}, traces=("t",), effect_without_record=1
    )
    assert list(row.counts) == ["GUARDED", "BYPASS", "UNGUARDED"]
    again = GuardRow.model_validate_json(row.model_dump_json())
    assert again == row and list(again.counts) == ["GUARDED", "BYPASS", "UNGUARDED"]


def test_shown_text_and_path_bounds() -> None:
    long = "x" * 201
    for bad in (
        {"expected": long},
        {"observed": long},
        {"notes": (long,)},
        {"test_results": (long,)},
    ):
        with pytest.raises(ValidationError):
            _identity(**bad)
    _identity(expected="x" * 200)
    with pytest.raises(ValidationError):
        _guard(tool=long)
    for path in ((), tuple("a" for _ in range(33))):
        with pytest.raises(ValidationError):
            _identity(path=path)
        with pytest.raises(ValidationError):
            _path_row(path=path)
        with pytest.raises(ValidationError):
            ObserveViolation(rule="fail_on_identity_mismatch", path=path)
    _path_row(path=tuple("a" for _ in range(32)))


def test_gate_refuses_a_violation_both_blocking_and_waived() -> None:
    v = ObserveViolation(rule="bypass", tool="t")
    with pytest.raises(ValidationError):
        ObserveGate(
            passed=False, violations=(v,), waived=(ObserveWaived(violation=v, waiver_id="W"),)
        )


def test_report_with_every_row_type_round_trips() -> None:
    totals = ObserveTotals(
        files=1,
        traces=1,
        spans=1,
        agent_spans=1,
        tool_calls=1,
        incomplete_traces=0,
        error_traces=0,
        unnamed_markers=0,
        door_records=2,
        records_without_call=1,
        records_by_time=1,
    )
    violation = ObserveViolation(rule="fail_on_untested_path", path=("a", "?"), tool="x")
    report = ObserveReport(
        scenario_suite="s",
        sources=("f.json",),
        totals=totals,
        window=ObserveWindow(first="2026-11-08T10:00:00Z", last="2026-11-08T10:00:01Z"),
        routes=(
            RouteRow(
                from_id="a", to_id="b", to_kind="agent", status="ON_MAP", count=1, traces=("t",)
            ),
        ),
        unknown=(UnknownRow(kind="tool", name="x", count=1, traces=("t",)),),
        identities=(_identity(notes=("n",), test_results=("CASE-1 direct: MATCH",)),),
        guards=(_guard(counts={"GUARDED": 1, "UNGUARDED": 1}, traces=("t",)),),
        paths=(_path_row(),),
        gate=ObserveGate(passed=True, waived=(ObserveWaived(violation=violation, waiver_id="W"),)),
        exit_code=0,
    )
    assert ObserveReport.model_validate_json(report.model_dump_json()) == report


def test_door_record_equality_and_hash() -> None:
    def make(subject_id: str = "u1") -> DoorRecord:
        return DoorRecord("allow", "user", subject_id, (("agent", "a"),), "act", None, None)

    assert make() == make() and hash(make()) == hash(make())
    assert make() != make("u2")
    assert len({make(), make(), make("u2")}) == 2
    assert "u1" not in repr(make())


def test_ids_stay_out_of_repr_and_span_is_frozen() -> None:
    span = Span(trace_id="a" * 32, span_id="b" * 16, parent_id=None, kind="other", user_id="SECRET")
    assert "SECRET" not in repr(span)
    with pytest.raises(FrozenInstanceError):
        span.user_id = "x"  # ty: ignore[invalid-assignment]
    link = RecordLink("s", "none", None, (), None, False, "SECRET", False)
    assert "SECRET" not in repr(link)


# ---- the waiver tables agree with the gate and the output orders ----


def test_output_orders_are_pinned() -> None:
    from typing import get_args

    from lockwalk.observe import output
    from lockwalk.observe.results import GuardStatus, IdentityResultName, PathStatus

    assert output._GUARD_ORDER == (
        "GUARDED",
        "DENIED",
        "DENIED_UNVERIFIED",
        "BYPASS",
        "UNGUARDED",
        "INCONCLUSIVE",
    )
    assert output._PATH_ORDER == ("TESTED", "TESTED_OTHER_PATH", "UNTESTED")
    assert output._IDENTITY_ORDER == ("MATCH", "OBSERVED", "MISMATCH", "INCONCLUSIVE")
    assert set(output._IDENTITY_ORDER) == set(get_args(IdentityResultName))
    assert set(output._GUARD_ORDER) == set(get_args(GuardStatus))
    assert set(output._PATH_ORDER) == set(get_args(PathStatus))


def test_waiver_tables_match_observe_gate_for_every_status() -> None:
    from typing import get_args

    from lockwalk import waivers
    from lockwalk.config import GateConfig
    from lockwalk.models import Risk
    from lockwalk.observe.checks import observe_gate
    from lockwalk.observe.results import GuardStatus, IdentityResultName, PathStatus

    config = GateConfig()
    risks = {"x": Risk.CRITICAL, "execute_trade": Risk.CRITICAL}

    def rules(**rows: object) -> set[str]:
        gate = observe_gate(rows.pop("routes", ()), (), config, risks=risks, **rows)  # ty: ignore[invalid-argument-type]
        return {violation.rule for violation in gate.violations}

    for status in get_args(IdentityResultName):
        assert rules(identities=(_identity(result=status),)) == set(waivers._IDENTITY_RULES[status])
    for status in get_args(PathStatus):
        assert rules(paths=(_path_row(status=status),)) == set(waivers._PATH_RULES[status])
    for status in get_args(GuardStatus):
        row = _guard(counts={status: 1}, traces=("t",))
        assert rules(guards=(row,)) == set(waivers._guard_rules(row))
    assert set(waivers._IDENTITY_RULES) == set(get_args(IdentityResultName))
    assert set(waivers._PATH_RULES) == set(get_args(PathStatus))
    assert set(waivers._GUARD_RULES) <= set(get_args(GuardStatus))
    for status in ("ON_MAP", "OFF_MAP"):
        row = RouteRow(
            from_id="a",
            to_id="b",
            to_kind="agent",
            status=status,
            count=1,
            traces=("t",),
            suggestion="s" if status == "OFF_MAP" else None,
        )
        assert rules(routes=(row,)) == set(waivers._ROUTE_RULES[status])


def test_decision_only_record_has_no_subject():
    record = decision_only("deny", "c1")
    assert record.subject_type is None
    assert record.subject_id is None
    assert record.action is None
    assert record.act == ()
    assert record.resource_type is None
    assert record.has_subject is False
    assert record.tool_call_id == "c1"
    with_subject = DoorRecord("allow", "user", "u", (), "act", None, None)
    assert with_subject.has_subject is True


def test_no_subject_warning_text():
    assert _link_warnings(LinkCounts(no_subject=2)) == [
        "2 door records have no subject (for example a person's approval); "
        "they count for guard checks only"
    ]
    assert _link_warnings(LinkCounts()) == []


def test_door_record_subject_and_action_go_together():
    for subject_type, subject_id, action in (
        ("user", None, "act"),
        (None, "u", "act"),
        ("user", "u", None),
        (None, None, "act"),
    ):
        with pytest.raises(ValueError):
            DoorRecord("allow", subject_type, subject_id, (), action, None, None)
    assert decision_only("deny", None).has_subject is False
    assert DoorRecord("allow", "user", "u", (), "act", None, None).has_subject is True
