from typing import get_args

import pytest
from pydantic import ValidationError

from lockwalk.errors import format_validation_error
from lockwalk.models import (
    _GATE_FIELDS,
    EdgeKind,
    Frozen,
    GateRule,
    GateViolation,
    GraphEdge,
    GraphNode,
    Inventory,
    InventoryTool,
    NeverReachesRule,
    NodeKind,
    Provenance,
    Risk,
    SchemaVersion,
    Seconds,
    SpecState,
    TestScenario,
    ToolDescriptor,
    check_name,
)
from lockwalk.urls import redact_url

BASE_CASE = {
    "id": "CASE-001",
    "actor": "alice",
    "role": "analyst",
    "agent": "finance-agent",
    "tool": "get_stock_price",
    "action": "market:read",
    "resource_fixture": "TSMC",
    "expect": "allow",
}


@pytest.mark.parametrize("name", ["get_stock_price", "Search the internet", "a.b-c", "x" * 200])
def test_check_name_accepts(name):
    assert check_name(name) == name


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("", "empty"),
        (" padded", "whitespace"),
        ("tab\t", "whitespace"),
        ("bell\x07", "control"),
        ("evil\ud800", "control"),
        ("a\u2028b", "control"),
        ("a\u2029b", "control"),
        ("a\ue000b", "control"),
        ("x" * 201, "at most"),
    ],
)
def test_check_name_rejects(name, fragment):
    with pytest.raises(ValueError, match=fragment):
        check_name(name)


def test_scenario_accepts_a_minimal_case():
    case = TestScenario.model_validate(BASE_CASE)
    assert case.conditions == {}
    assert case.delegation_mode is None


def test_scenario_rejects_unknown_fields():
    with pytest.raises(ValidationError) as info:
        TestScenario.model_validate({**BASE_CASE, "expected": "deny"})
    assert format_validation_error(info.value) == ["expected: Extra inputs are not permitted"]


def test_scenario_requires_expect():
    data = {key: value for key, value in BASE_CASE.items() if key != "expect"}
    with pytest.raises(ValidationError) as info:
        TestScenario.model_validate(data)
    assert format_validation_error(info.value) == ["expect: Field required"]


@pytest.mark.parametrize("bad", ["ALLOW", "maybe", True])
def test_scenario_expect_is_lowercase_allow_or_deny(bad):
    with pytest.raises(ValidationError):
        TestScenario.model_validate({**BASE_CASE, "expect": bad})


def test_scenario_rejects_nested_conditions():
    with pytest.raises(ValidationError) as info:
        TestScenario.model_validate({**BASE_CASE, "conditions": {"limits": {"max": 1}}})
    assert "condition 'limits' must be a string, number, or boolean" in str(info.value)


def test_scenario_accepts_scalar_conditions():
    case = TestScenario.model_validate(
        {**BASE_CASE, "conditions": {"amount": 100, "env": "prod", "approved": True}}
    )
    assert case.conditions == {"amount": 100, "env": "prod", "approved": True}


def test_unquoted_yaml_boolean_gets_a_hint():
    with pytest.raises(ValidationError) as info:
        TestScenario.model_validate({**BASE_CASE, "resource_fixture": False})
    [problem] = format_validation_error(info.value)
    assert problem.startswith("resource_fixture: Input should be a valid string")
    assert "put the value in quotes" in problem


def test_case_id_pattern():
    with pytest.raises(ValidationError):
        TestScenario.model_validate({**BASE_CASE, "id": "CASE 1"})


def test_models_are_immutable_and_strict_about_fields():
    assert ToolDescriptor.model_config.get("frozen") is True
    assert ToolDescriptor.model_config.get("extra") == "forbid"
    with pytest.raises(ValidationError):
        ToolDescriptor.model_validate({"name": "a", "unexpected": 1})


def test_risk_values():
    assert [risk.value for risk in Risk] == ["low", "medium", "high", "critical", "unknown"]


class _Timed(Frozen):
    timeout: Seconds


class _Versioned(Frozen):
    version: SchemaVersion


def test_seconds_accepts_a_number():
    assert _Timed.model_validate({"timeout": 5}).timeout == 5.0


@pytest.mark.parametrize(
    ("bad", "fragment"),
    [
        (True, "not a boolean"),
        ("5", "must be a number of seconds"),
        (0, "greater than"),
        (601, "less than or equal"),
        (float("nan"), "greater than"),
    ],
)
def test_seconds_rejects(bad, fragment):
    with pytest.raises(ValidationError, match=fragment):
        _Timed.model_validate({"timeout": bad})


@pytest.mark.parametrize("good", [1, "1"])
def test_schema_version_accepts(good):
    assert _Versioned.model_validate({"version": good}).version == "1"


@pytest.mark.parametrize("bad", [True, 2, 1.0, "2"])
def test_schema_version_rejects(bad):
    with pytest.raises(ValidationError):
        _Versioned.model_validate({"version": bad})


@pytest.mark.parametrize("hints", [{"x": 1}, {"x": "yes"}])
def test_hints_must_be_real_booleans(hints):
    with pytest.raises(ValidationError):
        ToolDescriptor(name="a", hints=hints)


def test_hints_accept_booleans():
    assert ToolDescriptor(name="a", hints={"readOnlyHint": True}).hints == {"readOnlyHint": True}


def test_check_name_rejects_invisible_and_trailing_characters():
    with pytest.raises(ValueError, match="control"):
        check_name("a\u200bb")
    with pytest.raises(ValueError, match="whitespace"):
        check_name("trailing\n")


def test_case_id_rejects_trailing_newline():
    with pytest.raises(ValidationError):
        TestScenario.model_validate({**BASE_CASE, "id": "CASE-1\n"})


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_scenario_rejects_non_finite_conditions(bad):
    with pytest.raises(ValidationError, match="finite"):
        TestScenario.model_validate({**BASE_CASE, "conditions": {"amount": bad}})


def test_inventory_tool_lookup():
    tool = InventoryTool(
        id="a",
        action=None,
        risk=Risk.LOW,
        resource_type=None,
        supported_agents=(),
        sources=(),
        description=None,
        hints={},
    )
    inventory = Inventory(agents=(), tools=(tool,), sources=(), drift=None, errors=(), warnings=())
    assert inventory.tool("a") == tool
    assert inventory.tool("zzz") is None


def _lookup_tool(tool_id, description=None):
    return InventoryTool(
        id=tool_id,
        action=None,
        risk=Risk.LOW,
        resource_type=None,
        supported_agents=(),
        sources=(),
        description=description,
        hints={},
    )


def _lookup_inventory(*tools):
    return Inventory(agents=(), tools=tools, sources=(), drift=None, errors=(), warnings=())


def test_inventory_lookup_repeated_id_returns_the_first():
    first = _lookup_tool("dup", "first")
    second = _lookup_tool("dup", "second")
    inventory = _lookup_inventory(_lookup_tool("a"), first, second)
    assert inventory.tool("dup") is first


def test_inventory_lookup_does_not_change_dump_or_equality():
    tools = (_lookup_tool("a"), _lookup_tool("b"))
    touched = _lookup_inventory(*tools)
    untouched = _lookup_inventory(*tools)
    before = touched.model_dump()
    touched.tool("a")
    assert touched.model_dump() == before
    assert "tools_by_id" not in touched.model_dump()
    assert set(touched.model_dump()) == set(Inventory.model_fields)
    assert touched.model_dump_json() == untouched.model_dump_json()
    assert touched == untouched
    assert untouched == touched
    assert repr(touched) == repr(untouched)


def test_inventory_lookup_is_not_stale_after_model_copy_update():
    old = _lookup_tool("old")
    new = _lookup_tool("new")
    inventory = _lookup_inventory(old)
    assert inventory.tool("old") is old
    replaced = inventory.model_copy(update={"tools": (new,)})
    assert replaced.tool("old") is None
    assert replaced.tool("new") is new
    assert inventory.tool("old") is old
    assert inventory.tool("new") is None


def test_inventory_lookup_survives_pickle_and_copies():
    import copy
    import pickle

    tool = _lookup_tool("a")
    inventory = _lookup_inventory(tool)
    inventory.tool("a")
    for clone in (
        pickle.loads(pickle.dumps(inventory)),
        copy.copy(inventory),
        copy.deepcopy(inventory),
        inventory.model_copy(),
        inventory.model_copy(deep=True),
    ):
        assert clone == inventory
        assert clone.tool("a") == tool
        assert clone.tool("zzz") is None
        assert clone.model_dump() == inventory.model_dump()


class _CountingId(str):
    """A str whose equality checks are counted."""

    comparisons = 0

    def __eq__(self, other):
        type(self).comparisons += 1
        return str.__eq__(self, other)

    __hash__ = str.__hash__


def test_inventory_lookup_does_not_scan_the_tools():
    count = 300
    inventory = _lookup_inventory(*(_lookup_tool(f"tool-{i}") for i in range(count)))
    # The probe is the left-hand-priority operand of every comparison, so each
    # comparison against a stored id is counted.
    wanted = [_CountingId(f"tool-{i}") for i in range(count)] + [_CountingId("missing")]
    for _ in range(2):  # the second round runs on the already-built index
        _CountingId.comparisons = 0
        for tool_id in wanted:
            inventory.tool(tool_id)
        # A scan would make about count * count / 2 comparisons.
        assert _CountingId.comparisons <= 2 * len(wanted)


CASE = {
    "id": "C1",
    "actor": "alice",
    "role": "analyst",
    "tool": "t",
    "action": "a:b",
    "resource_fixture": "r",
    "expect": "deny",
}


def test_case_needs_exactly_one_of_agent_or_path():
    assert TestScenario.model_validate({**CASE, "agent": "x"}).route == ("x",)
    assert TestScenario.model_validate({**CASE, "path": ["a", "b"]}).route == ("a", "b")
    for bad in ({}, {"agent": "x", "path": ["x"]}):
        with pytest.raises(ValidationError, match="exactly one of 'agent' or 'path'"):
            TestScenario.model_validate({**CASE, **bad})


def test_case_path_must_not_be_empty():
    with pytest.raises(ValidationError, match="path must not be empty"):
        TestScenario.model_validate({**CASE, "path": []})


def test_never_reaches_rule_needs_one_start_and_one_target():
    rule = NeverReachesRule.model_validate({"id": "R1", "role": "analyst", "tool": "t"})
    assert (rule.agent, rule.role, rule.tool, rule.target_agent) == (None, "analyst", "t", None)
    with pytest.raises(ValidationError, match="exactly one of 'agent' or 'role'"):
        NeverReachesRule.model_validate({"id": "R1", "agent": "a", "role": "r", "tool": "t"})
    with pytest.raises(ValidationError, match="exactly one of 'tool' or 'target_agent'"):
        NeverReachesRule.model_validate({"id": "R1", "agent": "a"})


def test_graph_models_validate_names_and_serialize_enum_values():
    edge = GraphEdge(
        from_id="a", to_id="b", kind=EdgeKind.HANDOFF, provenance=Provenance.DISCOVERED
    )
    assert edge.model_dump(mode="json") == {
        "from_id": "a",
        "to_id": "b",
        "kind": "handoff",
        "provenance": "discovered",
        "sources": [],
        "wrapped_by": [],
    }
    assert GraphNode(id="x").kind is NodeKind.AGENT
    with pytest.raises(ValidationError):
        GraphNode(id="bad\x1bname")


def test_spec_state_values_are_the_rendered_text():
    assert [state.value for state in SpecState] == ["yes", "ERROR"]


def test_path_names_are_validated():
    with pytest.raises(ValidationError):
        TestScenario.model_validate({**CASE, "path": ["ok", "bad\x1bname"]})
    with pytest.raises(ValidationError) as info:
        TestScenario.model_validate({**CASE, "path": [1]})
    assert "path must not be empty" not in str(info.value)


def test_graph_node_never_stores_credentials():
    node = GraphNode(id="x", remote_url="https://user:pw@host/a?k=1#f")
    assert node.remote_url == "https://host/a"


@pytest.mark.parametrize(
    ("rule", "fields", "missing"),
    [
        ("fail_on_unspecified_risk", {"tool": "t"}, "risk"),
        ("require_deny_case_for_risk", {"risk": Risk.HIGH}, "tool"),
        ("never_reaches", {"rule_id": "R1"}, "result"),
        ("fail_on_unspecified_role_risk", {"tool": "t", "risk": Risk.HIGH}, "role"),
    ],
)
def test_gate_violation_needs_the_fields_of_its_rule(rule, fields, missing):
    with pytest.raises(ValidationError, match=f"rule '{rule}' needs fields: {missing}"):
        GateViolation(rule=rule, **fields)
    assert GateViolation(rule="fail_on_unspecified_risk", tool="t", risk=Risk.LOW).tool == "t"


def test_redact_url_never_raises_and_keeps_valid_behavior():
    bad = "https://user:s\uff20cret@host/x"
    assert redact_url(bad) == "<invalid URL>"
    assert GraphNode(id="x", remote_url=bad).remote_url == "<invalid URL>"
    assert redact_url("https://user:pw@host:8080/a/b?k=1#f") == "https://host:8080/a/b"
    assert redact_url("http://host/a") == "http://host/a"


def test_gate_field_table_covers_every_rule():
    assert set(_GATE_FIELDS) == set(get_args(GateRule))


def test_error_rule_row_requires_problems():
    import pytest

    from lockwalk.models import RuleResult, RuleRow

    with pytest.raises(ValueError, match="at least one problem"):
        RuleRow(
            id="r", agent=None, role=None, tool=None, target_agent=None, result=RuleResult.ERROR
        )
