import pytest

from lockwalk.errors import StructuralError
from lockwalk.spec_loader import load_spec

GOOD = """
schema_version: '1'
scenario_suite: finance-demo-v1
cases:
  - id: CASE-001
    actor: alice
    role: analyst
    agent: finance-agent
    tool: get_stock_price
    action: market:read
    resource_fixture: TSMC
    expect: allow
  - id: CASE-004
    actor: alice
    role: analyst
    agent: research-agent
    tool: execute_trade
    action: trade:execute
    resource_fixture: dummy-order
    expect: deny
    reason: Research agent cannot execute trades
"""


def problems_of(write, text: str) -> tuple[str, ...]:
    path = write("security-spec.yaml", text)
    with pytest.raises(StructuralError) as info:
        load_spec(path)
    return info.value.problems


def test_loads_a_valid_spec(write):
    spec = load_spec(write("security-spec.yaml", GOOD))
    assert spec.scenario_suite == "finance-demo-v1"
    assert [case.id for case in spec.cases] == ["CASE-001", "CASE-004"]
    assert spec.cases[1].reason == "Research agent cannot execute trades"
    assert spec.tool_names() == {"get_stock_price", "execute_trade"}


def test_duplicate_case_id(write):
    text = GOOD.replace("id: CASE-004", "id: CASE-001")
    assert problems_of(write, text) == ("cases[1].id: duplicate case id 'CASE-001'",)


def test_missing_expect(write):
    text = GOOD.replace("    expect: allow\n", "")
    assert problems_of(write, text) == ("cases[0].expect: Field required",)


def test_expect_must_be_lowercase(write):
    [problem] = problems_of(write, GOOD.replace("expect: allow", "expect: ALLOW"))
    assert problem.startswith("cases[0].expect: Input should be 'allow' or 'deny'")


def test_unquoted_no_gets_a_hint(write):
    [problem] = problems_of(write, GOOD.replace("resource_fixture: TSMC", "resource_fixture: NO"))
    assert problem.startswith("cases[0].resource_fixture: Input should be a valid string")
    assert "put the value in quotes" in problem


def test_empty_cases_are_allowed(write):
    spec = load_spec(
        write("security-spec.yaml", "schema_version: '1'\nscenario_suite: s\ncases: []\n")
    )
    assert spec.cases == ()


def test_scenario_suite_is_required(write):
    assert problems_of(write, "schema_version: '1'\ncases: []\n") == (
        "scenario_suite: Field required",
    )


def test_top_level_must_be_a_mapping(write):
    [problem] = problems_of(write, "[]\n")
    assert "must contain a mapping" in problem


def test_empty_file(write):
    assert problems_of(write, "") == ("the file is empty",)


RULES = """\
schema_version: '1'
scenario_suite: s
cases:
  - id: CASE-1
    actor: a
    role: analyst
    path: [supervisor, finance-agent]
    tool: t
    action: x:y
    resource_fixture: f
    expect: deny
never_reaches:
  - id: RULE-1
    role: analyst
    tool: t
  - id: RULE-2
    agent: supervisor
    target_agent: trade-agent
"""


def test_never_reaches_rules_load(write):
    spec = load_spec(write("spec.yaml", RULES))
    assert [rule.id for rule in spec.never_reaches] == ["RULE-1", "RULE-2"]
    assert spec.cases[0].route == ("supervisor", "finance-agent")


def test_rule_ids_must_be_unique_and_differ_from_case_ids(write):
    text = RULES.replace("RULE-2", "RULE-1")
    assert "never_reaches[1].id: duplicate rule id 'RULE-1'" in problems_of(write, text)
    text = RULES.replace("RULE-2", "CASE-1")
    assert "never_reaches[1].id: id 'CASE-1' is already used by a case" in problems_of(write, text)
