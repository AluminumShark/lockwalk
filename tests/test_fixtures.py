from pathlib import Path

import pytest

from lockwalk.errors import StructuralError
from lockwalk.fixtures import load_fixtures
from lockwalk.registry import Registry

REGISTRY = Registry.model_validate(
    {
        "schema_version": "1",
        "roles": ["analyst", "trader"],
        "agents": [{"id": "trade-agent"}, {"id": "finance-agent"}],
        "tools": [{"id": "execute_trade", "action": "trade:execute", "risk": "critical"}],
    }
)

GOOD = """
schema_version: '1'
subjects:
  alice: {roles: [analyst]}
  bob:   {roles: [trader], properties: {desk: asia, limits: {daily: 5}}}
agents:
  trade-agent: {properties: {service_account: svc-trade}}
resources:
  alice-portfolio: {type: portfolio, id: p-alice, properties: {owner: alice}}
  bob-order: {type: order, id: o-1, properties: {amount: 5000}, tool_args: {order_id: o-1}}
probes:
  subjects: {analyst: alice, trader: bob}
  resources: {order: bob-order}
"""


def load(tmp_path: Path, text: str, registry: Registry = REGISTRY):
    path = tmp_path / "fixtures.yaml"
    path.write_text(text, encoding="utf-8")
    return load_fixtures(path, registry)


def test_good_file(tmp_path: Path) -> None:
    fixtures = load(tmp_path, GOOD)
    assert fixtures.subjects["bob"].properties == {"desk": "asia", "limits": {"daily": 5}}
    assert fixtures.resources["bob-order"].tool_args == {"order_id": "o-1"}
    assert fixtures.probes.subjects == {"analyst": "alice", "trader": "bob"}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("schema_version: '1'\nextra: 1\n", "extra"),
        ("schema_version: '2'\n", "schema_version"),
        ("schema_version: '1'\nsubjects: {a: {}}\n", "roles"),
        (
            "schema_version: '1'\nsubjects: {a: {roles: [x], properties: {roles: [y]}}}\n",
            "set by lockwalk",
        ),
        (
            "schema_version: '1'\nsubjects: {a: {roles: [x], properties: {act: 1}}}\n",
            "set by lockwalk",
        ),
        ("schema_version: '1'\nagents: {trade-agent: {properties: {act: 1}}}\n", "set by lockwalk"),
        ("schema_version: '1'\nresources: {r: {properties: {p: null}}}\n", "must be a string"),
        ("schema_version: '1'\nresources: {r: {properties: {p: .nan}}}\n", "finite"),
        ("schema_version: '1'\nagents: {ghost: {}}\n", "not declared in the registry"),
        (
            "schema_version: '1'\nprobes: {subjects: {admin: alice}}\n"
            "subjects: {alice: {roles: [admin]}}\n",
            "not in the registry roles list",
        ),
        ("schema_version: '1'\nprobes: {subjects: {analyst: nobody}}\n", "not under subjects"),
        (
            "schema_version: '1'\nprobes: {subjects: {analyst: bob}}\n"
            "subjects: {bob: {roles: [trader]}}\n",
            "does not have role",
        ),
        ("schema_version: '1'\nprobes: {resources: {order: nothing}}\n", "not under resources"),
        (
            "schema_version: '1'\nprobes: {resources: {order: r}}\n"
            "resources: {r: {type: portfolio}}\n",
            "must have type 'order'",
        ),
        ("", "empty"),
        ("- a\n", "mapping"),
    ],
)
def test_problems(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(StructuralError, match=message):
        load(tmp_path, text)


def test_probe_subjects_need_registry_roles(tmp_path: Path) -> None:
    registry = REGISTRY.model_copy(update={"roles": None})
    with pytest.raises(StructuralError, match="no top-level roles list"):
        load(
            tmp_path,
            "schema_version: '1'\nprobes: {subjects: {analyst: alice}}\n"
            "subjects: {alice: {roles: [analyst]}}\n",
            registry,
        )


def test_deep_nesting_is_rejected(tmp_path: Path) -> None:
    deep = "x"
    for _ in range(10):
        deep = "{a: " + deep + "}"
    with pytest.raises(StructuralError, match="nested more than"):
        load(tmp_path, f"schema_version: '1'\nresources: {{r: {{properties: {{p: {deep}}}}}}}\n")


def test_yaml_aliases_are_rejected(tmp_path: Path) -> None:
    text = (
        "schema_version: '1'\n"
        "resources:\n"
        "  r:\n"
        "    properties:\n"
        "      a: &shared [1, 2]\n"
        "      b: *shared\n"
    )
    with pytest.raises(StructuralError, match="more than once"):
        load(tmp_path, text)


def test_tool_args_error_names_the_field(tmp_path: Path) -> None:
    text = "schema_version: '1'\nresources: {r: {tool_args: {a: null}}}\n"
    with pytest.raises(StructuralError, match="tool_args"):
        load(tmp_path, text)
