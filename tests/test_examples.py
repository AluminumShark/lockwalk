from lockwalk.config import JsonSourceConfig, PythonSourceConfig
from lockwalk.inventory.jsonfile import JsonSource
from lockwalk.inventory.python import PythonSource
from lockwalk.registry import load_registry
from lockwalk.spec_loader import load_spec

DECLARED = ["get_stock_price", "read_portfolio", "execute_trade"]


def test_example_registry_and_spec_are_valid(example_dir):
    registry = load_registry(example_dir / "registry.yaml")
    spec = load_spec(example_dir / "security-spec.yaml")
    assert [tool.id for tool in registry.tools] == DECLARED
    assert [case.id for case in spec.cases] == ["CASE-001", "CASE-002", "CASE-003", "CASE-004"]


def test_langchain_example_is_collected(repo_root):
    config = PythonSourceConfig(target="examples.finance_agent.langchain_tools:FINANCE_TOOLS")
    result = PythonSource(config, repo_root).read()
    assert result.ok, result.error
    assert [tool.name for tool in result.tools] == DECLARED


def test_json_example_is_collected(example_dir):
    result = JsonSource(JsonSourceConfig(path="tools.json"), example_dir).read()
    assert result.ok, result.error
    assert [tool.name for tool in result.tools] == DECLARED
