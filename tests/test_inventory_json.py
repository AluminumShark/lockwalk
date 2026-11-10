from pathlib import Path

from lockwalk.config import JsonSourceConfig
from lockwalk.inventory.jsonfile import JsonSource
from lockwalk.models import SourceResult


def read(base_dir: Path, path: str, agents: tuple[str, ...] = ()) -> SourceResult:
    return JsonSource(JsonSourceConfig(path=path, agents=agents), base_dir).read()


def test_array_of_tool_descriptions(write, tmp_path):
    write(
        "tools.json",
        '[{"name": "get_stock_price"},'
        ' {"type": "function", "function": {"name": "execute_trade", "description": "Trade."}}]',
    )
    result = read(tmp_path, "tools.json")
    assert result.ok
    assert result.source.label == "json:tools.json"
    assert [(t.name, t.description) for t in result.tools] == [
        ("get_stock_price", None),
        ("execute_trade", "Trade."),
    ]


def test_mcp_tools_list_shape(write, tmp_path):
    write("tools.json", '{"tools": [{"name": "a", "annotations": {"readOnlyHint": true}}]}')
    result = read(tmp_path, "tools.json")
    assert result.ok
    assert result.tools[0].hints == {"readOnlyHint": True}


def test_missing_file(tmp_path):
    result = read(tmp_path, "missing.json")
    assert not result.ok
    assert result.error is not None
    assert result.error.startswith("file not found:")


def test_invalid_json(write, tmp_path):
    write("tools.json", "[{")
    result = read(tmp_path, "tools.json")
    assert result.error is not None
    assert result.error.startswith("invalid JSON:")


def test_wrong_top_level_shape(write, tmp_path):
    write("tools.json", '{"items": []}')
    assert read(tmp_path, "tools.json").error == (
        "expected a JSON array of tools, or an object with a 'tools' array"
    )


def test_unrecognized_item_keeps_the_other_tools(write, tmp_path):
    write("tools.json", '[{"name": "a"}, 5]')
    result = read(tmp_path, "tools.json")
    assert not result.ok
    assert [t.name for t in result.tools] == ["a"]
    assert result.error == "item 1: cannot recognize a tool in a value of type builtins.int"


def test_agents_are_passed_through(write, tmp_path):
    write("tools.json", '[{"name": "a"}]')
    assert read(tmp_path, "tools.json", agents=("finance-agent",)).agents == ("finance-agent",)


def test_duplicate_names_produce_a_warning(write, tmp_path):
    write("tools.json", '[{"name": "a"}, {"name": "a"}]')
    result = read(tmp_path, "tools.json")
    assert result.ok
    assert len(result.tools) == 1
    assert result.warnings == ("json:tools.json: duplicate tool name 'a' ignored",)


def test_utf8_bom_is_accepted(tmp_path):
    (tmp_path / "tools.json").write_bytes(b'\xef\xbb\xbf[{"name": "a"}]')
    result = read(tmp_path, "tools.json")
    assert result.ok
    assert len(result.tools) == 1


def test_deep_nesting_fails_the_source(tmp_path):
    (tmp_path / "tools.json").write_text("[" * 100000, encoding="utf-8")
    # Most builds raise RecursionError on the way down. A build with a deeper C stack (seen with
    # Python 3.14 on GitHub's Linux and macOS runners) reaches the end and finds the value
    # missing. The source fails either way.
    assert read(tmp_path, "tools.json").error in (
        "invalid JSON: nested too deeply",
        "invalid JSON: Expecting value: line 1 column 100001 (char 100000)",
    )


def test_nan_is_not_valid_json(write, tmp_path):
    write("tools.json", '[{"name": "a", "x": NaN}]')
    error = read(tmp_path, "tools.json").error
    assert error is not None
    assert error.startswith("invalid JSON:")


def test_empty_array_is_ok_with_no_tools(write, tmp_path):
    write("tools.json", "[]")
    result = read(tmp_path, "tools.json")
    assert result.ok
    assert result.tools == ()


def test_top_level_scalar_is_the_shape_error(write, tmp_path):
    write("tools.json", "5")
    assert read(tmp_path, "tools.json").error == (
        "expected a JSON array of tools, or an object with a 'tools' array"
    )


def test_non_utf8_bytes_cannot_be_read(tmp_path):
    (tmp_path / "tools.json").write_bytes(b"\xff\xfe[")
    error = read(tmp_path, "tools.json").error
    assert error is not None
    assert error.startswith("cannot read file:")
