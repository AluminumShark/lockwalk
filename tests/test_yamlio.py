import pytest

from lockwalk.errors import StructuralError, format_loc
from lockwalk.yamlio import load_yaml


def test_load_yaml_returns_data(write):
    path = write("a.yaml", "a: 1\nb: [x, y]\n")
    assert load_yaml(path) == {"a": 1, "b": ["x", "y"]}


def test_duplicate_key_is_a_structural_error(write):
    path = write("dup.yaml", "tools:\n  - id: a\n    id: b\n")
    with pytest.raises(StructuralError) as info:
        load_yaml(path)
    assert "duplicate key 'id'" in str(info.value)
    assert "line 3" in str(info.value)


def test_invalid_yaml_is_a_structural_error(write):
    with pytest.raises(StructuralError, match="invalid YAML"):
        load_yaml(write("bad.yaml", "a: [1, 2\n"))


def test_missing_file_is_a_structural_error(tmp_path):
    with pytest.raises(StructuralError, match="cannot read file"):
        load_yaml(tmp_path / "missing.yaml")


def test_python_tags_are_not_executed(write):
    path = write("evil.yaml", "a: !!python/object/apply:os.system ['echo hacked']\n")
    with pytest.raises(StructuralError, match="invalid YAML"):
        load_yaml(path)


def test_format_loc():
    assert format_loc(("tools", 2, "risk")) == "tools[2].risk"
    assert format_loc(("cases", 0)) == "cases[0]"
    assert format_loc(()) == ""
    assert format_loc((0, "x")) == "[0].x"


def test_merge_key_override_is_allowed(write):
    path = write("m.yaml", "base: &b {a: 1, b: 2}\nx:\n  <<: *b\n  a: 9\n")
    assert load_yaml(path)["x"] == {"a": 9, "b": 2}


def test_explicit_duplicate_next_to_a_merge_key_is_rejected(write):
    path = write("m.yaml", "base: &b {a: 1}\nx:\n  <<: *b\n  c: 1\n  c: 2\n")
    with pytest.raises(StructuralError, match="duplicate key 'c'"):
        load_yaml(path)


def test_unhashable_key_is_a_structural_error(write):
    with pytest.raises(StructuralError, match="unhashable"):
        load_yaml(write("u.yaml", "? [a]\n: 1\n"))


def test_yaml_errors_are_one_line(write):
    dup = write("dup.yaml", "tools:\n  - id: a\n    id: b\n")
    with pytest.raises(StructuralError) as info:
        load_yaml(dup)
    assert all("\n" not in p for p in info.value.problems)
    assert "(line 3, column 5)" in info.value.problems[0]
    with pytest.raises(StructuralError) as info:
        load_yaml(write("bad.yaml", "a: [1, 2\n"))
    assert all("\n" not in p for p in info.value.problems)


def test_structural_error_fields():
    err = StructuralError("f.yaml", ["a", "b"])
    assert err.source == "f.yaml"
    assert err.problems == ("a", "b")
    assert str(err) == "f.yaml: a; b"


def test_utf8_bom_is_accepted(tmp_path):
    path = tmp_path / "bom.yaml"
    path.write_bytes(b"\xef\xbb\xbfa: 1\n")
    assert load_yaml(path) == {"a": 1}


def test_deeply_nested_yaml_is_a_structural_error(write):
    path = write("deep.yaml", "a: " + "[" * 5000 + "\n")
    with pytest.raises(StructuralError) as info:
        load_yaml(path)
    assert "nested too deeply" in info.value.problems[0]


def test_calendar_invalid_date_is_a_structural_error(write):
    path = write("date.yaml", "when: 2026-02-30\n")
    with pytest.raises(StructuralError) as info:
        load_yaml(path)
    assert info.value.problems[0].startswith("invalid YAML value: ")
