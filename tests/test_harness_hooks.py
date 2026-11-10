import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from lockwalk.harness import hooks


@pytest.fixture(autouse=True)
def _clean_modules() -> Iterator[None]:
    before = set(sys.modules)
    path = list(sys.path)
    yield
    for name in set(sys.modules) - before:
        if name.startswith("_lockwalk_target_"):
            del sys.modules[name]
    sys.path[:] = path


def write(tmp_path: Path, body: str, name: str = "hooks_file.py") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


GOOD = """
def set_identity(subject):
    return None

SIDE_EFFECTS = {"execute_trade": "app.trading.place_order"}
"""


def problems_of(path: Path) -> tuple[str, ...]:
    with pytest.raises(hooks.HooksError) as info:
        hooks.load(path)
    return info.value.problems


def test_a_minimal_file_loads(tmp_path: Path) -> None:
    loaded = hooks.load(write(tmp_path, GOOD))
    assert loaded.side_effects == {"execute_trade": "app.trading.place_order"}
    assert loaded.door is None and loaded.read_door_call is None and loaded.run_path is None
    assert callable(loaded.set_identity)


def test_a_full_file_loads(tmp_path: Path) -> None:
    body = (
        GOOD
        + """
DOOR = "app.auth.check"

def read_door_call(args, kwargs, result):
    return {}

def run_path(route, subject, tool, args):
    return None
"""
    )
    loaded = hooks.load(write(tmp_path, body))
    assert loaded.door == "app.auth.check"
    assert callable(loaded.read_door_call) and callable(loaded.run_path)


def test_a_missing_file(tmp_path: Path) -> None:
    assert problems_of(tmp_path / "nope.py") == ("the hooks file nope.py was not found",)


def test_read_door_call_without_a_door_is_a_problem(tmp_path: Path) -> None:
    found = problems_of(write(tmp_path, GOOD + "\nread_door_call = 5\n"))
    assert len(found) == 1
    assert "read_door_call is defined but DOOR is not" in found[0]


@pytest.mark.parametrize(
    "name", ["DOORS", "door", "Door", "DOOR_PATH", "MY_DOOR", "doors", "DoorPath", "MY_DOORS_"]
)
def test_a_misspelled_door_name_is_a_problem(tmp_path: Path, name: str) -> None:
    found = problems_of(write(tmp_path, GOOD + f'\n{name} = "app.auth.check"\n'))
    assert len(found) == 1
    assert f"{name} looks like a misspelling of DOOR" in found[0]
    assert "app.auth.check" not in found[0]


def test_a_misspelled_door_is_never_used_as_the_door(tmp_path: Path) -> None:
    body = GOOD + '\nDOORS = "app.auth.check"\ndef read_door_call(a, k, r):\n    return {}\n'
    assert len(problems_of(write(tmp_path, body))) == 2


@pytest.mark.parametrize(
    "extra",
    [
        "",
        'BACKDOOR_TOKEN = "x"',
        'BACKDOOR = "x"',
        'DOORBELL = "x"',
        'INDOORS = "x"',
        'OUTDOOR_MODE = "x"',
        "_door = 1",
        "def door_check():\n    return 1",
        "import os as door",
        'DOOR = "app.auth.check"\nDOORS = "other"\ndoor = "x"\n'
        "def read_door_call(a, k, r):\n    return {}",
        "DOOR = None\nDOORS = 5",
        "DOORS = 5",
        'DOORS = ["a"]',
    ],
)
def test_other_door_like_names_stay_silent(tmp_path: Path, extra: str) -> None:
    hooks.load(write(tmp_path, GOOD + "\n" + extra + "\n"))


def test_read_door_call_is_required_with_a_door(tmp_path: Path) -> None:
    problems = problems_of(write(tmp_path, GOOD + '\nDOOR = "app.auth.check"\n'))
    assert problems == ("read_door_call is required when DOOR is set",)


def test_read_door_call_must_be_callable(tmp_path: Path) -> None:
    body = GOOD + '\nDOOR = "app.auth.check"\nread_door_call = 3\n'
    assert "read_door_call must be callable" in problems_of(write(tmp_path, body))[0]


def test_all_problems_are_reported_together(tmp_path: Path) -> None:
    body = """
set_identity = "not callable"
SIDE_EFFECTS = {"execute_trade": 5, "": "a.b", "x": "nodots", "y": "a.1b"}
DOOR = "single"
run_path = 3
"""
    problems = problems_of(write(tmp_path, body))
    joined = "\n".join(problems)
    assert "set_identity must be callable" in joined
    assert (
        "SIDE_EFFECTS must map tool names to 'module.attribute' paths; "
        "'execute_trade' maps to a int" in problems
    )
    assert "SIDE_EFFECTS keys must be non-empty tool names; got a str of 0 characters" in problems
    assert "'x' maps to a str of 6 characters" in joined
    assert "'y' maps to a str of 4 characters" in joined
    assert "nodots" not in joined and "a.1b" not in joined
    assert "DOOR must be a 'module.attribute' path; it is a str of 6 characters" in problems
    assert "run_path must be callable" in joined
    assert len(problems) == 7


def test_missing_required_hooks(tmp_path: Path) -> None:
    problems = problems_of(write(tmp_path, "X = 1\n"))
    assert len(problems) == 2
    assert problems[0].startswith("set_identity is required")
    assert problems[1].startswith("SIDE_EFFECTS is required")


@pytest.mark.parametrize("value", ["{}", "[]", "None", "'a.b'"])
def test_side_effects_must_be_a_non_empty_mapping(tmp_path: Path, value: str) -> None:
    body = f"def set_identity(s):\n    return None\nSIDE_EFFECTS = {value}\n"
    (problem,) = problems_of(write(tmp_path, body))
    assert problem.startswith("SIDE_EFFECTS must be a non-empty dict")


def test_an_import_error_propagates(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="boom"):
        hooks.load(write(tmp_path, "raise RuntimeError('boom')\n"))


def test_the_misspelling_message_names_both_ways_out(tmp_path: Path) -> None:
    found = problems_of(write(tmp_path, GOOD + '\nFRONT_DOOR = "abc"\n'))
    assert len(found) == 1
    message = found[0]
    assert "start the name with an underscore (_FRONT_DOOR)" in message
    assert "set DOOR = None" in message
    assert "abc" not in message


def test_the_misspelling_message_omits_door_none_when_a_reader_is_defined(
    tmp_path: Path,
) -> None:
    # DOOR = None drops read_door_call, so it must not be offered to someone who wrote one.
    body = GOOD + '\nFRONT_DOOR = "abc"\ndef read_door_call(a, k, r):\n    return {}\n'
    found = problems_of(write(tmp_path, body, "reader.py"))
    message = next(line for line in found if line.startswith("FRONT_DOOR"))
    assert "start the name with an underscore (_FRONT_DOOR)" in message
    assert "DOOR = None" not in message
    assert "abc" not in message


def test_each_way_out_the_message_names_really_works(tmp_path: Path) -> None:
    private = hooks.load(write(tmp_path, GOOD + '\n_FRONT_DOOR = "abc"\n', "private.py"))
    deliberate = hooks.load(
        write(tmp_path, GOOD + '\nFRONT_DOOR = "abc"\nDOOR = None\n', "deliberate.py")
    )
    assert private.door is None and deliberate.door is None


def test_both_ways_out_at_once_and_an_underscore_only_door_word_stay_silent(
    tmp_path: Path,
) -> None:
    body = GOOD + '\nDOOR = None\nFRONT_DOOR = "abc"\n_FRONT_DOOR = "abc"\n_DOOR = "abc"\n'
    assert hooks.load(write(tmp_path, body, "door_none.py")).door is None
