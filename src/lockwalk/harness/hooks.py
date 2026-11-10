"""Load and check the user's hooks file.

Required: set_identity and SIDE_EFFECTS. Optional: DOOR (with read_door_call, which is
required then), and run_path. A door-like name other than DOOR is a problem, not a no-door file.
Every problem found is reported in one HooksError.
"""

import keyword
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from lockwalk.inventory._python_worker import load_module


@dataclass(frozen=True)
class Hooks:
    set_identity: Callable[[dict[str, Any]], Any]
    side_effects: dict[str, str]  # tool name -> "module.attr" (where the tool looks it up)
    door: str | None
    read_door_call: Callable[..., Any] | None  # set exactly when door is set
    run_path: Callable[..., Any] | None


class HooksError(Exception):
    """The hooks file is missing, raises, or is malformed. Every door test is then ERROR."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = tuple(problems)


def is_dotted_path(value: object) -> bool:
    """A string of at least two parts joined by dots, each a Python identifier."""
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    return len(parts) >= 2 and all(p.isidentifier() and not keyword.iskeyword(p) for p in parts)


def _shown(value: object) -> str:
    """Describe a bad value by its type only; the value itself may be a secret."""
    if isinstance(value, str):
        return f"a str of {len(value)} characters"
    return f"a {type(value).__name__}"


def _side_effect_problems(value: object) -> list[str]:
    if not isinstance(value, dict) or not value:
        return [
            "SIDE_EFFECTS must be a non-empty dict of tool names to "
            f"'module.attribute' paths; it is {_shown(value)}"
        ]
    problems: list[str] = []
    for tool, path in value.items():
        if not isinstance(tool, str) or not tool:
            problems.append(f"SIDE_EFFECTS keys must be non-empty tool names; got {_shown(tool)}")
        elif not is_dotted_path(path):
            problems.append(
                "SIDE_EFFECTS must map tool names to 'module.attribute' paths; "
                f"{tool!r} maps to {_shown(path)}"
            )
    return problems


_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def _is_door_like(name: str, value: object) -> bool:
    """A public string constant with 'door' or 'doors' as a whole word in its name.

    Words are split on underscores and case changes, so MY_DOOR, DOOR_PATH, Door and
    DoorPath match while BACKDOOR, DOORBELL and OUTDOOR_MODE do not. Only strings are
    considered (DOOR itself is a path string), so functions and imports never match.
    """
    if name.startswith("_") or not isinstance(value, str):
        return False
    return any(word.lower() in ("door", "doors") for word in _WORD.findall(name))


def _door_name_problems(module: Any, has_read_door_call: bool) -> list[str]:
    """Problems for a hooks file that seems to mean a door but does not define DOOR.

    A misspelled DOOR would otherwise read as "no door": the door checks would quietly
    weaken. Nothing is guessed or corrected; the user must fix the name.

    DOOR = None is offered as a way out only when read_door_call is absent, because it
    drops read_door_call as well, and advising it would discard a hook the user wrote.
    """
    if hasattr(module, "DOOR"):
        return []
    opt_out = "" if has_read_door_call else " or set DOOR = None"
    problems = [
        f"{name} looks like a misspelling of DOOR; the hook is named exactly DOOR. "
        f"If {name} is deliberate, start the name with an underscore (_{name})" + opt_out
        for name, value in sorted(vars(module).items())
        if _is_door_like(name, value)
    ]
    if has_read_door_call:
        problems.append("read_door_call is defined but DOOR is not; set DOOR to the door path")
    return problems


def load(path: Path) -> Hooks:
    if not path.is_file():
        raise HooksError([f"the hooks file {path.name} was not found"])
    module = load_module(str(path))  # exceptions propagate; the worker reports them as fatal
    problems: list[str] = []
    set_identity = getattr(module, "set_identity", None)
    if set_identity is None:
        problems.append("set_identity is required: a function (subject) -> context manager")
    elif not callable(set_identity):
        problems.append("set_identity must be callable: a function (subject) -> context manager")
    side_effects = getattr(module, "SIDE_EFFECTS", None)
    if not hasattr(module, "SIDE_EFFECTS"):
        problems.append("SIDE_EFFECTS is required: a mapping of tool names to 'module.attribute'")
    else:
        problems.extend(_side_effect_problems(side_effects))
    door = getattr(module, "DOOR", None)
    read_door_call = getattr(module, "read_door_call", None)
    if door is not None and not is_dotted_path(door):
        problems.append(f"DOOR must be a 'module.attribute' path; it is {_shown(door)}")
    elif door is not None and read_door_call is None:
        problems.append("read_door_call is required when DOOR is set")
    elif door is not None and not callable(read_door_call):
        problems.append("read_door_call must be callable: (args, kwargs, result) -> dict")
    problems.extend(_door_name_problems(module, hasattr(module, "read_door_call")))
    run_path = getattr(module, "run_path", None)
    if run_path is not None and not callable(run_path):
        problems.append("run_path must be callable when present")
    if problems:
        raise HooksError(problems)
    return Hooks(
        set_identity=cast(Callable[[dict[str, Any]], Any], set_identity),
        side_effects=dict(cast(dict[str, str], side_effects)),
        door=door,
        read_door_call=read_door_call if door is not None else None,
        run_path=run_path,
    )
