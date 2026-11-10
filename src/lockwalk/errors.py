"""Error types, and helpers that turn validation failures into readable messages."""

from collections.abc import Sequence

from pydantic import ValidationError

COMMAND_LINE = "<command line>"

_YAML_BOOL_HINT = (
    " (YAML reads unquoted yes/no/on/off/true/false as booleans; put the value in quotes)"
)


class LockwalkError(Exception):
    """Base class for all lockwalk errors."""


class StructuralError(LockwalkError):
    """A file or command-line value is malformed. The run aborts with exit code 2."""

    def __init__(self, source: str, problems: Sequence[str]) -> None:
        self.source = source
        self.problems = tuple(problems)
        super().__init__(f"{source}: " + "; ".join(self.problems))


def format_loc(loc: Sequence[int | str]) -> str:
    """Format a pydantic error location such as ('tools', 2, 'risk') as 'tools[2].risk'."""
    text = ""
    for part in loc:
        if isinstance(part, int):
            text += f"[{part}]"
        elif text:
            text += f".{part}"
        else:
            text = str(part)
    return text


def format_validation_error(error: ValidationError) -> list[str]:
    """Return one readable line per problem in a pydantic ValidationError."""
    problems: list[str] = []
    for item in error.errors():
        message = item["msg"]
        if item["type"] == "string_type" and isinstance(item.get("input"), bool):
            message += _YAML_BOOL_HINT
        path = format_loc(item["loc"])
        problems.append(f"{path}: {message}" if path else message)
    return problems
