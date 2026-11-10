"""Secrets in MCP env and header values: the ${VAR} syntax, expansion, and hiding.

lockwalk never puts an env or header value into a SourceResult, an error, a label, a
report, a snapshot, or terminal output. This module also hides values that a careless
server echoes back (in its name, a tool, or an error message), and pydantic's own
quoting of inputs, which can hold such an echo.
"""

import json
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from pydantic import ValidationError

from lockwalk.errors import format_loc
from lockwalk.models import ToolDescriptor

# In env and header values, "$$" is a literal "$" and "${NAME}" is replaced from the
# environment when lockwalk connects. A name is any run of characters other than
# whitespace, "$", "{", "}" and "=" (so Windows names such as ProgramFiles(x86) work).
VARIABLE_REFERENCE = re.compile(r"\$(?:\$|\{(?P<name>[^\s${}=]+)\})")
# pydantic's error text quotes the input (shortened to its first and last characters),
# which may be a server's echo of a secret, cut where no full value can be matched.
PYDANTIC_INPUT_START = "input_value="
PYDANTIC_INPUT_END = ", input_type="
# lockwalk itself never shows a value of any length. These limits only decide which values
# it also hides in what a server sends back. Shorter values are too short to be credentials
# and too common ("1", "true", "info") to hide without garbling messages.
MIN_HIDDEN_LENGTH = 8
# Names (tool names, the server name) are checked only against token-like values, because
# config words such as "postgres_main" often appear in tool names by chance, and a tool
# whose name holds a hidden value is left out.
MIN_HIDDEN_NAME_LENGTH = 16


class SetupError(Exception):
    """env or headers cannot be prepared for a connection. Messages never hold a value."""


class UnsetVariableError(SetupError):
    """A ${NAME} reference names an environment variable that is not set."""

    def __init__(self, name: str) -> None:
        super().__init__(f"environment variable '{name}' is not set")


def check_template(value: str, where: str) -> None:
    """Check the '$' syntax of an env or header value. Messages never include the value."""
    if "$" in VARIABLE_REFERENCE.sub("", value):
        raise ValueError(f"{where}: a '$' must start a '${{NAME}}' reference or be written as '$$'")
    for match in VARIABLE_REFERENCE.finditer(value):
        name = match.group("name")
        if name is not None and not name.isprintable():
            raise ValueError(f"{where}: a variable name must not contain control characters")


def is_header_text(value: str) -> bool:
    """Whether a header value has only printable ASCII, spaces, and tabs."""
    return all(char == "\t" or " " <= char <= "~" for char in value)


def header_value_problem(key: str, value: str, *, template: bool) -> str | None:
    """What is wrong with a header value, naming only the key; None if it can be sent.

    HTTP libraries quote a value they reject in their error text, so lockwalk checks first.
    With template=True the value is not expanded yet, and ${NAME} references are skipped.
    """
    text = VARIABLE_REFERENCE.sub("", value) if template else value
    if not is_header_text(text):
        return f"header {key!r}: the value must be printable ASCII"
    if value != value.strip(" \t"):
        return f"header {key!r}: the value must not start or end with whitespace"
    return None


def expand_value(value: str, found: list[str] | None = None) -> str:
    """Replace each ${NAME} with os.environ[NAME] and each $$ with $, in a single pass.

    The value of every variable used is appended to `found`, so it can be hidden too.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group("name")
        if name is None:
            return "$"
        expanded = os.environ.get(name)
        if expanded is None:
            raise UnsetVariableError(name)
        if found is not None:
            found.append(expanded)
        return expanded

    return VARIABLE_REFERENCE.sub(replace, value)


def hidden(what: str) -> str:
    """What replaces a hidden value: the key it came from, never the value."""
    return f"<hidden {what}>"


def left_out(what: str) -> str:
    return f"a tool name contains the value of {what}, so that tool was left out"


def hide_pydantic_inputs(text: str) -> str:
    """Drop the inputs that pydantic's error text quotes.

    On each line, everything from the first 'input_value=' to the last ', input_type=' is
    replaced. This takes linear time: a regex such as 'input_value=.*(?=, input_type=)' is
    quadratic on a hostile message like 'input_value=' * N, which a server can send.
    """
    lines = []
    for line in text.split("\n"):
        start = line.find(PYDANTIC_INPUT_START)
        end = line.rfind(PYDANTIC_INPUT_END)
        if start != -1 and end > start:
            line = line[:start] + "input_value=<not shown>" + line[end:]
        lines.append(line)
    return "\n".join(lines)


def describe_validation_error(exc: ValidationError) -> str:
    """Render a pydantic ValidationError without the inputs it would otherwise quote."""
    problems = [
        f"{format_loc(item['loc'])}: {item['msg']}" if item["loc"] else item["msg"]
        for item in exc.errors(include_input=False, include_url=False)
    ]
    return f"{type(exc).__name__}: {exc.title}: " + "; ".join(problems)


def _forms(value: str) -> tuple[str, ...]:
    """The ways error text may write a value: raw, escaped, and inside str or bytes reprs."""
    data = value.encode("utf-8")
    return (
        value,
        repr(value)[1:-1],
        # A leading '"' makes repr quote with "'", escaping each "'" in the value as "\'",
        # as it does when the value sits in a longer text that holds both quote kinds.
        repr('"' + value)[2:-1],
        ascii(value)[1:-1],
        repr(data)[2:-1],
        repr(b'"' + data)[3:-1],
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
    )


@dataclass(frozen=True, repr=False)
class _Form:
    """One way a value can be written; `what` names its key, such as "env 'API_KEY'"."""

    text: str
    length: int  # of the value it stands for
    what: str


class SecretValues:
    """Expanded env and header values, plus the escaped forms error text may quote them in.

    Each value comes with the key it belongs to. Messages name that key, never the value.
    """

    def __init__(self, values: Iterable[tuple[str, str]]) -> None:
        forms: dict[str, _Form] = {}
        for what, value in values:
            if len(value) < MIN_HIDDEN_LENGTH:
                continue
            for text in _forms(value):
                known = forms.get(text)
                # The first key keeps the form; the length is the longest value it stands for.
                length = max(len(value), known.length) if known else len(value)
                forms[text] = _Form(text, length, known.what if known else what)
        # Longest first, so a value that holds another value is hidden whole.
        self._forms = sorted(forms.values(), key=lambda form: len(form.text), reverse=True)
        self._by_text = {form.text: form for form in self._forms}
        self._pattern = (
            re.compile("|".join(re.escape(form.text) for form in self._forms))
            if self._forms
            else None
        )

    def __bool__(self) -> bool:
        return bool(self._forms)

    def found_in(self, text: str, *, min_length: int = MIN_HIDDEN_LENGTH) -> str | None:
        """The key of a value (at least min_length long) that text holds in any form, or None."""
        for form in self._forms:
            if form.length >= min_length and form.text in text:
                return form.what
        return None

    def found_in_name(self, name: str) -> str | None:
        return self.found_in(name, min_length=MIN_HIDDEN_NAME_LENGTH)

    def scrub(self, text: str) -> str:
        """Replace every value with a marker naming its key, in one pass."""
        if self._pattern is None:
            return text
        return self._pattern.sub(lambda match: hidden(self._by_text[match.group()].what), text)

    def clean_tools(
        self, tools: Sequence[ToolDescriptor], errors: Sequence[str]
    ) -> tuple[list[ToolDescriptor], list[str]]:
        """Hide values in descriptions and errors, and leave out tools named after one."""
        kept: list[ToolDescriptor] = []
        problems = [self.scrub(error) for error in errors]
        for tool in tools:
            what = self.found_in_name(tool.name)
            if what is not None:
                problems.append(left_out(what))
            elif tool.description is not None and self.found_in(tool.description) is not None:
                kept.append(tool.model_copy(update={"description": self.scrub(tool.description)}))
            else:
                kept.append(tool)
        return kept, problems
