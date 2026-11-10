"""Subprocess side of the Python inventory source.

Run as: python -m lockwalk.inventory._python_worker <target> <output-file>

Importing the user's module runs its top-level code, so it happens in a separate process.
The result is written to <output-file> as JSON, never to stdout, because the user's module
may print while it is being imported.
"""

import importlib
import importlib.util
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from lockwalk.inventory.agent_shapes import discover
from lockwalk.inventory.normalize import (
    NormalizeError,
    describe_error,
    descriptor_from_dict,
    normalize_items,
    tool_key,
)
from lockwalk.inventory.targets import TargetError, parse_target
from lockwalk.models import GraphFragment


def load_module(module_part: str) -> object:
    """Import a module by dotted name, or load it from a .py file path."""
    if not module_part.endswith(".py"):
        return importlib.import_module(module_part)
    path = Path(module_part).resolve()
    if not path.is_file():
        raise TargetError(f"file not found: {path}")
    sys.path.insert(0, str(path.parent))
    # A mangled name keeps a file such as json.py from replacing the real stdlib module.
    spec = importlib.util.spec_from_file_location(f"_lockwalk_target_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise TargetError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def resolve(target: str) -> object:
    """Return the value the target points at, calling it first if it ends with ()."""
    module_part, parts, call = parse_target(target)
    value = load_module(module_part)
    for part in parts:
        try:
            value = getattr(value, part)
        except AttributeError as exc:
            raise TargetError(f"{module_part!r} has no attribute {'.'.join(parts)!r}") from exc
    if call:
        if not callable(value):
            raise TargetError(f"{'.'.join(parts)!r} is not callable, so '()' cannot be used")
        value = value()
    return value


def items_of(value: object) -> list[object]:
    """A list or tuple holds many tools; a description dict or any other object is one tool."""
    if isinstance(value, list | tuple):
        return list(value)
    if isinstance(value, Mapping):
        try:
            descriptor_from_dict(value)
        except NormalizeError as exc:
            raise TargetError(
                "the target is a dict that is not a tool description; "
                "point at a list of tools instead"
            ) from exc
    return [value]


def collect(target: str) -> dict[str, object]:
    """Resolve the target, normalize its tools, and walk its agent graph into a payload."""
    try:
        try:
            items = items_of(resolve(target))
        except TargetError as exc:
            return {"fatal": str(exc)}
        except BaseException as exc:  # the user's code may raise anything, even SystemExit
            return {"fatal": f"importing the target raised {describe_error(exc)}"}
        opened: dict[int, object] = {}
        tools, errors = normalize_items(items, opened=opened)
        fragment, graph_warnings = GraphFragment(), []
        try:
            found = discover(items, covered=opened)
        except BaseException as exc:  # the graph is extra; the tools must still be returned
            graph_warnings = [f"reading the agent graph raised {describe_error(exc)}"]
            # The tools that only the graph walk finds (team members, agents used as tools,
            # task tools, ToolNodes) are missing, so the source must not look complete.
            errors.append(
                f"reading the agent graph raised {describe_error(exc)}; tools that only the "
                "agent graph walk finds may be missing"
            )
        else:
            fragment, graph_warnings = found.fragment, list(found.warnings)
            # Tools that normalize_items never opens: handoff targets, team members, agents
            # used as tools, task tools, and LangGraph ToolNodes.
            seen = {tool_key(tool) for tool in tools}
            for tool in found.tools:
                key = tool_key(tool)
                if key not in seen:
                    seen.add(key)
                    tools.append(tool)
        return {
            "tools": [tool.model_dump(mode="json") for tool in tools],
            "errors": errors,
            "graph": fragment.model_dump(mode="json"),
            "graph_warnings": graph_warnings,
        }
    except BaseException as exc:  # a property may raise anything, even SystemExit
        return {"fatal": f"collecting tools raised {describe_error(exc)}"}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: python -m lockwalk.inventory._python_worker <target> <output-file>",
            file=sys.stderr,
        )
        return 2
    # The worker runs with -P, so the working directory is added only now, after its own
    # imports are done; user modules there cannot shadow the worker's dependencies.
    sys.path.insert(0, os.getcwd())
    payload = collect(argv[1])
    Path(argv[2]).write_text(json.dumps(payload), encoding="utf-8")
    return 0


if __name__ == "__main__":
    code = main(sys.argv)
    sys.stdout.flush()
    sys.stderr.flush()
    # Skip interpreter shutdown: a non-daemon thread started by the user's module would
    # otherwise keep the process alive after the result is already written.
    os._exit(code)
