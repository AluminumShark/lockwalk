"""Python inventory targets: '<module>:<attribute>' strings, parsed by one set of rules.

The config uses parse_target to reject a malformed target before any worker starts, and
the worker uses it again to import the target. This module imports nothing from lockwalk,
so it stays cheap to load in the worker process.
"""


class TargetError(Exception):
    """The target string is malformed, or it does not resolve to tools."""


def parse_target(target: str) -> tuple[str, list[str], bool]:
    """Split '<module>:<attr.path>[()]' into (module, attribute parts, call it)."""
    # rpartition keeps Windows drive letters ("C:\x\tools.py:TOOLS") in the module part.
    module_part, separator, attr_part = target.rpartition(":")
    if not separator or not module_part or not attr_part:
        raise TargetError(f"target {target!r} must look like '<module>:<attribute>'")
    call = attr_part.endswith("()")
    if call:
        attr_part = attr_part.removesuffix("()")
    parts = attr_part.split(".")
    if not all(part.isidentifier() for part in parts):
        raise TargetError(f"target {target!r} has an invalid attribute path {attr_part!r}")
    return module_part, parts, call
