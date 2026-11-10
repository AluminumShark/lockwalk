"""One check for "this value is plain JSON", shared by queries and fixtures.

The walk is iterative and linear: every non-empty list, tuple, or mapping is visited once,
and error paths are built only when something fails. Empty-string keys are rejected on
purpose (lockwalk never needs them). A non-empty container that shows up twice in one value
is rejected, which stops YAML aliases ("billion laughs") and cycles before anything
serializes the value. Empty containers cannot expand, so they may repeat.
"""

from typing import Any

# A link is (parent_link, segment); the root has link None. The segment is a raw key or index.
Link = tuple[Any, str | int] | None

_PATH_LIMIT = 200
_PATH_HEAD = 100
_PATH_TAIL = 97


class DuplicateKeyError(ValueError):
    """A JSON object repeats a key. The message never quotes the key."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """An object_pairs_hook for json.loads: refuse an object that repeats a key."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("a JSON object repeats a key")
        result[key] = value
    return result


def _render(where: str, link: Link) -> str:
    """Format where plus the chain as `where.key[2].other`, capped at 200 characters."""
    segments: list[str | int] = []
    while link is not None:
        link, segment = link
        segments.append(segment)
    parts = [where]
    parts.extend(f"[{s}]" if isinstance(s, int) else f".{s}" for s in reversed(segments))
    path = "".join(parts)
    if len(path) > _PATH_LIMIT:
        path = f"{path[:_PATH_HEAD]}...{path[-_PATH_TAIL:]}"
    return path


def check_json_value(value: object, where: str, *, allow_null: bool, max_depth: int) -> None:
    """Raise ValueError unless value is plain JSON no deeper than max_depth.

    The root is at depth 0 and its children at depth 1. `where` names the value in
    messages, for example `where[2].key`.
    """
    seen: set[int] = set()
    stack: list[tuple[object, Link, int]] = [(value, None, 0)]
    while stack:
        item, link, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(f"{_render(where, link)} is nested more than {max_depth} levels deep")
        if isinstance(item, str | int):
            continue
        if isinstance(item, float):
            if item != item or item in (float("inf"), float("-inf")):
                raise ValueError(f"{_render(where, link)} must be a finite number")
            continue
        if item is None and allow_null:
            continue
        if isinstance(item, list | tuple | dict):
            if item:
                if id(item) in seen:
                    raise ValueError(
                        f"{_render(where, link)} uses the same list or mapping more than once "
                        "(for example through a YAML alias); write each one out"
                    )
                seen.add(id(item))
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str) or not key:
                        raise ValueError(f"{_render(where, link)} keys must be non-empty strings")
                    stack.append((child, (link, key), depth + 1))
            else:
                stack.extend((child, (link, i), depth + 1) for i, child in enumerate(item))
            continue
        null = ", null" if allow_null else ""
        raise ValueError(
            f"{_render(where, link)} must be a string, number, boolean{null}, list, or mapping "
            f"(not {type(item).__name__})"
        )
