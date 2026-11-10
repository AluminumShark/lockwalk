"""Safe YAML loading that rejects duplicate keys instead of silently keeping the last one."""

from pathlib import Path
from typing import Any

import yaml
import yaml.constructor
import yaml.resolver

from lockwalk.errors import StructuralError
from lockwalk.urls import redact_urls

_DETAIL_LIMIT = 300


class _UniqueKeyLoader(yaml.SafeLoader):
    """A SafeLoader that raises on duplicate mapping keys."""


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.Node, deep: bool = False) -> dict:
    if not isinstance(node, yaml.MappingNode):
        raise yaml.constructor.ConstructorError(
            None,
            None,
            f"expected a mapping node, got {getattr(node, 'id', 'unknown')}",
            node.start_mark,
        )
    # Check duplicates among the keys written explicitly in this mapping, before merge keys
    # are flattened in, so a local key may legitimately override a merged one.
    seen: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from None
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_yaml(path: Path) -> Any:
    """Read a YAML file. Any read or parse problem becomes a StructuralError."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise StructuralError(str(path), [f"cannot read file: {exc}"]) from exc
    try:
        # _UniqueKeyLoader is a SafeLoader subclass, so no Python objects are constructed.
        return yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        if exc.problem is None:
            detail = " ".join(str(exc).split())
        else:
            detail = " ".join(exc.problem.split())
        if mark is not None:
            where = f" (line {mark.line + 1}, column {mark.column + 1})"
            raise StructuralError(str(path), [f"invalid YAML{where}: {detail}"]) from exc
        raise StructuralError(str(path), [f"invalid YAML: {detail}"]) from exc
    except yaml.YAMLError as exc:
        detail = " ".join(str(exc).split())
        raise StructuralError(str(path), [f"invalid YAML: {detail}"]) from exc
    except RecursionError as exc:
        raise StructuralError(str(path), ["the file is nested too deeply"]) from exc
    except ValueError as exc:
        # PyYAML's timestamp constructor raises a plain ValueError for dates such as 2026-02-30.
        detail = redact_urls(" ".join(str(exc).split()))
        if len(detail) > _DETAIL_LIMIT:
            detail = detail[: _DETAIL_LIMIT - 3] + "..."
        raise StructuralError(str(path), [f"invalid YAML value: {detail}"]) from exc
