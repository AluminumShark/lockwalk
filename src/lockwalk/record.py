"""Helpers for a door (an authorization point) to leave lockwalk records in a trace.

This module imports nothing else from lockwalk, and opentelemetry only inside the
functions, so `import lockwalk.record` is cheap and works without OpenTelemetry. Without
it the functions validate their arguments and then do nothing. They take the tracer from
the global TracerProvider; they never create or change one.
"""

import json
from collections.abc import Mapping
from typing import Any

# These names are duplicated from lockwalk.observe.keys on purpose (a test keeps them equal).
_DECISION = "lockwalk.door.decision"
_SUBJECT_TYPE = "lockwalk.door.subject.type"
_SUBJECT_ID = "lockwalk.door.subject.id"
_ACT = "lockwalk.door.act"
_ACTION = "lockwalk.door.action"
_RESOURCE_TYPE = "lockwalk.door.resource.type"
_TOOL_CALL_ID = "lockwalk.door.tool_call_id"
_EFFECT = "lockwalk.effect"

_DECISIONS = ("allow", "deny", "error")
_MAX_ACT_LINKS = 64
# Limits observe enforces when reading; longer values would be rejected there (exit 2).
_MAX_TEXT = 512  # characters, per string
_MAX_ACT_JSON = 65536  # measured in UTF-8 bytes (stricter than characters)


_otel_missing = False


def _otel_trace() -> Any:
    """The opentelemetry.trace module, or None when OpenTelemetry is not installed.

    A failed import is remembered so a missing OTel is not searched for on every call.
    The flag is not locked: two threads may both try the import once, which is harmless.
    """
    global _otel_missing
    if _otel_missing:
        return None
    try:
        from opentelemetry import trace
    except ImportError:
        _otel_missing = True
        return None
    return trace


def _text(value: Any, what: str) -> str:
    """Check one string to be written. Messages name the field and never the value."""
    if not isinstance(value, str):
        raise TypeError(f"{what} must be a string")
    if not value:
        raise ValueError(f"{what} must not be empty")
    if len(value) > _MAX_TEXT:
        raise ValueError(f"{what} is longer than {_MAX_TEXT} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        # Do not chain: the original error message contains the offending character.
        raise ValueError(f"{what} is not valid text") from None
    return value


def _identity(value: Any, what: str) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{what} must be a mapping with 'type' and 'id'")
    return _text(value.get("type"), f"{what}.type"), _text(value.get("id"), f"{what}.id")


def _act_chain(subject: Mapping[str, Any]) -> list[tuple[str, str]]:
    properties = subject.get("properties")
    act = properties.get("act") if isinstance(properties, Mapping) else None
    if act is None:
        act = subject.get("act")
    chain: list[tuple[str, str]] = []
    while act is not None:
        if len(chain) >= _MAX_ACT_LINKS:
            raise ValueError(f"act has more than {_MAX_ACT_LINKS} links")
        chain.append(_identity(act, "subject act link"))
        act = act.get("act")
    return chain


def _nest(chain: list[tuple[str, str]]) -> dict[str, Any]:
    link: dict[str, Any] = {}
    for kind, ident in reversed(chain):
        inner = link
        link = {"type": kind, "id": ident}
        if inner:
            link["act"] = inner
    return link


def record_authz(
    *,
    subject: Mapping[str, Any],
    action: str,
    decision: str,
    resource: Mapping[str, Any] | None = None,
    tool_call_id: str | None = None,
) -> None:
    """Record one authorization decision as a short `lockwalk.door` span.

    Only the subject's type, id and act chain, the action, the resource type and the tool
    call id are written; never the subject's properties or the resource id.
    Raises ValueError for a value over a limit, such as an act chain of more than 64 links.
    """
    if decision not in _DECISIONS:
        raise ValueError(f"decision must be one of {', '.join(_DECISIONS)}")
    subject_type, subject_id = _identity(subject, "subject")
    _text(action, "action")
    resource_type: str | None = None
    if resource is not None:
        if not isinstance(resource, Mapping):
            raise TypeError("resource must be a mapping")
        if resource.get("type") is not None:
            resource_type = _text(resource["type"], "resource.type")
    if tool_call_id is not None:
        _text(tool_call_id, "tool_call_id")
    chain = _act_chain(subject)
    act_json = json.dumps(_nest(chain), separators=(",", ":"), ensure_ascii=False) if chain else ""
    if len(act_json.encode("utf-8")) > _MAX_ACT_JSON:
        raise ValueError(f"subject act chain is longer than {_MAX_ACT_JSON} bytes as JSON")

    trace = _otel_trace()
    if trace is None:
        return
    attributes: dict[str, str] = {
        _DECISION: decision,
        _SUBJECT_TYPE: subject_type,
        _SUBJECT_ID: subject_id,
        _ACTION: action,
    }
    if chain:
        attributes[_ACT] = act_json
    if resource_type is not None:
        attributes[_RESOURCE_TYPE] = resource_type
    if tool_call_id is not None:
        attributes[_TOOL_CALL_ID] = tool_call_id
    tracer = trace.get_tracer("lockwalk.record")
    with tracer.start_as_current_span("lockwalk.door", attributes=attributes):
        pass


def record_effect() -> None:
    """Record that the guarded function really ran, as a short `lockwalk.effect` span."""
    trace = _otel_trace()
    if trace is None:
        return
    tracer = trace.get_tracer("lockwalk.record")
    with tracer.start_as_current_span("lockwalk.effect", attributes={_EFFECT: True}):
        pass
