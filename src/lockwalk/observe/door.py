"""The door's authorization records and effect markers."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from lockwalk.config import ObserveConfig
from lockwalk.jsonvalues import DuplicateKeyError, reject_duplicate_keys
from lockwalk.models import MAX_QUERY_DEPTH
from lockwalk.observe.keys import (
    DOOR_ACT,
    DOOR_ACTION,
    DOOR_DECISION,
    DOOR_RESOURCE_TYPE,
    DOOR_SUBJECT_ID,
    DOOR_SUBJECT_TYPE,
    DOOR_TOOL_CALL_ID,
    EFFECT,
    ENDUSER_ID,
    USER_ID,
)

Decision = Literal["allow", "deny", "error"]
MAX_DOOR_TEXT = 512
# A character count over this limit already means the byte count is over it.
MAX_ACT_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class DoorRecord:
    """A door's authorization record.

    subject_type, subject_id and action are None only in a decision-only record, which only a
    [[observe.rules]] door rule makes; act is then () and resource_type None.
    """

    decision: Decision
    subject_type: str | None
    subject_id: str | None = field(repr=False)  # may be a hash; compared for equality only
    act: tuple[tuple[str, str], ...]  # (type, id) per link, outermost first; () when no act
    action: str | None
    resource_type: str | None
    tool_call_id: str | None

    def __post_init__(self) -> None:
        if (self.subject_type is None) != (self.subject_id is None):
            raise ValueError("subject_type and subject_id must both be set or both be None")
        if (self.action is None) != (self.subject_type is None):
            raise ValueError("action must be set exactly when the subject is set")

    @property
    def has_subject(self) -> bool:
        return self.subject_type is not None and self.subject_id is not None


def decision_only(decision: Decision, tool_call_id: str | None) -> DoorRecord:
    """A record with a decision and no subject, from a door rule."""
    return DoorRecord(
        decision=decision,
        subject_type=None,
        subject_id=None,
        act=(),
        action=None,
        resource_type=None,
        tool_call_id=tool_call_id,
    )


@dataclass(frozen=True)
class DoorKeys:
    """The attribute names to read, after [observe.attributes]."""

    decision: str
    subject_type: str
    subject_id: str
    act: str
    action: str
    resource_type: str
    tool_call_id: str
    effect: str
    user: str
    enduser: str

    @classmethod
    def from_config(cls, config: ObserveConfig) -> "DoorKeys":
        m = config.attributes
        return cls(
            decision=m.get(DOOR_DECISION, DOOR_DECISION),
            subject_type=m.get(DOOR_SUBJECT_TYPE, DOOR_SUBJECT_TYPE),
            subject_id=m.get(DOOR_SUBJECT_ID, DOOR_SUBJECT_ID),
            act=m.get(DOOR_ACT, DOOR_ACT),
            action=m.get(DOOR_ACTION, DOOR_ACTION),
            resource_type=m.get(DOOR_RESOURCE_TYPE, DOOR_RESOURCE_TYPE),
            tool_call_id=m.get(DOOR_TOOL_CALL_ID, DOOR_TOOL_CALL_ID),
            effect=m.get(EFFECT, EFFECT),
            user=m.get(USER_ID, USER_ID),
            enduser=ENDUSER_ID,
        )


def check_text(value: object) -> str | None:
    """The value when it is a non-empty string of at most MAX_DOOR_TEXT characters."""
    if isinstance(value, str) and 0 < len(value) <= MAX_DOOR_TEXT:
        return value
    return None


def text_message(subject: str) -> str:
    return f"{subject} must be a non-empty string of at most {MAX_DOOR_TEXT} characters"


def act_links(value: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Walk nested {type, id, act} objects (outermost first) into (type, id) pairs.

    The caller handles an absent act (None); a nested "act": null ends the chain. Raises
    ValueError with a message that never quotes the input. Iterative, so a deep value cannot
    exhaust the stack. Keys other than type, id and act are ignored.
    """
    links: list[tuple[str, str]] = []
    current: object = value
    while current is not None:
        if not isinstance(current, dict):
            raise ValueError("each act link must be an object with type and id")
        if len(links) >= MAX_QUERY_DEPTH:
            raise ValueError(f"act is nested more than {MAX_QUERY_DEPTH} levels deep")
        link_type = check_text(current.get("type"))
        link_id = check_text(current.get("id"))
        if link_type is None or link_id is None:
            raise ValueError(
                f"each act link needs a type and an id, non-empty strings of at most "
                f"{MAX_DOOR_TEXT} characters"
            )
        links.append((link_type, link_id))
        current = current.get("act")
    return tuple(links)


def _read_act(text: object, key: str) -> tuple[tuple[str, str], ...] | str:
    if not isinstance(text, str):
        return f"{key} must be a JSON string"
    if len(text) > MAX_ACT_BYTES or len(text.encode("utf-8", "replace")) > MAX_ACT_BYTES:
        return f"{key} is larger than {MAX_ACT_BYTES // 1024} KiB"
    try:
        value = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except DuplicateKeyError:
        return f"{key} repeats a key"
    except RecursionError:
        return f"{key} is nested too deeply"
    except ValueError:
        return f"{key} is not valid JSON"
    if not isinstance(value, dict):
        return f"{key}: act must be an object"
    try:
        return act_links(value)
    except ValueError as exc:
        return f"{key}: {exc}"


def _required_texts(attributes: Mapping[str, object], names: Sequence[str]) -> dict[str, str] | str:
    texts: dict[str, str] = {}
    for key in names:
        if key not in attributes:
            return f"door record: {key} is missing"
        text = check_text(attributes[key])
        if text is None:
            return f"door record: {text_message(key)}"
        texts[key] = text
    return texts


def _optional_texts(
    attributes: Mapping[str, object], names: Sequence[str]
) -> dict[str, str | None] | str:
    texts: dict[str, str | None] = {}
    for key in names:
        texts[key] = None
        if key in attributes:
            text = check_text(attributes[key])
            if text is None:
                return f"door record: {text_message(key)}"
            texts[key] = text
    return texts


def read_door(attributes: Mapping[str, object], keys: DoorKeys) -> DoorRecord | str | None:
    """None when no door key is present, a problem message when the record is malformed.

    A message names the attribute key and never quotes a value.
    """
    names = (
        keys.decision,
        keys.subject_type,
        keys.subject_id,
        keys.act,
        keys.action,
        keys.resource_type,
        keys.tool_call_id,
    )
    if not any(name in attributes for name in names):
        return None
    required = _required_texts(
        attributes, (keys.decision, keys.subject_type, keys.subject_id, keys.action)
    )
    if isinstance(required, str):
        return required
    decision = required[keys.decision]
    if decision not in ("allow", "deny", "error"):
        return f"door record: {keys.decision} must be allow, deny or error"
    optional = _optional_texts(attributes, (keys.resource_type, keys.tool_call_id))
    if isinstance(optional, str):
        return optional
    act: tuple[tuple[str, str], ...] = ()
    if keys.act in attributes:
        parsed = _read_act(attributes[keys.act], keys.act)
        if isinstance(parsed, str):
            return f"door record: {parsed}"
        act = parsed
    return DoorRecord(
        decision=decision,
        subject_type=required[keys.subject_type],
        subject_id=required[keys.subject_id],
        act=act,
        action=required[keys.action],
        resource_type=optional[keys.resource_type],
        tool_call_id=optional[keys.tool_call_id],
    )


def read_effect(attributes: Mapping[str, object], keys: DoorKeys) -> bool | str:
    """True for a boolean true marker, False when absent or false, a message otherwise."""
    if keys.effect not in attributes:
        return False
    value = attributes[keys.effect]
    if value is True or value is False:
        return value
    return f"effect marker: {keys.effect} must be a boolean"


def read_user(attributes: Mapping[str, object], keys: DoorKeys) -> str | None:
    """The user id (mapped user.id, else enduser.id) when it is a valid text."""
    for key in (keys.user, keys.enduser):
        # A malformed id (not a string, empty, over the limit) counts as absent: fall back.
        user = check_text(attributes.get(key))
        if user is not None:
            return user
    return None
