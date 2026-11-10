"""What both policy adapters share: the question, the answer, and the interface.

A query uses the four fields of AuthZEN 1.0. The python adapter hands the
same four fields to the user's decide() function as plain dicts. Every adapter fails
closed: anything that is not a clear allow or deny is an ERROR answer, never a PASS.
"""

import json
from collections.abc import Sequence
from typing import Annotated, Any, Protocol, Self

from pydantic import Field, field_validator, model_validator

from lockwalk.jsonvalues import check_json_value
from lockwalk.models import MAX_QUERY_DEPTH, Frozen, NonEmptyStr, Verdict

# Keys of an AuthZEN response `context` whose string values lockwalk shows as the reason.
REASON_KEYS = ("reason", "reason_admin", "reason_user")


class Entity(Frozen):
    """An AuthZEN subject or resource."""

    type: NonEmptyStr
    id: NonEmptyStr
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("properties")
    @classmethod
    def _properties_are_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_json_value(value, "properties", allow_null=True, max_depth=MAX_QUERY_DEPTH)
        return value


class QueryAction(Frozen):
    name: NonEmptyStr


class Query(Frozen):
    """One question for the IAM: may this subject do this action on this resource?"""

    subject: Entity
    action: QueryAction
    resource: Entity
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("context")
    @classmethod
    def _context_is_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        check_json_value(value, "context", allow_null=True, max_depth=MAX_QUERY_DEPTH)
        return value

    def to_authzen(self) -> dict[str, Any]:
        """The JSON object sent to an AuthZEN PDP; also the arguments decide() gets."""
        return self.model_dump(mode="json")

    def key(self) -> str:
        """Equal exactly when two queries ask the same thing, so each is sent only once."""
        return json.dumps(self.to_authzen(), sort_keys=True, separators=(",", ":"), allow_nan=False)


class Decision(Frozen):
    """The IAM's answer to one query. error is set exactly when the verdict is ERROR."""

    verdict: Verdict
    reason: str | None = None  # masked, then truncated
    # masked, then truncated; never a secret or a response body
    error: str | None = Field(default=None, min_length=1)
    latency_ms: Annotated[float, Field(ge=0, allow_inf_nan=False)] | None = None

    @model_validator(mode="after")
    def _error_iff_error(self) -> Self:
        if (self.verdict is Verdict.ERROR) != (self.error is not None):
            raise ValueError("error must be set exactly when the verdict is error")
        return self


def error_decision(message: str, *, latency_ms: float | None = None) -> Decision:
    """An ERROR answer. The message must already be masked and truncated."""
    return Decision(verdict=Verdict.ERROR, error=message, latency_ms=latency_ms)


class PolicyAdapter(Protocol):
    """Sends questions to one IAM.

    decide gets at most batch_size queries and returns one Decision per query, in order.
    It never raises for a problem with the IAM (timeouts, bad answers, HTTP errors): those
    become ERROR decisions. notes are shown to the user after the run, for example that the
    PDP has no batch endpoint. close stops anything the adapter started.
    """

    @property
    def label(self) -> str: ...

    @property
    def batch_size(self) -> int: ...

    def decide(self, queries: Sequence[Query]) -> list[Decision]: ...

    def notes(self) -> tuple[str, ...]: ...

    def close(self) -> None: ...
