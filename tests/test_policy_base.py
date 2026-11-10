import pytest
from pydantic import ValidationError

from lockwalk.models import Verdict
from lockwalk.policy.base import Decision, Entity, Query, QueryAction, error_decision


def query(subject_props: dict | None = None, context: dict | None = None) -> Query:
    return Query(
        subject=Entity(type="user", id="alice", properties=subject_props or {"roles": ["analyst"]}),
        action=QueryAction(name="portfolio:read"),
        resource=Entity(type="portfolio", id="p-alice", properties={"owner": "alice"}),
        context=context or {"lockwalk": {"case": "CASE-1", "path": ["a"], "tool": "t"}},
    )


def test_to_authzen_has_the_four_fields() -> None:
    assert query().to_authzen() == {
        "subject": {"type": "user", "id": "alice", "properties": {"roles": ["analyst"]}},
        "action": {"name": "portfolio:read"},
        "resource": {"type": "portfolio", "id": "p-alice", "properties": {"owner": "alice"}},
        "context": {"lockwalk": {"case": "CASE-1", "path": ["a"], "tool": "t"}},
    }


def test_key_ignores_mapping_order_but_not_content() -> None:
    first = query(subject_props={"roles": ["analyst"], "desk": "asia"})
    second = query(subject_props={"desk": "asia", "roles": ["analyst"]})
    third = query(subject_props={"roles": ["trader"], "desk": "asia"})
    assert first.key() == second.key()
    assert first.key() != third.key()


def test_decision_error_is_set_exactly_for_error_verdicts() -> None:
    with pytest.raises(ValidationError):
        Decision(verdict=Verdict.DENY, error="x")
    with pytest.raises(ValidationError):
        Decision(verdict=Verdict.ERROR)
    assert error_decision("timed out after 2s").verdict is Verdict.ERROR


@pytest.mark.parametrize(
    "bad",
    [float("nan"), float("inf"), {1, 2}, b"x", {1: "a"}, object()],
)
def test_non_json_values_are_rejected(bad: object) -> None:
    with pytest.raises(ValidationError, match=r"must be a|finite|keys must"):
        Entity(type="user", id="a", properties={"k": bad})
    with pytest.raises(ValidationError, match=r"must be a|finite|keys must"):
        query(context={"k": [bad]})


def test_json_values_are_accepted() -> None:
    entity = Entity(type="u", id="a", properties={"a": None, "b": [1, [2.5, True]], "c": (1, "x")})
    assert entity.properties["a"] is None


def test_nan_and_none_cannot_make_equal_keys() -> None:
    with pytest.raises(ValidationError):
        query(subject_props={"x": float("nan")})


def test_decision_error_and_latency_are_strict() -> None:
    with pytest.raises(ValidationError):
        Decision(verdict=Verdict.ERROR, error="")
    for bad in (-1.0, float("nan"), float("inf")):
        with pytest.raises(ValidationError):
            Decision(verdict=Verdict.ALLOW, latency_ms=bad)
    assert Decision(verdict=Verdict.ALLOW, latency_ms=0.0).latency_ms == 0.0


def test_query_at_the_max_depth_still_has_a_key() -> None:
    from lockwalk.policy.base import MAX_QUERY_DEPTH

    value: object = 1
    for _ in range(MAX_QUERY_DEPTH - 1):  # properties dict is depth 0, "k" value depth 1
        value = [value]
    built = query(subject_props={"k": value})
    assert built.key()
    deeper = [value]
    with pytest.raises(ValidationError, match="levels deep"):
        query(subject_props={"k": deeper})
