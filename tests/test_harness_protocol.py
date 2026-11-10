"""Worker protocol models and reduce_subject."""

import pytest
from pydantic import ValidationError

from lockwalk.harness.protocol import (
    DirectJob,
    Observation,
    ScriptedJob,
    SurveyJob,
    TargetRef,
    ToolInfo,
    WorkerRequest,
    WorkerResult,
    reduce_subject,
)
from lockwalk.models import MAX_QUERY_DEPTH


def test_reduce_subject_keeps_type_id_and_the_act_chain_only() -> None:
    subject = {
        "type": "user",
        "id": "alice",
        "properties": {
            "roles": ["analyst"],
            "token": "secret",
            "act": {"type": "agent", "id": "b", "act": {"type": "agent", "id": "a"}},
        },
    }
    assert reduce_subject(subject) == {
        "type": "user",
        "id": "alice",
        "act": {"type": "agent", "id": "b", "act": {"type": "agent", "id": "a"}},
    }
    assert reduce_subject({"type": "agent", "id": "x", "properties": {"k": 1}}) == {
        "type": "agent",
        "id": "x",
    }


@pytest.mark.parametrize(
    "value",
    [
        None,
        "alice",
        {"type": "user"},
        {"type": "user", "id": 5},
        {"type": "", "id": "a"},
        {"type": "user", "id": "a", "properties": {"act": {"type": "agent"}}},
    ],
)
def test_reduce_subject_rejects_malformed_subjects(value: object) -> None:
    assert reduce_subject(value) is None


def test_reduce_subject_caps_the_depth() -> None:
    link: dict[str, object] = {"type": "agent", "id": "a0"}
    for i in range(MAX_QUERY_DEPTH + 5):
        link = {"type": "agent", "id": f"a{i + 1}", "act": link}
    assert reduce_subject({"type": "user", "id": "u", "properties": {"act": link}}) is None


def test_reduce_subject_is_idempotent_for_a_two_link_chain() -> None:
    subject = {
        "type": "user",
        "id": "alice",
        "properties": {"act": {"type": "agent", "id": "b", "act": {"type": "agent", "id": "a"}}},
    }
    once = reduce_subject(subject)
    assert once is not None and once["act"]["act"] == {"type": "agent", "id": "a"}
    assert reduce_subject(once) == once


def test_reduce_subject_prefers_properties_act_over_a_direct_act() -> None:
    subject = {
        "type": "user",
        "id": "alice",
        "act": {"type": "agent", "id": "direct"},
        "properties": {"act": {"type": "agent", "id": "props"}},
    }
    assert reduce_subject(subject) == {
        "type": "user",
        "id": "alice",
        "act": {"type": "agent", "id": "props"},
    }


def test_worker_result_holds_exactly_one_thing() -> None:
    WorkerResult(fatal="boom")
    WorkerResult(observation=Observation())
    with pytest.raises(ValidationError):
        WorkerResult()
    with pytest.raises(ValidationError):
        WorkerResult(fatal="boom", observation=Observation())


def test_jobs_round_trip_through_json() -> None:
    for job in (
        SurveyJob(),
        DirectJob(case_id="C", tool="t", args={"x": 1}, subject={"type": "user", "id": "a"}),
        ScriptedJob(
            case_id="C",
            route=("a", "b"),
            tool="t",
            args={},
            subject={"type": "user", "id": "a"},
        ),
    ):
        request = WorkerRequest(
            hooks="/abs/hooks.py",
            targets=(TargetRef(target="app:agents", base_dir="/abs"),),
            allow_hosts=(),
            job=job,
        )
        assert WorkerRequest.model_validate_json(request.model_dump_json()) == request


def test_tool_info_why_not_iff_not_callable() -> None:
    ToolInfo(name="t", kind="function")
    ToolInfo(name="t", kind="pydantic_ai", callable=False, why_not="takes a RunContext")
    with pytest.raises(ValidationError):
        ToolInfo(name="t", kind="function", callable=False)
    with pytest.raises(ValidationError):
        ToolInfo(name="t", kind="function", why_not="x")


@pytest.mark.parametrize("field", ["side_effect_calls", "door_calls_dropped"])
@pytest.mark.parametrize("value", [True, "1", -1, 1.0])
def test_observation_counts_must_be_real_non_negative_ints(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Observation.model_validate({field: value})
    assert Observation.model_validate({field: 2}).model_dump()[field] == 2
