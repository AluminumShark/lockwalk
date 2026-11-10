"""Evidence fields on report rows."""

import pytest
from pydantic import TypeAdapter, ValidationError

from lockwalk.harness.protocol import Observation, TimelineEntry
from lockwalk.models import (
    CaseRow,
    ControlRow,
    DoorControlRow,
    EvidenceRefs,
    IdentityCheckRow,
    IdentityResult,
    RunId,
)


def test_rows_have_no_evidence_by_default() -> None:
    assert ControlRow(action="a", resource_type="r", allowed=False).evidence is None
    assert DoorControlRow(tool="t", proven=False).evidence is None
    row = IdentityCheckRow(case_id="C", path=("a",), tool="t", result=IdentityResult.NOT_RUN)
    assert row.evidence is None


def test_evidence_ids_are_checked() -> None:
    assert TypeAdapter(EvidenceRefs).validate_python(("E-0001", "E-12345")) == (
        "E-0001",
        "E-12345",
    )
    for bad in (("E-1",), ("e-0001",), ("E-0001x",), ("Q-0001",)):
        with pytest.raises(ValidationError):
            TypeAdapter(EvidenceRefs).validate_python(bad)


def test_run_id_is_32_lowercase_hex() -> None:
    TypeAdapter(RunId).validate_python("0" * 32)
    for bad in ("0" * 31, "A" * 32, "g" * 32):
        with pytest.raises(ValidationError):
            TypeAdapter(RunId).validate_python(bad)


def test_case_row_keeps_actor_and_role() -> None:
    row = CaseRow(
        id="C",
        agent="a",
        tool="t",
        action="x:y",
        expect="deny",
        status="UNTESTED",
        action_verified=True,
        problems=(),
        actor="alice",
        role="analyst",
    )
    assert (row.actor, row.role) == ("alice", "analyst")


def test_timeline_entry_shapes() -> None:
    TimelineEntry(seq=1, at_ms=0.0, kind="effect", tool="t")
    TimelineEntry(seq=2, at_ms=1.5, kind="door", data={"subject": {"type": "user", "id": "a"}})
    TimelineEntry(seq=3, at_ms=2.0, kind="identity", data={"type": "user", "id": "a"})
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=0.0, kind="effect")  # no tool
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=0.0, kind="door")  # no data
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=0.0, kind="effect", tool="t", data={})  # effect has no data
    with pytest.raises(ValidationError):
        TimelineEntry(seq=0, at_ms=0.0, kind="effect", tool="t")
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=-1.0, kind="effect", tool="t")


def test_timeline_entry_rejects_odd_combinations_and_lax_numbers() -> None:
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=0.0, kind="identity", tool="t", data={"type": "user"})
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=0.0, kind="door", tool="t", data={"decision": True})
    with pytest.raises(ValidationError):
        TimelineEntry(seq=1, at_ms=0.0, kind="identity", data=None)
    with pytest.raises(ValidationError):
        TimelineEntry.model_validate({"seq": 1, "at_ms": "1", "kind": "effect", "tool": "t"})
    with pytest.raises(ValidationError):
        Observation.model_validate({"elapsed_ms": "1"})
    TimelineEntry.model_validate({"seq": 1, "at_ms": 1, "kind": "effect", "tool": "t"})


def test_observation_timeline_defaults() -> None:
    seen = Observation()
    assert seen.timeline == () and seen.timeline_dropped == 0 and seen.elapsed_ms is None
