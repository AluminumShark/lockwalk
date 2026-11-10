"""The evidence file format and the coverage.json reader."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from lockwalk.evidence import (
    EVIDENCE_FILE_NAME,
    Event,
    Evidence,
    EvidenceFileError,
    EvidenceHeader,
    event_id,
    invocation_id,
    new_run_id,
    query_id,
    read_evidence,
    write_evidence,
)
from lockwalk.report import REPORT_FILE_NAME, ReportFileError, read_report, write_report

RUN = "ab" * 16
NOW = datetime(2026, 11, 8, 10, 0, 0, tzinfo=UTC)


def sample(count: int = 3) -> Evidence:
    events = [
        Event(event=event_id(1), run=RUN, time=0.0, source="test_runner", type="run.started"),
        Event(
            event=event_id(2),
            run=RUN,
            time=0.01,
            source="policy_adapter",
            type="authz.evaluated",
            query=query_id(1),
            detail={"verdict": "deny"},
        ),
        Event(
            event=event_id(3),
            run=RUN,
            time=0.4,
            source="harness",
            type="door.called",
            case="CASE-1",
            mode="direct",
            invocation=invocation_id(1),
            detail={"subject": {"type": "user", "id": "alice"}, "decision": False},
        ),
    ][:count]
    header = EvidenceHeader(
        run=RUN, lockwalk_version="0.1.0", started_at="2026-11-08T10:00:00Z", events=count
    )
    return Evidence(header=header, events=tuple(events))


def test_ids() -> None:
    assert (event_id(1), query_id(12), invocation_id(12345)) == ("E-0001", "Q-0012", "I-12345")
    assert len(new_run_id()) == 32 and new_run_id() != new_run_id()


def test_write_then_read_round_trips(tmp_path: Path) -> None:
    path = write_evidence(sample(), tmp_path / "out")
    assert path == tmp_path / "out" / EVIDENCE_FILE_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["kind"] == "lockwalk-evidence"
    assert len(lines) == 4
    assert read_evidence(path) == sample()


def test_event_fields_must_match_the_type() -> None:
    with pytest.raises(ValidationError):  # authz.evaluated comes from the adapter
        Event(event="E-0001", run=RUN, time=0, source="harness", type="authz.evaluated")
    with pytest.raises(ValidationError):  # authz.evaluated needs its query id
        Event(event="E-0001", run=RUN, time=0, source="policy_adapter", type="authz.evaluated")
    with pytest.raises(ValidationError):  # harness events need case, mode, and invocation
        Event(event="E-0001", run=RUN, time=0, source="harness", type="effect.counted")
    with pytest.raises(ValidationError):
        Event(event="E-0001", run=RUN, time=-1, source="test_runner", type="run.started")


def test_times_are_strict_numbers() -> None:
    base: dict = {"event": "E-0001", "run": RUN, "source": "test_runner", "type": "run.started"}
    Event(**base, time=1)  # a JSON integer is fine
    for bad in ("0.5", True):
        with pytest.raises(ValidationError):
            Event.model_validate({**base, "time": bad})


def test_each_harness_field_is_set_exactly_for_harness_events() -> None:
    base: dict = {"event": "E-0001", "run": RUN, "time": 0}
    run = {"source": "test_runner", "type": "run.started"}
    harness = {"source": "harness", "type": "door.called"}
    full = {"case": "C", "mode": "direct", "invocation": "I-0001"}
    for extra in ({"mode": "direct"}, {"invocation": "I-0001"}, {"case": "C"}):
        (name,) = extra
        with pytest.raises(ValidationError, match=f"{name} is set exactly"):
            Event(**base, **run, **extra)
    for missing in ("mode", "invocation", "case"):
        partial = {key: value for key, value in full.items() if key != missing}
        with pytest.raises(ValidationError, match=f"{missing} is set exactly"):
            Event(**base, **harness, **partial)
    Event(**base, **harness, **full)


@pytest.mark.parametrize(
    ("mangle", "message"),
    [
        (lambda lines: lines[:-1], "header says"),  # cut off: fewer events than the header says
        (lambda lines: [*lines, lines[-1]], "not in order"),  # one event too many
        (lambda lines: [lines[0], lines[2], lines[1], lines[3]], "not in order"),
        (lambda lines: [lines[0].replace(RUN, "cd" * 16), *lines[1:]], "another run"),
        (lambda lines: [lines[0], "{not json", *lines[2:]], "not valid JSON"),
        (lambda lines: lines[1:], "line 1"),  # no header
        (lambda lines: [lines[0], lines[1], "[]", lines[3]], "not a JSON object"),
    ],
)
def test_untrustworthy_files_raise(tmp_path: Path, mangle, message: str) -> None:
    path = write_evidence(sample(), tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(mangle(lines)) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceFileError) as caught:
        read_evidence(path)
    assert message in str(caught.value)
    assert "alice" not in str(caught.value)  # never quotes the file


def test_times_must_not_go_backwards(tmp_path: Path) -> None:
    evidence = sample()
    late = evidence.events[1].model_copy(update={"time": 9.0})
    bad = Evidence(header=evidence.header, events=(evidence.events[0], late, evidence.events[2]))
    path = write_evidence(bad, tmp_path)
    with pytest.raises(EvidenceFileError, match="goes backwards"):
        read_evidence(path)


def test_an_overlong_line_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import lockwalk.evidence as module

    monkeypatch.setattr(module, "MAX_LINE_BYTES", 64)
    path = write_evidence(sample(), tmp_path)
    with pytest.raises(EvidenceFileError, match="including the newline"):
        read_evidence(path)


def test_the_line_cap_counts_the_newline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import lockwalk.evidence as module

    path = write_evidence(sample(0), tmp_path)
    cap = len(path.read_bytes())  # the header line with its newline fits exactly
    monkeypatch.setattr(module, "MAX_LINE_BYTES", cap)
    assert read_evidence(path).events == ()
    monkeypatch.setattr(module, "MAX_LINE_BYTES", cap - 1)
    with pytest.raises(EvidenceFileError, match="longer than"):
        read_evidence(path)


def test_crlf_line_endings_read_fine(tmp_path: Path) -> None:
    path = write_evidence(sample(), tmp_path)
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert read_evidence(path) == sample()


def test_header_only_file_reads_fine(tmp_path: Path) -> None:
    path = write_evidence(sample(0), tmp_path)
    assert read_evidence(path).events == ()


@pytest.mark.parametrize(
    "mangle",
    [
        lambda raw: b"\xef\xbb\xbf" + raw,  # UTF-8 BOM
        lambda raw: raw + b"\n",  # trailing blank line
        lambda raw: raw.replace(b'"time": 0.01', b'"time": NaN'),
    ],
)
def test_bom_blank_line_and_nan_are_refused(tmp_path: Path, mangle) -> None:
    path = write_evidence(sample(), tmp_path)
    original = path.read_bytes()
    changed = mangle(original)
    assert changed != original
    path.write_bytes(changed)
    with pytest.raises(EvidenceFileError):
        read_evidence(path)


def test_duplicate_keys_are_refused(tmp_path: Path) -> None:
    path = write_evidence(sample(), tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert '"type": "run.started"' in lines[1]
    lines[1] = lines[1].replace('"type": "run.started"', '"type": "run.started","type":"run.error"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceFileError, match="repeats a key") as caught:
        read_evidence(path)
    assert "run.error" not in str(caught.value)


def test_other_os_errors_become_file_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_evidence(tmp_path / "missing.jsonl")
    with pytest.raises(EvidenceFileError, match="cannot be read"):
        read_evidence(tmp_path)  # a directory


def test_read_report_round_trips(make_report, tmp_path: Path) -> None:
    report = make_report().model_copy(update={"run_id": RUN})
    path = write_report(report, tmp_path, generated_at=NOW, version="x")
    assert read_report(path) == report


def test_read_report_refuses_other_versions_and_junk(make_report, tmp_path: Path) -> None:
    path = tmp_path / REPORT_FILE_NAME
    with pytest.raises(ReportFileError):
        read_report(path)  # missing
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReportFileError):
        read_report(path)
    write_report(make_report(), tmp_path, generated_at=NOW, version="x")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["schema_version"] = "3"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ReportFileError) as caught:
        read_report(path)
    assert "lockwalk test" in str(caught.value)


def test_read_report_refuses_duplicate_keys(make_report, tmp_path: Path) -> None:
    path = write_report(make_report(), tmp_path, generated_at=NOW, version="x")
    text = path.read_text(encoding="utf-8")
    assert '"mode"' in text
    path.write_text(text.replace('"mode"', '"mode": "static",\n  "mode"', 1), encoding="utf-8")
    with pytest.raises(ReportFileError, match="repeats a JSON key"):
        read_report(path)
