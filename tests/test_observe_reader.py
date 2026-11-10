"""The user's reader function: records, limits, masking, timeouts, cleanup."""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from lockwalk.harness import runner as harness_runner
from lockwalk.observe import reader
from lockwalk.observe.reader import ReaderRecord, run_reader
from lockwalk.observe.spans import Limits, ReadResult

APPS = Path(__file__).parent / "observe_apps"
MIB = 1024 * 1024
LIMITS = Limits(max_spans=1000, max_line_bytes=MIB, max_total_bytes=64 * MIB)


def run(
    target: str,
    paths: tuple[str, ...] = (),
    *,
    limits: Limits = LIMITS,
    timeout_s: float = 60.0,
    only_trace: str | None = None,
    cwd: Path = APPS,
) -> ReadResult:
    return run_reader(
        target, cwd=cwd, paths=paths, timeout_s=timeout_s, limits=limits, only_trace=only_trace
    )


def messages(result: ReadResult) -> list[str]:
    return [f"{p.where}: {p.message}" for p in result.problems]


def test_records_become_spans() -> None:
    result = run("reader_ok:read")
    assert result.problems == () and not result.truncated
    assert result.sources == ("reader reader_ok:read",)
    kinds = [(s.kind, s.name) for s in result.spans]
    assert kinds == [
        ("other", None),
        ("agent", "supervisor"),
        ("agent", "trade-agent"),
        ("tool", "execute_trade"),
        ("handoff", None),
    ]
    first, supervisor, trade, tool, handoff = result.spans
    assert first.trace_id == "T1" and first.span_id == "A" and first.parent_id is None
    assert supervisor.parent_id == "A"
    assert supervisor.start_ns == 1767225600_000_001_000
    assert supervisor.end_ns == 1767225601_000_000_000
    assert trade.caller == "supervisor"
    assert tool.parent_id == "C" and tool.caller is None
    assert (handoff.handoff_from, handoff.handoff_to) == ("supervisor", "trade-agent")
    assert supervisor.where == "reader record 2"
    assert not supervisor.unnamed_marker


def test_only_trace_is_exact_and_ids_keep_their_case() -> None:
    assert [s.span_id for s in run("reader_ok:read", only_trace="T2").spans] == ["E"]
    assert run("reader_ok:read", only_trace="t2").spans == ()
    spans = run("reader_hostile:read_ids").spans
    assert [(s.trace_id, s.span_id) for s in spans] == [("Tr", "Ab"), ("Tr", "ab"), ("tr", "x")]
    assert len(run("reader_hostile:read_ids", only_trace="Tr").spans) == 2


def test_path_form_and_paths_are_passed_as_written(tmp_path: Path) -> None:
    target = f"{APPS / 'reader_cwd.py'}:read_paths"
    result = run(target, ("a.jsonl", "dir/b.jsonl"), cwd=tmp_path)
    assert [s.name for s in result.spans] == ["a.jsonl", "dir/b.jsonl"]


def test_reader_runs_in_cwd(tmp_path: Path) -> None:
    (tmp_path / "data.txt").write_text("from-cwd", encoding="utf-8")
    result = run(f"{APPS / 'reader_cwd.py'}:read", cwd=tmp_path)
    assert result.problems == ()
    assert [s.name for s in result.spans] == ["from-cwd"]


def test_module_in_cwd_is_importable(tmp_path: Path) -> None:
    (tmp_path / "my_reader.py").write_text(
        "def read(paths):\n    yield {'trace_id': 't', 'span_id': 's', 'kind': 'other'}\n",
        encoding="utf-8",
    )
    assert len(run("my_reader:read", cwd=tmp_path).spans) == 1


def test_async_generator_and_coroutine() -> None:
    result = run("reader_async:read")
    assert result.problems == ()
    assert [(s.kind, s.name) for s in result.spans] == [("agent", "async-agent"), ("tool", "t")]
    result = run("reader_async:read_list")
    assert result.problems == () and [s.name for s in result.spans] == ["listed"]


def test_printing_does_not_break_anything() -> None:
    result = run("reader_prints:read")
    assert result.problems == () and [s.name for s in result.spans] == ["printed"]


def test_invalid_records_are_skipped_with_problems() -> None:
    result = run("reader_bad:read_invalid")
    assert [s.span_id for s in result.spans] == ["C"]
    text = messages(result)
    assert len(text) == 4
    assert text[0].startswith("reader record 1: ") and "name" in text[0]
    assert text[1].startswith("reader record 2: ")
    assert text[2].startswith("reader record 4: ") and "handoff" in text[2]
    assert text[3].startswith("reader record 5: ")
    assert "hunter2" not in "".join(text)


def test_record_problems_are_capped() -> None:
    result = run("reader_many:read_invalid", ("150",))
    assert result.spans == ()
    text = messages(result)
    assert reader.MAX_RECORD_PROBLEMS == 100 and len(text) == 101
    assert text[-1].endswith("50 more records did not validate")


def test_non_dict_item_is_an_error_naming_position_and_type() -> None:
    result = run("reader_bad:read_non_dict")
    assert len(result.problems) == 1
    assert "the reader failed: TypeError: record 2 is a str, not a dict" in messages(result)[0]
    assert [s.span_id for s in result.spans] == ["A"]


def test_non_json_item_is_an_error() -> None:
    result = run("reader_bad:read_set")
    assert "record 1 cannot be written as JSON (TypeError)" in messages(result)[0]
    assert result.spans == ()


def test_not_iterable_is_an_error() -> None:
    assert "not an iterable of dicts" in messages(run("reader_bad:read_not_iterable"))[0]


def test_not_callable_and_missing_target_are_errors() -> None:
    assert "not callable" in messages(run("reader_cwd:NOT_CALLABLE"))[0]
    assert "the reader failed" in messages(run("reader_cwd:nothing_here"))[0]
    assert "the reader failed" in messages(run("no_such_module_xyz:read"))[0]


def test_exception_message_is_masked() -> None:
    result = run("reader_raises:read")
    text = messages(result)
    assert len(text) == 1 and "u:p@" not in text[0]
    assert text[0].endswith("the reader failed: RuntimeError: token https://x/y")


def test_exception_message_is_truncated() -> None:
    text = messages(run("reader_raises:read_long"))[0]
    assert text.startswith("reader reader_raises:read_long: the reader failed: ValueError: xxx")
    assert len(text) < 400 and text.endswith("...")


def test_system_exit_is_an_error() -> None:
    assert "SystemExit: 3" in messages(run("reader_raises:read_exit"))[0]


def test_max_records_stops_and_marks_truncated() -> None:
    limits = Limits(max_spans=5, max_line_bytes=MIB, max_total_bytes=MIB)
    result = run("reader_many:read", ("50",), limits=limits)
    assert len(result.spans) == 5 and result.truncated
    assert messages(result) == [
        "reader reader_many:read: the reader returned more than 5 records ([observe] max_spans)"
    ]


def test_exactly_max_records_is_fine() -> None:
    limits = Limits(max_spans=5, max_line_bytes=MIB, max_total_bytes=MIB)
    result = run("reader_many:read", ("5",), limits=limits)
    assert len(result.spans) == 5 and not result.truncated and result.problems == ()


def test_line_limit_stops() -> None:
    limits = Limits(max_spans=10, max_line_bytes=300, max_total_bytes=MIB)
    result = run("reader_many:read_wide", limits=limits)
    assert len(result.spans) == 1 and result.truncated
    assert "larger than the limit" in messages(result)[0]


def test_total_limit_stops() -> None:
    limits = Limits(max_spans=1000, max_line_bytes=MIB, max_total_bytes=500)
    result = run("reader_many:read", ("100",), limits=limits)
    lines = [len(f'{{"trace_id": "T", "span_id": "S{n}", "kind": "other"}}\n') for n in range(100)]
    fits = [n for n in range(100) if sum(lines[: n + 1]) <= 500]
    assert result.truncated and len(result.spans) == len(fits)
    assert "larger than the limit" in messages(result)[0]


def test_records_file_never_exceeds_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    sizes: list[int] = []
    real = reader._read_records

    def spy(path: Path, *args: Any, **kwargs: Any) -> ReadResult:
        sizes.append(path.stat().st_size)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(reader, "_read_records", spy)
    limits = Limits(max_spans=1000, max_line_bytes=MIB, max_total_bytes=1000)
    result = run("reader_many:read", ("500",), limits=limits)
    assert result.truncated and sizes and 0 < sizes[0] <= 1000


def _alive(pid: int) -> bool:
    if sys.platform != "win32":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = ctypes.c_ulong()
    kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
    kernel32.CloseHandle(ctypes.c_void_p(handle))
    return code.value == 259  # STILL_ACTIVE


def assert_gone(pids: list[int]) -> None:
    deadline = time.monotonic() + 5
    while any(_alive(pid) for pid in pids) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not any(_alive(pid) for pid in pids)


def test_timeout_kills_the_worker_and_its_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "pid"
    real = reader._wait

    def fast(process: Any, result_path: Path, timeout_s: float) -> str:
        # Let the reader start its child first, then use a short deadline.
        deadline = time.monotonic() + 30
        while (
            not (pid_file.exists() and pid_file.read_text().strip()) and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        return real(process, result_path, timeout_s)

    monkeypatch.setattr(reader, "_wait", fast)
    result = run("reader_sleeps:read", (str(pid_file),), timeout_s=0.2)
    assert messages(result) == [
        "reader reader_sleeps:read: the reader did not finish within 0.2s "
        "([observe] reader_timeout_s)"
    ]
    assert result.spans == () and not result.truncated
    assert_gone([int(Path(f"{pid_file}{suffix}").read_text()) for suffix in ("", ".child")])


@pytest.mark.skipif(
    sys.platform != "win32" and not harness_runner._HAS_WAITID,
    reason="no os.waitid (macOS): a child left by a reader that returned normally may survive",
)
def test_child_left_by_a_normal_return_is_cleaned_up(tmp_path: Path) -> None:
    pid_file = tmp_path / "pid"
    result = run("reader_hostile:read_leaves_child", (str(pid_file),))
    assert result.problems == () and len(result.spans) == 1
    assert_gone([int(pid_file.read_text())])


def test_worker_that_dies_without_a_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reader, "WORKER", "no_such_worker_module_xyz")
    assert messages(run("reader_ok:read")) == [
        "reader reader_ok:read: the reader process exited without a result"
    ]


def test_cannot_start_in_a_missing_directory(tmp_path: Path) -> None:
    result = run("reader_ok:read", cwd=tmp_path / "missing")
    assert len(result.problems) == 1 and "cannot start the reader" in messages(result)[0]


def test_unreadable_result_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    for bad in (
        '{"count": 1}',
        "not json",
        '{"count": -1, "stopped": null, "error": null}',
        '{"count": 11, "stopped": null, "error": null}',
        '{"count": true, "stopped": null, "error": null}',
        '{"count": 1, "stopped": "x", "error": null}',
        '{"count": 1, "stopped": null, "error": 5}',
        '{"count": 1, "count": 1, "stopped": null, "error": null}',
    ):
        path.write_text(bad, encoding="utf-8")
        assert isinstance(reader._parse_result(path, 10), str), bad
    path.write_text('{"count": 1, "stopped": null, "error": null}', encoding="utf-8")
    assert not isinstance(reader._parse_result(path, 10), str)


def test_times_must_be_iso_text_with_a_zone() -> None:
    base = {"trace_id": "t", "span_id": "s", "kind": "other"}
    for bad in ("1767225600", "1767225600.5", "2026-01-01T00:00:00", "2026-01-01", 1767225600):
        with pytest.raises(ValidationError):
            ReaderRecord.model_validate({**base, "start": bad})
    for good in ("2026-01-01T00:00:00Z", "2026-01-01 00:00:00+08:00"):
        assert ReaderRecord.model_validate({**base, "start": good}).start is not None


def test_reader_record_rules() -> None:
    base = {"trace_id": "t", "span_id": "s"}
    ReaderRecord.model_validate({**base, "kind": "tool", "name": "x", "effect": True})
    ReaderRecord.model_validate({**base, "kind": "handoff", "from": "a", "to": "b"})
    for bad in (
        {"kind": "tool"},
        {"kind": "other", "name": "x"},
        {"kind": "tool", "name": "x", "caller": "y"},
        {"kind": "agent", "name": "x", "from": "a", "to": "b"},
        {"kind": "handoff", "to": "b"},
        {"kind": "other", "kind_": 1},
        {"kind": "other", "from_": "a"},
        {"kind": "other", "trace_id": ""},
        {"kind": "other", "effect": "yes"},
        {"kind": "other", "start": "2026-01-01T00:00:00"},
        {"kind": "agent", "name": "x" * 513},
        {"kind": "bogus"},
    ):
        with pytest.raises(ValidationError):
            ReaderRecord.model_validate({**base, **bad})


def test_epoch_numbers_are_refused_for_times() -> None:
    result = run("reader_hostile:read_epoch")
    assert result.spans == () and "reader record 1" in messages(result)[0]


def test_huge_exception_message_is_still_a_reader_failure() -> None:
    text = messages(run("reader_raises:read_huge_message"))
    assert len(text) == 1 and "the reader failed: ValueError: yyy" in text[0]
    assert "unreadable" not in text[0] and len(text[0]) < 400


def test_unencodable_items_are_errors_naming_the_type() -> None:
    broken = messages(run("reader_hostile:read_broken_items"))[0]
    assert "record 1 cannot be written as JSON (RuntimeError)" in broken
    opaque = messages(run("reader_hostile:read_object_value"))[0]
    assert "record 1 cannot be written as JSON (TypeError)" in opaque


def test_endless_item_stops_at_the_line_limit() -> None:
    limits = Limits(max_spans=10, max_line_bytes=10_000, max_total_bytes=MIB)
    result = run("reader_hostile:read_endless_item", limits=limits, timeout_s=30)
    assert result.truncated and result.spans == ()
    assert "larger than the limit" in messages(result)[0]


@pytest.mark.parametrize("name", ["read_infinite", "read_infinite_async"])
def test_infinite_generator_is_stopped_and_closed(tmp_path: Path, name: str) -> None:
    marker = tmp_path / "marker"
    limits = Limits(max_spans=7, max_line_bytes=MIB, max_total_bytes=MIB)
    result = run(f"reader_hostile:{name}", (str(marker),), limits=limits, timeout_s=30)
    assert len(result.spans) == 7 and result.truncated
    assert marker.read_text() == "closed"


def test_parse_result_survives_deep_nesting_and_non_files(tmp_path: Path) -> None:
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 60_000, encoding="utf-8")
    assert isinstance(reader._parse_result(deep, 10), str)
    folder = tmp_path / "dir"
    folder.mkdir()
    assert isinstance(reader._parse_result(folder, 10), str)
    assert isinstance(reader._parse_result(tmp_path / "missing", 10), str)
    target = tmp_path / "real.json"
    target.write_text('{"count": 0, "stopped": null, "error": null}', encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        return  # symlinks need privileges on Windows
    assert isinstance(reader._parse_result(link, 10), str)


GOOD = b'{"trace_id": "T", "span_id": "A", "kind": "other"}\n'


def _records(tmp_path: Path, data: bytes, count: int, limits: Limits = LIMITS) -> ReadResult:
    path = tmp_path / "records.jsonl"
    path.write_bytes(data)
    return reader._read_records(
        path, reader._WorkerResult(count, None, None), ("reader x",), limits, None
    )


def test_read_records_refuses_hostile_files(tmp_path: Path) -> None:
    tight = Limits(max_spans=10, max_line_bytes=len(GOOD) - 1, max_total_bytes=MIB)
    assert len(_records(tmp_path, GOOD, 1, tight).spans) == 1
    total = Limits(max_spans=10, max_line_bytes=MIB, max_total_bytes=len(GOOD) * 2)
    for result in (
        _records(tmp_path, GOOD + b"x" * 500 + b"\n", 2, tight),  # a line over the limit
        _records(tmp_path, GOOD.rstrip(b"\n"), 1),  # no trailing newline
        _records(tmp_path, GOOD, 3),  # fewer lines than the count
        _records(tmp_path, GOOD * 5, 5, total),  # over the total with a forged count
    ):
        assert [p.message for p in result.problems][-1] == "the reader process wrote bad records"
    # a line in another encoding is a record problem, not a crash
    result = _records(tmp_path, b'{"trace_id": "\xff"}\n', 1)
    assert result.spans == () and "UTF-8" in result.problems[0].message


def test_read_records_refuses_non_files(tmp_path: Path) -> None:
    folder = tmp_path / "records.jsonl"
    folder.mkdir()
    result = reader._read_records(
        folder, reader._WorkerResult(1, None, None), ("reader x",), LIMITS, None
    )
    assert "unreadable records file" in result.problems[0].message


def test_authz_items_become_child_spans() -> None:
    result = run("reader_doors:read")
    assert result.problems == ()
    assert [s.span_id for s in result.spans] == ["A", "B", "B#door1", "B#door2"]
    first, tool, one, two = result.spans
    assert first.user_id == "u-1" and not first.effect
    assert tool.effect and tool.tool_call_id == "call-1" and tool.door is None
    for child in (one, two):
        assert child.kind == "other" and child.parent_id == "B" and child.trace_id == "T"
        assert (child.start_ns, child.end_ns) == (tool.start_ns, tool.end_ns)
        assert child.where == tool.where and child.name is None
    assert one.door is not None and two.door is not None
    assert (one.door.decision, one.door.subject_type, one.door.subject_id) == (
        "allow",
        "user",
        "u-1",
    )
    assert one.door.act == (("agent", "bot"),) and one.door.resource_type == "account"
    assert one.door.tool_call_id == "call-1" and one.door.action == "trade:execute"
    assert two.door.decision == "deny" and two.door.act == () and two.door.resource_type is None


def _item(**changes: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "decision": "allow",
        "subject": {"type": "user", "id": "u"},
        "action": "a",
    }
    return {**item, **changes}


def test_reader_door_rules() -> None:
    base = {"trace_id": "t", "span_id": "s", "kind": "other"}
    deep: dict[str, Any] = {"type": "a", "id": "b"}
    for _ in range(64):
        deep = {"type": "a", "id": "b", "act": deep}
    for good in (_item(), _item(subject={"type": "u", "id": "i", "act": {"type": "a", "id": "b"}})):
        ReaderRecord.model_validate({**base, "authz": [good]})
    for bad in (
        _item(decision="maybe"),
        _item(action=""),
        _item(action="x" * 513),
        _item(subject={"type": "u"}),
        _item(subject={"type": "u", "id": ""}),
        _item(subject={"type": "u", "id": "i", "act": {"type": "a"}}),
        _item(subject={"type": "u", "id": "i", "act": {"type": "a", "id": 3}}),
        _item(subject={"type": "u", "id": "i", "act": deep}),
        _item(resource_type=""),
        _item(tool_call_id=5),
        _item(extra=1),
        "text",
    ):
        with pytest.raises(ValidationError):
            ReaderRecord.model_validate({**base, "authz": [bad]})
    with pytest.raises(ValidationError):
        ReaderRecord.model_validate({**base, "tool_call_id": "c"})  # only for tool spans
    ReaderRecord.model_validate({**base, "kind": "tool", "name": "t", "tool_call_id": "c"})


def test_invalid_authz_message_never_has_the_value(tmp_path: Path) -> None:
    secret = "s3cr3t-value-XYZ"
    line = {"trace_id": "t", "span_id": "s", "kind": "other", "authz": [_item(decision=secret)]}
    result = _records(tmp_path, (json.dumps(line) + "\n").encode(), 1)
    assert result.spans == () and len(result.problems) == 1
    assert secret not in result.problems[0].message


def test_reader_ids_must_not_contain_the_child_marker() -> None:
    base = {"trace_id": "t", "span_id": "s", "kind": "other"}
    ReaderRecord.model_validate(base)
    for field in ("span_id", "parent_id"):
        with pytest.raises(ValidationError, match=field):
            ReaderRecord.model_validate({**base, field: "a#door1"})


def test_reader_act_null_means_absent() -> None:
    base = {"trace_id": "t", "span_id": "s", "kind": "other"}
    item = _item(subject={"type": "u", "id": "i", "act": None})
    record = ReaderRecord.model_validate({**base, "authz": [item]})
    assert record.authz is not None and record.authz[0].to_record().act == ()
    for bad in ([], "x", 5, {}):
        with pytest.raises(ValidationError):
            ReaderRecord.model_validate(
                {**base, "authz": [_item(subject={"type": "u", "id": "i", "act": bad})]}
            )
