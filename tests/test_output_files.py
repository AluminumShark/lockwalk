"""The helpers shared by every file lockwalk writes (coverage.json and snapshots)."""

import os
from datetime import UTC, datetime, timedelta, timezone

import pytest

from lockwalk.output_files import utc_timestamp, write_text_atomic


def test_write_creates_the_directory_and_replaces_the_file(tmp_path):
    path = tmp_path / "a" / "b" / "out.json"
    write_text_atomic(path, "first\n", prefix=".out-")
    write_text_atomic(path, "second\n", prefix=".out-")
    assert path.read_text(encoding="utf-8") == "second\n"
    assert [p.name for p in path.parent.iterdir()] == ["out.json"]


def test_write_keeps_utf8_and_survives_a_lone_surrogate(tmp_path):
    path = tmp_path / "out.json"
    chinese = chr(0x522A) + chr(0x9664)
    write_text_atomic(path, chinese + chr(0xD800), prefix=".out-")
    data = path.read_bytes()
    assert chinese.encode("utf-8") in data
    assert data.endswith(b"\\ud800")


def test_a_failed_write_leaves_the_old_file_and_no_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "out.json"
    path.write_text("old", encoding="utf-8")

    def broken_replace(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        write_text_atomic(path, "new", prefix=".out-")
    assert path.read_text(encoding="utf-8") == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


@pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX only")
def test_write_uses_the_umask_mode(tmp_path):
    path = tmp_path / "out.json"
    write_text_atomic(path, "x", prefix=".out-")
    umask = os.umask(0)
    os.umask(umask)
    assert path.stat().st_mode & 0o777 == 0o666 & ~umask


@pytest.mark.skipif(os.name == "nt", reason="the mode is only set on POSIX")
def test_a_failed_chmod_closes_and_removes_the_temp_file(tmp_path, monkeypatch):
    fd_dir = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
    open_before = len(os.listdir(fd_dir))

    def broken_chmod(*args: object, **kwargs: object) -> None:
        raise OSError("chmod failed")

    monkeypatch.setattr(os, "chmod", broken_chmod)
    with pytest.raises(OSError, match="chmod failed"):
        write_text_atomic(tmp_path / "out.json", "x", prefix=".out-")
    assert len(os.listdir(fd_dir)) == open_before
    assert list(tmp_path.iterdir()) == []


def test_timestamp_is_utc_with_a_z():
    taipei = timezone(timedelta(hours=8))
    assert utc_timestamp(datetime(2026, 11, 6, 20, 0, 5, tzinfo=taipei)) == "2026-11-06T12:00:05Z"
    assert utc_timestamp(datetime(2026, 11, 6, tzinfo=UTC)) == "2026-11-06T00:00:00Z"


def test_timestamp_needs_a_timezone():
    with pytest.raises(ValueError) as caught:
        utc_timestamp(datetime(2026, 11, 6), name="when")
    assert str(caught.value) == "when must be timezone-aware"
