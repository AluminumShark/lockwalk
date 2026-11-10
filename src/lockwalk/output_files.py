"""Helpers shared by every file lockwalk writes: coverage.json and inventory snapshots."""

import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

# Timestamps in written files: UTC, to the second, with a trailing Z.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_timestamp(moment: datetime, *, name: str = "the time") -> str:
    """Format a timezone-aware datetime as 2026-01-01T00:00:00Z.

    A naive datetime raises ValueError naming `name`, because its zone is unknown.
    """
    if moment.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return moment.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def write_text_atomic(path: Path, text: str, *, prefix: str) -> None:
    """Write UTF-8 text to path, creating its directory, so readers never see half a file.

    The text goes to a temporary file beside the target (named with `prefix`), which then
    replaces the target. If anything fails, the old file stays and the temporary file is
    removed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=prefix, suffix=".tmp")
    try:
        # The stream owns the descriptor from here on, so it is closed whatever fails.
        # backslashreplace: a lone surrogate in some text must not make the write fail.
        with os.fdopen(
            handle, "w", encoding="utf-8", errors="backslashreplace", newline="\n"
        ) as stream:
            if os.name != "nt":
                # mkstemp creates the file as 0600; give it the usual umask-based mode.
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(temp_name, 0o666 & ~umask)
            stream.write(text)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
