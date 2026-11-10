"""The worker's record of one run: side effect calls, door calls, and script marks."""

import bisect
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from lockwalk.harness.protocol import (
    MAX_TIMELINE,
    MAX_TIMELINE_TEXT,
    TimelineEntry,
    TimelineKind,
    has_long_string,
)

MAX_EVENTS = 10_000
TOO_LARGE = "the door call is too large to keep"


@dataclass(frozen=True)
class Window:
    side_effect_calls: int  # calls of the tool's side effect in the whole run
    door_calls: tuple[dict[str, Any], ...]  # door calls inside the window, the first `keep`
    door_calls_dropped: int
    bypass: bool  # with a DOOR: some side effect call had no door call before it


class EventLog:
    """Ordered events from the counters, the door recorder, and the fake models.

    Tools may run in worker threads, so every method takes the lock. After MAX_EVENTS
    events only the counts still go up, and overflowed is set; the run is then ERROR.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._kept = 0
        self._counts: dict[str, int] = {}
        self._effects: dict[str, list[int]] = {}  # tool -> sequence numbers
        self._doors: list[tuple[int, dict[str, Any]]] = []  # in sequence order
        self.overflowed = False
        self._clock = clock
        self._t0 = clock()
        self._timeline: list[TimelineEntry] = []
        self._timeline_dropped = 0

    def _next(self) -> int:
        self._seq += 1
        return self._seq

    def _keep(self) -> bool:
        if self._kept >= MAX_EVENTS:
            self.overflowed = True
            return False
        self._kept += 1
        return True

    def side_effect(self, tool: str) -> None:
        with self._lock:
            seq = self._next()
            self._counts[tool] = self._counts.get(tool, 0) + 1
            if self._keep():
                self._effects.setdefault(tool, []).append(seq)
            self._note(seq, "effect", tool=tool)

    def door(self, call: dict[str, Any]) -> None:
        """Record one door call, after the door returned (so before any side effect it allows)."""
        with self._lock:
            seq = self._next()
            if self._keep():
                self._doors.append((seq, call))
            self._note(seq, "door", data=call)

    def begin(self) -> None:
        """The job starts now: timeline offsets count from here.

        Entries recorded before begin() are measured from the log's construction time.
        """
        with self._lock:
            self._t0 = self._clock()

    def identity(self, subject: dict[str, Any]) -> None:
        """The run's identity was set (a reduced subject, protocol.reduce_subject)."""
        with self._lock:
            self._note(self._next(), "identity", data=subject)

    def timeline(self) -> tuple[tuple[TimelineEntry, ...], int]:
        """The kept entries in sequence order, and how many more were only counted."""
        with self._lock:
            return tuple(self._timeline), self._timeline_dropped

    def elapsed_ms(self) -> float:
        """Milliseconds since begin() (since construction if begin() was never called)."""
        with self._lock:
            return self._offset_ms()

    def _offset_ms(self) -> float:  # the caller holds the lock
        return float(round(max(0.0, (self._clock() - self._t0) * 1000), 3))

    def _note(  # the caller holds the lock
        self,
        seq: int,
        kind: TimelineKind,
        *,
        tool: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        if len(self._timeline) >= MAX_TIMELINE:
            self._timeline_dropped += 1
            return
        try:  # this runs inside the user's tool: it must never raise into it
            if tool is not None:
                tool = tool[:MAX_TIMELINE_TEXT]
            if data is not None and has_long_string(data):
                if kind == "identity":
                    self._timeline_dropped += 1
                    return
                data = {"error": TOO_LARGE}
            self._timeline.append(
                TimelineEntry(seq=seq, at_ms=self._offset_ms(), kind=kind, tool=tool, data=data)
            )
        except Exception:
            self._timeline_dropped += 1

    def mark(self) -> int:
        with self._lock:
            return self._next()

    def count(self, tool: str) -> int:
        with self._lock:
            return self._counts.get(tool, 0)

    def window(
        self, tool: str, start: int, end: int | None, *, door_configured: bool, keep: int
    ) -> Window:
        """The tool's window (start, end]; end None means up to now.

        A side effect call inside the window needs a door call inside the window before it.
        One before the window (unexpected) needs a door call before it anywhere in the run.
        A side effect after the window's end is judged with the window's door calls too;
        scripted mode asks for the tool once, so a later call means the tool ran again
        within the same run.
        """
        with self._lock:
            limit = self._seq if end is None else end
            inside = [call for seq, call in self._doors if start < seq <= limit]
            door_seqs = [seq for seq, _ in self._doors]
            bypass = False
            if door_configured:
                for effect in self._effects.get(tool, []):
                    floor = start if effect > start else 0
                    before = bisect.bisect_left(door_seqs, effect)
                    if before == 0 or door_seqs[before - 1] <= floor:
                        bypass = True
                        break
            return Window(
                side_effect_calls=self._counts.get(tool, 0),
                door_calls=tuple(inside[:keep]),
                door_calls_dropped=max(0, len(inside) - keep),
                bypass=bypass,
            )
