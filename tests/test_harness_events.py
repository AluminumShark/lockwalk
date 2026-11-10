"""EventLog: counts, windows, and bypass detection."""

import threading

import pytest

from lockwalk.harness import events
from lockwalk.harness.events import EventLog
from lockwalk.harness.protocol import MAX_TIMELINE, MAX_TIMELINE_TEXT

ALLOW = {"subject": {"type": "user", "id": "alice"}, "decision": True}


def test_window_counts_the_whole_run_and_keeps_door_calls_inside_it() -> None:
    log = EventLog()
    log.door(ALLOW)  # before the window: not the tool's
    start = log.mark()
    log.door(ALLOW)
    log.side_effect("t")
    end = log.mark()
    log.door(ALLOW)  # after the window
    window = log.window("t", start, end, door_configured=True, keep=20)
    assert window.side_effect_calls == 1
    assert window.door_calls == (ALLOW,)
    assert window.door_calls_dropped == 0
    assert window.bypass is False


def test_a_side_effect_without_a_door_call_before_it_is_a_bypass() -> None:
    log = EventLog()
    log.door(ALLOW)
    start = log.mark()
    log.side_effect("t")  # the door call before start does not count
    assert log.window("t", start, None, door_configured=True, keep=20).bypass is True
    assert log.window("t", start, None, door_configured=False, keep=20).bypass is False


def test_side_effects_of_other_tools_do_not_count() -> None:
    log = EventLog()
    start = log.mark()
    log.side_effect("other")
    window = log.window("t", start, None, door_configured=True, keep=20)
    assert window.side_effect_calls == 0 and window.bypass is False


def test_door_calls_beyond_keep_are_counted_not_kept() -> None:
    log = EventLog()
    start = log.mark()
    for _ in range(5):
        log.door(ALLOW)
    window = log.window("t", start, None, door_configured=True, keep=2)
    assert len(window.door_calls) == 2 and window.door_calls_dropped == 3


def test_the_log_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(events, "MAX_EVENTS", 3)
    log = EventLog()
    for _ in range(5):
        log.side_effect("t")
    assert log.overflowed is True
    assert log.count("t") == 5  # counts keep going up


def test_threads_can_record_at_the_same_time() -> None:
    log = EventLog()

    def record() -> None:
        for _ in range(200):
            log.side_effect("t")

    threads = [threading.Thread(target=record) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert log.count("t") == 400


def test_an_effect_before_the_window_is_fine_with_a_door_call_before_it() -> None:
    log = EventLog()
    log.door(ALLOW)
    log.side_effect("t")
    start = log.mark()
    assert log.window("t", start, None, door_configured=True, keep=20).bypass is False


def test_an_effect_after_the_end_is_judged_with_the_windows_door_calls() -> None:
    log = EventLog()
    start = log.mark()
    log.door(ALLOW)
    end = log.mark()
    log.side_effect("t")  # the tool ran again after the window closed
    window = log.window("t", start, end, door_configured=True, keep=20)
    assert window.side_effect_calls == 1 and window.bypass is False


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_timeline_records_identity_door_and_effects_in_order() -> None:
    clock = FakeClock()
    log = EventLog(clock=clock)
    clock.now = 105.0
    log.begin()  # job start: offsets count from here
    log.identity({"type": "user", "id": "alice"})
    clock.now = 105.002
    log.door({"subject": {"type": "user", "id": "alice"}, "decision": False})
    clock.now = 105.0035
    log.side_effect("execute_trade")
    entries, dropped = log.timeline()
    assert dropped == 0
    assert [entry.kind for entry in entries] == ["identity", "door", "effect"]
    assert [entry.seq for entry in entries] == sorted(entry.seq for entry in entries)
    assert [entry.at_ms for entry in entries] == [0.0, 2.0, 3.5]
    assert all(type(entry.at_ms) is float for entry in entries)
    assert entries[2].tool == "execute_trade" and entries[2].data is None
    assert entries[1].data == {"subject": {"type": "user", "id": "alice"}, "decision": False}
    assert log.elapsed_ms() == 3.5


def test_timeline_keeps_the_first_entries_and_counts_the_rest() -> None:
    log = EventLog()
    for _ in range(MAX_TIMELINE + 5):
        log.side_effect("t")
    entries, dropped = log.timeline()
    assert len(entries) == MAX_TIMELINE and dropped == 5
    assert log.count("t") == MAX_TIMELINE + 5  # counting is not affected


def test_identity_entries_do_not_change_the_window() -> None:
    log = EventLog()
    log.identity({"type": "user", "id": "a"})
    start = log.mark()
    log.door({"subject": {"type": "user", "id": "a"}, "decision": True})
    log.side_effect("t")
    window = log.window("t", start, None, door_configured=True, keep=5)
    assert window.bypass is False and len(window.door_calls) == 1


def test_offsets_before_begin_are_never_negative() -> None:
    clock = FakeClock()
    log = EventLog(clock=clock)
    log.begin()
    clock.now = 99.0  # a clock that went back
    log.side_effect("t")
    assert log.timeline()[0][0].at_ms == 0.0


def test_oversized_door_data_is_replaced_and_oversized_identity_is_dropped() -> None:
    log = EventLog()
    big = "x" * (MAX_TIMELINE_TEXT + 1)
    log.identity({"type": "user", "id": big})
    log.door({"subject": {"type": "user", "id": big}, "decision": True})
    log.side_effect(big)
    entries, dropped = log.timeline()
    assert dropped == 1  # the identity
    assert [e.kind for e in entries] == ["door", "effect"]
    assert entries[0].data == {"error": events.TOO_LARGE}
    assert entries[1].tool == big[:MAX_TIMELINE_TEXT]
    # the window still sees the real door call
    window = log.window(big, 0, None, door_configured=True, keep=5)
    assert window.door_calls[0]["subject"]["id"] == big


def test_a_clock_returning_ints_still_gives_float_offsets() -> None:
    log = EventLog(clock=lambda: 5)
    log.side_effect("t")
    assert type(log.timeline()[0][0].at_ms) is float
    assert type(log.elapsed_ms()) is float


def test_note_never_raises_into_the_tool() -> None:
    state = {"broken": False}

    def clock() -> float:
        if state["broken"]:
            raise RuntimeError("clock failed")
        return 0.0

    log = EventLog(clock=clock)
    state["broken"] = True
    log.side_effect("t")  # must not raise into the user's tool
    assert log.count("t") == 1
    entries, dropped = log.timeline()
    assert entries == () and dropped == 1


def test_concurrent_calls_keep_unique_ordered_seqs_and_exact_counts() -> None:
    log = EventLog()
    call = {"subject": {"type": "user", "id": "a"}, "decision": True}

    def work() -> None:
        for _ in range(20):
            log.door(call)
            log.side_effect("t")

    # 5 threads x 40 entries is exactly MAX_TIMELINE on purpose: nothing is dropped
    threads = [threading.Thread(target=work) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    entries, dropped = log.timeline()
    seqs = [e.seq for e in entries]
    assert dropped == 0 and len(seqs) == 200
    assert seqs == sorted(set(seqs))
    assert log.count("t") == 100


def test_timeline_survives_event_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(events, "MAX_EVENTS", 3)
    log = EventLog()
    for _ in range(5):
        log.side_effect("t")
    assert log.overflowed and log.count("t") == 5
    assert len(log.timeline()[0]) == 5
