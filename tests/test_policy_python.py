import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from lockwalk.config import PolicyConfig
from lockwalk.models import Verdict
from lockwalk.policy import python as policy_python
from lockwalk.policy.base import Decision, Entity, Query, QueryAction
from lockwalk.policy.python import PythonAdapter

TARGETS = Path(__file__).parent / "policy_targets"


def ask(who: str) -> Query:
    return Query(
        subject=Entity(type="user", id=who),
        action=QueryAction(name="read"),
        resource=Entity(type="doc", id="d1"),
    )


def make(target: str, **extra: object) -> PythonAdapter:
    config = PolicyConfig.model_validate({"adapter": "python", "target": target, **extra})
    return PythonAdapter(config, TARGETS)


def one(adapter: PythonAdapter, who: str) -> Decision:
    (decision,) = adapter.decide([ask(who)])
    return decision


@pytest.fixture(scope="module")
def basic() -> Iterator[PythonAdapter]:
    # "basic.py" is relative: it only resolves because the worker runs in base_dir.
    adapter = make("basic.py:decide", timeout_s=10)
    try:
        yield adapter
    finally:
        adapter.close()


def test_allow_deny_and_reason(basic: PythonAdapter) -> None:
    allow, deny, owner = basic.decide([ask("alice"), ask("bob"), ask("carol")])
    assert allow.verdict is Verdict.ALLOW
    assert allow.reason is None
    assert allow.latency_ms is not None
    assert deny.verdict is Verdict.DENY
    assert owner.verdict is Verdict.ALLOW
    assert owner.reason == "owner"


def test_label_and_batch_size(basic: PythonAdapter) -> None:
    assert basic.label == "python:basic.py:decide"
    assert basic.batch_size == 100
    assert make("basic.py:decide", batch_size=7).batch_size == 7


@pytest.mark.parametrize("who", ["erin", "hank"])
def test_bad_return_value_is_error(basic: PythonAdapter, who: str) -> None:
    decision = one(basic, who)
    assert decision.verdict is Verdict.ERROR
    assert decision.error is not None
    assert decision.error.startswith("decide returned ")
    assert "it must return True, False, or" in decision.error


def test_exception_is_error_and_later_queries_work(basic: PythonAdapter) -> None:
    decision = one(basic, "dave")
    assert decision.verdict is Verdict.ERROR
    assert decision.error is not None
    assert decision.error.startswith("ValueError: bad at ")
    assert "pw" not in decision.error
    assert "u:" not in decision.error
    assert one(basic, "alice").verdict is Verdict.ALLOW


def test_system_exit_is_error(basic: PythonAdapter) -> None:
    decision = one(basic, "ivy")
    assert decision.verdict is Verdict.ERROR
    assert decision.error is not None
    assert decision.error.startswith("SystemExit")
    assert one(basic, "bob").verdict is Verdict.DENY


def test_printing_does_not_break_the_protocol(basic: PythonAdapter) -> None:
    results = [one(basic, "alice"), one(basic, "bob"), one(basic, "alice")]
    assert [d.verdict for d in results] == [Verdict.ALLOW, Verdict.DENY, Verdict.ALLOW]
    assert basic.notes() == ()


def test_async_decide() -> None:
    adapter = make("asyncy.py:decide", timeout_s=10)
    try:
        assert one(adapter, "x").verdict is Verdict.ALLOW
    finally:
        adapter.close()


def test_decide_many_called_once_per_chunk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = tmp_path / "calls.txt"
    monkeypatch.setenv("LOCKWALK_TEST_CALLS", str(calls))
    adapter = make("batchy.py:decide", timeout_s=10, batch_size=3)
    try:
        queries = [ask(f"u{i}") for i in range(7)]
        decisions: list[Decision] = []
        for start in range(0, len(queries), adapter.batch_size):
            decisions += adapter.decide(queries[start : start + adapter.batch_size])
        assert [d.verdict for d in decisions] == [Verdict.ALLOW] * 7
        assert calls.read_text(encoding="utf-8").split() == ["3", "3", "1"]
        short = adapter.decide([ask("a"), ask("short"), ask("b")])
        assert [d.verdict for d in short] == [Verdict.ERROR] * 3
        assert short[0].error == "decide_many returned 2 answers for 3 questions"
        assert one(adapter, "ok").verdict is Verdict.ALLOW
    finally:
        adapter.close()


def test_crash_mid_chunk_continues_with_a_new_worker() -> None:
    adapter = make("basic.py:decide", timeout_s=10)
    try:
        decisions = adapter.decide([ask(name) for name in ["alice", "gina", "bob", "alice"]])
        assert [d.verdict for d in decisions] == [
            Verdict.ALLOW,
            Verdict.ERROR,
            Verdict.DENY,
            Verdict.ALLOW,
        ]
        assert decisions[1].error == "the decide worker exited"
        assert adapter.notes() == ("the decide worker was restarted 1 time(s)",)
    finally:
        adapter.close()


def test_timeout_skips_the_rest_of_the_call_and_the_next_call_works() -> None:
    # The timeout was 1 s, which flaked when a restarted worker took over 1 s to start on a
    # busy machine. 3 s gives the start-up room; "frank" sleeps 5 s, so he still times out.
    adapter = make("basic.py:decide", timeout_s=3)
    try:
        names = ["alice", "gina", "alice", "frank", "bob", "alice"]
        decisions = adapter.decide([ask(name) for name in names])
        skipped = "skipped: the decide worker timed out on an earlier question"
        assert [d.verdict for d in decisions] == [
            Verdict.ALLOW,
            Verdict.ERROR,
            Verdict.ALLOW,
            Verdict.ERROR,
            Verdict.ERROR,
            Verdict.ERROR,
        ]
        assert decisions[1].error == "the decide worker exited"
        assert decisions[3].error == "timed out after 3s"
        assert [d.error for d in decisions[4:]] == [skipped, skipped]
        assert adapter.notes() == ("the decide worker was restarted 1 time(s)",)
        assert one(adapter, "bob").verdict is Verdict.DENY
        assert adapter.notes() == ("the decide worker was restarted 2 time(s)",)
    finally:
        adapter.close()


def test_secret_url_straddling_the_truncation_cut_is_masked() -> None:
    adapter = make("straddle.py:decide", timeout_s=10)
    try:
        allowed, raised = adapter.decide([ask("ok"), ask("boom")])
        assert allowed.verdict is Verdict.ALLOW
        assert allowed.reason is not None
        assert "Sup3rS3cret" not in allowed.reason
        assert raised.verdict is Verdict.ERROR
        assert raised.error is not None
        assert "Sup3rS3cret" not in raised.error
    finally:
        adapter.close()


def test_kill_without_a_later_query_is_not_a_restart() -> None:
    adapter = make("basic.py:decide", timeout_s=10)
    try:
        assert one(adapter, "gina").verdict is Verdict.ERROR
        assert adapter.notes() == ()
    finally:
        adapter.close()


def test_oversized_answer_is_error_and_worker_restarts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_python, "MAX_LINE_BYTES", 100)
    adapter = make("bigreason.py:decide", timeout_s=10)
    try:
        decision = one(adapter, "long")
        assert decision.verdict is Verdict.ERROR
        assert decision.error == "the decide worker sent an answer larger than 1 MiB"
        assert one(adapter, "short").verdict is Verdict.ALLOW
        assert adapter.notes() == ("the decide worker was restarted 1 time(s)",)
    finally:
        adapter.close()


def test_long_reason_is_truncated() -> None:
    adapter = make("bigreason.py:decide", timeout_s=10)
    try:
        decision = one(adapter, "long")
        assert decision.verdict is Verdict.ALLOW
        assert decision.reason == "x" * 297 + "..."
    finally:
        adapter.close()


def test_decide_many_is_ignored_for_a_dotted_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = tmp_path / "calls.txt"
    monkeypatch.setenv("LOCKWALK_TEST_CALLS", str(calls))
    adapter = make("batchy.py:Holder.decide", timeout_s=10)
    try:
        decisions = adapter.decide([ask("a"), ask("b")])
        assert [d.verdict for d in decisions] == [Verdict.ALLOW] * 2
        assert not calls.exists()
    finally:
        adapter.close()


def test_import_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = tmp_path / "calls.txt"
    monkeypatch.setenv("LOCKWALK_TEST_CALLS", str(calls))
    monkeypatch.setattr(policy_python, "IMPORT_TIMEOUT_S", 1.0)
    adapter = make("slowimport.py:decide", timeout_s=10)
    try:
        first = adapter.decide([ask("a"), ask("b")])
        second = one(adapter, "c")
        for decision in (*first, second):
            assert decision.verdict is Verdict.ERROR
            assert decision.error == (
                "the decide worker could not start: timed out after 1s while importing the target"
            )
        assert calls.read_text(encoding="utf-8").split() == ["start"]
    finally:
        adapter.close()


def test_worker_exit_is_error_and_next_query_works() -> None:
    adapter = make("basic.py:decide", timeout_s=10)
    try:
        decision = one(adapter, "gina")
        assert decision.verdict is Verdict.ERROR
        assert decision.error == "the decide worker exited"
        assert one(adapter, "bob").verdict is Verdict.DENY
        assert adapter.notes() == ("the decide worker was restarted 1 time(s)",)
    finally:
        adapter.close()


def test_import_failure_starts_the_worker_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = tmp_path / "calls.txt"
    monkeypatch.setenv("LOCKWALK_TEST_CALLS", str(calls))
    adapter = make("broken.py:decide", timeout_s=10)
    try:
        first = one(adapter, "alice")
        second = one(adapter, "bob")
        for decision in (first, second):
            assert decision.verdict is Verdict.ERROR
            assert decision.error is not None
            assert decision.error.startswith("the decide worker could not start: ")
            assert "importing the target raised RuntimeError: boom at " in decision.error
            assert "pw" not in decision.error
        assert calls.read_text(encoding="utf-8").split() == ["start"]
        assert adapter.notes() == ()
    finally:
        adapter.close()


@pytest.mark.parametrize(
    ("target", "text"),
    [
        ("no_such_module_xyz:decide", "No module named"),
        ("basic.py:nope", "has no attribute 'nope'"),
        ("notcallable.py:decide", "is not callable"),
        ("missing_file.py:decide", "file not found"),
    ],
)
def test_unresolvable_target_is_could_not_start(target: str, text: str) -> None:
    adapter = make(target, timeout_s=10)
    try:
        decision = one(adapter, "alice")
        assert decision.verdict is Verdict.ERROR
        assert decision.error is not None
        assert decision.error.startswith("the decide worker could not start: ")
        assert text in decision.error
    finally:
        adapter.close()


def test_close_stops_the_process_and_is_repeatable() -> None:
    adapter = make("basic.py:decide", timeout_s=10)
    assert one(adapter, "alice").verdict is Verdict.ALLOW
    process = adapter._process
    assert isinstance(process, subprocess.Popen)
    assert process.poll() is None
    adapter.close()
    assert process.poll() is not None
    adapter.close()


def test_close_without_start_is_fine() -> None:
    make("basic.py:decide").close()


def test_decision_is_json_safe(basic: PythonAdapter) -> None:
    json.dumps(one(basic, "carol").model_dump(mode="json"))


def test_decide_exception_hides_environment_values(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "NOTAREALTOKEN0000-leak-check"
    monkeypatch.setenv("LOCKWALK_TEST_SECRET", secret)
    adapter = make("leaky.py:decide", timeout_s=10)
    try:
        decision = one(adapter, "alice")
    finally:
        adapter.close()
    assert decision.verdict is Verdict.ERROR
    assert decision.error is not None
    assert secret not in decision.error
    assert "LOCKWALK_TEST_SECRET" in decision.error
