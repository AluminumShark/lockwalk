from collections.abc import Sequence
from typing import Any

from lockwalk.models import Verdict
from lockwalk.policy.base import Decision, Entity, Query, QueryAction
from lockwalk.runner import ask_all


def q(user: str) -> Query:
    return Query(
        subject=Entity(type="user", id=user),
        action=QueryAction(name="x:y"),
        resource=Entity(type="r", id="1"),
    )


class FakeAdapter:
    def __init__(self, *, batch_size: int = 2, mode: str = "ok") -> None:
        self._batch_size = batch_size
        self.mode = mode
        self.calls: list[list[str]] = []

    @property
    def label(self) -> str:
        return "fake"

    @property
    def batch_size(self) -> int:
        return self._batch_size

    def decide(self, queries: Sequence[Query]) -> list[Decision]:
        self.calls.append([query.subject.id for query in queries])
        if self.mode == "raise":
            raise RuntimeError("boom at https://user:secret@pdp.example/x")
        answers = [Decision(verdict=Verdict.ALLOW) for _ in queries]
        return answers[:-1] if self.mode == "short" else answers

    def notes(self) -> tuple[str, ...]:
        return ()

    def close(self) -> None:
        pass


def test_each_distinct_query_is_asked_once_in_batches() -> None:
    adapter = FakeAdapter(batch_size=2)
    answers = ask_all(adapter, [q("a"), q("b"), q("a"), q("c"), q("d")])
    assert adapter.calls == [["a", "b"], ["c", "d"]]
    assert set(answers) == {q(name).key() for name in "abcd"}
    assert all(d.verdict is Verdict.ALLOW for d in answers.values())


def test_an_adapter_that_raises_fails_the_batch_closed() -> None:
    answers = ask_all(FakeAdapter(mode="raise"), [q("a"), q("b")])
    assert all(d.verdict is Verdict.ERROR for d in answers.values())
    assert all("secret" not in (d.error or "") for d in answers.values())


def test_a_wrong_answer_count_fails_the_batch_closed() -> None:
    answers = ask_all(FakeAdapter(mode="short"), [q("a"), q("b")])
    assert [d.verdict for d in answers.values()] == [Verdict.ERROR, Verdict.ERROR]
    assert "1 answers for 2 questions" in (answers[q("a").key()].error or "")


class ScriptedAdapter(FakeAdapter):
    def __init__(self, result: Any, *, batch_size: int = 2) -> None:
        super().__init__(batch_size=batch_size)
        self.result = result

    def decide(self, queries: Sequence[Query]) -> list[Decision]:
        self.calls.append([query.subject.id for query in queries])
        return self.result


def test_a_generator_of_decisions_works() -> None:
    gen = (Decision(verdict=Verdict.ALLOW) for _ in range(2))
    answers = ask_all(ScriptedAdapter(gen), [q("a"), q("b")])
    assert all(d.verdict is Verdict.ALLOW for d in answers.values())


def test_an_item_that_is_not_a_decision_becomes_an_error() -> None:
    adapter = ScriptedAdapter([None, Decision(verdict=Verdict.ALLOW)])
    answers = ask_all(adapter, [q("a"), q("b")])
    assert answers[q("a").key()].verdict is Verdict.ERROR
    assert "not an answer" in (answers[q("a").key()].error or "")
    assert answers[q("b").key()].verdict is Verdict.ALLOW


def test_a_non_iterable_return_fails_the_batch_closed() -> None:
    answers = ask_all(ScriptedAdapter(3), [q("a"), q("b")])
    assert all(d.verdict is Verdict.ERROR for d in answers.values())


def test_batch_size_zero_means_one_per_call() -> None:
    adapter = FakeAdapter(batch_size=0)
    ask_all(adapter, [q("a"), q("b")])
    assert adapter.calls == [["a"], ["b"]]


def test_ask_all_reports_each_batch_before_sending_it() -> None:
    seen: list[list[str]] = []
    adapter = FakeAdapter(batch_size=2)
    queries = [q(f"u{n}") for n in range(3)]
    sent_when_reported: list[int] = []

    def on_batch(keys: Sequence[str]) -> None:
        seen.append(list(keys))
        sent_when_reported.append(len(adapter.calls))

    ask_all(adapter, queries, on_batch=on_batch)
    assert [len(batch) for batch in seen] == [2, 1]
    assert sent_when_reported == [0, 1]  # on_batch ran before each decide call
    assert seen[0] == [queries[0].key(), queries[1].key()]
