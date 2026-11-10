"""Ask the IAM every distinct question once, in batches, and never let a failure pass."""

from collections.abc import Callable, Iterable, Sequence

from lockwalk.inventory.base import truncate
from lockwalk.inventory.normalize import describe_error
from lockwalk.policy.base import Decision, PolicyAdapter, Query, error_decision


def _fail_batch(batch: Sequence[Query], message: str) -> list[Decision]:
    """Every query of the batch gets the same ERROR answer."""
    error = error_decision(truncate(message))
    return [error for _ in batch]


def ask_all(
    adapter: PolicyAdapter,
    queries: Iterable[Query],
    *,
    on_batch: Callable[[Sequence[str]], None] | None = None,
) -> dict[str, Decision]:
    """Return query.key() -> Decision for every distinct query.

    Queries go out in first-seen order, at most adapter.batch_size at a time. An adapter
    should never raise; if it does, or if it returns the wrong number of answers, every
    query of that batch gets an ERROR decision, because none of its answers can be trusted.

    on_batch is called with the keys of each batch right before it is sent; the evidence
    recorder uses it.
    """
    unique: dict[str, Query] = {}
    for query in queries:
        unique.setdefault(query.key(), query)
    keys = list(unique)
    size = max(1, adapter.batch_size)
    answers: dict[str, Decision] = {}
    for start in range(0, len(keys), size):
        batch_keys = keys[start : start + size]
        batch = [unique[key] for key in batch_keys]
        if on_batch is not None:
            on_batch(batch_keys)
        try:
            decisions = list(adapter.decide(batch))
        except Exception as exc:
            decisions = _fail_batch(batch, f"the policy adapter failed: {describe_error(exc)}")
        else:
            if len(decisions) != len(batch):
                decisions = _fail_batch(
                    batch,
                    f"the policy adapter returned {len(decisions)} answers "
                    f"for {len(batch)} questions",
                )
            else:
                decisions = [
                    item
                    if isinstance(item, Decision)
                    else error_decision(
                        truncate("the policy adapter returned something that is not an answer")
                    )
                    for item in decisions
                ]
        answers.update(zip(batch_keys, decisions, strict=True))
    return answers
