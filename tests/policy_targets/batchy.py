"""A decide() with a batch function that records how many questions each call got."""

import os


def decide(subject, action, resource, context):
    return True


class Holder:
    @staticmethod
    def decide(subject, action, resource, context):
        return True


def decide_many(queries):
    with open(os.environ["LOCKWALK_TEST_CALLS"], "a", encoding="utf-8") as handle:
        handle.write(f"{len(queries)}\n")
    if any(query["subject"]["id"] == "short" for query in queries):
        return [True] * (len(queries) - 1)
    return [True] * len(queries)
