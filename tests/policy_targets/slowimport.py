"""A module that takes too long to import, and leaves a trace per attempt."""

import os
import time

with open(os.environ["LOCKWALK_TEST_CALLS"], "a", encoding="utf-8") as handle:
    handle.write("start\n")

time.sleep(30)


def decide(subject, action, resource, context):
    return True
