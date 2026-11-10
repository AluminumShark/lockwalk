"""A module that raises at import, after leaving a trace so tests can count the attempts."""

import os

with open(os.environ["LOCKWALK_TEST_CALLS"], "a", encoding="utf-8") as handle:
    handle.write("start\n")

raise RuntimeError("boom at https://u:pw@h/x")
