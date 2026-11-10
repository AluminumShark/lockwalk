"""Fail unless a pytest JUnit report shows at least one test and only passed tests.

Usage: python scripts/check_no_skips.py REPORT.xml

The report fails the check when it holds no test case, a skipped test, a failed test, a test
with an error, or a test suite whose `failures`, `errors` or `skipped` count is above zero
(a collection error can leave only such a count and no test case).

The docker tests skip themselves when docker or their image is missing. In CI that would
leave a green job that tested nothing, so the job checks its own report with this script.
"""

import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path

COUNTS = ("failures", "errors", "skipped")
# A test case child element, and the word the report uses for it.
CASE_PROBLEMS = (("skipped", "skipped"), ("failure", "failed"), ("error", "error"))


def problems(report: Path) -> list[str]:
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError) as error:
        return [f"cannot read {report}: {error}"]
    cases = list(root.iter("testcase"))
    found: list[str] = []
    if not cases:
        found.append("no tests ran")
    for case in cases:
        name = f"{case.get('classname', '')}::{case.get('name', '')}"
        for element, word in CASE_PROBLEMS:
            if case.find(element) is not None:
                found.append(f"{word}: {name}")
    for suite in root.iter():
        if suite.tag not in ("testsuite", "testsuites"):
            continue
        label = suite.get("name", suite.tag)
        for count in COUNTS:
            value = suite.get(count)
            if value is None:
                continue
            try:
                number = int(value)
            except ValueError:
                found.append(f"suite {label!r} has {count}={value!r}, which is not a number")
                continue
            if number > 0:
                found.append(f"suite {label!r} reports {count}={number}")
    return found


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python scripts/check_no_skips.py REPORT.xml", file=sys.stderr)
        return 2
    found = problems(Path(args[0]))
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
