"""Nothing that ships or gets published cites private documents or local paths.

The patterns are built by joining strings, so this file does not trip its own check.
"""

import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_FOLDER = "super" + "powers"
# Folders the public export keeps. Every file in them is read, whatever its suffix.
FOLDERS = ("docs", "examples", "src", "tests", "scripts", ".github")
# Not published, or not present in an exported copy: virtual environments, caches, run output,
# build output, and the private folder. Skipped wherever they appear in the path.
SKIPPED_PARTS = {
    PRIVATE_FOLDER,
    "__pycache__",
    ".venv",
    ".lockwalk",
    "dist",
    ".git",
    ".claude",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}
# The private spec file sits at the top level; the export drops it.
PRIVATE_TOP_LEVEL_PREFIX = "PROJECT_" + "SPEC"

SECTION_SIGN = "\u00a7"

PATTERNS = {
    "private docs folder": re.compile("docs/" + PRIVATE_FOLDER),
    "private spec": re.compile(PRIVATE_TOP_LEVEL_PREFIX),
    # Also hits the compact forms, with an underscore or none at all.
    "internal project number": re.compile("sub[-_ ]?" + "project", re.IGNORECASE),
    "design citation": re.compile(
        r"\bdesign (?:section|doc|decisions? \d|\d|" + SECTION_SIGN + ")", re.IGNORECASE
    ),
    "plan citation": re.compile(
        r"\bplan (?:decision|task|items? \d|" + SECTION_SIGN + r"|[A-E]\d\b)", re.IGNORECASE
    ),
    # Words about "the plan" that only make sense with the private plan in hand. Misses other
    # verbs ("the plan wanted"); a plain "the plan" in ordinary text is allowed.
    "plan quote": re.compile(
        r"\bthe plan(?:'s)? (?:said|says|interface|called|named|promised)\b"
        r"|\b[A-E]\d (?:in|of|from) the (?:plan|spec|design)\b",
        re.IGNORECASE,
    ),
    # A section sign followed by a number, with or without "spec" or "design" before it.
    "section citation": re.compile(SECTION_SIGN + r"\s?\d"),
    # Misses a spec citation written without a dot ("spec 3"); that is ordinary enough to allow.
    "spec citation": re.compile(r"\bspec \d+\.\d+|\bhermes spec \d", re.IGNORECASE),
    # A short work-batch tag standing alone (letters sp and a digit). Not inside a longer word.
    "internal batch tag": re.compile(r"\bsp[1-9]\b", re.IGNORECASE),
    # A letter and digit naming a work batch, followed by a noun or verb, or after until/and/or.
    # Upper case only, so hex data in lower case passes. Misses a label standing alone at the end
    # of a phrase, and C, D or E labels that are not followed by "test" or "task". It also hits a
    # spreadsheet cell written next to a lower-case word.
    "internal batch label": re.compile(
        r"\b[A-E]\d (?:tests?|task)\b|\b[AB]\d [a-z]|\b(?:until|and|or) [AB]\d\b"
    ),
    # A batch label inside an identifier: an upper-case prefix before an underscore, or a
    # lower-case suffix after one. Misses a label in the middle of a name.
    "internal batch name": re.compile(r"\b[A-E]\d_[A-Z]{2,}|(?<=[a-z])_[a-e]\d\b"),
    "internal task label": re.compile(r"\btask [A-E]\d\b", re.IGNORECASE),
    # Misses a bare "2a" with no "the" or noun after it.
    "internal table label": re.compile(
        r"\bthe 2[ab]\b|\b2[ab] (?:table|data|shape|format)\b", re.IGNORECASE
    ),
    # Also hits the compact and underscore forms, not only the spaced one.
    "internal stage": re.compile(r"(?<![A-Za-z])stage[ _-]?\d", re.IGNORECASE),
    "internal phase": re.compile(r"\bPhase [0-9A-E]\b"),
    "internal task number": re.compile(r"\bTask [A-E]?\d\b"),
    "early experiment": re.compile(r"\bspi" + r"ke\b", re.IGNORECASE),
    # A home folder on Windows, macOS or Linux, whoever it belongs to. A "/home/" inside a
    # longer path, such as "$WORK/home/plugins", is not a home folder.
    "local path": re.compile(r"[A-Za-z]:\\Users\\|/Users/[A-Za-z]|(?<![\w$}.])/home/[a-z]"),
}


def _text_of(path: Path) -> str | None:
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return None  # a binary file


def published_files() -> list[Path]:
    """Every text file the public export keeps, whatever its suffix.

    Top level: each file, except the private spec. Folders: everything under FOLDERS, pruning the
    folders that are not published. Files that do not decode as UTF-8 are left out.
    """
    found = [
        path
        for path in ROOT.iterdir()
        if path.is_file()
        and not path.name.startswith(PRIVATE_TOP_LEVEL_PREFIX)
        and path.name not in SKIPPED_PARTS
    ]
    for folder in FOLDERS:
        for directory, subfolders, names in os.walk(ROOT / folder):
            subfolders[:] = [name for name in subfolders if name not in SKIPPED_PARTS]
            found.extend(Path(directory) / name for name in names)
    return sorted(path for path in found if _text_of(path) is not None)


def problems_in(text: str) -> list[str]:
    return [
        f"line {number}: {name}"
        for number, line in enumerate(text.splitlines(), 1)
        for name, pattern in PATTERNS.items()
        if pattern.search(line)
    ]


def test_the_guard_catches_each_kind() -> None:
    samples = [
        ("private docs folder", "see docs/" + PRIVATE_FOLDER + "/plans"),
        ("private spec", "PROJECT_" + "SPEC_x.md"),
        ("internal project number", "the sub-" + "project 3 shape"),
        ("internal project number", "def test_x_sub_" + "project_1_message():"),
        ("internal project number", "the sub" + "project3 code"),
        ("design citation", "(design " + "4.7)"),
        ("design citation", "Design " + "section 17 item 6"),
        ("design citation", "as in design " + "decision 5"),
        ("plan citation", "plan " + "decision 2"),
        ("plan citation", "(plan " + "A1)"),
        ("plan citation", "see plan " + "item 4"),
        ("plan quote", "the plan " + "said so"),
        ("plan quote", "The plan" + "'s interface: discover(values)"),
        ("plan quote", "D1 in " + "the plan"),
        ("section citation", "(" + SECTION_SIGN + "7.1)"),
        ("section citation", "spec " + SECTION_SIGN + "4.4"),
        ("spec citation", "hermes " + "spec " + "3.4"),
        ("internal batch tag", "the " + "sp" + "3 work"),
        ("internal batch name", "os.environ.get(" + '"B5' + '_SURVEY")'),
        ("internal batch name", "no_such_module" + "_b1.func"),
        ("internal stage", "read in stage " + "3"),
        ("internal stage", "def test_" + "stage" + "3_x():"),
        ("internal stage", "the " + "stage" + "3 keys"),
        ("internal phase", "Phase " + "2"),
        ("internal task number", "Task " + "B1"),
        ("internal task label", "(task " + "B2)"),
        ("internal batch label", "for the B" + "3 tests"),
        ("internal batch label", "which A" + "1 added"),
        ("internal batch label", "unchanged until B" + "5"),
        ("internal table label", "from the 2" + "a table"),
        ("early experiment", "from a spi" + "ke"),
        ("local path", "C:\\" + "Users\\someone"),
        ("local path", "/mnt/c/" + "Users/someone"),
        ("local path", "cd /" + "home/someone/project"),
    ]
    for name, sample in samples:
        assert any(name in problem for problem in problems_in(sample)), sample


def test_ordinary_words_pass() -> None:
    ordinary = [
        "The design of the gate. A staged rollout. A CrewAI Task runs.",
        'trace_id = "a1" * 16',
        'span_id = "b2" * 8',
        'return "b4-real"',
        "case C1 and C2 cover the tool; the 2nd table has 2 rows.",
        "Plan the work, then run the plan.",
        "Run the tests in group B or the unit tests.",
        "The plan lists each case; the plan's rows are sorted by path.",
        "A plan item is one planned case, and the plan shows what it needs.",
        "The spec 2 cases are in the spec file; see spec.yaml, version 3.",
        "A word such as lisp3x or wasp3 holds the letters but is not a tag.",
        "A staging area, upstage, and a stagehand all pass.",
        "Set trace_id to a1 or 0xb2; the id is tool_call_1 or agent_x2.",
        "The sub-agent and the subprocess run one after the other.",
        "Section 4 of RFC 9110 and the mark \u00a7 alone are fine.",
    ]
    for line in ordinary:
        assert problems_in(line) == [], line


@pytest.mark.parametrize("path", published_files(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_private_references(path: Path) -> None:
    assert problems_in(path.read_text(encoding="utf-8")) == []
