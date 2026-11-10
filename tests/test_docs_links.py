"""Every relative link and anchor in the public Markdown files points at something real.

Links to this project's GitHub pages count as relative: the README twins use them because PyPI
cannot resolve relative paths. External links are not fetched, because tests stay offline.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GITHUB = re.compile(
    r"^https://(?:github\.com/AluminumShark/lockwalk/(?:blob|tree)/main/"
    r"|raw\.githubusercontent\.com/AluminumShark/lockwalk/main/)(.*)$"
)
LINK = re.compile(r"\[(?:[^\]\n]|\n(?!\s*\n))*\]\(\s*([^)\s]+)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
HEADING = re.compile(r"^#{1,6} +(.+?) *#* *$")
EXTERNAL = ("http://", "https://", "mailto:")
PRIVATE = "super" + "powers"


def public_markdown() -> list[Path]:
    found = [
        *ROOT.glob("*.md"),
        *(ROOT / "docs").glob("*.md"),
        *(ROOT / "examples").rglob("*.md"),
    ]
    return sorted(
        path for path in found if PRIVATE not in path.parts and not path.name.startswith("PROJECT_")
    )


def without_code(text: str) -> list[str]:
    """The lines outside fenced code blocks."""
    lines: list[str] = []
    fence = ""
    for line in text.splitlines():
        stripped = line.lstrip()
        if fence:
            if stripped.startswith(fence):
                fence = ""
            continue
        if stripped.startswith(("```", "~~~")):
            fence = stripped[:3]
            continue
        lines.append(line)
    return lines


def slug(heading: str) -> str:
    """The anchor GitHub gives a heading."""
    plain = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading).replace("`", "").lower()
    kept = "".join(c for c in plain if c.isalnum() or c in " -_")
    return kept.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    result: set[str] = set()
    for line in without_code(path.read_text(encoding="utf-8")):
        match = HEADING.match(line)
        if match is None:
            continue
        base = slug(match.group(1))
        count = seen.get(base, 0)
        seen[base] = count + 1
        result.add(base if count == 0 else f"{base}-{count}")
    return result


def broken_links(path: Path) -> list[str]:
    problems: list[str] = []
    text = "\n".join(without_code(path.read_text(encoding="utf-8")))
    # Inline code can show a link as an example; it is not a link.
    text = re.sub(r"`[^`\n]*`", "", text)
    for target in LINK.findall(text):
        github = GITHUB.match(target)
        if github is not None:
            base = ROOT
            target = github.group(1)
        elif target.startswith(EXTERNAL):
            continue
        else:
            base = path.parent
        name, _, anchor = target.partition("#")
        destination = (base / name).resolve() if name else path
        if not destination.exists():
            problems.append(f"{target}: no such file")
            continue
        if anchor and destination.suffix == ".md" and anchor not in anchors(destination):
            problems.append(f"{target}: no such heading")
    return problems


@pytest.mark.parametrize("path", public_markdown(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_links_point_at_something_real(path: Path) -> None:
    assert broken_links(path) == []


def test_slug_matches_github_for_awkward_headings() -> None:
    assert slug("Waivers and --summary") == "waivers-and---summary"
    assert slug("How is this different from my policy engine's own tests?") == (
        "how-is-this-different-from-my-policy-engines-own-tests"
    )
    assert slug("`ask_every_hop`") == "ask_every_hop"


def test_a_broken_link_is_found(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text("# Top\n\n[a](#top) [b](#nope) [c](missing.md)\n", encoding="utf-8")
    assert broken_links(page) == ["#nope: no such heading", "missing.md: no such file"]


def test_a_link_whose_text_wraps_across_lines_is_found(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text("# Top\n\nsee [a link that\nwraps](missing.md) here\n", encoding="utf-8")
    assert broken_links(page) == ["missing.md: no such file"]


def test_a_link_with_a_title_is_found(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text("# Top\n\n[x](#nope \"a title\") [y](gone.md 't')\n", encoding="utf-8")
    assert broken_links(page) == ["#nope: no such heading", "gone.md: no such file"]


def test_a_missing_image_on_the_raw_host_is_found(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    url = "https://raw.githubusercontent.com/AluminumShark/lockwalk/main/docs/images/none.svg"
    page.write_text(f"# Top\n\n![a picture]({url})\n", encoding="utf-8")
    assert broken_links(page) == ["docs/images/none.svg: no such file"]
