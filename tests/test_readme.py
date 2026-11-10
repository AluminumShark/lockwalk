"""The README keeps working as written, and its two pictures stay plain and true."""

import re
import shlex
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import get_args

import pytest
from typer.testing import CliRunner

from lockwalk.cli import app
from lockwalk.models import CaseStatus, EscalationResult, GateRule, ToolCoverage

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")
FENCE = "```"


def block_after(text: str, marker: str) -> str:
    """The fenced code block right after an HTML comment marker."""
    start = text.index(f"<!-- {marker} -->")
    opening = text.index(FENCE, start)
    body = text.index("\n", opening) + 1
    return text[body : text.index(FENCE, body)]


def pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def test_one_readme_serves_github_and_pypi() -> None:
    # PyPI shows neither Mermaid nor a relative path, so the README has to use neither.
    assert not (ROOT / "README.pypi.md").exists()
    text = README.read_text(encoding="utf-8")
    assert "mermaid" not in text
    for target in LINK.findall(text):
        assert target.startswith(("https://", "#")), target


def test_the_readme_stays_short() -> None:
    assert len(README.read_text(encoding="utf-8").splitlines()) <= 320


def test_pypi_shows_the_readme_and_has_project_urls() -> None:
    project = pyproject()
    assert project["readme"] == "README.md"
    assert set(project["urls"]) == {"Homepage", "Documentation", "Issues", "Changelog"}
    for url in project["urls"].values():
        assert url.startswith("https://github.com/AluminumShark/lockwalk")


def test_the_extras_the_readme_installs_exist() -> None:
    text = README.read_text(encoding="utf-8")
    for extra in re.findall(r"lockwalk\[(\w+)\]", text):
        assert extra in pyproject()["optional-dependencies"]


def test_the_quick_start_works_as_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = README.read_text(encoding="utf-8")
    (tmp_path / "registry.yaml").write_text(block_after(text, "quickstart:registry"), "utf-8")
    spec = tmp_path / "security-spec.yaml"
    spec.write_text(block_after(text, "quickstart:spec"), "utf-8")
    monkeypatch.chdir(tmp_path)
    command = ["coverage", "--registry", "registry.yaml", "--spec", "security-spec.yaml"]
    assert "lockwalk " + " ".join(command) in block_after(text, "quickstart:run")

    before = CliRunner().invoke(app, command)
    assert before.exit_code == 1, before.output
    for line in block_after(text, "quickstart:output").strip().splitlines():
        assert line.strip() in before.output

    spec.write_text(spec.read_text("utf-8") + block_after(text, "quickstart:fix"), "utf-8")
    after = CliRunner().invoke(app, command)
    assert after.exit_code == 0, after.output
    assert "Gate: PASS (exit 0)" in after.output


def test_the_next_step_works_as_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # It builds on the quick start's two files, after the fix block was added. Nothing here
    # reaches the network: the policy is a Python function in the folder.
    text = README.read_text(encoding="utf-8")
    (tmp_path / "registry.yaml").write_text(block_after(text, "quickstart:registry"), "utf-8")
    spec = block_after(text, "quickstart:spec") + block_after(text, "quickstart:fix")
    spec += block_after(text, "next:case")
    (tmp_path / "security-spec.yaml").write_text(spec, "utf-8")
    (tmp_path / "my_iam.py").write_text(block_after(text, "next:iam"), "utf-8")
    monkeypatch.chdir(tmp_path)

    command = block_after(text, "next:run").strip()
    assert command.startswith("lockwalk test ")
    result = CliRunner().invoke(app, shlex.split(command)[1:])
    assert result.exit_code == 0, result.output
    for line in block_after(text, "next:output").strip().splitlines():
        assert line.strip() in result.output
    # The next step is a small one: what the reader types stays under 30 lines.
    typed = [block_after(text, marker) for marker in ("next:iam", "next:case", "next:run")]
    assert sum(len(block.splitlines()) for block in typed) < 30


def test_the_python_discovery_command_works_as_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The README names my_app.agents:main_agent. A plain list of functions is the smallest
    # object that module could hold, and it needs no agent framework.
    package = tmp_path / "my_app"
    package.mkdir()
    (package / "agents.py").write_text(
        "def read_ticket(ticket_id: str) -> str:\n"
        '    """Read a ticket."""\n'
        "    return ticket_id\n\n\n"
        "main_agent = [read_ticket]\n",
        "utf-8",
    )
    monkeypatch.chdir(tmp_path)
    command = "lockwalk discover --python my_app.agents:main_agent"
    text = README.read_text(encoding="utf-8")
    assert command in text
    # It belongs under the discover command, where a reader has a target to point it at.
    assert text.index(command) > text.index("**`lockwalk discover`**")
    assert text.index(command) < text.index("**`lockwalk coverage`**")
    result = CliRunner().invoke(app, shlex.split(command)[1:])
    assert result.exit_code == 0, result.output
    assert "read_ticket" in result.output


def test_the_words_section_stays_short_and_defines_the_terms() -> None:
    text = README.read_text(encoding="utf-8")
    section = text.split("## Words you will see", 1)[1].split("\n## ", 1)[0]
    assert len([line for line in section.splitlines() if line.strip()]) < 20
    terms = (
        "IAM",
        "Policy engine",
        "PDP",
        "PEP",
        "Door",
        "AuthZEN",
        "AuthN",
        "The map",
        "Fixture",
        "Waiver",
        "Harness",
        "Gate",
        "Trace",
    )
    for term in terms:
        assert term in section, term
    assert "`[harness]`" in section
    # The words explain the picture, so they come right after it, before anything uses them.
    order = [line for line in text.splitlines() if line.startswith("## ")]
    assert order.index("## Words you will see") == order.index("## Where it fits") + 1
    # The status words are defined in the text, not only in the picture.
    body = text.replace(section, "")
    for word in ("UNSPECIFIED", "FAIL_POLICY", "FAIL_EXECUTION"):
        assert f"`{word}`" in body, word


def test_the_policy_forms_the_readme_names_are_the_ones_test_accepts() -> None:
    text = README.read_text(encoding="utf-8")
    help_text = " ".join(CliRunner().invoke(app, ["test", "--help"]).output.split())
    for form in ("authzen:URL", "python:module:function"):
        assert f"--policy {form}" in text, form
        assert form in help_text, form


def test_the_readme_does_not_claim_more_than_it_checks() -> None:
    text = " ".join(README.read_text(encoding="utf-8").split())
    assert "never needs an adapter" not in text
    assert "keep an agent system safe" not in text
    assert "prompt injection" in text
    assert "imports your Python modules" in text


DOCS = ROOT / "docs"
PUBLIC_GUIDES = ("coverage", "test", "observe", "ci", "security")


def guide(name: str) -> str:
    return (DOCS / f"lockwalk-{name}.md").read_text(encoding="utf-8")


def headings(text: str) -> list[str]:
    return re.findall(r"^#{1,3} (.+)$", text, flags=re.MULTILINE)


def test_the_security_page_answers_the_readers_questions_near_the_top() -> None:
    text = guide("security")
    wanted = [
        "What a hostile module or server can do",
        "What lockwalk trusts without checking",
        "What can end up where",
    ]
    found = headings(text)
    assert [h for h in found if h in wanted] == wanted
    assert found.index("What lockwalk checks") < found.index(wanted[0])
    assert found.index(wanted[-1]) < found.index("Security notes")
    layers = text.split("## What lockwalk checks", 1)[1].split("\n## ", 1)[0]
    assert "lockwalk observe" in layers
    table = text.split("## What can end up where", 1)[1].split("\n## ", 1)[0]
    for output in ("coverage.json", "evidence.jsonl", "observe.json", "pull request comment"):
        assert output in table, output
    for kept_out in ("owner", "reason", "actor", "lockwalk-diff", "snapshot"):
        assert kept_out in table.lower(), kept_out


def test_exception_text_is_described_per_path() -> None:
    # decide() hides environment values of 8 or more characters; door tests do not.
    text = guide("security")
    assert "8 or more characters" in text
    section = text.split("### Exception text", 1)[1].split("\n### ", 1)[0]
    for place in (
        "Python sources",
        "`decide()`",
        "AuthZEN",
        "Door tests",
        "reader function",
        "MCP",
    ):
        assert place in section, place
    assert "Only URL credentials, query strings, and fragments are removed" not in guide("test")


def test_the_ci_page_says_what_a_pull_request_can_change() -> None:
    text = guide("ci")
    assert "## What a pull request can change" in text
    section = text.split("## What a pull request can change", 1)[1]
    for word in (".lockwalk.toml", "waivers file", "hooks file", "comment", "secret"):
        assert word in section, word


def test_the_guides_define_the_status_words_and_have_no_build_history() -> None:
    assert "`UNSPECIFIED`" in guide("coverage")
    glossary = (DOCS / "README.md").read_text(encoding="utf-8")
    for word in (
        "UNSPECIFIED",
        "UNTESTED",
        "NOT_TESTED",
        "NOT_RUN",
        "UNGUARDED",
        "UNKNOWN",
        "INCONCLUSIVE",
        "FAIL_POLICY",
        "FAIL_EXECUTION",
        "PEP",
        "PDP",
        "IAM",
        "Witness",
        "Opaque",
        "Positive control",
        "Harness",
        "Door",
    ):
        assert f"| {word} " in glossary or f"| `{word}` " in glossary, word
    history = re.compile(r"earlier build|this branch|worked before|existing files|see Development")
    for name in PUBLIC_GUIDES:
        assert not history.search(guide(name)), name
    assert "CONTRIBUTING.md" in guide("coverage")


IMAGES = ROOT / "docs" / "images"
IMAGE_BASE = "https://raw.githubusercontent.com/AluminumShark/lockwalk/main/docs/images/"
PICTURES = ("where-lockwalk-sits.svg", "how-lockwalk-works.svg")
SVG = "{http://www.w3.org/2000/svg}"


def image_texts(name: str) -> list[str]:
    root = ET.parse(IMAGES / name).getroot()
    return [element.text or "" for element in root.iter(f"{SVG}text")]


@pytest.mark.parametrize("name", PICTURES)
def test_the_readme_shows_each_picture_with_a_description(name: str) -> None:
    pattern = rf"!\[([^\]]+)\]\({re.escape(IMAGE_BASE + name)}\)"
    match = re.search(pattern, README.read_text("utf-8"))
    assert match is not None
    # The description stands in when the image cannot load, so it has to say what the picture does.
    for word in ("lockwalk", "coverage", "observe"):
        assert word in match.group(1).lower()


@pytest.mark.parametrize("name", PICTURES)
def test_each_picture_is_plain(name: str) -> None:
    # A picture on a public page must not run anything or load anything from elsewhere.
    text = (IMAGES / name).read_text("utf-8")
    assert text.isascii()
    for banned in ("<script", "foreignObject", "<image", "href", "http://www.w3.org/1999/xlink"):
        assert banned not in text, banned
    assert "url(http" not in text
    root = ET.parse(IMAGES / name).getroot()
    assert root.find(f"{SVG}title") is not None
    assert root.find(f"{SVG}desc") is not None


def test_where_it_fits_names_real_results() -> None:
    texts = image_texts("where-lockwalk-sits.svg")
    assert ToolCoverage.UNSPECIFIED.value in texts
    assert "never_reaches" in get_args(GateRule)
    assert "never_reaches" in texts
    assert EscalationResult.ESCALATION.value in texts
    assert CaseStatus.FAIL_POLICY.value in texts
    assert CaseStatus.FAIL_EXECUTION.value in texts
    # The picture shows agents calling agents, not a single straight line.
    for word in ("Entry agent", "Agent A", "Agent B", "as a tool", "PEP", "Policy engine (PDP)"):
        assert word in texts, word
    assert "lockwalk coverage" in texts
    assert "lockwalk test" in texts
    joined = " ".join(texts)
    for word in ("lockwalk observe", "OFF_MAP", "UNKNOWN", "MISMATCH", "BYPASS"):
        assert word in joined, word


def test_how_it_works_names_real_commands_and_reports() -> None:
    texts = image_texts("how-lockwalk-works.svg")
    for command in ("coverage", "test", "observe", "diff"):
        assert f"lockwalk {command}" in texts, command
        assert CliRunner().invoke(app, [command, "--help"]).exit_code == 0, command
    for file in ("registry.yaml", "security-spec.yaml", "coverage.json", "observe.json"):
        assert file in texts, file
