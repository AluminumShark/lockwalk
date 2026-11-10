"""The Hermes example in examples/hermes runs through the real CLI, and its files are clean.

The traces were recorded from a real Hermes Agent with a fake model and scrubbed (see
examples/hermes/record). Nothing here calls a model, a network or Hermes itself. Trace ids and
timestamps change on every re-record, so no test pins them.
"""

import importlib.util
import json
import re
import shutil
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from typer.testing import CliRunner

from lockwalk.cli import app
from lockwalk.observe import pipeline as observe_pipeline

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = REPO_ROOT / "examples" / "hermes"
TRACES = EXAMPLE / "traces"
TRACE_NAMES = ["delegate", "approve_allow", "approve_deny", "unattended_block", "bypass_edited"]

runner = CliRunner()
NO_SUBJECT = (
    "{n} door records have no subject (for example a person's approval); "
    "they count for guard checks only"
)
DENIED_UNVERIFIED_NOTE = (
    "  - 1 denied call(s) of terminal are DENIED_UNVERIFIED: no effect marker was seen for "
    "the tool, so the denial is not proven"
)


@pytest.fixture(autouse=True)
def no_local_test_report(monkeypatch: pytest.MonkeyPatch) -> None:
    """A manual `lockwalk test` run may leave a test report that observe would read; the output
    must not depend on it."""
    monkeypatch.setattr(observe_pipeline, "load_test_report", lambda _path: (None, None))


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the example (without the recorder), which is also the working directory."""
    root = tmp_path / "hermes"
    shutil.copytree(
        EXAMPLE, root, ignore=shutil.ignore_patterns("record", "__pycache__", ".lockwalk")
    )
    monkeypatch.chdir(root)
    return root


def observe(project: Path, names: list[str], *extra: str) -> tuple[int, list[str], dict]:
    out = project / "out"
    args = ["observe", "--output-dir", str(out), *extra]
    for name in names:
        args += ["--traces", f"traces/{name}.jsonl"]
    result = runner.invoke(app, args)
    report = json.loads((out / "observe.json").read_text(encoding="utf-8"))
    return result.exit_code, result.output.splitlines(), report


def violations(report: dict) -> list[tuple[str, str | None, str | None]]:
    return [(v["rule"], v.get("agent"), v.get("tool")) for v in report["gate"]["violations"]]


def route_set(report: dict, status: str) -> set[tuple[str, str]]:
    return {(r["from_id"], r["to_id"]) for r in report["routes"] if r["status"] == status}


def guard_counts(report: dict) -> dict[tuple[str, str], dict[str, int]]:
    return {(g["agent"], g["tool"]): g["counts"] for g in report["guards"]}


def test_delegate_has_no_door_for_a_plain_command(project: Path) -> None:
    code, lines, report = observe(project, ["delegate"])
    assert code == 1
    on_map = route_set(report, "ON_MAP")
    assert {("user", "hermes-agent"), ("hermes-agent", "leaf")} <= on_map
    assert not route_set(report, "OFF_MAP")
    assert guard_counts(report) == {
        ("leaf", "terminal"): {"UNGUARDED": 1},
        ("hermes-agent", "delegate_task"): {"UNGUARDED": 1},
    }
    # Only the critical terminal call blocks; the medium delegate_task call does not.
    assert violations(report) == [("fail_on_unguarded_call", "leaf", "terminal")]
    assert report["identities"] == []
    assert report["warnings"] == []
    assert report["unknown"] == []
    assert report["errors"] == []
    assert report["exit_code"] == 1
    assert "  leaf / terminal: UNGUARDED 1" in lines
    assert "  hermes-agent / delegate_task: UNGUARDED 1" in lines
    assert "Real paths no case tests (UNTESTED):" in lines
    assert any(line.startswith("  hermes-agent / delegate_task: 1 time(s)") for line in lines)
    assert "Tested paths: 1 TESTED" in lines
    assert "Gate: FAIL (exit 1) - 1 violation(s)" in lines


def without_agent_rule(text: str) -> str:
    """The TOML text without its `kind = "agent"` [[observe.rules]] table."""
    blocks = re.findall(r"\[\[observe\.rules\]\]\n(?:[^\n\[#][^\n]*\n)+", text)
    agent = [block for block in blocks if re.search(r'^kind = "agent"$', block, re.M)]
    assert len(agent) == 1, "expected exactly one agent rule in .lockwalk.toml"
    result = text.replace(agent[0], "")
    kinds = [rule["kind"] for rule in tomllib.loads(result)["observe"]["rules"]]
    assert "agent" not in kinds
    assert len(kinds) == len(blocks) - 1
    return result


def test_delegate_without_the_agent_rule_is_off_map(project: Path) -> None:
    toml = project / ".lockwalk.toml"
    toml.write_text(without_agent_rule(toml.read_text(encoding="utf-8")), encoding="utf-8")
    code, _, report = observe(project, ["delegate"])
    assert code == 1
    assert ("leaf", "hermes-agent") in route_set(report, "OFF_MAP")


def test_approve_allow_is_guarded(project: Path) -> None:
    code, lines, report = observe(project, ["approve_allow"])
    assert code == 0
    assert guard_counts(report) == {("hermes-agent", "terminal"): {"GUARDED": 1}}
    assert report["identities"] == []
    # One record for one call: the approval span.
    assert report["warnings"] == [NO_SUBJECT.format(n=1)]
    assert report["gate"]["violations"] == []
    assert report["exit_code"] == 0
    assert "Guarded calls: 1 GUARDED" in lines
    assert "Gate: PASS (exit 0)" in lines


def test_approve_deny_alone_is_denied_unverified(project: Path) -> None:
    code, lines, report = observe(project, ["approve_deny"])
    assert code == 0
    assert guard_counts(report) == {("hermes-agent", "terminal"): {"DENIED_UNVERIFIED": 1}}
    assert report["identities"] == []
    # Two records for one call: the approval span and the `blocked` outcome of the tool span.
    assert report["warnings"] == [NO_SUBJECT.format(n=2)]
    assert report["gate"]["violations"] == []
    assert DENIED_UNVERIFIED_NOTE in lines


def test_approve_deny_with_approve_allow_is_denied(project: Path) -> None:
    code, lines, report = observe(project, ["approve_deny", "approve_allow"])
    assert code == 0
    assert guard_counts(report) == {("hermes-agent", "terminal"): {"GUARDED": 1, "DENIED": 1}}
    # 2 records for the denied call (approval and `blocked` outcome) plus 1 for the allowed one.
    assert report["warnings"] == [NO_SUBJECT.format(n=3)]
    assert report["gate"]["violations"] == []
    assert "Guarded calls: 1 GUARDED, 1 DENIED" in lines


GUIDE = REPO_ROOT / "docs" / "lockwalk-observe.md"


def hermes_section() -> str:
    text = GUIDE.read_text(encoding="utf-8")
    return text.split("\n### Hermes Agent\n", 1)[1].split("\n### ", 1)[0]


def test_guide_shows_the_real_summary_output(project: Path) -> None:
    """The text block of the Hermes section is what --summary prints (without the report path).
    --summary is used because the full output has a Window line with the recording times, which
    change on every re-record."""
    _, lines, _ = observe(project, ["approve_deny", "approve_allow"], "--summary")
    shown = lines[: next(i for i, line in enumerate(lines) if line.startswith("Report written"))]
    block = hermes_section().split("```text\n", 1)[1].split("```", 1)[0].splitlines()
    assert block == shown[:-1]  # the last shown line is the empty one before the report path
    assert not re.search(r"\d{4}-\d{2}-\d{2}T|[0-9a-f]{32}", "\n".join(block))


def test_guide_rules_are_those_of_the_example() -> None:
    toml_block = hermes_section().split("```toml\n")[2].split("```", 1)[0]  # [1] is the header
    rules = (EXAMPLE / ".lockwalk.toml").read_text(encoding="utf-8").split("# A sub-agent", 1)[1]
    assert toml_block == "# A sub-agent" + rules


def test_unattended_block_is_denied_by_the_blocked_rule(project: Path) -> None:
    code, _, report = observe(project, ["unattended_block"])
    assert code == 0
    assert guard_counts(report) == {("hermes-agent", "terminal"): {"DENIED_UNVERIFIED": 1}}
    assert report["identities"] == []
    # One record: the `blocked` outcome (there is no approval span in unattended mode).
    assert report["warnings"] == [NO_SUBJECT.format(n=1)]
    assert report["gate"]["violations"] == []


def test_bypass_edited_is_a_bypass(project: Path) -> None:
    code, lines, report = observe(project, ["bypass_edited"])
    assert code == 1
    assert guard_counts(report) == {("hermes-agent", "terminal"): {"BYPASS": 1}}
    assert violations(report) == [("bypass", "hermes-agent", "terminal")]
    assert report["exit_code"] == 1
    assert "  hermes-agent / terminal: BYPASS 1" in lines


def test_all_five_traces_run_together_and_report_the_bypass(project: Path) -> None:
    """The whole traces folder is one run: five files, five distinct traces, and the BYPASS of
    bypass_edited is found next to the other findings (a BYPASS is a gate violation: exit 1)."""
    out = project / "out"
    result = runner.invoke(app, ["observe", "--output-dir", str(out), "--traces", "traces"])
    report = json.loads((out / "observe.json").read_text(encoding="utf-8"))
    assert report["errors"] == []
    assert report["unknown"] == []
    assert result.exit_code == 1, result.output
    assert report["exit_code"] == 1
    assert guard_counts(report)[("hermes-agent", "terminal")]["BYPASS"] == 1
    assert ("bypass", "hermes-agent", "terminal") in violations(report)
    assert any(
        x.startswith("Read:") and "5 traces, 34 spans" in x for x in result.output.splitlines()
    )


@pytest.mark.parametrize("name", TRACE_NAMES)
def test_no_trace_has_static_errors(name: str, project: Path) -> None:
    code, _, report = observe(project, [name])
    assert code in (0, 1)
    assert report["errors"] == []
    assert report["unknown"] == []


def test_coverage_reports_the_tools_without_a_case(project: Path) -> None:
    result = runner.invoke(app, ["coverage", "--output-dir", str(project / "cov")])
    assert result.exit_code == 1
    (line,) = [x for x in result.output.splitlines() if x.startswith("Tools without spec:")]
    assert "delegate_task, risk=medium" in line
    assert "execute_code, risk=critical" in line
    assert "terminal, risk" not in line  # the spec has cases for terminal


def test_registry_tools_are_the_tools_in_tools_json() -> None:
    registry = yaml.safe_load((EXAMPLE / "registry.yaml").read_text(encoding="utf-8"))
    exported = json.loads((EXAMPLE / "tools.json").read_text(encoding="utf-8"))
    registry_ids = [tool["id"] for tool in registry["tools"]]
    assert len(set(registry_ids)) == len(registry_ids)
    assert sorted(registry_ids) == sorted(tool["name"] for tool in exported["tools"])


def trace_id(name: str) -> str:
    doc = json.loads((TRACES / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()[0])
    return doc["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"]


def test_inspect_shows_the_approval_as_a_decision_only_record(project: Path) -> None:
    result = runner.invoke(
        app,
        ["inspect", "--trace", trace_id("approve_allow"), "--traces", "traces/approve_allow.jsonl"],
    )
    assert result.exit_code == 0, result.output
    assert "door: allow (decision only, no subject) (linked by tool call id)" in result.output


# ---- privacy of the committed files ----


@pytest.fixture(scope="module")
def scrub() -> ModuleType:
    """scrub.py, loaded without writing bytecode into the example folder."""
    spec = importlib.util.spec_from_file_location(
        "hermes_record_scrub", EXAMPLE / "record" / "scrub.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def documents(name: str) -> list[dict]:
    path = TRACES / f"{name}.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def spans_of(docs: list[dict]) -> list[dict]:
    return [
        span
        for doc in docs
        for rs in doc["resourceSpans"]
        for ss in rs["scopeSpans"]
        for span in ss["spans"]
    ]


def strings(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from strings(item)


# Parts that point at a path, a drive, a URL or an address. None of the files holds one.
FORBIDDEN = ("/home/", "/tmp/", "/Users/", "\\Users\\", "/root", "C:\\", "://", "@")
PRIVACY_FILES = [f"traces/{name}.jsonl" for name in TRACE_NAMES] + ["tools.json"]


@pytest.mark.parametrize("name", TRACE_NAMES)
def test_traces_hold_only_allowed_attributes(name: str, scrub: ModuleType) -> None:
    docs = documents(name)
    assert docs
    for doc in docs:
        for rs in doc["resourceSpans"]:
            keys = {a["key"] for a in rs["resource"]["attributes"]}
            assert keys <= scrub.KEEP_RESOURCE
    assert spans_of(docs)
    for span in spans_of(docs):
        assert "events" not in span
        assert "links" not in span
        for attr in span["attributes"]:
            assert attr["key"] in scrub.KEEP_SPAN
            if attr["key"] == "user.id":
                assert attr["value"] == {"stringValue": scrub.DEMO_USER}


@pytest.mark.parametrize("relative", PRIVACY_FILES)
def test_committed_files_hold_no_path_or_address(relative: str) -> None:
    text = (EXAMPLE / relative).read_text(encoding="utf-8")
    for part in FORBIDDEN:
        if part in text:
            pytest.fail(f"{relative} contains {part!r}")


@pytest.mark.parametrize("name", TRACE_NAMES)
def test_scrubbing_a_committed_trace_changes_nothing(name: str, scrub: ModuleType) -> None:
    """Every value passes VALUE_RULES and the allowlists: scrubbing again gives the same bytes."""
    docs = documents(name)
    again = [scrub.scrub_document(doc) for doc in docs]
    assert again == docs
    dumped = "".join(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n" for d in again)
    assert dumped == (TRACES / f"{name}.jsonl").read_bytes().decode("utf-8")


def test_bypass_edited_differs_from_approve_deny_only_in_ids_and_the_outcome() -> None:
    """The copy has its own trace and span ids (so both files can be read in one folder run);
    apart from the ids, the only difference is the tool outcome, blocked -> completed."""
    deny = spans_of(documents("approve_deny"))
    bypass = spans_of(documents("bypass_edited"))
    assert len(deny) == len(bypass)
    hex32, hex16 = re.compile(r"[0-9a-f]{32}"), re.compile(r"[0-9a-f]{16}")
    # Every id is rewritten, valid, and not shared with the source file.
    deny_traces = {s["traceId"] for s in deny}
    bypass_traces = {s["traceId"] for s in bypass}
    assert len(deny_traces) == len(bypass_traces) == 1
    assert deny_traces.isdisjoint(bypass_traces)
    assert all(hex32.fullmatch(t) for t in bypass_traces)
    deny_ids = [s["spanId"] for s in deny]
    bypass_ids = [s["spanId"] for s in bypass]
    assert len(set(bypass_ids)) == len(bypass_ids)
    assert set(deny_ids).isdisjoint(bypass_ids)
    assert all(hex16.fullmatch(i) for i in bypass_ids)
    # The rewrite is one consistent mapping: every parent link points at the rewritten parent.
    mapping = dict(zip(deny_ids, bypass_ids, strict=True))
    changed = []
    for before, after in zip(deny, bypass, strict=True):
        assert after.get("parentSpanId", "") == mapping.get(before.get("parentSpanId", ""), "")
        restored = {
            **after,
            "traceId": before["traceId"],
            "spanId": before["spanId"],
            **({"parentSpanId": before["parentSpanId"]} if "parentSpanId" in before else {}),
        }
        if before == restored:
            continue
        outcome = {"stringValue": "completed"}
        key = "hermes.tool.outcome"
        assert before["name"] == after["name"] == "tool.terminal"
        assert {a["key"]: a["value"] for a in before["attributes"]}[key] == {
            "stringValue": "blocked"
        }
        assert {a["key"]: a["value"] for a in after["attributes"]}[key] == outcome
        rest_before = [a for a in before["attributes"] if a["key"] != key]
        rest_after = [a for a in after["attributes"] if a["key"] != key]
        assert rest_before == rest_after
        assert {k: v for k, v in before.items() if k != "attributes"} == {
            k: v for k, v in restored.items() if k != "attributes"
        }
        changed.append(before["name"])
    assert changed == ["tool.terminal"]


def test_edit_bypass_rewrites_ids_deterministically(scrub: ModuleType) -> None:
    """Scrubbing the same input with --edit-bypass twice gives the same bytes, and the committed
    bypass_edited.jsonl is exactly that output for approve_deny."""

    def edited() -> str:
        docs = [scrub.scrub_document(d, edit_bypass=True) for d in documents("approve_deny")]
        return "".join(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n" for d in docs)

    assert edited() == edited()
    assert edited() == (TRACES / "bypass_edited.jsonl").read_bytes().decode("utf-8")
