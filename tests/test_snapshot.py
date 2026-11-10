"""Offline inventory snapshots: write them, read them back as a JSON source."""

import json
import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from lockwalk.config import JsonSourceConfig
from lockwalk.graph.analysis import (
    evaluate_rules,
    graph_section,
    holderless_warnings,
    role_reachability,
)
from lockwalk.graph.build import build_graph
from lockwalk.inventory.jsonfile import UNAVAILABLE_IN_SNAPSHOT, JsonSource
from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import (
    EdgeKind,
    GraphEdge,
    GraphFragment,
    GraphNode,
    Inventory,
    NeverReachesRule,
    NodeKind,
    Provenance,
    RuleResult,
    SourceRef,
    SourceResult,
    ToolDescriptor,
)
from lockwalk.registry import Registry
from lockwalk.snapshot import SNAPSHOT_VERSION, SnapshotRefused, snapshot_document, write_snapshot

CAPTURED = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
WHEN = "2026-11-06T12:00:00Z"
UNAVAILABLE_NOTE = (
    "the snapshot saves these optional sources as unavailable, because they could not be "
    "read: mcp:pricing"
)


def handoff(a: str, b: str) -> GraphEdge:
    return GraphEdge(from_id=a, to_id=b, kind=EdgeKind.HANDOFF, provenance=Provenance.DISCOVERED)


def uses(a: str, tool: str) -> GraphEdge:
    return GraphEdge(
        from_id=a, to_id=tool, kind=EdgeKind.USES_TOOL, provenance=Provenance.DISCOVERED
    )


# desk could not read its tools (an Agno tools factory): it is opaque, with hidden tools.
DESK_FRAGMENT = GraphFragment(
    nodes=(
        GraphNode(id="desk", entry=True, opaque=True, tools_hidden=True),
        GraphNode(id="helper"),
    ),
    edges=(handoff("desk", "helper"), uses("helper", "search")),
)


def make_inventory(registry: dict[str, Any] | None = None) -> Inventory:
    """An MCP source that was read, a Python source with its graph, and an optional MCP
    source that could not be read."""
    sources = [
        SourceResult(
            source=SourceRef(kind="mcp", label="mcp:finance-tools"),
            ok=True,
            tools=(
                ToolDescriptor(
                    name="get_stock_price", description="Price", hints={"readOnlyHint": True}
                ),
                ToolDescriptor(name="execute_trade"),
            ),
            agents=("finance-agent",),
            warnings=("mcp:finance-tools: WARNING-TEXT",),
        ),
        SourceResult(
            source=SourceRef(kind="python", label="python:app:desk"),
            ok=True,
            tools=(ToolDescriptor(name="search", description="Find things"),),
            graph=DESK_FRAGMENT,
        ),
        SourceResult(
            source=SourceRef(kind="mcp", label="mcp:pricing"),
            ok=False,
            optional=True,
            agents=("finance-agent",),
            error="ConnectError: ERROR-TEXT https://user:hunter2@127.0.0.1:8/mcp?api_key=SECRET123",
        ),
    ]
    return merge_inventory(
        sources,
        registry=None if registry is None else Registry.model_validate(registry),
        registry_label="registry:registry.yaml",
    )


def read_json_source(base: Path, path: str, agents: tuple[str, ...] = ()) -> SourceResult:
    """The one result of a plain JSON file, or of a snapshot of one source."""
    return JsonSource(JsonSourceConfig(path=path, agents=agents), base).read()


def read_snapshot(base: Path, path: str, agents: tuple[str, ...] = ()) -> list[SourceResult]:
    """Every result of a snapshot: one per source it saved."""
    return JsonSource(JsonSourceConfig(path=path, agents=agents), base).read_all()


# ---- writing ----


def test_document_holds_every_source_with_what_the_graph_needs(finance_registry):
    document = snapshot_document(make_inventory(finance_registry), captured_at=CAPTURED)
    assert SNAPSHOT_VERSION == "2"
    assert document == {
        "lockwalk_snapshot": "2",
        "captured_at": WHEN,
        "sources": [
            {
                "label": "mcp:finance-tools",
                "kind": "mcp",
                "status": "ok",
                "optional": False,
                "agents": ["finance-agent"],
                "tools": [
                    {
                        "name": "get_stock_price",
                        "description": "Price",
                        "hints": {"readOnlyHint": True},
                    },
                    {"name": "execute_trade", "description": None, "hints": {}},
                ],
                "graph": None,
            },
            {
                "label": "python:app:desk",
                "kind": "python",
                "status": "ok",
                "optional": False,
                "agents": [],
                "tools": [{"name": "search", "description": "Find things", "hints": {}}],
                "graph": DESK_FRAGMENT.model_dump(mode="json"),
            },
            {
                "label": "mcp:pricing",
                "kind": "mcp",
                "status": "unavailable",
                "optional": True,
                "agents": ["finance-agent"],
                "tools": [],
                "graph": None,
            },
        ],
    }
    graph = document["sources"][1]["graph"]  # ty: ignore[not-subscriptable]
    assert graph["nodes"][0]["opaque"] is True
    assert graph["nodes"][0]["tools_hidden"] is True


def test_document_holds_no_errors_or_warnings(finance_registry):
    text = json.dumps(snapshot_document(make_inventory(finance_registry), captured_at=CAPTURED))
    for absent in ("ERROR-TEXT", "WARNING-TEXT", "hunter2", "SECRET123", "registry"):
        assert absent not in text


def failed_inventory() -> Inventory:
    return merge_inventory(
        [
            SourceResult(source=SourceRef(kind="json", label="json:t.json"), ok=True),
            SourceResult(
                source=SourceRef(kind="json", label="json:missing.json"),
                ok=False,
                error="file not found: ERROR-TEXT",
            ),
            # Optional, but it returned some tools and then failed: an error, as live.
            SourceResult(
                source=SourceRef(kind="mcp", label="mcp:partial"),
                ok=False,
                optional=True,
                tools=(ToolDescriptor(name="half"),),
                error="1 bad item",
            ),
        ]
    )


def test_a_failed_source_refuses_the_snapshot(tmp_path):
    """Leaving a failed source out could make a replay pass where the live run did not."""
    refusal = (
        "these sources failed: json:missing.json, mcp:partial; a snapshot cannot leave a "
        "source out, so fix them first (an MCP source that may be down can be "
        "optional = true, with agents)"
    )
    with pytest.raises(SnapshotRefused) as refused:
        snapshot_document(failed_inventory(), captured_at=CAPTURED)
    assert str(refused.value) == refusal
    path = tmp_path / "s.json"
    path.write_text("old", encoding="utf-8")
    with pytest.raises(SnapshotRefused):
        write_snapshot(failed_inventory(), path, captured_at=CAPTURED)
    assert [p.name for p in tmp_path.iterdir()] == ["s.json"]
    assert path.read_text(encoding="utf-8") == "old"


def test_captured_at_is_stored_in_utc():
    taipei = timezone(timedelta(hours=8))
    captured = datetime(2026, 11, 6, 20, 0, 5, tzinfo=taipei)
    document = snapshot_document(make_inventory(), captured_at=captured)
    assert document["captured_at"] == "2026-11-06T12:00:05Z"


def test_captured_at_must_be_timezone_aware(tmp_path):
    with pytest.raises(ValueError, match="captured_at must be timezone-aware"):
        snapshot_document(make_inventory(), captured_at=datetime(2026, 11, 6, 12, 0))
    with pytest.raises(ValueError, match="captured_at must be timezone-aware"):
        write_snapshot(make_inventory(), tmp_path / "s.json", captured_at=datetime(2026, 11, 6))
    assert not (tmp_path / "s.json").exists()


def test_write_then_read_round_trip(tmp_path, finance_registry):
    path = tmp_path / "out" / "snap.json"
    notes = write_snapshot(make_inventory(finance_registry), path, captured_at=CAPTURED)
    assert notes == [UNAVAILABLE_NOTE]
    assert [p.name for p in path.parent.iterdir()] == ["snap.json"]
    # Each saved source comes back as it was read: label, kind, tools, agents, and graph.
    finance, python, pricing = read_snapshot(tmp_path, "out/snap.json")
    assert (finance.ok, python.ok) == (True, True)
    assert finance.source == SourceRef(kind="mcp", label="mcp:finance-tools")
    assert python.source == SourceRef(kind="python", label="python:app:desk")
    assert [tool.name for tool in finance.tools] == ["get_stock_price", "execute_trade"]
    assert finance.tools[0].hints == {"readOnlyHint": True}
    assert [tool.description for tool in python.tools] == ["Find things"]
    assert (finance.graph, python.graph) == (None, DESK_FRAGMENT)
    assert finance.agents == ("finance-agent",)
    assert python.agents == ()
    # The optional source that could not be read is unavailable again, without its error.
    assert pricing.source == SourceRef(kind="mcp", label="mcp:pricing")
    assert (pricing.ok, pricing.optional, pricing.unavailable) == (False, True, True)
    assert pricing.error == UNAVAILABLE_IN_SNAPSHOT
    assert pricing.agents == ("finance-agent",)
    assert finance.warnings == (
        "json:out/snap.json: snapshot captured at 2026-11-06T12:00:00Z from 3 source(s): "
        "mcp:finance-tools, python:app:desk, mcp:pricing; it may be out of date",
        "json:out/snap.json: the agent graph of 1 source(s) comes from the snapshot, "
        "not from your code",
    )
    assert python.warnings == pricing.warnings == ()
    with pytest.raises(ValueError, match="holds 3 sources; use read_all"):
        read_json_source(tmp_path, "out/snap.json")


def test_no_note_when_every_source_was_read(tmp_path):
    inventory = merge_inventory(
        [SourceResult(source=SourceRef(kind="json", label="json:t.json"), ok=True)]
    )
    assert write_snapshot(inventory, tmp_path / "s.json", captured_at=CAPTURED) == []
    result = read_json_source(tmp_path, "s.json")
    assert result.ok
    assert result.tools == ()
    assert len(result.warnings) == 1  # only the date: no source had a graph


def test_snapshot_keeps_text_that_is_not_ascii(tmp_path):
    chinese = chr(0x522A) + chr(0x9664)
    surrogate = chr(0xD800)
    inventory = merge_inventory(
        [
            SourceResult(
                source=SourceRef(kind="json", label="json:t.json"),
                ok=True,
                tools=(
                    ToolDescriptor(name="delete", description=chinese),
                    ToolDescriptor(name="odd", description="x" + surrogate),
                ),
            )
        ]
    )
    path = tmp_path / "s.json"
    write_snapshot(inventory, path, captured_at=CAPTURED)
    assert chinese.encode("utf-8") in path.read_bytes()  # ensure_ascii=False
    result = read_json_source(tmp_path, "s.json")
    assert result.ok, result.error
    assert result.tools[0].description == chinese


def test_write_replaces_an_old_snapshot(tmp_path):
    path = tmp_path / "s.json"
    path.write_text("old", encoding="utf-8")
    write_snapshot(make_inventory(), path, captured_at=CAPTURED)
    assert json.loads(path.read_text(encoding="utf-8"))["lockwalk_snapshot"] == "2"


def test_a_failed_write_leaves_the_old_file_and_no_temp_file(tmp_path, monkeypatch):
    path = tmp_path / "s.json"
    path.write_text("old", encoding="utf-8")

    def broken_replace(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        write_snapshot(make_inventory(), path, captured_at=CAPTURED)
    assert path.read_text(encoding="utf-8") == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["s.json"]


def test_credentials_and_urls_stay_out(tmp_path):
    """The graph holds only what coverage.json shows: remote_url is already redacted."""
    remote = GraphNode(
        id="oracle",
        kind=NodeKind.REMOTE_AGENT,
        opaque=True,
        remote_url="https://carol:hunter2@oracle.example/a2a?key=SECRET123#frag",
    )
    inventory = merge_inventory(
        [
            SourceResult(
                source=SourceRef(kind="mcp", label="mcp:https://127.0.0.1:9/mcp"),
                ok=True,
                tools=(ToolDescriptor(name="a"),),
            ),
            SourceResult(
                source=SourceRef(kind="python", label="python:app:top"),
                ok=True,
                graph=GraphFragment(nodes=(GraphNode(id="top", entry=True), remote)),
            ),
            SourceResult(
                source=SourceRef(kind="mcp", label="mcp:pricing"),
                ok=False,
                optional=True,
                agents=("top",),
                error="ConnectError: https://user:hunter2@127.0.0.1:8/mcp?api_key=SECRET123",
            ),
        ]
    )
    path = tmp_path / "s.json"
    write_snapshot(inventory, path, captured_at=CAPTURED)
    text = path.read_text(encoding="utf-8")
    for secret in ("hunter2", "SECRET123", "127.0.0.1:8", "frag"):
        assert secret not in text
    assert "https://oracle.example/a2a" in text


# ---- reading snapshots as a JSON source ----


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def entry(
    label: str,
    *,
    kind: str = "mcp",
    status: str = "ok",
    optional: bool = False,
    agents: list[str] | None = None,
    tools: list[object] | None = None,
    graph: object = None,
) -> dict[str, object]:
    """One saved source in the snapshot format."""
    return {
        "label": label,
        "kind": kind,
        "status": status,
        "optional": optional,
        "agents": [] if agents is None else agents,
        "tools": [] if tools is None else tools,
        "graph": graph,
    }


def write_snapshot_of(path: Path, *sources: dict[str, object]) -> None:
    write_json(path, {"lockwalk_snapshot": "2", "captured_at": WHEN, "sources": list(sources)})


@pytest.mark.parametrize(("version", "shown"), [("3", "'3'"), (1, "1"), (None, "None")])
def test_unsupported_snapshot_version(tmp_path, version, shown):
    write_json(
        tmp_path / "s.json", {"lockwalk_snapshot": version, "captured_at": "x", "sources": []}
    )
    result = read_json_source(tmp_path, "s.json")
    assert not result.ok
    assert result.tools == ()
    assert result.error == f"unsupported snapshot version {shown}"


def test_a_version_1_snapshot_must_be_saved_again(tmp_path):
    """Version 1 held neither the agent graph nor the unread sources: replaying it could
    give a false PASS, so it is rejected."""
    write_json(
        tmp_path / "s.json",
        {
            "lockwalk_snapshot": "1",
            "captured_at": WHEN,
            "sources": [{"label": "mcp:a", "agents": [], "tools": [{"name": "t"}]}],
        },
    )
    result = read_json_source(tmp_path, "s.json")
    assert (result.ok, result.tools) == (False, ())
    assert result.error == (
        "snapshot version '1' holds neither the agent graph nor the sources that could not be "
        "read, so it cannot be replayed safely; save the snapshot again"
    )


BAD_TIME = "invalid snapshot: captured_at must look like 2026-01-01T00:00:00Z"
BAD_SHAPE = "invalid snapshot: sources[0] must have a string 'label' and a 'tools' list"
NOT_OPAQUE = {"nodes": [{"id": "desk", "tools_hidden": True}], "edges": []}


@pytest.mark.parametrize(
    ("document", "problem"),
    [
        ({"sources": []}, BAD_TIME),
        ({"captured_at": 5, "sources": []}, BAD_TIME),
        ({"captured_at": "x", "sources": []}, BAD_TIME),
        ({"captured_at": "2026-11-06 12:00:00", "sources": []}, BAD_TIME),
        ({"captured_at": "2026-11-06T12:00:00+08:00", "sources": []}, BAD_TIME),
        ({"captured_at": "2026-1-6T12:00:00Z", "sources": []}, BAD_TIME),
        ({"captured_at": "2026-13-06T12:00:00Z", "sources": []}, BAD_TIME),
        ({"captured_at": WHEN + "x" * 500, "sources": []}, BAD_TIME),
        ({"captured_at": WHEN}, "invalid snapshot: 'sources' must be a list"),
        ({"captured_at": WHEN, "sources": [5]}, "invalid snapshot: sources[0] must be an object"),
        ({"captured_at": WHEN, "sources": [{"tools": []}]}, BAD_SHAPE),
        ({"captured_at": WHEN, "sources": [{"label": "a"}]}, BAD_SHAPE),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", kind="registry")]},
            "invalid snapshot: sources[0].kind must be one of: mcp, python, json",
        ),
        (
            {"captured_at": WHEN, "sources": [{**entry("mcp:a"), "error": "x", "unexpected": 1}]},
            "invalid snapshot: sources[0] has unknown keys: error, unexpected",
        ),
        (
            {"captured_at": WHEN, "sources": [], "spare": True},
            "invalid snapshot has unknown keys: spare",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", kind="python")]},
            "invalid snapshot: sources[0].label must start with 'python:', the kind of the source",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("a")]},
            "invalid snapshot: sources[0].label must start with 'mcp:', the kind of the source",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", status="failed")]},
            "invalid snapshot: sources[0].status must be 'ok' or 'unavailable'",
        ),
        (
            {"captured_at": WHEN, "sources": [{**entry("mcp:a"), "optional": "no"}]},
            "invalid snapshot: sources[0].optional must be true or false",
        ),
        (
            {"captured_at": WHEN, "sources": [{**entry("mcp:a"), "agents": None}]},
            "invalid snapshot: sources[0].agents must be a list of agent names",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", status="unavailable")]},
            "invalid snapshot: sources[0]: an unavailable source must be optional",
        ),
        (
            {
                "captured_at": WHEN,
                "sources": [
                    entry("mcp:a", status="unavailable", optional=True, tools=[{"name": "t"}])
                ],
            },
            "invalid snapshot: sources[0]: an unavailable source must be optional",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", graph={"nodes": [], "spare": 1})]},
            "invalid snapshot: sources[0].graph: spare: Extra inputs are not permitted",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", graph=NOT_OPAQUE)]},
            "invalid snapshot: sources[0].graph: nodes[0]: Value error, a node whose tools are "
            "hidden must be opaque",
        ),
        (
            {"captured_at": WHEN, "sources": [entry("mcp:a", graph={"nodes": [{"id": " x"}]})]},
            "invalid snapshot: sources[0].graph: nodes[0].id: Value error, name must not",
        ),
    ],
)
def test_malformed_snapshots_fail(tmp_path, document, problem):
    write_json(tmp_path / "s.json", {"lockwalk_snapshot": "2", **document})
    result = read_json_source(tmp_path, "s.json")
    assert not result.ok
    assert result.error
    assert result.error.startswith(problem), result.error


def snapshot_with_sources(path: Path, labels: list[str]) -> None:
    write_snapshot_of(path, *(entry(label) for label in labels))


def test_the_snapshot_warning_names_at_most_three_sources(tmp_path):
    snapshot_with_sources(tmp_path / "s.json", [f"mcp:server-{n}" for n in range(5)])
    [warning] = [w for result in read_snapshot(tmp_path, "s.json") for w in result.warnings]
    assert warning == (
        f"json:s.json: snapshot captured at {WHEN} from 5 source(s): "
        "mcp:server-0, mcp:server-1, mcp:server-2, ...; it may be out of date"
    )


def test_the_snapshot_warning_with_no_sources(tmp_path):
    snapshot_with_sources(tmp_path / "s.json", [])
    result = read_json_source(tmp_path, "s.json")
    assert (result.source.label, result.ok, result.tools) == ("json:s.json", True, ())
    [warning] = result.warnings
    assert warning == (
        f"json:s.json: snapshot captured at {WHEN} from 0 source(s); it may be out of date"
    )


def test_the_snapshot_warning_stays_short(tmp_path):
    snapshot_with_sources(tmp_path / "s.json", ["mcp:" + "x" * 1000, "mcp:" + "y" * 1000])
    [warning] = [w for result in read_snapshot(tmp_path, "s.json") for w in result.warnings]
    assert len(warning) <= 300
    assert warning.startswith("json:s.json: snapshot captured at")
    assert warning.endswith("...")


def test_a_bad_tool_in_a_snapshot_names_its_source(tmp_path):
    write_snapshot_of(
        tmp_path / "s.json",
        entry("mcp:a", tools=[{"name": "ok"}]),
        entry("mcp:b", tools=[{"name": "fine"}, {"description": "no name"}]),
        entry("mcp:c", tools=[{"name": "x", "hints": {"readOnlyHint": "yes"}}]),
    )
    a, b, c = read_snapshot(tmp_path, "s.json")
    # Only the saved sources with a bad tool fail, each with its own error.
    assert (a.ok, b.ok, c.ok) == (True, False, False)
    assert [tool.name for tool in (*a.tools, *b.tools, *c.tools)] == ["ok", "fine"]
    assert a.error is None
    assert b.error == "item 1 of snapshot json:s.json: name: Field required"
    assert c.error == (
        "item 0 of snapshot json:s.json: hints.readOnlyHint: Input should be a valid boolean"
    )
    assert a.warnings[0].startswith("json:s.json: snapshot captured at")
    errors = merge_inventory([a, b, c]).errors
    assert errors == (f"mcp:b: {b.error}", f"mcp:c: {c.error}")


def test_plain_tool_files_are_not_snapshots(tmp_path):
    write_json(tmp_path / "t.json", {"tools": [{"name": "a"}]})
    result = read_json_source(tmp_path, "t.json")
    assert result.ok
    assert result.warnings == ()


def test_each_saved_source_keeps_its_own_agents(tmp_path):
    write_snapshot_of(
        tmp_path / "s.json", entry("mcp:a", agents=["x", "y"]), entry("mcp:b", agents=["y", "z"])
    )
    a, b = read_snapshot(tmp_path, "s.json")
    assert (a.ok, b.ok) == (True, True)
    # Nothing crosses from one source to another.
    assert a.agents == ("x", "y")
    assert b.agents == ("y", "z")


def test_a_json_source_with_agents_cannot_read_a_snapshot(tmp_path):
    """Extra agents would get every saved tool, which can hide that no agent holds one."""
    write_snapshot_of(tmp_path / "s.json", entry("mcp:a", tools=[{"name": "t"}]))
    [result] = read_snapshot(tmp_path, "s.json", agents=("ops-agent",))
    assert (result.source.label, result.ok, result.tools, result.agents) == (
        "json:s.json",
        False,
        (),
        (),
    )
    assert result.error == (
        "a snapshot keeps each source's agents; remove 'agents' from this [[inventory.json]]"
    )
    # A plain JSON file of tools still takes agents.
    write_json(tmp_path / "t.json", [{"name": "t"}])
    plain = read_json_source(tmp_path, "t.json", agents=("ops-agent",))
    assert (plain.ok, plain.agents) == (True, ("ops-agent",))


@pytest.mark.parametrize(
    ("agents", "detail"),
    [
        ("finance-agent", ""),
        ([5], ""),
        ([" padded"], ": ' padded': name must not start or end with whitespace"),
    ],
)
def test_bad_snapshot_agents_fail_the_source(tmp_path, agents, detail):
    write_snapshot_of(tmp_path / "s.json", {**entry("mcp:a"), "agents": agents})
    result = read_json_source(tmp_path, "s.json")
    assert not result.ok
    assert result.agents == ()
    assert result.error == (
        f"invalid snapshot: sources[0].agents must be a list of agent names{detail}"
    )


# ---- a snapshot gives the same graph findings as the live run ----


def mcp(label: str, tools: tuple[str, ...], agents: tuple[str, ...] = ()) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="mcp", label=label),
        ok=True,
        tools=tuple(ToolDescriptor(name=name) for name in tools),
        agents=agents,
    )


def findings(registry: dict[str, Any], rules: list[NeverReachesRule], sources: list[SourceResult]):
    """Everything the invariant compares: rule rows, reachability rows, opaque nodes, the
    tools_hidden flags, the holderless warning, and the edges."""
    parsed = Registry.model_validate(registry)
    inventory = merge_inventory(sources, registry=parsed, registry_label="registry")
    assert inventory.errors == ()
    graph = build_graph(parsed, inventory, registry_label="registry")
    rows = evaluate_rules(graph, rules, inventory)
    return (
        rows,
        role_reachability(graph, inventory, (), rows),
        graph_section(graph).opaque,
        {node.id: node.tools_hidden for node in graph.nodes},
        holderless_warnings(graph, inventory, has_rules=bool(rules)),
        graph.edges,
    )


def replayed(tmp_path: Path, live: list[SourceResult]) -> list[SourceResult]:
    """Save the live sources as a snapshot and read it back, as --tools-json does."""
    write_snapshot(merge_inventory(live), tmp_path / "snap.json", captured_at=CAPTURED)
    return read_snapshot(tmp_path, "snap.json")


def assert_same_as_live(tmp_path: Path, registry, rules, live, *, kept=()) -> tuple:
    """`kept` are live sources that are not in the snapshot (they stay live in both runs)."""
    expected = findings(registry, rules, [*kept, *live])
    assert findings(registry, rules, [*kept, *replayed(tmp_path, live)]) == expected
    return expected


MIXED_REGISTRY = {
    "schema_version": "1",
    "roles": ["analyst"],
    "agents": [
        {"id": "finance-agent", "entry": True, "roles": ["analyst"], "calls": []},
        {"id": "ops-agent", "calls": []},
    ],
    "tools": [
        {"id": "execute_trade", "action": "trade:execute", "risk": "critical"},
        {"id": "read_portfolio", "action": "portfolio:read", "risk": "high"},
        {"id": "stub", "action": "ops:stub", "risk": "low"},
    ],
}


def test_a_snapshot_of_a_source_without_agents_stays_inconclusive(tmp_path):
    """The snapmix probe: ops-agent used ops-tools only. Reading both saved sources as one
    gave ops-agent the finance tools too, which hid that nobody holds execute_trade."""
    live = [
        mcp("mcp:ops-tools", ("stub",), ("ops-agent",)),
        mcp("mcp:finance-tools", ("read_portfolio", "execute_trade")),
    ]
    rules = [NeverReachesRule(id="RULE-001", role="analyst", tool="execute_trade")]
    rows, _, _, _, warnings, _ = assert_same_as_live(tmp_path, MIXED_REGISTRY, rules, live)
    assert [(row.id, row.result) for row in rows] == [("RULE-001", RuleResult.INCONCLUSIVE)]
    assert len(warnings) == 1
    assert "reaches them: execute_trade, read_portfolio;" in warnings[0]


def test_saved_sources_with_different_agents_do_not_share_tools(tmp_path):
    registry = {
        "schema_version": "1",
        "agents": [
            {"id": "a-agent", "entry": True, "calls": []},
            {"id": "b-agent", "entry": True, "calls": []},
        ],
        "tools": [
            {"id": "ta", "action": "a:x", "risk": "high"},
            {"id": "tb", "action": "b:x", "risk": "critical"},
        ],
    }
    live = [mcp("mcp:a", ("ta",), ("a-agent",)), mcp("mcp:b", ("tb",), ("b-agent",))]
    rules = [
        NeverReachesRule(id="R1", agent="a-agent", tool="tb"),
        NeverReachesRule(id="R2", agent="b-agent", tool="tb"),
    ]
    rows, *_, edges = assert_same_as_live(tmp_path, registry, rules, live)
    assert [(row.id, row.result) for row in rows] == [
        ("R1", RuleResult.PASS),
        ("R2", RuleResult.FAIL),
    ]
    assert {(e.from_id, e.to_id) for e in edges} == {("a-agent", "ta"), ("b-agent", "tb")}


def test_a_delegation_tool_in_a_saved_source_links_only_that_sources_agents(tmp_path):
    registry = {
        "schema_version": "1",
        "agents": [
            {"id": "a-agent", "entry": True, "calls": []},
            {"id": "b-agent", "entry": True, "calls": []},
            {"id": "oracle", "calls": []},
        ],
        "delegation_tools": [{"id": "ask_oracle", "agent": "oracle"}],
        "tools": [{"id": "quote", "action": "q:x", "risk": "low", "supported_agents": ["oracle"]}],
    }
    live = [mcp("mcp:a", ("ask_oracle",), ("a-agent",)), mcp("mcp:b", ("other",), ("b-agent",))]
    rules = [
        NeverReachesRule(id="R1", agent="a-agent", target_agent="oracle"),
        NeverReachesRule(id="R2", agent="b-agent", target_agent="oracle"),
    ]
    rows, *_ = assert_same_as_live(tmp_path, registry, rules, live)
    assert [(row.id, row.result) for row in rows] == [
        ("R1", RuleResult.FAIL),
        ("R2", RuleResult.PASS),
    ]


def test_a_saved_mcp_source_still_matches_the_mcp_node_of_an_agent(tmp_path):
    """A Python source draws desk -> mcp:finance-tools; the saved MCP source keeps its
    label, so the node gets its tools as it does live."""
    registry = {
        "schema_version": "1",
        "agents": [{"id": "desk", "entry": True, "calls": []}],
        "tools": [{"id": "execute_trade", "action": "t:x", "risk": "critical"}],
    }
    fragment = GraphFragment(
        nodes=(
            GraphNode(id="desk", entry=True),
            GraphNode(id="mcp:finance-tools", kind=NodeKind.MCP_SERVER),
        ),
        edges=(
            GraphEdge(
                from_id="desk",
                to_id="mcp:finance-tools",
                kind=EdgeKind.REMOTE,
                provenance=Provenance.DISCOVERED,
            ),
        ),
    )
    python = SourceResult(
        source=SourceRef(kind="python", label="python:app"), ok=True, graph=fragment
    )
    rules = [NeverReachesRule(id="R1", agent="desk", tool="execute_trade")]
    live = [mcp("mcp:finance-tools", ("execute_trade",))]
    # The Python source is in the snapshot too, with its graph.
    rows, _, opaque, *_ = assert_same_as_live(tmp_path, registry, rules, [python, *live])
    assert [(row.id, row.result) for row in rows] == [("R1", RuleResult.FAIL)]
    assert opaque == ()


FACTORY_REGISTRY = {
    "schema_version": "1",
    "roles": ["analyst"],
    "agents": [
        {"id": "desk", "entry": True, "roles": ["analyst"], "calls": []},
        {"id": "backoffice", "calls": []},
    ],
    "tools": [
        {
            "id": "execute_trade",
            "action": "t:x",
            "risk": "critical",
            "supported_agents": ["backoffice"],
        }
    ],
}
FACTORY_RULES = [NeverReachesRule(id="RULE-001", role="analyst", tool="execute_trade")]


def test_a_saved_graph_keeps_an_agent_with_hidden_tools_opaque(tmp_path):
    """Repro A: desk's tools come from a factory. Without the saved graph, desk replayed as
    a plain registry agent with calls: [], and the rule passed."""
    fragment = GraphFragment(
        nodes=(
            GraphNode(id="desk", entry=True, opaque=True, tools_hidden=True),
            GraphNode(id="backoffice", entry=True),
        ),
        edges=(uses("backoffice", "execute_trade"),),
    )
    live = [
        SourceResult(
            source=SourceRef(kind="python", label="python:app.py:ROOT"),
            ok=True,
            tools=(ToolDescriptor(name="execute_trade"),),
            graph=fragment,
        )
    ]
    rows, _, opaque, hidden, *_ = assert_same_as_live(
        tmp_path, FACTORY_REGISTRY, FACTORY_RULES, live
    )
    assert [(row.id, row.result) for row in rows] == [("RULE-001", RuleResult.INCONCLUSIVE)]
    assert opaque == ("desk",)
    assert hidden["desk"] is True


def test_an_unavailable_optional_source_replays_as_the_same_opaque_node(tmp_path):
    """Repro B: the optional pricing server could not be read. Without it in the
    snapshot, its opaque node vanished on replay, and the rule passed."""
    live = [
        SourceResult(
            source=SourceRef(kind="mcp", label="mcp:pricing"),
            ok=False,
            optional=True,
            agents=("desk",),
            error="ConnectError: connection refused",
        )
    ]
    rows, _, opaque, *_ = assert_same_as_live(tmp_path, FACTORY_REGISTRY, FACTORY_RULES, live)
    assert [(row.id, row.result) for row in rows] == [("RULE-001", RuleResult.INCONCLUSIVE)]
    assert opaque == ("mcp:pricing",)


def test_a_kind_that_does_not_match_its_label_cannot_merge_duplicates(tmp_path):
    """Python sources may share identical tools; a saved MCP source relabeled as Python
    would turn a duplicate-tool error into a silent merge, so it is rejected."""
    tool = {"name": "execute_trade", "description": "Execute.", "hints": {}}
    write_snapshot_of(
        tmp_path / "s.json",
        entry("mcp:a", kind="python", tools=[tool]),
        entry("python:app:b", kind="python", tools=[tool]),
    )
    [result] = read_snapshot(tmp_path, "s.json")
    assert (result.ok, result.tools) == (False, ())
    assert result.error == (
        "invalid snapshot: sources[0].label must start with 'python:', the kind of the source"
    )
