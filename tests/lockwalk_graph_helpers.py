"""Helpers for checking agent graph fragments, shared by the discovery tests.

pyproject.toml puts tests/ on sys.path (pytest's pythonpath setting), so test modules,
the CrewAI ones included, import this module by name in every pytest import mode.
"""

from lockwalk.models import GraphFragment


def edge_set(fragment: GraphFragment) -> set[tuple[str, str, str, str]]:
    """The fragment's edges as (from_id, to_id, kind, provenance) strings."""
    return {(e.from_id, e.to_id, e.kind.value, e.provenance.value) for e in fragment.edges}


def node_ids(fragment: GraphFragment) -> list[str]:
    return [node.id for node in fragment.nodes]


def assert_closed(fragment: GraphFragment) -> None:
    """Node ids are unique, every edge starts at a node, and every edge that is not
    uses_tool ends at one (the graph checks report any other edge as a graph error)."""
    ids = node_ids(fragment)
    assert len(set(ids)) == len(ids), f"node ids must be unique: {ids}"
    for edge in fragment.edges:
        assert edge.from_id in ids, edge
        if edge.kind.value != "uses_tool":
            assert edge.to_id in ids, edge
