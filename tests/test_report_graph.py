from datetime import UTC, datetime

from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import (
    Drift,
    EdgeKind,
    GateResult,
    GateViolation,
    GraphDrift,
    GraphEdge,
    GraphNode,
    GraphSection,
    Provenance,
    ReachRow,
    ReachStatus,
    Risk,
    RuleResult,
    RuleRow,
    SourceRef,
    SourceResult,
    ToolDescriptor,
)
from lockwalk.report import (
    format_witness,
    render_coverage,
    render_discover,
    render_graph,
    render_graph_notes,
    render_reachability,
    render_rules,
    report_to_dict,
)

ESC = chr(27)
NL = chr(10)
BS = chr(92)


def edge(a, b, kind=EdgeKind.AGENT_AS_TOOL, prov=Provenance.DISCOVERED):
    return GraphEdge(from_id=a, to_id=b, kind=kind, provenance=prov)


def tool_edge(a, t):
    return edge(a, t, EdgeKind.USES_TOOL)


def rule(rule_id, result, **fields):
    base = {"agent": None, "role": None, "tool": None, "target_agent": None}
    return RuleRow.model_validate({**base, **fields, "id": rule_id, "result": result})


def test_graph_empty_without_nodes():
    assert render_graph(GraphSection(), {}) == []


def test_graph_tree_with_annotations():
    section = GraphSection(
        entry_agents=("a",),
        nodes=(
            GraphNode(id="a"),
            GraphNode(id="b", delegation_mode="user"),
            GraphNode(id="c", opaque=True),
        ),
        edges=(
            tool_edge("a", "zeta"),
            tool_edge("a", "alpha"),
            edge("a", "c", EdgeKind.HANDOFF, Provenance.DECLARED),
            edge("a", "b"),
            tool_edge("b", "alpha"),
            edge("b", "a"),
            edge("b", "c", EdgeKind.CALLS),
        ),
    )
    lines = render_graph(section, {"alpha": Risk.HIGH})
    assert lines == [
        "Agent graph (entry agents: a):",
        "  a",
        "    -[agent_as_tool, discovered]-> b  [delegation_mode=user]",
        "      -[agent_as_tool, discovered]-> a  (cycle)",
        "      -[calls, discovered]-> c  (opaque)",
        "      -[uses_tool, discovered]-> alpha  (risk=high)",
        "    -[handoff, declared]-> c  (opaque)  (see above)",
        "    -[uses_tool, discovered]-> alpha  (risk=high)",
        "    -[uses_tool, discovered]-> zeta  (risk=unknown)",
    ]


def test_graph_inferred_header_and_entry_see_above():
    section = GraphSection(
        entry_agents=("a", "b"),
        entry_inferred=True,
        nodes=(GraphNode(id="a"), GraphNode(id="b")),
        edges=(edge("a", "b"),),
    )
    assert render_graph(section, {}) == [
        "Agent graph (no entry agent marked; treating all 2 agents as entries):",
        "  a",
        "    -[agent_as_tool, discovered]-> b",
        "  b  (see above)",
    ]


def test_reachability_formats():
    assert render_reachability(None) == []
    assert render_reachability([]) == ["Role reachability: (no role reaches any tool)"]
    rows = [
        ReachRow(
            role="analyst",
            tool="read",
            risk=Risk.LOW,
            status=ReachStatus.REACHABLE,
            delegation_mode="user",
            covered_by=("c1", "c2"),
        ),
        ReachRow(
            role="ops", tool="execute_trade", risk=Risk.CRITICAL, status=ReachStatus.REACHABLE
        ),
        ReachRow(
            role="ops",
            tool="x",
            risk=Risk.LOW,
            status=ReachStatus.INCONCLUSIVE,
            opaque_reached=("ext",),
        ),
        ReachRow(
            role="ops",
            tool="y",
            risk=Risk.LOW,
            status=ReachStatus.INCONCLUSIVE,
            opaque_reached=("ext", "mcp"),
        ),
    ]
    assert render_reachability(rows) == [
        "Role reachability:",
        "  analyst  read           low       REACHABLE  delegation_mode=user     covered_by=c1, c2",
        "  ops      execute_trade  critical  REACHABLE  delegation_mode=unknown  covered_by=NONE",
        "  ops  (2 more tool(s))  INCONCLUSIVE: route passes through opaque ext, mcp",
    ]


def test_rules_formats():
    path = (edge("a", "b"), tool_edge("b", "t"))
    rows = [
        rule("r1", RuleResult.PASS, role="r", tool="t"),
        rule("r2", RuleResult.FAIL, role="r", tool="t", witness=path),
        rule("r3", RuleResult.FAIL, role="r", target_agent="a"),
        rule("r3b", RuleResult.FAIL, agent="a", target_agent="b"),
        rule("r4", RuleResult.INCONCLUSIVE, agent="a", tool="t", opaque_reached=("x", "y")),
        rule("r4b", RuleResult.INCONCLUSIVE, agent="a", tool="t", problems=("nobody uses t",)),
        rule(
            "r4c",
            RuleResult.INCONCLUSIVE,
            agent="a",
            tool="t",
            opaque_reached=("x",),
            problems=("nobody uses t",),
        ),
        rule("r5", RuleResult.ERROR, agent="a", tool="t", problems=("p1", "p2")),
    ]
    assert render_rules([]) == []
    assert render_rules(rows) == [
        "Never-reaches rules:",
        "  r1  PASS          role:r -> tool:t",
        "  r2  FAIL          role:r -> tool:t",
        "    a -[agent_as_tool, discovered]-> b -[uses_tool, discovered]-> t",
        "  r3  FAIL          role:r -> agent:a",
        "    (the role can use this entry agent directly)",
        "  r3b  FAIL          agent:a -> agent:b",
        "    (no edges in the witness)",
        "  r4  INCONCLUSIVE  agent:a -> tool:t (passes through opaque: x, y)",
        "  r4b  INCONCLUSIVE  agent:a -> tool:t - nobody uses t",
        "  r4c  INCONCLUSIVE  agent:a -> tool:t (passes through opaque: x) - nobody uses t",
        "  r5  ERROR         agent:a -> tool:t - p1; p2",
    ]


def test_format_witness():
    assert format_witness([edge("a", "b", EdgeKind.HANDOFF, Provenance.INFERRED)]) == (
        "a -[handoff, inferred]-> b"
    )


def test_graph_notes():
    assert render_graph_notes(GraphSection()) == []
    section = GraphSection(
        cycles=(("a", "b", "a"), ("x", "x")),
        opaque=("a", "b"),
        edges=(edge("a", "b", prov=Provenance.INFERRED),),
        drift=GraphDrift(
            discovered_only_agents=("d",),
            declared_only_agents=("e",),
            undeclared_edges=(edge("a", "b"),),
            complete=True,
        ),
    )
    assert render_graph_notes(section) == [
        "Graph notes:",
        "  Cycles: a -> b -> a; x -> x",
        "  Opaque: a, b",
        "  Inferred edges: 1",
        "  Graph drift: discovered only: d; declared only: e; undeclared edges: a -> b",
    ]


def test_coverage_places_blocks_before_errors_and_verdict(make_report):
    section = GraphSection(
        entry_agents=("a",), nodes=(GraphNode(id="a"),), edges=(tool_edge("a", "t"),)
    )
    violations = (
        GateViolation(rule="never_reaches", rule_id="r2", result=RuleResult.FAIL),
        GateViolation(
            rule="fail_on_unspecified_role_risk", role="ops", tool="t", risk=Risk.CRITICAL
        ),
        GateViolation(rule="fail_on_unspecified_risk", tool="t", risk=Risk.HIGH),
    )
    report = make_report().model_copy(
        update={
            "agent_graph": section.model_copy(update={"opaque": ("a",)}),
            "reachability": (),
            "rules": (rule("r2", RuleResult.PASS, role="r", tool="t"),),
            "errors": ("e1",),
            "warnings": ("w1",),
            "gate": GateResult(passed=False, violations=violations),
            "exit_code": 1,
        }
    )
    lines = render_coverage(report)
    start = lines.index("Agent graph (entry agents: a):")
    assert lines[start - 1] == ""
    assert lines[start + 3] == "Role reachability: (no role reaches any tool)"
    drift = next(i for i, line in enumerate(lines) if line.startswith("Inventory drift:"))
    reach_at = lines.index("Role reachability: (no role reaches any tool)")
    rules_at = lines.index("Never-reaches rules:")
    notes_at = lines.index("Graph notes:")
    errors_at = lines.index("Errors:")
    warnings_at = lines.index("Warnings:")
    assert drift < start < reach_at < rules_at < notes_at < errors_at < warnings_at
    assert "Gate: FAIL (exit 1)" in lines
    assert "  - never_reaches: r2 (FAIL)" in lines
    assert "  - fail_on_unspecified_role_risk: ops -> t (risk=critical)" in lines
    assert "  - fail_on_unspecified_risk: t (risk=high)" in lines


def test_empty_graph_adds_nothing(make_report):
    assert "Agent graph" not in NL.join(render_coverage(make_report()))


def test_hostile_names_are_escaped(make_report):
    hostile = f"x{ESC}[2J{NL}Gate: PASS (exit 0)"
    section = GraphSection(
        entry_agents=("a",),
        nodes=(GraphNode(id="a"),),
        cycles=((hostile, hostile),),
        opaque=(hostile,),
    )
    rules = (rule("r", RuleResult.ERROR, role=hostile, target_agent="a", problems=(hostile,)),)
    reach = ReachRow(
        role=hostile,
        tool="t",
        risk=Risk.LOW,
        status=ReachStatus.REACHABLE,
        covered_by=(hostile,),
    )
    report = make_report().model_copy(
        update={"agent_graph": section, "rules": rules, "reachability": (reach,)}
    )
    lines = render_coverage(report)
    text = NL.join(lines)
    assert ESC not in text
    assert f"x{BS}x1b[2J{BS}x0aGate: PASS (exit 0)" in text
    assert lines.count("Gate: PASS (exit 0)") == 1
    assert all(line.isascii() for line in lines)


def test_json_round_trip_keys(make_report):
    section = GraphSection(
        entry_agents=("a",),
        nodes=(GraphNode(id="a"),),
        edges=(tool_edge("a", "t"),),
        cycles=(("a", "a"),),
        opaque=("a",),
        drift=GraphDrift(
            discovered_only_agents=(),
            declared_only_agents=(),
            undeclared_edges=(),
            complete=True,
        ),
    )
    rules = (rule("r", RuleResult.FAIL, agent="a", tool="t", witness=(tool_edge("a", "t"),)),)
    reach = ReachRow(role="ops", tool="t", risk=Risk.LOW, status=ReachStatus.REACHABLE)
    report = make_report().model_copy(
        update={"agent_graph": section, "rules": rules, "reachability": (reach,)}
    )
    document = report_to_dict(report, generated_at=datetime(2026, 11, 6, tzinfo=UTC), version="x")
    assert set(document["agent_graph"]) == {
        "entry_agents",
        "entry_inferred",
        "nodes",
        "edges",
        "cycles",
        "opaque",
        "unreachable",
        "drift",
    }
    assert set(document["agent_graph"]["drift"]) == {
        "discovered_only_agents",
        "declared_only_agents",
        "undeclared_edges",
        "complete",
    }
    assert set(document["rules"][0]) == {
        "id",
        "agent",
        "role",
        "tool",
        "target_agent",
        "result",
        "witness",
        "opaque_reached",
        "problems",
        "reason",
        "waived_by",
    }
    assert document["rules"][0]["result"] == "FAIL"
    assert document["reachability"][0]["status"] == "REACHABLE"
    assert set(document["reachability"][0]) == {
        "role",
        "tool",
        "risk",
        "status",
        "witness",
        "delegation_mode",
        "opaque_reached",
        "covered_by",
        "waived_by",
    }


def test_render_discover_places_graph_blocks_before_errors():
    mcp = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:finance-tools"),
        ok=True,
        tools=(ToolDescriptor(name="t"),),
    )
    inventory = merge_inventory([mcp], registry=None).model_copy(
        update={
            "errors": ("boom",),
            "warnings": ("careful",),
            "drift": Drift(discovered_only=("t",), registry_only=(), complete=True),
        }
    )
    section = GraphSection(
        entry_agents=("a",),
        nodes=(GraphNode(id="a"),),
        edges=(tool_edge("a", "t"),),
        opaque=("a",),
    )
    lines = render_discover(inventory, None, graph=section, reachability=[])
    drift = next(i for i, line in enumerate(lines) if line.startswith("Inventory drift:"))
    graph_at = lines.index("Agent graph (entry agents: a):")
    reach_at = lines.index("Role reachability: (no role reaches any tool)")
    notes_at = lines.index("Graph notes:")
    assert lines[graph_at - 1] == ""
    assert drift < graph_at < reach_at < notes_at < lines.index("Errors:")
    assert lines.index("Errors:") < lines.index("Warnings:")


def test_render_discover_lists_the_errors_and_warnings_it_is_given():
    mcp = SourceResult(source=SourceRef(kind="mcp", label="mcp:m"), ok=True)
    inventory = merge_inventory([mcp]).model_copy(
        update={"errors": ("inventory boom",), "warnings": ("careful",)}
    )
    # By default, the inventory's own.
    lines = render_discover(inventory, None)
    assert lines[lines.index("Errors:") + 1] == "  - inventory boom"
    assert lines[lines.index("Warnings:") + 1] == "  - careful"
    assert lines[-1] == "Result: ERROR (exit 2)"
    # Given lists replace them, and the result line follows the given errors alone.
    lines = render_discover(inventory, None, errors=[], warnings=["careful", "graph note"])
    assert "Errors:" not in lines
    warnings_at = lines.index("Warnings:")
    assert lines[warnings_at + 1 : warnings_at + 3] == ["  - careful", "  - graph note"]
    assert lines[-1] == "Result: OK (exit 0)"
    lines = render_discover(inventory, None, errors=["graph " + ESC + "boom"])
    assert lines[lines.index("Errors:") + 1] == "  - graph \\x1bboom"
    assert lines[-1] == "Result: ERROR (exit 2)"


def test_render_discover_places_rules_between_reachability_and_notes():
    inventory = merge_inventory([SourceResult(source=SourceRef(kind="mcp", label="m"), ok=True)])
    section = GraphSection(
        entry_agents=("a",), nodes=(GraphNode(id="a"),), edges=(tool_edge("a", "t"),)
    )
    rows = [
        rule("r1", RuleResult.FAIL, agent="a", tool="t", witness=(tool_edge("a", "t"),)),
        rule("r2", RuleResult.ERROR, agent="a", tool="x", problems=("p1",)),
    ]
    lines = render_discover(
        inventory,
        None,
        graph=section.model_copy(update={"opaque": ("a",)}),
        reachability=[],
        rules=rows,
    )
    rules_at = lines.index("Never-reaches rules:")
    assert lines[rules_at + 1 : rules_at + 4] == [
        "  r1  FAIL          agent:a -> tool:t",
        "    a -[uses_tool, discovered]-> t",
        "  r2  ERROR         agent:a -> tool:x - p1",
    ]
    reach_at = lines.index("Role reachability: (no role reaches any tool)")
    assert reach_at < rules_at < lines.index("Graph notes:")
    # A rule error is not an error of the listing.
    assert lines[-1] == "Result: OK (exit 0)"
    assert render_discover(inventory, None, graph=section) == render_discover(
        inventory, None, graph=section, rules=()
    )


def test_long_chain_does_not_recurse():
    count = 2000
    nodes = tuple(GraphNode(id=f"n{i}") for i in range(count))
    edges = tuple(edge(f"n{i}", f"n{i + 1}") for i in range(count - 1))
    section = GraphSection(entry_agents=("n0",), nodes=nodes, edges=edges)
    lines = render_graph(section, {})
    assert len(lines) == 1 + count
    last = lines[-1]
    assert last.startswith(" " * (2 + 2 * (count - 1)) + "-[")
    assert not last.startswith(" " * (3 + 2 * (count - 1)))


def test_graph_without_entry_agents_is_one_line():
    section = GraphSection(nodes=(GraphNode(id="a", opaque=True),), opaque=("a",))
    assert render_graph(section, {}) == ["Agent graph: (no entry agents)"]
    assert render_graph_notes(section) == ["Graph notes:", "  Opaque: a"]


def test_self_loop_and_entry_tags():
    section = GraphSection(
        entry_agents=("a",),
        nodes=(GraphNode(id="a", delegation_mode="user", opaque=True),),
        edges=(edge("a", "a"),),
    )
    assert render_graph(section, {}) == [
        "Agent graph (entry agents: a):",
        "  a  [delegation_mode=user]  (opaque)",
        "    -[agent_as_tool, discovered]-> a  [delegation_mode=user]  (opaque)  (cycle)",
    ]


def test_edge_to_a_missing_node_and_entry_that_is_not_a_node():
    section = GraphSection(
        entry_agents=("ghost", "a"),
        nodes=(GraphNode(id="a"),),
        edges=(edge("a", "lost"),),
    )
    assert render_graph(section, {}) == [
        "Agent graph (entry agents: ghost, a):",
        "  ghost",
        "  a",
        "    -[agent_as_tool, discovered]-> lost",
    ]


def test_input_order_does_not_change_the_output():
    edges = (
        edge("a", "b", prov=Provenance.INFERRED),
        edge("a", "b", prov=Provenance.DECLARED),
        tool_edge("a", "t"),
        edge("a", "t", EdgeKind.USES_TOOL, Provenance.INFERRED),
    )
    nodes = (GraphNode(id="a"), GraphNode(id="b"))

    def draw(order):
        section = GraphSection(entry_agents=("a",), nodes=nodes, edges=order)
        return render_graph(section, {})

    assert draw(edges) == draw(tuple(reversed(edges)))
    rows = [
        ReachRow(
            role=role,
            tool=tool,
            risk=Risk.LOW,
            status=ReachStatus.INCONCLUSIVE,
            opaque_reached=opaque,
        )
        for role, tool, opaque in (("b", "x", ("m", "e")), ("a", "y", ("z",)), ("b", "w", ("e",)))
    ]
    # Roles keep the input order (first time seen); opaque ids are sorted within a line.
    assert render_reachability(rows) == [
        "Role reachability:",
        "  b  (2 more tool(s))  INCONCLUSIVE: route passes through opaque e, m",
        "  a  (1 more tool(s))  INCONCLUSIVE: route passes through opaque z",
    ]
    # Reversed input sees b first as well, and still sorts the opaque ids.
    assert render_reachability(list(reversed(rows))) == render_reachability(rows)
    swapped = [rows[1], rows[0], rows[2]]
    assert render_reachability(swapped)[1].startswith("  a  ")


def test_reachability_columns_align_on_escaped_width():
    accented = chr(0xE9)
    rows = [
        ReachRow(role=accented, tool="t", risk=Risk.LOW, status=ReachStatus.REACHABLE),
        ReachRow(role="ab", tool="t", risk=Risk.LOW, status=ReachStatus.REACHABLE),
    ]
    first, second = render_reachability(rows)[1:]
    assert first.isascii()
    assert first.index("REACHABLE") == second.index("REACHABLE")


def hostile_text():
    return "".join(chr(code) for code in (13, 10, 27, 0x202E)) + "z"


def hostile_section():
    bad = hostile_text()
    hostile_edge = GraphEdge.model_construct(
        from_id=bad, to_id=bad, kind=EdgeKind.HANDOFF, provenance=Provenance.DECLARED, sources=()
    )
    return GraphSection.model_construct(
        entry_agents=(bad, "a"),
        entry_inferred=False,
        nodes=(GraphNode.model_construct(id=bad, kind="agent", opaque=True),),
        edges=(hostile_edge,),
        cycles=((bad, bad),),
        opaque=(bad,),
        drift=GraphDrift.model_construct(
            discovered_only_agents=(bad,),
            declared_only_agents=(bad,),
            undeclared_edges=(hostile_edge,),
            complete=True,
        ),
    )


def hostile_reach():
    bad = hostile_text()
    return (
        ReachRow.model_construct(
            role=bad,
            tool=bad,
            risk=Risk.HIGH,
            status=ReachStatus.REACHABLE,
            witness=(),
            delegation_mode=None,
            opaque_reached=(),
            covered_by=(bad,),
        ),
        ReachRow.model_construct(
            role=bad,
            tool=bad,
            risk=Risk.HIGH,
            status=ReachStatus.INCONCLUSIVE,
            witness=(),
            delegation_mode=None,
            opaque_reached=(bad,),
            covered_by=(),
        ),
    )


def assert_clean(lines):
    assert lines
    for line in lines:
        assert line.isascii()
        assert not any(ord(char) < 32 or ord(char) == 127 for char in line)


def test_hostile_text_in_coverage_is_fully_escaped(make_report):
    bad = hostile_text()
    rules = (
        RuleRow.model_construct(
            id=bad,
            agent=bad,
            role=None,
            tool=bad,
            target_agent=None,
            result=RuleResult.ERROR,
            witness=(),
            opaque_reached=(bad,),
            problems=(bad,),
            reason=bad,
        ),
    )
    violations = (
        GateViolation.model_construct(rule="never_reaches", rule_id=bad, result=RuleResult.FAIL),
        GateViolation.model_construct(
            rule="fail_on_unspecified_role_risk", role=bad, tool=bad, risk=Risk.HIGH
        ),
    )
    report = make_report().model_copy(
        update={
            "agent_graph": hostile_section(),
            "reachability": hostile_reach(),
            "rules": rules,
            "gate": GateResult(passed=False, violations=violations),
            "exit_code": 1,
        }
    )
    assert_clean(render_coverage(report))


def test_hostile_text_in_discover_is_fully_escaped():
    mcp = SourceResult(
        source=SourceRef(kind="mcp", label="mcp:x"), ok=True, tools=(ToolDescriptor(name="t"),)
    )
    inventory = merge_inventory([mcp], registry=None)
    lines = render_discover(inventory, None, graph=hostile_section(), reachability=hostile_reach())
    assert_clean(lines)
    assert any("Graph notes:" in line for line in lines)


def test_graph_notes_name_at_most_five_unreachable_agents():
    assert render_graph_notes(GraphSection(unreachable=("b", "c"))) == [
        "Graph notes:",
        "  Not reachable from entry agents: b, c",
    ]
    many = GraphSection(opaque=("x",), unreachable=tuple(f"a{n}" for n in range(7)))
    assert render_graph_notes(many) == [
        "Graph notes:",
        "  Opaque: x",
        "  Not reachable from entry agents: a0, a1, a2, a3, a4, ...",
    ]
