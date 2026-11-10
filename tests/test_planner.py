from lockwalk.inventory.merge import merge_inventory
from lockwalk.models import CaseStatus, SourceRef, SourceResult, ToolDescriptor
from lockwalk.planner import plan_cases
from lockwalk.registry import Registry
from lockwalk.spec_loader import SpecFile

REGISTRY = Registry.model_validate(
    {
        "schema_version": "1",
        "agents": [{"id": "research-agent"}, {"id": "finance-agent"}],
        "tools": [
            {
                "id": "execute_trade",
                "action": "trade:execute",
                "risk": "critical",
                "supported_agents": ["finance-agent"],
            }
        ],
    }
)
BASE = {"actor": "alice", "role": "analyst", "resource_fixture": "x", "expect": "deny"}


def spec_with(*cases: dict[str, str]) -> SpecFile:
    return SpecFile.model_validate(
        {"schema_version": "1", "scenario_suite": "t", "cases": [{**BASE, **c} for c in cases]}
    )


def inventory(*discovered: SourceResult):
    return merge_inventory(list(discovered), registry=REGISTRY, registry_label="registry:r.yaml")


def mcp(*names: str, ok: bool = True) -> SourceResult:
    return SourceResult(
        source=SourceRef(kind="mcp", label="mcp:down" if not ok else "mcp:x"),
        ok=ok,
        error=None if ok else "timed out after 10s",
        tools=tuple(ToolDescriptor(name=name) for name in names),
    )


def test_valid_case_is_untested_and_action_verified():
    [planned] = plan_cases(
        spec_with(
            {
                "id": "C1",
                "agent": "finance-agent",
                "tool": "execute_trade",
                "action": "trade:execute",
            }
        ),
        inventory(),
    )
    assert planned.status is CaseStatus.UNTESTED
    assert planned.action_verified is True
    assert planned.problems == ()


def test_negative_combination_outside_supported_agents_is_allowed():
    [planned] = plan_cases(
        spec_with(
            {
                "id": "C1",
                "agent": "research-agent",
                "tool": "execute_trade",
                "action": "trade:execute",
            }
        ),
        inventory(),
    )
    assert planned.status is CaseStatus.UNTESTED


def test_unknown_agent_is_an_error():
    [planned] = plan_cases(
        spec_with(
            {"id": "C1", "agent": "ghost", "tool": "execute_trade", "action": "trade:execute"}
        ),
        inventory(),
    )
    assert planned.status is CaseStatus.ERROR
    assert planned.problems == ("agent 'ghost' is not declared in the registry",)


def test_unknown_tool_is_an_error():
    [planned] = plan_cases(
        spec_with({"id": "C1", "agent": "finance-agent", "tool": "ghost_tool", "action": "a:b"}),
        inventory(),
    )
    assert planned.status is CaseStatus.ERROR
    assert planned.problems == ("tool 'ghost_tool' is not in the inventory",)


def test_unknown_tool_mentions_failed_sources():
    [planned] = plan_cases(
        spec_with({"id": "C1", "agent": "finance-agent", "tool": "ghost_tool", "action": "a:b"}),
        inventory(mcp(ok=False)),
    )
    assert planned.problems == (
        "tool 'ghost_tool' is not in the inventory "
        "(it may be missing because these sources failed: mcp:down)",
    )


def test_action_mismatch_is_an_error():
    [planned] = plan_cases(
        spec_with(
            {"id": "C1", "agent": "finance-agent", "tool": "execute_trade", "action": "trade:run"}
        ),
        inventory(),
    )
    assert planned.status is CaseStatus.ERROR
    assert planned.problems == (
        "action 'trade:run' does not match the registry action 'trade:execute' "
        "for tool 'execute_trade'",
    )


def test_discovered_only_tool_cannot_verify_the_action():
    [planned] = plan_cases(
        spec_with(
            {"id": "C1", "agent": "finance-agent", "tool": "delete_portfolio", "action": "p:del"}
        ),
        inventory(mcp("execute_trade", "delete_portfolio")),
    )
    assert planned.status is CaseStatus.UNTESTED
    assert planned.action_verified is False


def test_several_problems_are_all_reported():
    [planned] = plan_cases(
        spec_with({"id": "C1", "agent": "ghost", "tool": "ghost_tool", "action": "a:b"}),
        inventory(),
    )
    assert len(planned.problems) == 2


def test_matching_is_case_sensitive():
    # A look-alike name must never match a declared tool or action.
    tool_case, action_case = plan_cases(
        spec_with(
            {
                "id": "C1",
                "agent": "finance-agent",
                "tool": "Execute_Trade",
                "action": "trade:execute",
            },
            {
                "id": "C2",
                "agent": "finance-agent",
                "tool": "execute_trade",
                "action": "TRADE:EXECUTE",
            },
        ),
        inventory(),
    )
    assert tool_case.status is CaseStatus.ERROR
    assert tool_case.problems == ("tool 'Execute_Trade' is not in the inventory",)
    assert action_case.status is CaseStatus.ERROR
    assert action_case.action_verified is False


def test_path_case_checks_every_agent_name():
    case = {"id": "C1", "tool": "execute_trade", "action": "trade:execute"}
    spec = SpecFile.model_validate(
        {
            "schema_version": "1",
            "scenario_suite": "t",
            "cases": [{**BASE, **case, "path": ["finance-agent", "ghost"]}],
        }
    )
    [planned] = plan_cases(spec, inventory())
    assert planned.status is CaseStatus.ERROR
    assert planned.problems == ("agent 'ghost' is not declared in the registry",)


def test_case_targeting_a_delegation_tool_is_an_error():
    registry = Registry.model_validate(
        {
            "schema_version": "1",
            "agents": [{"id": "finance-agent"}],
            "tools": [],
            "delegation_tools": [{"id": "ask_oracle", "agent": "finance-agent"}],
        }
    )
    inv = merge_inventory([], registry=registry, registry_label="registry:r.yaml")
    [planned] = plan_cases(
        spec_with({"id": "C1", "agent": "finance-agent", "tool": "ask_oracle", "action": "a:b"}),
        inv,
    )
    assert planned.status is CaseStatus.ERROR
    assert planned.problems == (
        "tool 'ask_oracle' is a delegation to agent 'finance-agent'; "
        "target the tools behind that agent instead",
    )
