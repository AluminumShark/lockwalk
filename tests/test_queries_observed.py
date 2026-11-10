"""Tests for asking the IAM with the identity the door received."""

from typing import Any, Literal

from test_queries import (
    build,
    case,
    make_fixtures,
    make_inventory,
    policy,
    simple_graph,
    tool,
)

from lockwalk.models import DelegationMode
from lockwalk.queries import build_queries


def run(
    mode: DelegationMode | Literal["undeclared"],
    observed: dict[str, dict[str, Any]] | None,
    **kw: Any,
):
    """mode "undeclared" means the node declares nothing."""
    declared: DelegationMode | None = None
    if mode != "undeclared":
        declared = mode
    return build_queries(
        [case(**kw)],
        simple_graph(declared),
        make_inventory(tool("pay")),
        make_fixtures(),
        policy(),
        observed=observed,
    )


def test_none_is_unchanged() -> None:
    plain = build([case(mode="agent")], simple_graph("agent"))
    assert run("agent", None) == plain
    assert run("agent", {}) == plain


def test_same_as_declared_changes_nothing() -> None:
    assert run("agent", {"C1": {"type": "agent", "id": "a"}}) == run("agent", None)
    assert run("user", {"C1": {"type": "user", "id": "alice"}}) == run("user", None)


def test_declared_user_observed_as_agent() -> None:
    (ask,) = run("user", {"C1": {"type": "agent", "id": "a"}}).cases
    hop = ask.tool_hop
    assert hop.mode == "observed" and len(hop.queries) == 1
    assert hop.queries[0].subject.type == "agent"
    assert hop.queries[0].subject.properties == {"tier": "gold"}
    assert ask.plain_user is not None and ask.plain_user.subject.id == "alice"
    assert hop.control == ("pay:send", "payment")


def test_undeclared_observed_as_user_has_no_plain_user() -> None:
    (ask,) = run("undeclared", {"C1": {"type": "user", "id": "alice"}}).cases
    assert ask.tool_hop.mode == "observed"
    (query,) = ask.tool_hop.queries
    assert query.subject.id == "alice"
    assert query.subject.properties["roles"] == ["analyst", "viewer"]
    assert ask.plain_user is None


def test_undeclared_observed_as_agent() -> None:
    (ask,) = run("undeclared", {"C1": {"type": "agent", "id": "a"}}).cases
    assert ask.tool_hop.mode == "observed"
    assert ask.tool_hop.queries[0].subject.type == "agent"
    assert ask.plain_user is not None and ask.plain_user.subject.type == "user"


def test_on_behalf_of_with_own_chain_changes_nothing() -> None:
    chain = {"type": "user", "id": "alice", "act": {"type": "agent", "id": "a"}}
    assert run("on_behalf_of", {"C1": chain}) == run("on_behalf_of", None)


def test_on_behalf_of_other_chain_is_observed() -> None:
    seen = {"type": "user", "id": "alice", "act": {"type": "agent", "id": "x"}}
    (ask,) = run("on_behalf_of", {"C1": seen}).cases
    assert ask.tool_hop.mode == "observed"
    assert ask.tool_hop.queries[0].subject.properties["act"] == {"type": "agent", "id": "x"}


def test_other_user_from_fixtures() -> None:
    (ask,) = run("user", {"C1": {"type": "user", "id": "bob"}}).cases
    subject = ask.tool_hop.queries[0].subject
    assert subject.id == "bob" and subject.properties == {"roles": ["admin"]}


def test_unknown_user_and_other_type() -> None:
    (ask,) = run("user", {"C1": {"type": "user", "id": "zed"}}).cases
    assert ask.tool_hop.queries[0].subject.properties == {"roles": ["analyst"]}
    (ask,) = run("user", {"C1": {"type": "service", "id": "svc"}}).cases
    assert ask.tool_hop.queries[0].subject.type == "service"


def test_other_cases_untouched() -> None:
    plan = [case("C1"), case("C2")]
    args = (simple_graph("user"), make_inventory(tool("pay")), make_fixtures(), policy())
    base = build_queries(plan, *args)
    got = build_queries(plan, *args, observed={"C1": {"type": "agent", "id": "a"}})
    assert got.cases[1] == base.cases[1] and got.cases[0] != base.cases[0]


def test_agent_hops_never_change() -> None:
    plan = [case("C1")]
    args = (simple_graph("user"), make_inventory(tool("pay")), make_fixtures())
    pol = policy(ask_every_hop=True)
    base = build_queries(plan, *args, pol)
    got = build_queries(plan, *args, pol, observed={"C1": {"type": "agent", "id": "a"}})
    assert got.cases[0].hops[:-1] == base.cases[0].hops[:-1]
    assert got.cases[0].tool_hop.mode == "observed"
