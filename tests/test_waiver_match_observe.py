"""The observe waiver match kinds."""

import pytest
from pydantic import ValidationError

from lockwalk.waivers import OBSERVE_KINDS, WaiverMatch


def test_observe_kinds_constant_matches_the_model_fields() -> None:
    assert {"route", "unknown", "unguarded", "observed_identity", "untested_path"} == OBSERVE_KINDS
    assert set(WaiverMatch.model_fields) >= OBSERVE_KINDS


def test_route_uses_the_from_alias() -> None:
    match = WaiverMatch.model_validate({"route": {"from": "user", "to": "trade-agent"}})
    assert match.kind == "route"
    assert (
        match.route is not None and match.route.from_ == "user" and match.route.to == "trade-agent"
    )
    with pytest.raises(ValidationError):
        WaiverMatch.model_validate({"route": {"from_": "user", "to": "x"}})
    with pytest.raises(ValidationError):
        WaiverMatch.model_validate({"route": {"from": "user"}})


def test_unknown_kinds_and_names() -> None:
    for kind in ("agent", "tool", "caller"):
        assert (
            WaiverMatch.model_validate({"unknown": {"kind": kind, "name": "x"}}).kind == "unknown"
        )
    with pytest.raises(ValidationError):
        WaiverMatch.model_validate({"unknown": {"kind": "span", "name": "x"}})
    with pytest.raises(ValidationError):
        WaiverMatch.model_validate({"unknown": {"kind": "tool", "name": ""}})


def test_unguarded_agent_may_be_none_marker() -> None:
    match = WaiverMatch.model_validate({"unguarded": {"agent": "(none)", "tool": "t"}})
    assert match.unguarded is not None and match.unguarded.agent == "(none)"
    with pytest.raises(ValidationError):
        WaiverMatch.model_validate({"unguarded": {"tool": "t"}})


def test_path_matches_take_exact_lists() -> None:
    ident = WaiverMatch.model_validate({"observed_identity": {"path": ["a", "b"], "tool": None}})
    assert ident.observed_identity is not None
    assert ident.observed_identity.path == ("a", "b") and ident.observed_identity.tool is None
    assert WaiverMatch.model_validate({"observed_identity": {"path": ["a"]}}).kind == (
        "observed_identity"
    )
    untested = WaiverMatch.model_validate({"untested_path": {"path": ["a", "?"], "tool": "t"}})
    assert untested.kind == "untested_path"
    for bad in (
        {"untested_path": {"path": ["a"]}},  # tool is required here
        {"untested_path": {"path": [], "tool": "t"}},
        {"untested_path": {"path": "a", "tool": "t"}},
        {"observed_identity": {"path": [""]}},
        {"untested_path": {"path": ["a"], "tool": "t", "extra": 1}},
    ):
        with pytest.raises(ValidationError):
            WaiverMatch.model_validate(bad)


def test_exactly_one_kind_across_old_and_new() -> None:
    with pytest.raises(ValidationError, match="exactly one"):
        WaiverMatch.model_validate({"case": "CASE-001", "route": {"from": "a", "to": "b"}})
    with pytest.raises(ValidationError, match="exactly one"):
        WaiverMatch.model_validate({})
    assert WaiverMatch.model_validate({"case": "CASE-001"}).kind == "case"


def test_untested_path_requires_the_tool_on_the_field() -> None:
    with pytest.raises(ValidationError, match="tool"):
        WaiverMatch.model_validate({"untested_path": {"path": ["a"]}})


def test_path_lists_are_bounded() -> None:
    with pytest.raises(ValidationError):
        WaiverMatch.model_validate({"observed_identity": {"path": ["a"] * 33}})
