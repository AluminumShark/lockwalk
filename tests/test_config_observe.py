"""[observe] and [[observe.rules]] ."""

from pathlib import Path

import pytest

from lockwalk.config import ConfigFile, ObserveConfig, ObserveRule, load_config
from lockwalk.errors import StructuralError
from lockwalk.models import Risk


def write(directory: Path, text: str) -> Path:
    path = directory / ".lockwalk.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults() -> None:
    config = ConfigFile().observe
    assert config.traces == () and config.reader is None
    assert (config.max_spans, config.max_line_mb, config.max_total_mb) == (1_000_000, 64, 4096)
    assert config.reader_timeout_s == 120.0
    gate = ConfigFile().gate
    assert gate.fail_on_off_map_route is True and gate.fail_on_unknown_component is True


def test_a_full_section_loads(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        """
[observe]
traces = ["traces/"]
max_spans = 10
[observe.agents]
"Pricing Agent" = "pricing-agent"
[observe.tools]
"get_price_v2" = "get_stock_price"
[observe.attributes]
"lockwalk.door.decision" = "authz.result"
[[observe.rules]]
kind = "agent"
when = { "langfuse.observation.type" = "agent" }
name = "span.name"
[[observe.rules]]
kind = "handoff"
when = { "logfire.msg_template" = "Handoff" }
from = "from_agent"
to = "to_agent"
""",
    )
    config = load_config(path).file.observe
    assert config.agents == {"Pricing Agent": "pricing-agent"}
    assert config.rules[1].from_ == "from_agent" and config.rules[1].to == "to_agent"


@pytest.mark.parametrize(
    "rule",
    [
        {"kind": "agent", "when": {}, "name": "span.name"},  # empty when
        {"kind": "agent", "when": {"a": "b"}},  # no name
        {"kind": "handoff", "when": {"a": "b"}, "from": "x"},  # no to
        {"kind": "handoff", "when": {"a": "b"}, "from": "x", "to": "y", "name": "n"},
        {"kind": "tool", "when": {"a": "b"}, "name": "n", "to": "y"},
        {"kind": "span", "when": {"a": "b"}, "name": "n"},
        {"kind": "agent", "when": {"a": "b"}, "name": "n", "extra": 1},
    ],
)
def test_bad_rules_are_refused(rule: dict) -> None:
    with pytest.raises(ValueError):
        ObserveRule.model_validate(rule)


def test_rule_messages_and_aliases() -> None:
    with pytest.raises(ValueError, match="a tool rule needs 'name'"):
        ObserveRule.model_validate({"kind": "tool", "when": {"a": "b"}})
    with pytest.raises(ValueError, match="an agent rule needs 'name'"):
        ObserveRule.model_validate({"kind": "agent", "when": {"a": "b"}})
    from_alias = ObserveRule.model_validate(
        {"kind": "handoff", "when": {"a": "b"}, "from": "x", "to": "y"}
    )
    by_keyword = ObserveRule(kind="handoff", when={"a": "b"}, from_="x", to="y")
    assert from_alias == by_keyword
    assert by_keyword.model_dump(by_alias=True)["from"] == "x"


def test_bounds_on_sizes_and_text() -> None:
    many = {f"n{i}": "a" for i in range(1001)}
    for data in (
        {"agents": many},
        {"tools": many},
        {"attributes": {f"k{i}": f"v{i}" for i in range(1001)}},
        {"traces": [f"t{i}" for i in range(1001)]},
        {"traces": ["x" * 501]},
        {"traces": ["bad\nname"]},
        {"agents": {"x" * 501: "a"}},
        {"agents": {"Bad\x00": "a"}},
        {"max_spans": 5_000_001},
    ):
        with pytest.raises(ValueError):
            ObserveConfig.model_validate(data)
    for rule in (
        {"kind": "agent", "when": {"a": "b" * 501}, "name": "n"},
        {"kind": "agent", "when": {"a\tb": "c"}, "name": "n"},
        {"kind": "agent", "when": {"a": "b"}, "name": "n" * 501},
    ):
        with pytest.raises(ValueError):
            ObserveRule.model_validate(rule)
    ObserveConfig.model_validate({"traces": ["x" * 500], "max_spans": 5_000_000})


def test_attribute_targets_are_checked() -> None:
    for data, text in (
        ({"attributes": {"lockwalk.door.decision": "gen_ai.agent.name"}}, "own meaning"),
        ({"attributes": {"lockwalk.door.decision": "span.name"}}, "own meaning"),
        (
            {"attributes": {"lockwalk.door.decision": "x", "lockwalk.door.act": "x"}},
            "same target",
        ),
    ):
        with pytest.raises(ValueError, match=text):
            ObserveConfig.model_validate(data)


def test_test_report_is_resolved_against_the_config_directory(tmp_path: Path) -> None:
    from lockwalk.settings import resolve_settings

    path = write(tmp_path, '[observe]\ntest_report = "out/c.json"\n')
    settings = resolve_settings(cwd=tmp_path / "elsewhere", config_path=path)
    assert settings.test_report == tmp_path / "out" / "c.json"


def test_bad_settings_are_refused() -> None:
    for data in (
        {"attributes": {"gen_ai.agent.name": "x"}},  # not a mappable key
        {"agents": {"X": "a"}, "tools": {"X": "t"}},  # one name in both tables
        {"reader": "no-colon"},
        {"max_spans": 0},
        {"reader_timeout_s": 0},
    ):
        with pytest.raises(ValueError):
            ObserveConfig.model_validate(data)


def test_a_bad_section_is_a_structural_error(tmp_path: Path) -> None:
    path = write(tmp_path, "[observe]\nmax_spans = -1\n")
    with pytest.raises(StructuralError):
        load_config(path)


def test_trace_args_come_from_the_command_line_or_the_file(tmp_path: Path) -> None:
    from lockwalk.settings import resolve_settings

    (tmp_path / "conf").mkdir()
    path = write(tmp_path / "conf", '[observe]\ntraces = ["a.jsonl"]\n')
    from_file = resolve_settings(cwd=tmp_path, config_path=path)
    assert from_file.trace_args == ("a.jsonl",) and from_file.trace_base == tmp_path / "conf"
    from_cli = resolve_settings(cwd=tmp_path, config_path=path, traces=["b.jsonl"])
    assert from_cli.trace_args == ("b.jsonl",) and from_cli.trace_base == tmp_path


def test_rule_values_may_be_empty_or_padded() -> None:
    rule = ObserveRule.model_validate({"kind": "agent", "when": {"a": "", "b": " x "}, "name": "n"})
    assert rule.when == {"a": "", "b": " x "}
    with pytest.raises(ValueError):
        ObserveRule.model_validate({"kind": "agent", "when": {"a": "x\ty"}, "name": "n"})
    with pytest.raises(ValueError):
        ObserveConfig.model_validate({"reader": "m:" + "f" * 600})
    with pytest.raises(ValueError):
        ObserveConfig.model_validate({"test_report": "a\nb"})


def test_test_report_without_a_config_file_is_under_the_current_directory(
    tmp_path: Path,
) -> None:
    from lockwalk.settings import resolve_settings

    settings = resolve_settings(cwd=tmp_path)
    assert settings.test_report == tmp_path / ".lockwalk" / "coverage.json"


def test_gate_keys_for_observation_defaults_and_values(tmp_path: Path) -> None:
    gate = ConfigFile().gate
    assert gate.fail_on_inconclusive_observation is True
    assert gate.fail_on_unguarded_call == (Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN)
    assert gate.fail_on_untested_path == (Risk.CRITICAL, Risk.UNKNOWN)
    path = write(
        tmp_path,
        "[gate]\nfail_on_inconclusive_observation = false\n"
        'fail_on_unguarded_call = ["critical"]\nfail_on_untested_path = []\n',
    )
    loaded = load_config(path).file.gate
    assert loaded.fail_on_inconclusive_observation is False
    assert loaded.fail_on_unguarded_call == (Risk.CRITICAL,)
    assert loaded.fail_on_untested_path == ()
    for bad in ('fail_on_unguarded_call = ["bogus"]', 'fail_on_inconclusive_observation = "no"'):
        with pytest.raises(StructuralError):
            load_config(write(tmp_path, f"[gate]\n{bad}\n"))


def test_door_and_effect_rules_load_from_toml(tmp_path: Path) -> None:
    path = tmp_path / "x.toml"
    path.write_text(
        "[[observe.rules]]\n"
        'kind = "door"\n'
        'when = { "gen_ai.operation.name" = "approval", "app.granted" = false }\n'
        'decision = "deny"\n'
        'tool_call_id = "gen_ai.tool.call.id"\n'
        "[[observe.rules]]\n"
        'kind = "effect"\n'
        'when = { "app.outcome" = "completed", "app.attempt" = 2 }\n',
        encoding="utf-8",
    )
    door, effect = load_config(path).file.observe.rules
    assert door.kind == "door" and door.decision == "deny"
    assert door.tool_call_id == "gen_ai.tool.call.id"
    assert door.when["app.granted"] is False
    assert effect.kind == "effect" and effect.when["app.attempt"] == 2
    assert type(effect.when["app.attempt"]) is int


@pytest.mark.parametrize(
    "rule",
    [
        {"kind": "door", "when": {"a": "b"}},  # no decision
        {"kind": "door", "when": {"a": "b"}, "decision": "maybe"},
        {"kind": "door", "when": {"a": "b"}, "decision": "deny", "name": "n"},
        {"kind": "door", "when": {"a": "b"}, "decision": "deny", "from": "x", "to": "y"},
        {"kind": "door", "when": {"a": "b"}, "decision": "deny", "tool_call_id": "span.name"},
        {"kind": "effect", "when": {"a": "b"}, "decision": "allow"},
        {"kind": "effect", "when": {"a": "b"}, "tool_call_id": "c"},
        {"kind": "effect", "when": {"a": "b"}, "name": "n"},
        {"kind": "effect", "when": {}},
        {"kind": "agent", "when": {"a": "b"}, "name": "n", "decision": "allow"},
        {"kind": "tool", "when": {"a": "b"}, "name": "n", "tool_call_id": "c"},
        {"kind": "handoff", "when": {"a": "b"}, "from": "x", "to": "y", "decision": "deny"},
        {"kind": "agent", "when": {"a": 1.5}, "name": "n"},  # float
        {"kind": "agent", "when": {"span.name": True}, "name": "n"},
        {"kind": "agent", "when": {"a": 2**63}, "name": "n"},  # over int64
    ],
)
def test_bad_door_and_effect_rules_are_refused(rule: dict) -> None:
    with pytest.raises(ValueError):
        ObserveRule.model_validate(rule)


def test_rule_messages_for_door_and_effect() -> None:
    with pytest.raises(ValueError, match="a door rule needs 'decision'"):
        ObserveRule.model_validate({"kind": "door", "when": {"a": "b"}})
    with pytest.raises(ValueError, match="an effect rule has only 'when'"):
        ObserveRule.model_validate({"kind": "effect", "when": {"a": "b"}, "name": "n"})
    with pytest.raises(ValueError, match="only for door rules"):
        ObserveRule.model_validate(
            {"kind": "tool", "when": {"a": "b"}, "name": "n", "decision": "allow"}
        )


def test_when_keeps_the_toml_type() -> None:
    rule = ObserveRule.model_validate(
        {"kind": "agent", "when": {"s": "true", "b": True, "i": 1}, "name": "n"}
    )
    assert rule.when["s"] == "true" and isinstance(rule.when["s"], str)
    assert rule.when["b"] is True
    assert type(rule.when["i"]) is int


def test_when_value_errors_are_readable() -> None:
    def rule(value: object) -> dict:
        return {"kind": "agent", "when": {"a": value}, "name": "n"}

    for bad in (1.5, None, ["x"]):
        with pytest.raises(ValueError, match="must be a string, a boolean or an integer"):
            ObserveRule.model_validate(rule(bad))
    with pytest.raises(ValueError, match="at most 500"):
        ObserveRule.model_validate(rule("x" * 501))
    with pytest.raises(ValueError, match="control characters"):
        ObserveRule.model_validate(rule("x	y"))
    with pytest.raises(ValueError, match="less than or equal to"):
        ObserveRule.model_validate(rule(2**63))
    with pytest.raises(ValueError, match="greater than or equal to"):
        ObserveRule.model_validate(rule(-(2**63) - 1))
    for ok in (2**63 - 1, -(2**63), -5):
        assert ObserveRule.model_validate(rule(ok)).when["a"] == ok


def test_float_when_value_message_through_load_config(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        '[[observe.rules]]\nkind = "agent"\nname = "n"\nwhen = { a = 1.5 }\n',
    )
    with pytest.raises(StructuralError) as info:
        load_config(path)
    text = str(info.value)
    assert "a 'when' value must be a string, a boolean or an integer" in text
    assert "function-after" not in text


def test_key_refusals_have_the_right_reason() -> None:
    with pytest.raises(ValueError, match=r"'span.name' condition must be a string"):
        ObserveRule.model_validate({"kind": "agent", "when": {"span.name": True}, "name": "n"})
    with pytest.raises(ValueError, match=r"must name an attribute, not span.name"):
        ObserveRule.model_validate(
            {"kind": "door", "when": {"a": "b"}, "decision": "deny", "tool_call_id": "span.name"}
        )


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ('"' + "x" * 501 + '"', "at most 500"),
        (str(2**63), "less than or equal to"),
        ("1.5", "must be a string, a boolean or an integer"),
    ],
)
def test_when_value_gives_one_clear_error(tmp_path: Path, value: str, reason: str) -> None:
    path = write(
        tmp_path, f'[[observe.rules]]\nkind = "agent"\nname = "n"\nwhen = {{ a = {value} }}\n'
    )
    with pytest.raises(StructuralError) as info:
        load_config(path)
    text = str(info.value)
    assert reason in text
    for absent in ("function-after", "valid boolean", "valid integer"):
        assert absent not in text
