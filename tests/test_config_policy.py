from pathlib import Path

import pytest
from pydantic import ValidationError

from lockwalk.config import ConfigFile, GateConfig, PolicyConfig, load_config
from lockwalk.errors import StructuralError
from lockwalk.models import Risk


def test_authzen_policy_defaults() -> None:
    policy = PolicyConfig(adapter="authzen", url="http://localhost:3592")
    assert policy.timeout == 2.0
    assert policy.batch_size == 100 and policy.max_queries == 5000
    assert policy.ask_every_hop is False and policy.invoke_action == "agent:invoke"
    assert policy.label == "authzen:http://localhost:3592"


def test_python_policy_defaults() -> None:
    policy = PolicyConfig(adapter="python", target="my_iam:decide")
    assert policy.timeout == 5.0
    assert policy.label == "python:my_iam:decide"


def test_label_drops_query_and_fragment() -> None:
    policy = PolicyConfig(adapter="authzen", url="https://pdp.example/v1?api_key=s3cret#x")
    assert policy.label == "authzen:https://pdp.example/v1"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"adapter": "authzen"}, "needs 'url'"),
        (
            {"adapter": "authzen", "url": "http://h", "target": "m:f"},
            "only applies to adapter 'python'",
        ),
        ({"adapter": "python"}, "needs 'target'"),
        (
            {"adapter": "python", "target": "m:f", "url": "http://h"},
            "only apply to adapter 'authzen'",
        ),
        (
            {"adapter": "python", "target": "m:f", "headers": {"A": "b"}},
            "only apply to adapter 'authzen'",
        ),
        ({"adapter": "python", "target": "m:f()"}, r"cannot end with '\(\)'"),
        ({"adapter": "python", "target": "no-colon"}, "must look like"),
        ({"adapter": "authzen", "url": "ftp://h"}, "must look like http"),
        ({"adapter": "authzen", "url": "http://u:pw@h"}, "user name or password"),
        ({"adapter": "authzen", "url": "http://h", "headers": {"Bad/Name": "x"}}, "header name"),
        ({"adapter": "authzen", "url": "http://h", "headers": {"A": "$X"}}, "must start a"),
        ({"adapter": "authzen", "url": "http://h", "batch_size": 0}, "greater than or equal to 1"),
        ({"adapter": "authzen", "url": "http://h", "batch_size": True}, "valid integer"),
        ({"adapter": "authzen", "url": "http://h", "timeout_s": True}, "not a boolean"),
        ({"adapter": "other", "url": "http://h"}, "'authzen' or 'python'"),
        (
            {"adapter": "authzen", "url": "http://h", "roles_property": "act"},
            "roles_property cannot be 'act': lockwalk puts the delegation chain there",
        ),
        ({"adapter": "authzen", "url": "http://h", "roles_property": ""}, "must not be empty"),
    ],
)
def test_policy_config_problems(data: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PolicyConfig.model_validate(data)


def test_header_values_never_appear_in_errors() -> None:
    with pytest.raises(ValidationError) as caught:
        PolicyConfig.model_validate(
            {"adapter": "authzen", "url": "http://h", "headers": {"A": "Bearer s3cret\x01"}}
        )
    assert "s3cret" not in str(caught.value)


def test_gate_and_config_file_have_the_new_keys() -> None:
    gate = GateConfig()
    assert gate.fail_on_inconclusive_case is True
    assert gate.fail_on_escalation is True
    assert gate.fail_on_inconclusive_escalation is True
    assert gate.fail_on_unchecked_escalation == (Risk.CRITICAL, Risk.UNKNOWN)
    file = ConfigFile.model_validate(
        {
            "lockwalk": {"fixtures": "fixtures.yaml"},
            "policy": {"adapter": "python", "target": "m:f"},
        }
    )
    assert file.lockwalk.fixtures == "fixtures.yaml"
    assert file.policy is not None and file.policy.target == "m:f"
    assert ConfigFile().policy is None


def test_url_query_token_is_not_in_repr() -> None:
    policy = PolicyConfig(adapter="authzen", url="https://h/x?token=SECRETQ")
    assert "SECRETQ" not in repr(policy)


def test_nested_config_errors_do_not_leak(tmp_path: Path) -> None:
    path = tmp_path / ".lockwalk.toml"
    path.write_text(
        '[policy]\nadapter = "authzen"\nurl = "http://user:pw9@h"\n'
        'headers = { A = "tok7' + chr(92) + 'u0001" }\n',
        encoding="utf-8",
    )
    with pytest.raises(StructuralError) as caught:
        load_config(path)
    text = str(caught.value) + "".join(caught.value.problems)
    assert "pw9" not in text and "tok7" not in text


def test_roles_property_default_and_custom() -> None:
    assert PolicyConfig(adapter="python", target="m:f").roles_property == "roles"
    custom = PolicyConfig(adapter="python", target="m:f", roles_property="cerbos.roles")
    assert custom.roles_property == "cerbos.roles"
