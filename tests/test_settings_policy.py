from pathlib import Path

import pytest

from lockwalk.errors import StructuralError
from lockwalk.settings import resolve_settings


def config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "cfg" / ".lockwalk.toml"
    path.parent.mkdir()
    path.write_text(text, encoding="utf-8")
    return path


def test_fixtures_and_policy_come_from_the_config_file(tmp_path: Path) -> None:
    path = config(
        tmp_path,
        '[lockwalk]\nfixtures = "f.yaml"\n[policy]\nadapter = "python"\ntarget = "iam.py:decide"\n',
    )
    settings = resolve_settings(cwd=tmp_path, config_path=path)
    assert settings.fixtures == path.parent / "f.yaml"
    assert settings.policy is not None and settings.policy.target == "iam.py:decide"
    assert settings.policy_base_dir == path.parent


def test_command_line_fixtures_win(tmp_path: Path) -> None:
    path = config(tmp_path, '[lockwalk]\nfixtures = "f.yaml"\n')
    settings = resolve_settings(cwd=tmp_path, config_path=path, fixtures="mine.yaml")
    assert settings.fixtures == tmp_path / "mine.yaml"


def test_policy_option_replaces_where_but_keeps_how(tmp_path: Path) -> None:
    path = config(
        tmp_path,
        "[policy]\n"
        'adapter = "authzen"\n'
        'url = "http://pdp.internal:3592"\n'
        'headers = { Authorization = "Bearer ${PDP_TOKEN}" }\n'
        "timeout_s = 4.0\n"
        "ask_every_hop = true\n"
        'roles_property = "cerbos.roles"\n',
    )
    settings = resolve_settings(
        cwd=tmp_path, config_path=path, policy="authzen:http://localhost:9999"
    )
    assert settings.policy is not None
    assert settings.policy.url == "http://localhost:9999"
    assert settings.policy.headers == {}  # never sent to another host
    assert settings.policy.timeout == 4.0 and settings.policy.ask_every_hop is True
    assert settings.policy.roles_property == "cerbos.roles"
    assert settings.policy_base_dir == tmp_path
    assert any("--policy replaces" in note for note in settings.notes)


def test_policy_option_can_switch_adapter(tmp_path: Path) -> None:
    settings = resolve_settings(cwd=tmp_path, policy="python:iam.py:decide")
    assert settings.policy is not None
    assert settings.policy.adapter == "python" and settings.policy.target == "iam.py:decide"


@pytest.mark.parametrize("value", ["cerbos:http://h", "authzen", "authzen:", "python:"])
def test_bad_policy_option(tmp_path: Path, value: str) -> None:
    with pytest.raises(StructuralError, match="--policy"):
        resolve_settings(cwd=tmp_path, policy=value)


def test_bad_policy_url_is_not_quoted(tmp_path: Path) -> None:
    with pytest.raises(StructuralError) as caught:
        resolve_settings(cwd=tmp_path, policy="authzen:http://u:s3cret@h")
    assert "s3cret" not in str(caught.value)


def test_no_policy_by_default(tmp_path: Path) -> None:
    settings = resolve_settings(cwd=tmp_path)
    assert settings.policy is None and settings.fixtures is None


def test_url_query_token_is_not_in_settings_repr(tmp_path: Path) -> None:
    path = config(tmp_path, '[policy]\nadapter = "authzen"\nurl = "https://h/x?token=SECRETQ"\n')
    assert "SECRETQ" not in repr(resolve_settings(cwd=tmp_path, config_path=path))


def test_policy_option_drops_file_headers_and_url_secret(tmp_path: Path) -> None:
    path = config(
        tmp_path,
        '[policy]\nadapter = "authzen"\nurl = "http://old"\nheaders = { A = "b" }\n',
    )
    settings = resolve_settings(
        cwd=tmp_path, config_path=path, policy="authzen:http://h/x?token=SECRETQ"
    )
    assert settings.policy is not None and settings.policy.headers == {}
    assert "SECRETQ" not in repr(settings)


def test_policy_option_keeps_timeout_when_switching_adapter(tmp_path: Path) -> None:
    path = config(tmp_path, '[policy]\nadapter = "authzen"\nurl = "http://h"\ntimeout_s = 4.0\n')
    settings = resolve_settings(cwd=tmp_path, config_path=path, policy="python:m:f")
    assert settings.policy is not None and settings.policy.timeout == 4.0


def test_policy_base_dir_without_config_file(tmp_path: Path) -> None:
    settings = resolve_settings(cwd=tmp_path, policy="python:m:f")
    assert settings.policy_base_dir == tmp_path
