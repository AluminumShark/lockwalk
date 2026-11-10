"""[harness], fail_on_identity_mismatch, --no-harness, and optional tool_args."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from lockwalk.config import ConfigFile, GateConfig, HarnessConfig
from lockwalk.fixtures import ResourceFixture
from lockwalk.settings import resolve_settings


def test_harness_defaults() -> None:
    config = HarnessConfig(hooks="lockwalk_hooks.py")
    assert config.modes == ("direct", "scripted")
    assert config.timeout_s == 10.0
    assert config.import_timeout_s == 30.0
    assert config.allow_hosts == ()
    assert GateConfig().fail_on_identity_mismatch is True
    assert ConfigFile().harness is None


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"hooks": ""},
        {"hooks": "h.py", "modes": []},
        {"hooks": "h.py", "modes": ["direct", "direct"]},
        {"hooks": "h.py", "modes": ["live"]},
        {"hooks": "h.py", "timeout_s": 0},
        {"hooks": "h.py", "allow_hosts": ["https://pdp.example"]},
        {"hooks": "h.py", "allow_hosts": ["pdp.example:8443"]},
        {"hooks": "h.py", "allow_hosts": ["pdp.example/path"]},
        {"hooks": "h.py", "allow_hosts": ["user@pdp.example"]},
        {"hooks": "h.py", "unknown": 1},
        {"hooks": "h.py", "allow_hosts": ["fe80::1%eth0"]},
        {"hooks": "h.py", "allow_hosts": ["::1::2"]},
        {"hooks": "h.py", "allow_hosts": ["999.1.1.1"]},
        {"hooks": "h.py", "allow_hosts": ["1.2.3.4.5"]},
        {"hooks": "h.py", "allow_hosts": ["a..b"]},
        {"hooks": "h.py", "allow_hosts": ["."]},
        {"hooks": "h.py", "allow_hosts": ["-"]},
        {"hooks": "h.py", "allow_hosts": ["_"]},
        {"hooks": "h.py", "allow_hosts": ["a."]},
    ],
)
def test_bad_harness_configs_are_rejected(data: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        HarnessConfig.model_validate(data)


def test_allow_hosts_accept_names_and_addresses_and_are_lowered() -> None:
    config = HarnessConfig(hooks="h.py", allow_hosts=("PDP.Example", "10.0.0.5", "::1"))
    assert config.allow_hosts == ("pdp.example", "10.0.0.5", "::1")


def test_allow_hosts_are_stored_in_canonical_form() -> None:
    hosts = ("0:0:0:0:0:0:0:1", "2001:DB8::A", "10.0.0.5", "a-b_c.Example")
    config = HarnessConfig(hooks="h.py", allow_hosts=hosts)
    assert config.allow_hosts == ("::1", "2001:db8::a", "10.0.0.5", "a-b_c.example")


def test_no_harness_without_a_harness_section_adds_no_note(tmp_path: Path) -> None:
    (tmp_path / ".lockwalk.toml").write_text("[lockwalk]\n", encoding="utf-8")
    settings = resolve_settings(cwd=tmp_path, no_harness=True)
    assert settings.harness is None
    assert not any("--no-harness" in note for note in settings.notes)


def test_settings_carry_the_harness_and_no_harness_drops_it(tmp_path: Path) -> None:
    (tmp_path / ".lockwalk.toml").write_text(
        '[harness]\nhooks = "lockwalk_hooks.py"\nmodes = ["direct"]\n', encoding="utf-8"
    )
    settings = resolve_settings(cwd=tmp_path)
    assert settings.harness is not None
    assert settings.harness.modes == ("direct",)
    assert settings.harness_base_dir == tmp_path.absolute()
    skipped = resolve_settings(cwd=tmp_path, no_harness=True)
    assert skipped.harness is None
    assert skipped.harness_base_dir is None
    assert any("--no-harness" in note for note in skipped.notes)


def test_tool_args_none_means_not_given() -> None:
    assert ResourceFixture().tool_args is None
    assert ResourceFixture(tool_args={}).tool_args == {}
    with pytest.raises(ValidationError):
        ResourceFixture(tool_args={"x": float("nan")})
