from pathlib import Path

import click
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from lockwalk.cli import app
from lockwalk.config import GateConfig, load_config
from lockwalk.errors import StructuralError
from lockwalk.settings import resolve_settings
from lockwalk.testing import run_test


def test_max_waiver_days_default_and_bounds():
    assert GateConfig().max_waiver_days == 90
    assert GateConfig(max_waiver_days=1).max_waiver_days == 1
    assert GateConfig(max_waiver_days=3650).max_waiver_days == 3650
    for bad in (0, 3651, -1, 1.5, "90", True):
        with pytest.raises(ValidationError):
            GateConfig(max_waiver_days=bad)


def test_max_waiver_days_from_the_config_file(write):
    path = write(".lockwalk.toml", "[gate]\nmax_waiver_days = 30\n")
    assert load_config(path).file.gate.max_waiver_days == 30
    path = write(".lockwalk.toml", "[gate]\nmax_waiver_days = 0\n")
    with pytest.raises(StructuralError):
        load_config(path)


def test_waivers_key_is_relative_to_the_config_file(write, tmp_path):
    write("conf/.lockwalk.toml", "[lockwalk]\nwaivers = 'w.yaml'\n")
    settings = resolve_settings(cwd=tmp_path, config_path=Path("conf/.lockwalk.toml"))
    assert settings.waivers == tmp_path / "conf" / "w.yaml"


def test_waivers_default_is_none(tmp_path):
    assert resolve_settings(cwd=tmp_path).waivers is None


def test_command_line_waivers_override_the_config_file(write, tmp_path):
    write("conf/.lockwalk.toml", "[lockwalk]\nwaivers = 'w.yaml'\n")
    settings = resolve_settings(
        cwd=tmp_path, config_path=Path("conf/.lockwalk.toml"), waivers="other.yaml"
    )
    assert settings.waivers == tmp_path / "other.yaml"


def test_empty_waivers_key_is_rejected(write):
    with pytest.raises(StructuralError):
        load_config(write(".lockwalk.toml", "[lockwalk]\nwaivers = ''\n"))


def test_run_test_accepts_waivers():
    import inspect

    assert "waivers" in inspect.signature(run_test).parameters


@pytest.mark.parametrize("command", ["coverage", "test"])
def test_help_lists_waivers_and_summary(command):
    result = CliRunner().invoke(app, [command, "--help"], terminal_width=200)
    assert result.exit_code == 0
    # On GitHub Actions typer adds colour codes that split "--waivers" into "-" and "-waivers".
    text = click.unstyle(result.output)
    assert "--waivers" in text
    assert "--summary" in text
