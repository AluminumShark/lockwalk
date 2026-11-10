"""The smoke script, without a network: only its own guards."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "smoke_wheel.py"
_spec = importlib.util.spec_from_file_location("smoke_wheel", SCRIPT)
assert _spec is not None and _spec.loader is not None
smoke_wheel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke_wheel)


def test_the_wheel_version_comes_from_the_file_name():
    assert smoke_wheel._wheel_version(Path("lockwalk-0.1.0.dev0-py3-none-any.whl")) == "0.1.0.dev0"


def test_a_foreign_wheel_name_is_refused():
    with pytest.raises(smoke_wheel.SmokeError):
        smoke_wheel._wheel_version(Path("other-1.0-py3-none-any.whl"))


def test_a_missing_uv_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(smoke_wheel.shutil, "which", lambda _name: None)
    assert smoke_wheel.main([str(tmp_path)]) == 1
    with pytest.raises(smoke_wheel.SmokeError, match="uv"):
        smoke_wheel.smoke(tmp_path)


def test_a_timeout_is_a_clear_error(tmp_path, monkeypatch):
    def hang(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(smoke_wheel.subprocess, "run", hang)
    with pytest.raises(smoke_wheel.SmokeError, match="step one: timed out after 5 s"):
        smoke_wheel._run("step one", ["x"], tmp_path, timeout=5)


def test_a_command_that_cannot_start_is_a_clear_error(tmp_path, monkeypatch):
    def broken(command, **kwargs):
        raise FileNotFoundError("nope")

    monkeypatch.setattr(smoke_wheel.subprocess, "run", broken)
    with pytest.raises(smoke_wheel.SmokeError, match="cannot start"):
        smoke_wheel._run("step", ["x"], tmp_path)


def test_the_clean_environment_drops_python_settings(monkeypatch):
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PYTHON", "UV_PROJECT_ENVIRONMENT"):
        monkeypatch.setenv(name, "x")
    env = smoke_wheel._clean_env()
    assert not {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "UV_PYTHON"} & set(env)
    assert "UV_PROJECT_ENVIRONMENT" not in env


def test_the_extras_are_installed_with_the_wheel_path_and_then_imported(tmp_path, monkeypatch):
    calls = []

    def fake_run(step, command, cwd, expect=0, timeout=smoke_wheel.CLI_TIMEOUT):
        calls.append((step, [str(part) for part in command], timeout))
        return ""

    monkeypatch.setattr(smoke_wheel, "_run", fake_run)
    wheel = tmp_path / "lockwalk-1.0-py3-none-any.whl"
    smoke_wheel._check_extras(Path("py"), wheel, tmp_path)
    install, imports = calls
    assert install[1][:4] == ["uv", "pip", "install", "--python"]
    assert install[1][-1] == f"{wheel}[mcp,otel]"
    assert install[2] == smoke_wheel.INSTALL_TIMEOUT
    assert imports[1][:3] == ["py", "-I", "-c"]
    assert imports[2] == smoke_wheel.CLI_TIMEOUT


@pytest.mark.parametrize("failing", ["install extras", "import extras"])
def test_a_broken_extra_fails_with_the_step_name(tmp_path, monkeypatch, failing):
    def fake_run(step, command, cwd, expect=0, timeout=0):
        if step.startswith(failing):
            raise smoke_wheel.SmokeError(f"{step}: exit code 1, expected 0\nboom")
        return ""

    monkeypatch.setattr(smoke_wheel, "_run", fake_run)
    with pytest.raises(smoke_wheel.SmokeError, match=failing):
        smoke_wheel._check_extras(Path("py"), tmp_path / "w.whl", tmp_path)


def test_the_extras_import_code_runs_where_the_extras_are_installed():
    pytest.importorskip("mcp")
    pytest.importorskip("opentelemetry.trace")
    done = subprocess.run(
        [sys.executable, "-I", "-c", smoke_wheel.EXTRAS_IMPORT],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr


def test_the_extras_import_code_fails_when_an_extra_is_missing():
    code = "import sys; sys.modules['mcp'] = None\n" + smoke_wheel.EXTRAS_IMPORT
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert done.returncode != 0
