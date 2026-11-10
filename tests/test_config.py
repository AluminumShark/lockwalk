from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from lockwalk.config import (
    GateConfig,
    JsonSourceConfig,
    McpSourceConfig,
    PythonSourceConfig,
    load_config,
)
from lockwalk.errors import COMMAND_LINE, StructuralError
from lockwalk.models import Risk
from lockwalk.settings import SourceEntry, fallback_output_dir, resolve_settings


def problems_of(write, text: str) -> tuple[str, ...]:
    path = write(".lockwalk.toml", text)
    with pytest.raises(StructuralError) as info:
        load_config(path)
    return info.value.problems


def test_defaults(write):
    loaded = load_config(write(".lockwalk.toml", "[lockwalk]\nregistry = 'registry.yaml'\n"))
    assert loaded.file.lockwalk.registry == "registry.yaml"
    assert loaded.file.lockwalk.output_dir == ".lockwalk"
    assert loaded.file.gate.fail_on_unspecified_risk == (Risk.CRITICAL, Risk.UNKNOWN)
    assert loaded.file.gate.require_deny_case_for_risk == (Risk.HIGH, Risk.CRITICAL, Risk.UNKNOWN)
    assert loaded.file.inventory.mcp == ()


def test_empty_file_is_valid(write):
    assert load_config(write(".lockwalk.toml", "")).file.lockwalk.spec is None


def test_all_source_kinds(write):
    loaded = load_config(
        write(
            ".lockwalk.toml",
            """
            [[inventory.mcp]]
            name = "finance-tools"
            target = "stdio://server.py"

            [[inventory.mcp]]
            command = "node"
            args = ["server.js"]
            timeout_s = 5

            [[inventory.python]]
            target = "myapp.tools:TOOLS"
            agents = ["finance-agent"]

            [[inventory.json]]
            path = "tools.json"
            """,
        )
    )
    inventory = loaded.file.inventory
    assert [mcp.name for mcp in inventory.mcp] == ["finance-tools", None]
    assert inventory.mcp[1].args == ("server.js",)
    assert inventory.mcp[1].timeout_s == 5.0
    assert inventory.python[0].agents == ("finance-agent",)
    assert inventory.json_files[0].path == "tools.json"


def test_custom_gate(write):
    loaded = load_config(
        write(
            ".lockwalk.toml",
            "[gate]\nfail_on_unspecified_risk = ['high']\nrequire_deny_case_for_risk = []\n",
        )
    )
    assert loaded.file.gate == GateConfig(
        fail_on_unspecified_risk=(Risk.HIGH,), require_deny_case_for_risk=()
    )


def test_invalid_risk_in_gate(write):
    [problem] = problems_of(write, "[gate]\nfail_on_unspecified_risk = ['severe']\n")
    assert problem.startswith("gate.fail_on_unspecified_risk[0]: Input should be")


def test_unknown_key(write):
    assert problems_of(write, "[lockwalk]\nregisty = 'x'\n") == (
        "lockwalk.registy: Extra inputs are not permitted",
    )


def test_invalid_toml(write):
    [problem] = problems_of(write, "[lockwalk\n")
    assert problem.startswith("invalid TOML:")


def test_missing_file(tmp_path):
    with pytest.raises(StructuralError, match="cannot read file"):
        load_config(tmp_path / "missing.toml")


@pytest.mark.parametrize(
    ("table", "fragment"),
    [
        ('target = "stdio://s.py"\ncommand = "node"', "set exactly one of 'target' or 'command'"),
        ('name = "x"', "set exactly one of 'target' or 'command'"),
        (
            'target = "stdio://s.py"\nargs = ["a"]',
            "'args' can only be used together with 'command'",
        ),
        ('target = "ftp://host"', "must start with stdio://, http://, or https://"),
        ('target = "stdio://server.js"', "must point to a .py file"),
        ('command = "node"\ntimeout_s = true', "must be a number, not a boolean"),
        ('command = "node"\ntimeout_s = 0', "greater than 0"),
    ],
)
def test_invalid_mcp_tables(write, table, fragment):
    problems = problems_of(write, f"[[inventory.mcp]]\n{table}\n")
    assert any(fragment in problem for problem in problems), problems


def test_settings_without_a_config_file_use_cwd(tmp_path):
    settings = resolve_settings(cwd=tmp_path, registry="r.yaml", spec="s.yaml")
    assert settings.registry == tmp_path / "r.yaml"
    assert settings.spec == tmp_path / "s.yaml"
    assert settings.output_dir == tmp_path / ".lockwalk"
    assert settings.sources == ()
    assert settings.notes == ()
    assert settings.gate == GateConfig()


def test_config_paths_are_relative_to_the_config_file(write, tmp_path):
    write(
        "project/.lockwalk.toml",
        """
        [lockwalk]
        registry = "registry.yaml"
        spec = "spec.yaml"
        output_dir = "out"

        [[inventory.json]]
        path = "tools.json"
        """,
    )
    settings = resolve_settings(cwd=tmp_path, config_path=Path("project/.lockwalk.toml"))
    project = tmp_path / "project"
    assert settings.registry == project / "registry.yaml"
    assert settings.spec == project / "spec.yaml"
    assert settings.output_dir == project / "out"
    assert settings.sources == (
        SourceEntry(config=JsonSourceConfig(path="tools.json"), base_dir=project),
    )


def test_config_in_cwd_is_loaded_automatically(write, tmp_path):
    write(".lockwalk.toml", "[lockwalk]\nregistry = 'registry.yaml'\n")
    assert resolve_settings(cwd=tmp_path).registry == tmp_path / "registry.yaml"


def test_cli_values_override_the_config_file(write, tmp_path):
    write(".lockwalk.toml", "[lockwalk]\nregistry = 'registry.yaml'\n")
    settings = resolve_settings(cwd=tmp_path, registry="other.yaml", output_dir="o")
    assert settings.registry == tmp_path / "other.yaml"
    assert settings.output_dir == tmp_path / "o"


def test_cli_sources_replace_config_sources(write, tmp_path):
    write(
        ".lockwalk.toml",
        "[[inventory.json]]\npath = 'a.json'\n\n[[inventory.json]]\npath = 'b.json'\n",
    )
    settings = resolve_settings(
        cwd=tmp_path,
        mcp=["http://localhost:8000/mcp"],
        python=["m:T"],
        tools_json=["c.json"],
    )
    assert [type(entry.config).__name__ for entry in settings.sources] == [
        "McpSourceConfig",
        "PythonSourceConfig",
        "JsonSourceConfig",
    ]
    assert all(entry.base_dir == tmp_path for entry in settings.sources)
    assert settings.notes == (
        "Inventory sources from the command line replace the 2 source(s) in .lockwalk.toml.",
    )


def test_invalid_cli_source_is_a_structural_error(tmp_path):
    with pytest.raises(StructuralError) as info:
        resolve_settings(cwd=tmp_path, mcp=["ftp://x"])
    assert info.value.source == COMMAND_LINE
    assert info.value.problems[0].startswith("--mcp ftp://x: target:")


def test_explicit_missing_config_is_an_error(tmp_path):
    with pytest.raises(StructuralError):
        resolve_settings(cwd=tmp_path, config_path=Path("missing.toml"))


@pytest.mark.parametrize(
    "table",
    ['command = ""', 'name = ""\ntarget = "stdio://s.py"'],
)
def test_empty_mcp_name_or_command(write, table):
    problems = problems_of(write, f"[[inventory.mcp]]\n{table}\n")
    assert any("must not be empty" in problem for problem in problems), problems


@pytest.mark.parametrize(
    ("target", "fragment"),
    [
        ("http://", "must look like"),
        ("https://exa mple.com/mcp", "must look like"),
        ("stdio://.py", "must point to a .py file"),
        ("stdio://dir/.py", "must point to a .py file"),
        (" stdio://s.py", "whitespace"),
    ],
)
def test_malformed_mcp_targets(write, target, fragment):
    problems = problems_of(write, f'[[inventory.mcp]]\ntarget = "{target}"\n')
    assert any(fragment in problem for problem in problems), problems


@pytest.mark.parametrize("target", ["stdio://C:/tools/server.py", "stdio://C:\tools\\server.py"])
def test_windows_stdio_paths_are_accepted(target):
    assert McpSourceConfig(target=target).target == target


def test_absolute_cli_path_overrides_the_base(tmp_path):
    absolute = tmp_path / "abs" / "r.yaml"
    assert resolve_settings(cwd=tmp_path, registry=str(absolute)).registry == absolute


def test_relative_cwd_becomes_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    registry = resolve_settings(cwd=Path("."), registry="r.yaml").registry
    assert registry is not None
    assert registry.is_absolute()
    assert registry.resolve() == (tmp_path / "r.yaml").resolve()


def test_no_note_when_the_config_file_has_no_sources(write, tmp_path):
    write(".lockwalk.toml", "[lockwalk]\nregistry = 'r.yaml'\n")
    assert resolve_settings(cwd=tmp_path, tools_json=["t.json"]).notes == ()


def test_duplicate_toml_keys(write):
    [problem] = problems_of(write, "[lockwalk]\nregistry = 'a'\nregistry = 'b'\n")
    assert problem.startswith("invalid TOML:")


def test_python_field_name_is_not_a_toml_key(write):
    problems = problems_of(write, "[[inventory.json_files]]\npath = 'x'\n")
    assert any("Extra inputs are not permitted" in problem for problem in problems), problems


def test_utf8_bom_is_accepted(tmp_path):
    path = tmp_path / ".lockwalk.toml"
    path.write_bytes(b"\xef\xbb\xbf[lockwalk]\nregistry = 'r.yaml'\n")
    assert load_config(path).file.lockwalk.registry == "r.yaml"


def test_deeply_nested_toml_is_a_structural_error(write):
    from lockwalk.config import load_config

    path = write(".lockwalk.toml", "a = " + "[" * 5000 + "]" * 5000 + "\n")
    with pytest.raises(StructuralError) as info:
        load_config(path)
    assert "nested too deeply" in info.value.problems[0]


def test_new_gate_settings_have_safe_defaults():
    gate = GateConfig()
    assert gate.fail_on_never_reaches_inconclusive is True
    assert gate.fail_on_unspecified_role_risk == (Risk.CRITICAL, Risk.UNKNOWN)


def test_optional_mcp_source_needs_agents():
    with pytest.raises(ValidationError, match="'optional' sources must list 'agents'"):
        McpSourceConfig(target="https://h/mcp", optional=True)
    assert McpSourceConfig(target="https://h/mcp", optional=True, agents=("a",), name="n").optional


BAD_URLS = (
    "https://user:s\uff20cret@host/mcp",
    "https://user:pw@/x",
    "https://h/a b",
    "https://svc:abc/def@host/x",
    "https://u:1234/tok@host/x",
    "https://u:pa?ss@host/x",
    "https://host:99999/x",
    "https://host:abc/x",
    "https://host/a\u200bb",
)
LEAKS = ("cret", "user:", "pw@", "def", "tok", "pa?ss", "svc:", "u:")


def test_mcp_target_errors_never_leak_credentials(write):
    for bad in BAD_URLS:
        text = f'[[inventory.mcp]]\ntarget = "{bad}"\n'
        problems = problems_of(write, text)
        assert problems
        assert not any(leak in p for p in problems for leak in LEAKS)


def test_optional_source_name_rules():
    base: dict[str, Any] = {"target": "https://h/mcp", "optional": True, "agents": ("a",)}
    with pytest.raises(ValidationError, match="'optional' sources need a 'name'"):
        McpSourceConfig(**base)
    with pytest.raises(ValidationError, match="control"):
        McpSourceConfig(**base, name="bad\x07name")
    with pytest.raises(ValidationError, match="at most 196"):
        McpSourceConfig(**base, name="n" * 197)
    assert McpSourceConfig(**base, name="n" * 196).name == "n" * 196


def test_strict_booleans_in_config(write):
    [problem] = problems_of(
        write,
        "[[inventory.mcp]]\ntarget = 'https://h/mcp'\nname = 'n'\n"
        "agents = ['a']\noptional = 'yes'\n",
    )
    assert problem.startswith("inventory.mcp[0].optional:")
    [problem] = problems_of(write, "[gate]\nfail_on_never_reaches_inconclusive = 1\n")
    assert problem.startswith("gate.fail_on_never_reaches_inconclusive:")


# ---- Python targets: checked with the worker's own parsing rules, before any worker starts ----

BACKSLASH = chr(92)


@pytest.mark.parametrize(
    "target",
    [
        "myapp.tools:TOOLS",
        "tools.py:TOOLS",
        "pkg.mod:build.tools()",
        "/abs/dir/tools.py:TOOLS",
        "C:" + BACKSLASH + "x" + BACKSLASH + "tools.py:TOOLS",  # rpartition keeps the drive
    ],
)
def test_valid_python_targets(target):
    assert PythonSourceConfig(target=target).target == target


@pytest.mark.parametrize(
    ("target", "problem"),
    [
        ("no_colon_here", "target 'no_colon_here' must look like '<module>:<attribute>'"),
        (":TOOLS", "target ':TOOLS' must look like '<module>:<attribute>'"),
        ("mod:", "target 'mod:' must look like '<module>:<attribute>'"),
        ("mod:TOOLS.", "target 'mod:TOOLS.' has an invalid attribute path 'TOOLS.'"),
        ("mod:1abc", "target 'mod:1abc' has an invalid attribute path '1abc'"),
        ("mod:()", "target 'mod:()' has an invalid attribute path ''"),
    ],
)
def test_malformed_python_targets(write, target, problem):
    [found] = problems_of(write, f"[[inventory.python]]\ntarget = '{target}'\n")
    assert found == f"inventory.python[0].target: Value error, {problem}"


def test_malformed_python_target_on_the_command_line(tmp_path):
    with pytest.raises(StructuralError) as info:
        resolve_settings(cwd=tmp_path, python=["no_colon_here"])
    assert info.value.source == COMMAND_LINE
    assert info.value.problems == (
        "--python no_colon_here: target: Value error, "
        "target 'no_colon_here' must look like '<module>:<attribute>'",
    )


def test_the_worker_and_the_config_share_one_parser():
    from lockwalk.inventory import _python_worker, targets

    assert _python_worker.parse_target is targets.parse_target
    assert _python_worker.TargetError is targets.TargetError
    assert targets.parse_target("pkg.mod:a.b()") == ("pkg.mod", ["a", "b"], True)


# ---- where a failed run looks for the previous report ----


def test_fallback_output_dir(write, tmp_path):
    def fallback(config: str | None, output_dir: str | None = None) -> Path:
        path = None if config is None else Path(config)
        return fallback_output_dir(cwd=tmp_path, config_path=path, output_dir=output_dir)

    # No config file anywhere: the default directory in cwd.
    assert fallback(None) == tmp_path / ".lockwalk"
    # A readable config file (the problem was elsewhere): its own output_dir.
    write(".lockwalk.toml", "[lockwalk]\noutput_dir = 'here'\n")
    write("sub/.lockwalk.toml", "[lockwalk]\noutput_dir = 'there'\n")
    assert fallback(None) == tmp_path / "here"
    assert fallback("sub/.lockwalk.toml") == tmp_path / "sub" / "there"
    # A config file that is valid TOML but fails validation elsewhere: its output_dir is
    # still read straight from the TOML.
    write(
        "sub/.lockwalk.toml",
        "[lockwalk]\noutput_dir = 'there'\n[[inventory.python]]\ntarget = 'x'\n",
    )
    assert fallback("sub/.lockwalk.toml") == tmp_path / "sub" / "there"
    write(
        "sub/.lockwalk.toml",
        "[lockwalk]\noutput_dir = 'there'\n[gate]\nfail_on_unspecified_risk = 1\n",
    )
    assert fallback("sub/.lockwalk.toml") == tmp_path / "sub" / "there"
    # Without a usable output_dir, or a file that is no TOML at all, or a missing one:
    # the default directory next to it.
    write("sub/.lockwalk.toml", "[lockwalk]\nregistyr = 'x'\n")
    assert fallback("sub/.lockwalk.toml") == tmp_path / "sub" / ".lockwalk"
    for text in ("[lockwalk]\noutput_dir = ''\nx = 1\n", "[lockwalk]\noutput_dir = 3\n"):
        write("sub/.lockwalk.toml", text)
        assert fallback("sub/.lockwalk.toml") == tmp_path / "sub" / ".lockwalk", text
    for text in ("lockwalk = 1\n", "[lockwalk\noutput_dir = 'there'\n"):
        write("sub/.lockwalk.toml", text)
        assert fallback("sub/.lockwalk.toml") == tmp_path / "sub" / ".lockwalk", text
    (tmp_path / "sub" / "bad.toml").write_bytes(b"[lockwalk]\noutput_dir = '\xff'\n")
    assert fallback("sub/bad.toml") == tmp_path / "sub" / ".lockwalk"
    assert fallback("gone/x.toml") == tmp_path / "gone" / ".lockwalk"
    # The command line wins over everything.
    assert fallback("sub/.lockwalk.toml", "out") == tmp_path / "out"
