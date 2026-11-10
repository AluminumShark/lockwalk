"""Combine .lockwalk.toml and command-line options into the settings for one run.

Precedence: command line > config file > defaults. Relative paths from the command line
are resolved against the current directory; relative paths from the config file are
resolved against the directory that contains it.
"""

import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from lockwalk.config import (
    ConfigFile,
    GateConfig,
    HarnessConfig,
    JsonSourceConfig,
    LoadedConfig,
    McpSourceConfig,
    ObserveConfig,
    PolicyConfig,
    PythonSourceConfig,
    load_config,
)
from lockwalk.errors import COMMAND_LINE, StructuralError, format_validation_error

CONFIG_FILE_NAME = ".lockwalk.toml"

SourceConfig = McpSourceConfig | PythonSourceConfig | JsonSourceConfig


@dataclass(frozen=True)
class SourceEntry:
    """One inventory source, plus the directory its relative paths are resolved against."""

    config: SourceConfig
    base_dir: Path


@dataclass(frozen=True)
class RunSettings:
    registry: Path | None
    spec: Path | None
    output_dir: Path
    gate: GateConfig
    sources: tuple[SourceEntry, ...]
    notes: tuple[str, ...]
    fixtures: Path | None = None
    waivers: Path | None = None
    policy: PolicyConfig | None = None
    policy_base_dir: Path | None = None  # where a decide target's relative paths start
    harness: HarnessConfig | None = None
    harness_base_dir: Path | None = None  # where the hooks file and the worker's cwd are
    observe: ObserveConfig = field(default_factory=ObserveConfig)
    # [observe] test_report, relative to the config file's directory (no command-line option).
    # Always set by resolve_settings; the default only helps code that builds settings by hand.
    test_report: Path | None = None
    trace_args: tuple[str, ...] = ()  # --traces values, or [observe] traces, as written
    trace_base: Path | None = None  # what trace_args are relative to; also the reader's cwd


def resolve_settings(
    *,
    cwd: Path,
    config_path: Path | None = None,
    registry: str | None = None,
    spec: str | None = None,
    mcp: Sequence[str] = (),
    python: Sequence[str] = (),
    tools_json: Sequence[str] = (),
    output_dir: str | None = None,
    fixtures: str | None = None,
    waivers: str | None = None,
    policy: str | None = None,
    no_harness: bool = False,
    traces: Sequence[str] = (),
) -> RunSettings:
    """Build the settings for one run. Malformed input raises StructuralError.

    A non-empty `traces` replaces [observe] traces (it does not add to it).

    A relative cwd is made absolute first, so every returned path is absolute.
    """
    cwd = cwd.absolute()
    loaded = _load(cwd, config_path)
    file = loaded.file if loaded is not None else ConfigFile()
    base_dir = loaded.base_dir if loaded is not None else cwd

    cli_sources = _cli_sources(cwd, mcp, python, tools_json)
    file_sources = _file_sources(file, base_dir)
    notes: list[str] = []
    if cli_sources:
        sources = cli_sources
        if file_sources and loaded is not None:
            notes.append(
                "Inventory sources from the command line replace the "
                f"{len(file_sources)} source(s) in {loaded.path.name}."
            )
    else:
        sources = file_sources

    chosen_policy, policy_base_dir = file.policy, base_dir
    if policy is not None:
        chosen_policy, policy_base_dir = policy_from_cli(policy, file.policy), cwd
        if file.policy is not None and loaded is not None:
            notes.append(
                f"--policy replaces the [policy] adapter in {loaded.path.name}; "
                "its url, target, and headers are not used."
            )

    harness = None if no_harness else file.harness
    if no_harness and file.harness is not None and loaded is not None:
        notes.append(
            f"--no-harness: the door tests in [harness] of {loaded.path.name} are skipped."
        )

    if traces:
        trace_args, trace_base = tuple(traces), cwd
    else:
        trace_args, trace_base = file.observe.traces, base_dir

    test_report = base_dir / file.observe.test_report

    return RunSettings(
        registry=_pick(cwd, registry, base_dir, file.lockwalk.registry),
        spec=_pick(cwd, spec, base_dir, file.lockwalk.spec),
        output_dir=(
            cwd / output_dir if output_dir is not None else base_dir / file.lockwalk.output_dir
        ),
        gate=file.gate,
        sources=sources,
        notes=tuple(notes),
        fixtures=_pick(cwd, fixtures, base_dir, file.lockwalk.fixtures),
        waivers=_pick(cwd, waivers, base_dir, file.lockwalk.waivers),
        policy=chosen_policy,
        policy_base_dir=policy_base_dir,
        harness=harness,
        harness_base_dir=base_dir if harness is not None else None,
        observe=file.observe,
        test_report=test_report,
        trace_args=trace_args,
        trace_base=trace_base,
    )


# Settings that are not about where the IAM is. --policy keeps them from the config file.
_KEPT_POLICY_SETTINGS = (
    "timeout_s",
    "batch_size",
    "max_queries",
    "ask_every_hop",
    "invoke_action",
    "roles_property",
)


def policy_from_cli(value: str, file_policy: PolicyConfig | None) -> PolicyConfig:
    """Parse --policy authzen:URL or --policy python:TARGET.

    The url, target, and headers of the config file are never used, so a token meant for
    one PDP is never sent to another. Messages never quote a URL: it may hold
    credentials.
    """
    adapter, separator, rest = value.partition(":")
    if adapter not in ("authzen", "python") or not separator or not rest:
        raise StructuralError(
            COMMAND_LINE,
            [
                "--policy must look like authzen:http(s)://host[:port][/path] "
                "or python:module:function"
            ],
        )
    data: dict[str, object] = {"adapter": adapter}
    data["url" if adapter == "authzen" else "target"] = rest
    if file_policy is not None:
        data.update({name: getattr(file_policy, name) for name in _KEPT_POLICY_SETTINGS})
    try:
        return PolicyConfig.model_validate(data)
    except ValidationError as exc:
        raise StructuralError(
            COMMAND_LINE, [f"--policy: {problem}" for problem in format_validation_error(exc)]
        ) from exc


def fallback_output_dir(*, cwd: Path, config_path: Path | None, output_dir: str | None) -> Path:
    """The best-known output directory for a run whose settings could not be resolved.

    The command-line value wins, as in resolve_settings. Otherwise the config file
    (--config, or ./.lockwalk.toml) decides:
    - when it is valid (the problem was elsewhere, for example a bad command-line
      source), its own output_dir;
    - when it is valid TOML that fails validation (for example a bad Python target or
      gate value), the [lockwalk].output_dir string read straight from the TOML;
    - otherwise, the default directory next to that file.
    """
    cwd = cwd.absolute()
    if output_dir is not None:
        return cwd / output_dir
    path = cwd / (config_path if config_path is not None else Path(CONFIG_FILE_NAME))
    try:
        loaded = load_config(path)
    except StructuralError:
        return path.parent / (_raw_output_dir(path) or ConfigFile().lockwalk.output_dir)
    return loaded.base_dir / loaded.file.lockwalk.output_dir


def _raw_output_dir(path: Path) -> str | None:
    """[lockwalk].output_dir of a config file that failed validation, if it is a string.

    Nothing else in the file is trusted, and any problem reading it gives None.
    """
    try:
        data = tomllib.loads(path.read_bytes().decode("utf-8-sig"))
        value = data.get("lockwalk", {}).get("output_dir")
    except Exception:
        return None
    return value if isinstance(value, str) and value else None


def _load(cwd: Path, config_path: Path | None) -> LoadedConfig | None:
    if config_path is not None:
        return load_config(cwd / config_path)
    default = cwd / CONFIG_FILE_NAME
    return load_config(default) if default.is_file() else None


def _pick(cwd: Path, cli_value: str | None, base_dir: Path, file_value: str | None) -> Path | None:
    if cli_value is not None:
        return cwd / cli_value
    if file_value is not None:
        return base_dir / file_value
    return None


def _file_sources(file: ConfigFile, base_dir: Path) -> tuple[SourceEntry, ...]:
    configs: list[SourceConfig] = [
        *file.inventory.mcp,
        *file.inventory.python,
        *file.inventory.json_files,
    ]
    return tuple(SourceEntry(config=config, base_dir=base_dir) for config in configs)


def _cli_sources(
    cwd: Path, mcp: Sequence[str], python: Sequence[str], tools_json: Sequence[str]
) -> tuple[SourceEntry, ...]:
    configs: list[SourceConfig] = []
    problems: list[str] = []
    for value in mcp:
        try:
            configs.append(McpSourceConfig(target=value))
        except ValidationError as exc:
            problems.extend(f"--mcp {value}: {p}" for p in format_validation_error(exc))
    for value in python:
        try:
            configs.append(PythonSourceConfig(target=value))
        except ValidationError as exc:
            problems.extend(f"--python {value}: {p}" for p in format_validation_error(exc))
    for value in tools_json:
        try:
            configs.append(JsonSourceConfig(path=value))
        except ValidationError as exc:
            problems.extend(f"--tools-json {value}: {p}" for p in format_validation_error(exc))
    if problems:
        raise StructuralError(COMMAND_LINE, problems)
    return tuple(SourceEntry(config=config, base_dir=cwd) for config in configs)
