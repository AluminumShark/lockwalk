"""Inventory source: an MCP server's tools/list. lockwalk never calls tools/call.

The mcp package is optional (pip install 'lockwalk[mcp]'), so it is imported lazily.

env (stdio servers) and headers (http(s) servers) may hold secrets. Their ${VAR}
references are expanded only here, when lockwalk connects (see lockwalk.masking). lockwalk
never puts a value in a SourceResult, an error, or a label, and it also hides values that
a careless server echoes back (in its name, a tool, or an error message).
"""

import functools
import importlib.util
import logging
import sys
import tempfile
from collections.abc import Generator
from contextlib import AsyncExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO
from urllib.parse import urlsplit

from pydantic import ValidationError

from lockwalk.config import McpSourceConfig
from lockwalk.inventory.base import failed, finish
from lockwalk.inventory.mcp_naming import program_name
from lockwalk.inventory.normalize import normalize_items
from lockwalk.masking import (
    SecretValues,
    SetupError,
    describe_validation_error,
    expand_value,
    header_value_problem,
    hide_pydantic_inputs,
)
from lockwalk.models import SourceRef, SourceResult, check_name
from lockwalk.urls import redact_url

if TYPE_CHECKING:
    from mcp import StdioServerParameters
    from mcp.client import Transport

MAX_PAGES = 100
NOT_INSTALLED = (
    "MCP support is not installed; install it with: pip install 'lockwalk[mcp]' "
    "(or: uv add 'lockwalk[mcp]')"
)
# The SDK logs under "mcp.*", and its ClientSession under a logger named "client".
QUIET_LOGGERS = ("mcp", "client")
# The timeouts of the SDK's own HTTP client (mcp.shared._httpx_utils), so a source with
# headers behaves like one without. timeout_s bounds the whole read anyway.
HTTP_TIMEOUT_S = 30.0
HTTP_READ_TIMEOUT_S = 300.0


def root_cause(exc: BaseException) -> BaseException:
    """Return the first leaf exception inside (possibly nested) exception groups."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def _is_url(target: str) -> bool:
    return target.startswith(("http://", "https://"))


def command_name(command: str) -> str:
    """The program name of a command, or "command" when it has none.

    Labels use it instead of the command line, because args may hold secrets such as tokens.
    The rule is program_name in mcp_naming.py, shared with the node ids of MCP servers.
    """
    return program_name(command) or "command"


@contextmanager
def quiet_mcp_logging() -> Generator[None, None, None]:
    """Raise the SDK's loggers to CRITICAL while a source is read, then restore them.

    Otherwise logging's last-resort handler prints SDK tracebacks (for example for a server
    that writes non-JSON to stdout) to lockwalk's stderr, server output included.
    """
    names = set(QUIET_LOGGERS)
    for name, item in list(logging.Logger.manager.loggerDict.items()):
        if isinstance(item, logging.Logger) and name.startswith(
            tuple(f"{root}." for root in QUIET_LOGGERS)
        ):
            names.add(name)
    loggers = [logging.getLogger(name) for name in sorted(names)]
    saved = [logger.level for logger in loggers]
    for logger in loggers:
        logger.setLevel(logging.CRITICAL)
    try:
        yield
    finally:
        for logger, level in zip(loggers, saved, strict=True):
            logger.setLevel(level)


@dataclass(frozen=True)
class _Http:
    """A streamable HTTP server, with expanded headers."""

    url: str
    headers: dict[str, str] = field(repr=False)


class McpSource:
    def __init__(self, config: McpSourceConfig, base_dir: Path) -> None:
        self._config = config
        self._base_dir = base_dir

    def read(self) -> SourceResult:
        fallback = SourceRef(kind="mcp", label=self._label(None))
        if importlib.util.find_spec("mcp") is None:
            return self._failed(fallback, NOT_INSTALLED)
        try:
            server, secrets = self._prepare()
        except SetupError as exc:
            return self._failed(fallback, str(exc))
        import anyio

        captured: list[tuple[str | None, list[dict[str, Any]]]] = []
        # Set when the server connected but its tools/list reply was unusable. Kept outside
        # the exception, because a slow teardown can replace that with a timeout.
        unusable: list[BaseException] = []
        # The stdio client defaults its errlog to sys.stderr, which has no fileno() under
        # CliRunner, Jupyter, and some IDEs. This file gives the subprocess a real stderr
        # handle and keeps server output out of lockwalk's terminal output and reports.
        with (
            tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as errlog,
            quiet_mcp_logging(),
        ):
            try:
                server_name, items = anyio.run(
                    functools.partial(self._list_tools, server, unusable), captured, errlog
                )
            except Exception as exc:  # connect, protocol, and timeout errors all fail the source
                if not captured:
                    if unusable:
                        # The server connected, so 'optional' (for a server that is down)
                        # does not apply: an unusable reply is an error.
                        message = self._describe(root_cause(unusable[0]))
                        return failed(fallback, secrets.scrub(message), agents=self._config.agents)
                    message = self._describe(root_cause(exc))
                    return self._failed(fallback, secrets.scrub(message))
                # The tool list was fully read; only the client teardown ran over the deadline.
                server_name, items = captured[0]
        tools, errors = normalize_items(items)
        if secrets:
            tools, errors = secrets.clean_tools(tools, errors)
            if server_name is not None and secrets.found_in_name(server_name) is not None:
                server_name = None
        ref = SourceRef(kind="mcp", label=self._label(server_name))
        return finish(ref, tools, errors, self._config.agents)

    def _failed(self, source: SourceRef, message: str) -> SourceResult:
        """A source that produced no tool list, and the only results that honor 'optional'.

        That is: the mcp extra is missing, env or headers could not be prepared (SetupError),
        or lockwalk could not connect or finish in time. A server that connected and then
        answered tools/list with something unusable (a reply the MCP SDK rejects, an error,
        or more than MAX_PAGES pages) is not covered; read() returns it as a plain failure.
        """
        result = failed(source, message, agents=self._config.agents)
        return result.model_copy(update={"optional": self._config.optional})

    def _prepare(self) -> "tuple[StdioServerParameters | _Http, SecretValues]":
        """Expand env and headers. Raise SetupError, which never quotes a value."""
        values: list[tuple[str, str]] = []

        def expand_all(kind: str, entries: dict[str, str]) -> dict[str, str]:
            expanded: dict[str, str] = {}
            for key, value in entries.items():
                pieces: list[str] = []
                expanded[key] = expand_value(value, pieces)
                what = f"{kind} {key!r}"
                values.extend((what, text) for text in (expanded[key], *pieces))
            return expanded

        env = expand_all("env", self._config.env)
        headers = expand_all("header", self._config.headers)
        for key, value in headers.items():
            problem = header_value_problem(key, value, template=False)
            if problem is not None:
                raise SetupError(problem)
        return self._server(env, headers), SecretValues(values)

    async def _list_tools(
        self,
        server: "StdioServerParameters | _Http",
        unusable: list[BaseException],
        captured: list[tuple[str | None, list[dict[str, Any]]]],
        errlog: TextIO,
    ) -> tuple[str | None, list[dict[str, Any]]]:
        import anyio
        from mcp import Client, StdioServerParameters
        from mcp.client.stdio import stdio_client

        items: list[dict[str, Any]] = []
        with anyio.fail_after(self._config.timeout_s):
            async with AsyncExitStack() as stack:
                transport = (
                    stdio_client(server, errlog=errlog)
                    if isinstance(server, StdioServerParameters)
                    else await _http_transport(stack, server)
                )
                client = await stack.enter_async_context(Client(transport))
                info = client.server_info
                try:
                    await self._read_pages(client, items)
                except TimeoutError:
                    raise  # a timeout is not a reply; 'optional' still applies
                except Exception as exc:
                    unusable.append(exc)
                    raise
                # Recorded before teardown so a slow shutdown cannot discard a finished read.
                server_name = info.name if info is not None else None
                captured.append((server_name, items))
        return server_name, items

    async def _read_pages(self, client: Any, items: list[dict[str, Any]]) -> None:
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            result = await client.list_tools(cursor=cursor)
            items.extend(
                tool.model_dump(by_alias=True, mode="json", exclude_none=True)
                for tool in result.tools
            )
            cursor = result.next_cursor
            if not cursor:
                return
        raise RuntimeError(f"tools/list returned more than {MAX_PAGES} pages")

    def _server(
        self, env: dict[str, str], headers: dict[str, str]
    ) -> "StdioServerParameters | _Http":
        from mcp import StdioServerParameters

        cwd = str(self._base_dir)
        # The SDK adds env on top of its minimal stdio environment (PATH and a few more).
        extra = env or None
        target = self._config.target
        if target is None:
            command = self._config.command or ""  # McpSourceConfig guarantees it is set
            args = list(self._config.args)
            return StdioServerParameters(command=command, args=args, env=extra, cwd=cwd)
        if target.startswith("stdio://"):
            script = self._base_dir / target.removeprefix("stdio://")
            return StdioServerParameters(
                command=sys.executable, args=[str(script)], env=extra, cwd=cwd
            )
        return _Http(url=target, headers=headers)

    def _display(self) -> str:
        """How a source without a name is labeled. Never the args, which may hold secrets."""
        target = self._config.target
        if target is not None:
            return redact_url(target) if _is_url(target) else target
        return command_name(self._config.command or "")

    def _label(self, server_name: str | None) -> str:
        # serverInfo.name comes from an untrusted server, so only a valid name is used.
        if server_name is not None:
            try:
                check_name(server_name)
            except ValueError:
                server_name = None
        name = self._config.name or server_name
        return f"mcp:{name}" if name else f"mcp:{self._display()}"

    def _describe(self, exc: BaseException) -> str:
        # pydantic quotes a shortened input, which may be cut inside an echoed secret, so the
        # caller's scrub could not match it whole. Such inputs are never shown.
        text = hide_pydantic_inputs(self._describe_raw(exc))
        target = self._config.target
        if target is not None and _is_url(target):
            # Exceptions such as httpx errors may echo the URL, credentials included.
            text = text.replace(target, redact_url(target))
            userinfo = urlsplit(target).netloc.rpartition("@")[0]
            if userinfo:
                text = text.replace(userinfo + "@", "")
        return text

    def _describe_raw(self, exc: BaseException) -> str:
        if isinstance(exc, TimeoutError):
            return f"timed out after {self._config.timeout_s:g}s"
        if isinstance(exc, ValidationError):  # for example a server reply that fails the SDK
            return describe_validation_error(exc)
        if "Connection closed" in str(exc):
            return (
                f"{type(exc).__name__}: {exc} (the server exited or closed the connection "
                "before replying; run the server command yourself to see its error output)"
            )
        if isinstance(exc, OSError) and self._config.is_stdio:
            # The command as written (or the stdio:// target) helps find a typo; args stay out.
            program = self._config.command or self._config.target
            return f"cannot start the MCP server ({program}): {exc.strerror or exc}"
        return f"{type(exc).__name__}: {exc}"


async def _http_transport(stack: AsyncExitStack, server: _Http) -> "Transport":
    """A streamable HTTP transport whose every request carries the configured headers.

    mcp SDK 2.3 takes headers through an httpx2.AsyncClient passed as http_client; the
    caller owns that client, so the exit stack closes it after the MCP client is done.
    """
    import httpx2
    from mcp.client.streamable_http import streamable_http_client

    timeout = httpx2.Timeout(HTTP_TIMEOUT_S, read=HTTP_READ_TIMEOUT_S)
    http_client = await stack.enter_async_context(
        httpx2.AsyncClient(headers=server.headers, timeout=timeout)
    )
    return streamable_http_client(server.url, http_client=http_client)
