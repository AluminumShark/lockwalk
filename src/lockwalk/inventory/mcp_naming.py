"""MCP servers found on agents: recognizing them, and naming them without leaking secrets.

A server object is read once into a ServerConfig. Its node id is "mcp:<name>":
- its name, or else its id, unless that may have been built from its command line
  (frameworks such as Agno put the arguments into a default name, and arguments can hold
  tokens); then the base name of its command, never an argument;
- for a server with no command line and no name, its URL without credentials, query, or
  fragment.
A ServerConfig is only compared (to tell two servers apart), never shown as it is.
"""

import re
from collections.abc import Mapping, Sequence
from typing import NamedTuple

from lockwalk.urls import redact_url, redact_urls

MCP_PREFIX = "mcp:"

# Default MCP server names that frameworks build from the command line (verified):
# Agno MCPTools names a server "mcp_<command and arguments as a slug>" (cut to 64
# characters) and gives it the id "mcp-<...>"; the OpenAI Agents SDK names an
# MCPServerStdio "stdio: <command>".
_COMMAND_LINE_DEFAULTS = ("mcp_", "mcp-", "stdio:")

# "/" and the backslash (built with chr(92) so no escape sequence is needed in the source).
_PATH_SEPARATORS = re.compile("[/" + re.escape(chr(92)) + "]")
_PATH_START = re.compile("^([A-Za-z]:)?[/" + re.escape(chr(92)) + "]")

# File name endings that are dropped from a program name (Windows executables).
EXECUTABLE_SUFFIXES = (".exe", ".cmd", ".bat", ".com")
# The endings accepted for a path that contains spaces. ".com" is left out on purpose.
SPACED_PATH_SUFFIXES = (".exe", ".cmd", ".bat")
# Any whitespace except a plain space (tab, newline, ...).
_OTHER_WHITESPACE = re.compile(r"[^\S ]")


class ServerConfig(NamedTuple):
    """What lockwalk reads from one MCP server object, read once."""

    kind: tuple[str, str]  # module and qualified name of its type
    text: str | None  # a server given as a plain string (CrewAI Agent(mcps=["https://..."]))
    names: tuple[str, ...]  # its .name, then its .id, when they are non-empty strings
    urls: tuple[str, ...]  # raw URLs from .url, .params, and .server_params
    command: str | None  # the command of a stdio server
    args: tuple[str, ...] | None  # its arguments; None when one cannot be read as text


def read_server(item: object) -> ServerConfig:
    """Read the fields that name and identify an MCP server.

    OpenAI Agents SDK: .name, and .params (an mcp StdioServerParameters, or a dict with
    "url"). Agno MCPTools: .name, .id, .url, and .server_params (Agno splits a command
    string into .command and .args there). CrewAI and Pydantic AI: .command, .args, .url,
    and for Pydantic AI .id. In each of them the command field holds only the executable.
    """
    kind = (type(item).__module__, type(item).__qualname__)
    if isinstance(item, str):
        return ServerConfig(kind, item, (), (), None, ())
    params = getattr(item, "params", None)
    server_params = getattr(item, "server_params", None)
    names = tuple(
        value
        for value in (getattr(item, "name", None), getattr(item, "id", None))
        if isinstance(value, str) and value
    )
    urls = tuple(
        url
        for url in (_field(item, "url"), _field(params, "url"), _field(server_params, "url"))
        if isinstance(url, str)
    )
    for holder in (params, server_params, item):
        command = _field(holder, "command")
        if isinstance(command, str) and command.strip():
            raw = _field(holder, "args")
            args = _texts(raw) if isinstance(raw, list | tuple) else ()
            return ServerConfig(kind, None, names, urls, command, args)
    return ServerConfig(kind, None, names, urls, None, ())


def server_name(config: ServerConfig) -> str | None:
    """The name to show for a server (without the "mcp:" prefix), or None."""
    if config.text is not None:
        return config.text or None
    for name in config.names:
        if config.command is None or not _from_command_line(name, config.command, config.args):
            return name
    if config.command is not None:
        return command_basename(config.command)
    return server_url(config)


def node_id_text(name: str) -> str:
    """The mcp_server node id for a server name; any URL in it loses its credentials."""
    return MCP_PREFIX + redact_urls(name)


def server_url(config: ServerConfig) -> str | None:
    """The first http(s) URL of the server, without credentials, query, or fragment."""
    candidates = (config.text,) if config.text is not None else config.urls
    for url in candidates:
        if url.lower().startswith(("http://", "https://")):
            return redact_url(url)
    return None


def command_basename(command: str) -> str | None:
    """The program name of a command (see program_name), or None when it has none."""
    return program_name(command) or None


def program_name(command: str) -> str:
    """The program name of a command, without its directory and without a .exe-like suffix.

    This is the one place that decides which part of a command may be shown. An argument
    must never be shown, because it may hold a token. The command is launched as one
    program name (the arguments are a separate list), so a path with a space in it, such
    as C:/Program Files/nodejs/npx.cmd, is written without quotes and is a valid command.

    The program is the last path part of the whole text when all of these hold:
    - the text does not start with a quote;
    - it starts like a path (an optional drive letter, then "/" or a backslash);
    - no word after the first starts with "-" or "/" (the first word is exempt, because
      a path such as /opt/my tools/server.exe starts with "/");
    - it contains no "=", and no whitespace other than a plain space;
    - no word after the first contains ":" (this drops a drive-letter argument);
    - its last path part has no space and ends with .exe, .cmd, or .bat (not .com, because
      an email address or a domain is a more likely shape for a secret than a .com program).
    Otherwise the program is the first word (or the quoted part when the text starts with
    a quote). Whether the file exists is never checked, so a label is the same on every
    machine. A URL gives "". The result is "" only when the command has no program.
    """
    text = command.strip()
    executable, _ = split_command(text)
    if text[:1] not in ("'", '"') and _is_spaced_path(text):
        executable = text
    if "://" in executable:
        return ""
    name = _PATH_SEPARATORS.split(executable.rstrip("/" + chr(92)))[-1].strip() or executable
    stem, dot, suffix = name.rpartition(".")
    if dot and stem and f".{suffix.lower()}" in EXECUTABLE_SUFFIXES:
        return stem
    return name


def _is_spaced_path(text: str) -> bool:
    """True when the whole text is one executable path that has a space in it."""
    if not _PATH_START.match(text) or "=" in text or _OTHER_WHITESPACE.search(text):
        return False
    if any(word[:1] in ("-", "/") or ":" in word for word in text.split()[1:]):
        return False
    last = _PATH_SEPARATORS.split(text)[-1]
    return " " not in last and last.lower().endswith(SPACED_PATH_SUFFIXES)


def split_command(command: str) -> tuple[str, list[str]]:
    """Split a command string into (the first word, the words after it).

    The first word is the quoted part when the command starts with a quote. Words are
    never joined, so an argument (a relative path, a URL) can never become part of the
    first word. This is plain splitting for naming and for spotting arguments written into
    a command string; it is not how a server is launched (the command is launched as one
    program name, with no splitting). program_name decides the program that is shown.
    """
    text = command.strip()
    if text[:1] in ("'", '"'):
        close = text.find(text[0], 1)
        if close == -1:
            return text[1:], []
        return text[1:close], text[close + 1 :].split()
    words = text.split()
    return (words[0], words[1:]) if words else ("", [])


def _from_command_line(name: str, command: str, args: tuple[str, ...] | None) -> bool:
    """True when a server name may have been built from its command line.

    A known framework default always counts, and so does any name when an argument could
    not be read. Otherwise the name counts as built from the command line when it shares a
    word with the executable and with an argument, or with two different arguments. A name
    the user chose usually shares neither (for example "github" for
    "npx -y @modelcontextprotocol/server-github" shares only one argument). Arguments
    written into the command string after the executable count as arguments too.
    """
    if args is None or name.lower().startswith(_COMMAND_LINE_DEFAULTS) or name == "MCPTools":
        return True
    executable, inline = split_command(command)
    if _is_spaced_path(command.strip()):
        executable, inline = program_name(command), []
    words = _words(name)
    hits = sum(1 for arg in (*args, *inline) if _shares_word(words, _words(arg)))
    executable_words = _words(executable) | _words(command_basename(command) or "")
    return hits >= 2 or (hits == 1 and _shares_word(words, executable_words))


def _words(text: str) -> set[str]:
    return {word for word in re.findall(r"[^\W_]+", text.lower()) if len(word) >= 2}


def _shares_word(first: set[str], second: set[str]) -> bool:
    """Equal words, or one inside the other when both have 3 or more characters.

    The second rule catches a word that a framework cut short (Agno cuts names at 64).
    """
    return any(
        a == b or (len(a) >= 3 and len(b) >= 3 and (a in b or b in a))
        for a in first
        for b in second
    )


def _texts(values: Sequence[object]) -> tuple[str, ...] | None:
    """The values as text, or None when one of them cannot be turned into text."""
    texts: list[str] = []
    for value in values:
        if isinstance(value, str):
            texts.append(value)
            continue
        try:
            texts.append(str(value))  # for example a pathlib.Path
        except Exception:
            return None
    return tuple(texts)


def _field(holder: object, name: str) -> object:
    """holder[name] for a mapping, else holder.name."""
    if isinstance(holder, Mapping):
        return holder.get(name)
    return None if holder is None else getattr(holder, name, None)
