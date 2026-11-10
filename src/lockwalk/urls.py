"""URL helpers with no lockwalk imports. Messages never include the URL itself."""

import re
import string
from urllib.parse import urlsplit, urlunsplit

INVALID_URL = "<invalid URL>"

# The characters of a URL scheme (RFC 3986): a letter, then letters, digits, "+", ".", "-".
_SCHEME_START = frozenset(string.ascii_letters)
_SCHEME_CHARACTERS = frozenset(string.ascii_letters + string.digits + "+.-")
# A URL inside a longer text ends only at whitespace (what str.isspace accepts). A quote
# does not end it: RFC 3986 allows "'" in the user name and password.
_URL_END = re.compile(r"\s")
# Punctuation that often follows a URL in prose or in a repr(); only a trailing run of it
# is kept out of the URL.
_TRAILING_PUNCTUATION = "'\")]>,;"


def check_http_url(value: str, what: str) -> str:
    """Accept only http(s) URLs with a real hostname and no whitespace or control characters.

    urlsplit can raise ValueError messages that quote the host part, which may hold
    credentials. That error is swallowed here, and no message ever contains the value.
    """
    message = f"{what} must look like http(s)://host[:port]/path"
    if any(char.isspace() or not char.isprintable() for char in value):
        raise ValueError(message)
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        parts.port  # noqa: B018 - reading it validates the port
    except ValueError:
        raise ValueError(message) from None
    if parts.scheme not in ("http", "https") or not hostname:
        raise ValueError(message)
    if "@" in parts.path + parts.query + parts.fragment:
        raise ValueError(
            f"{what} has '@' after the host part: percent-encode '/', '?' and '#' in a user "
            "name or password (as %2F, %3F, %23), and write an '@' that belongs to the path, "
            "query, or fragment as %40"
        )
    return value


def redact_url(url: str) -> str:
    """Drop userinfo, query, and fragment, so credentials never reach labels or reports."""
    try:
        parts = urlsplit(url)
        # A "/", "?" or "#" ends the netloc early, so credentials can hide after it.
        if "@" in parts.path + parts.query + parts.fragment:
            return INVALID_URL
        parts.port  # noqa: B018 - a bad "port" may really be a password
        host = parts.netloc.rpartition("@")[2]
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except ValueError:
        # urlsplit messages can quote the netloc, credentials included.
        return INVALID_URL


def redact_urls(text: str) -> str:
    """Apply redact_url to every URL inside a longer text; the rest is left as it is.

    For example an exception message, or the OpenAI Agents SDK default MCP server name
    "streamable_http: https://user:pass@host/mcp?token=...". A URL is a scheme, "://", and
    everything up to the next whitespace. Only a trailing run of quotes, closing brackets,
    commas, and semicolons is kept out of it (and put back after it); a quote inside the
    URL never splits it, so "https://user:it's-secret@host" is redacted whole. The text is
    never cut first, since a cut could split a "user:pass@" and leave part of it. The scan
    is linear: each "://" is found with str.find, and no character is looked at more than a
    few times.

    Known limit: a non-breaking space (or other Unicode whitespace) inside a password ends
    the URL there, so the rest of the password stays visible, as it did before.
    """
    pieces: list[str] = []
    done = 0  # text[:done] is already in pieces
    floor = 0  # no scheme starts before this: it is the end of the last "://" or URL
    while (mark := text.find("://", floor)) != -1:
        start = mark
        while start > floor and text[start - 1] in _SCHEME_CHARACTERS:
            start -= 1
        while start < mark and text[start] not in _SCHEME_START:
            start += 1  # a scheme starts with a letter, as in "9https://..."
        if start == mark:  # "://" with no scheme in front of it
            floor = mark + 3
            continue
        found = _URL_END.search(text, mark + 3)
        end = found.start() if found is not None else len(text)
        token = text[start:end]
        url = token.rstrip(_TRAILING_PUNCTUATION)
        pieces.append(text[done:start])
        pieces.append(redact_url(url))
        pieces.append(token[len(url) :])
        done = floor = end
    pieces.append(text[done:])
    return "".join(pieces)
