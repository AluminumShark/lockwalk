"""Network guard for the fake-framework tests: any non-loopback attempt fails the test."""

import socket
from typing import Any

import pytest

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail on any connect or lookup that is not loopback.

    asyncio's self-pipe on Windows connects a socket pair over 127.0.0.1, so loopback passes.
    """
    real_connect = socket.socket.connect
    real_getaddrinfo = socket.getaddrinfo

    def connect(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in LOOPBACK:
            raise AssertionError(f"network attempt: connect {host!r}")
        real_connect(self, address)

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host not in LOOPBACK:
            raise AssertionError(f"network attempt: lookup {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
