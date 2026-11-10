"""The Python-level network guard of the harness subprocess.

install() patches the process for good (nothing is undone: the worker process is thrown
away after one job). Only localhost, every loopback address, the allowed hosts, and
the addresses an allowed name resolved to may be connected to. Code that calls the C
socket type directly (_socket) is out of reach; the guard is a safety net, not a sandbox.

Known gaps: reverse lookups (gethostbyaddr, getnameinfo), uvloop, unconnected UDP on the
Windows Proactor loop, C extensions that open sockets themselves, and other processes.
"""

import asyncio
import asyncio.selector_events
import ipaddress
import socket
import threading
from collections.abc import Sequence
from typing import Any

MAX_BLOCKED = 20
MAX_HOST_CHARS = 200

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class BlockedConnection(ConnectionRefusedError):
    """Raised instead of connecting to a host the guard does not allow."""


class Guard:
    def __init__(self) -> None:
        self.blocked: list[str] = []  # hosts or addresses refused, first-seen order, capped


def parse_ip(text: str) -> IPAddress | None:
    """An address as an ipaddress object: zone dropped, IPv4-mapped IPv6 as IPv4."""
    head, sep, zone = text.partition("%")
    try:
        ip = ipaddress.ip_address(head)
    except ValueError:
        return None
    if sep and (not zone or not isinstance(ip, ipaddress.IPv6Address)):
        return None  # "127.0.0.1%x.evil.invalid" is a host name to the resolver
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def host_text(host: object) -> str | None:
    if isinstance(host, bytes):
        try:
            return host.decode("ascii").strip().lower()
        except UnicodeDecodeError:
            return None
    if isinstance(host, str):
        return host.strip().lower()
    return None


def clean_host(host: object) -> str:
    """A host fit to record and print: no credentials, no control or non-ASCII characters."""
    text = host_text(host)
    if text is None:
        return type(host).__name__
    text = text.rsplit("@", 1)[-1]
    out: list[str] = []
    for char in text:
        code = ord(char)
        if 32 <= code < 127:
            out.append(char)
        elif code < 256:
            out.append(f"{chr(92)}x{code:02x}")
        else:
            out.append(f"{chr(92)}u{code:04x}")
    return "".join(out)[:MAX_HOST_CHARS]


def permits(host: object, names: set[str], ips: set[IPAddress]) -> bool:
    """Whether a connection to `host` (a name or an address) is allowed."""
    text = host_text(host)
    if text is None:
        return False
    ip = parse_ip(text)
    if ip is not None:
        return ip.is_loopback or ip in ips
    return text in names


def install(allow_hosts: Sequence[str]) -> Guard:
    shield = Guard()
    lock = threading.Lock()
    names: set[str] = {"localhost"}
    ips: set[IPAddress] = set()
    for entry in allow_hosts:
        text = host_text(entry)
        if not text:
            continue
        ip = parse_ip(text)
        if ip is None:
            names.add(text)
        else:
            ips.add(ip)

    def refuse(host: object) -> BlockedConnection:
        shown = clean_host(host)
        with lock:
            if shown not in shield.blocked and len(shield.blocked) < MAX_BLOCKED:
                shield.blocked.append(shown)
        return BlockedConnection(
            f"lockwalk blocked a connection to {shown}: door tests only allow localhost, "
            "the [policy] host, and [harness] allow_hosts"
        )

    def check_peer(address: object, family: object = None) -> None:
        """Raise for an AF_INET/AF_INET6 tuple address whose host is not allowed."""
        if isinstance(address, (str, bytes)) or not isinstance(address, tuple) or not address:
            return  # AF_UNIX and other families
        if family is not None and family not in (socket.AF_INET, socket.AF_INET6):
            return
        if not permits(address[0], names, ips):
            raise refuse(address[0])

    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is None:
            return real_getaddrinfo(host, *args, **kwargs)
        text = host_text(host)
        if text is None:
            raise refuse(host)
        if parse_ip(text) is None:
            if text not in names:
                raise refuse(host)
            found = real_getaddrinfo(host, *args, **kwargs)
            for item in found:
                ip = parse_ip(str(item[4][0]))
                if ip is not None:
                    ips.add(ip)
            return found
        return real_getaddrinfo(host, *args, **kwargs)

    def name_only(original: Any) -> Any:
        def guarded(host: Any, *args: Any, **kwargs: Any) -> Any:
            if host is not None:
                text = host_text(host)
                if text is None or (parse_ip(text) is None and text not in names):
                    raise refuse(host)
            return original(host, *args, **kwargs)

        return guarded

    setattr(socket, "getaddrinfo", getaddrinfo)  # noqa: B010
    setattr(socket, "gethostbyname", name_only(socket.gethostbyname))  # noqa: B010
    setattr(socket, "gethostbyname_ex", name_only(socket.gethostbyname_ex))  # noqa: B010

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_create_connection = socket.create_connection

    def connect(self: socket.socket, address: Any) -> Any:
        check_peer(address, self.family)
        return real_connect(self, address)

    def connect_ex(self: socket.socket, address: Any) -> Any:
        check_peer(address, self.family)
        return real_connect_ex(self, address)

    def sendto(self: socket.socket, *args: Any) -> Any:
        if args:
            check_peer(args[-1], self.family)
        return real_sendto(self, *args)

    real_sendmsg = getattr(socket.socket, "sendmsg", None)  # not on Windows

    def sendmsg(self: socket.socket, *args: Any, **kwargs: Any) -> Any:
        address = args[3] if len(args) > 3 else kwargs.get("address")
        if address is not None:
            check_peer(address, self.family)
        assert real_sendmsg is not None
        return real_sendmsg(self, *args, **kwargs)

    def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        check_peer(address)
        return real_create_connection(address, *args, **kwargs)

    setattr(socket.socket, "connect", connect)  # noqa: B010
    setattr(socket.socket, "connect_ex", connect_ex)  # noqa: B010
    setattr(socket.socket, "sendto", sendto)  # noqa: B010
    if real_sendmsg is not None:
        setattr(socket.socket, "sendmsg", sendmsg)  # noqa: B010
    setattr(socket, "create_connection", create_connection)  # noqa: B010

    loops: list[Any] = [asyncio.selector_events.BaseSelectorEventLoop]
    proactor = getattr(asyncio, "ProactorEventLoop", None)  # Windows only
    if proactor is not None:
        loops.append(proactor)
    for loop_class in loops:
        original = loop_class.sock_connect

        def make(original: Any) -> Any:
            async def sock_connect(self: Any, sock: Any, address: Any) -> Any:
                check_peer(address, getattr(sock, "family", None))
                return await original(self, sock, address)

            return sock_connect

        loop_class.sock_connect = make(original)
    return shield
