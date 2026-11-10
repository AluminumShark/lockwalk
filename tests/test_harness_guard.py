"""Guard checks run in a child process: the patches are never undone."""

import json
import subprocess
import sys
import textwrap

import pytest

from lockwalk.harness import guard

PRELUDE = """
import json, socket, sys, asyncio, threading, time
from lockwalk.harness import guard
shield = guard.install(ALLOW)
out = {}

def attempt(fn):
    try:
        fn()
    except guard.BlockedConnection as exc:
        return "blocked: " + str(exc)
    except BaseException as exc:
        return "other: " + type(exc).__name__
    return "passed"
"""


def run_child(body: str, allow: list[str] | None = None) -> dict:
    code = "ALLOW = " + repr(allow or []) + "\n" + PRELUDE + textwrap.dedent(body)
    code += "\nprint(json.dumps(out))\n"
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=False
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_blocked_entry_points_and_a_single_blocked_entry() -> None:
    out = run_child(
        """
        def conn():
            socket.socket().connect(("203.0.113.1", 80))
        out["connect"] = attempt(conn)
        out["connect_again"] = attempt(conn)
        out["connect_ex"] = attempt(lambda: socket.socket().connect_ex(("203.0.113.1", 80)))
        out["create"] = attempt(lambda: socket.create_connection(("203.0.113.1", 80), 1))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out["sendto"] = attempt(lambda: udp.sendto(b"x", ("203.0.113.1", 9)))
        out["gai"] = attempt(lambda: socket.getaddrinfo("blocked.invalid", 80))
        out["gethostbyname"] = attempt(lambda: socket.gethostbyname("blocked.invalid"))
        out["gethostbyname_ex"] = attempt(lambda: socket.gethostbyname_ex("blocked.invalid"))
        out["mapped"] = attempt(
            lambda: socket.socket(socket.AF_INET6).connect(("::ffff:203.0.113.1", 80, 0, 0))
        )
        out["blocked"] = shield.blocked
        """
    )
    for key in ("connect", "connect_again", "connect_ex", "create", "sendto", "gai"):
        assert out[key].startswith("blocked: lockwalk blocked a connection to "), key
    assert out["gethostbyname"].startswith("blocked: ")
    assert out["gethostbyname_ex"].startswith("blocked: ")
    assert out["mapped"].startswith("blocked: ")
    assert (
        "door tests only allow localhost, the [policy] host, and [harness] allow_hosts"
        in (out["connect"])
    )
    # the host once, no port, no mapped prefix collapse (the guard shows the host as given)
    assert out["blocked"] == ["203.0.113.1", "blocked.invalid", "::ffff:203.0.113.1"]


def test_a_zone_suffix_on_an_ipv4_address_is_a_host_name() -> None:
    out = run_child(
        """
        host = "127.0.0.1%x.evil.invalid"
        out["gai"] = attempt(lambda: socket.getaddrinfo(host, 80))
        out["ghbn"] = attempt(lambda: socket.gethostbyname(host))
        out["connect"] = attempt(lambda: socket.socket().connect((host, 80)))
        """
    )
    for key in ("gai", "ghbn", "connect"):
        assert out[key].startswith("blocked: "), key


def test_hosts_the_guard_cannot_read_are_refused() -> None:
    out = run_child(
        """
        bad = bytes([255, 254]) + b".invalid"
        out["gai_bytes"] = attempt(lambda: socket.getaddrinfo(bad, 80))
        out["ghbn_bytes"] = attempt(lambda: socket.gethostbyname(bad))
        out["gai_array"] = attempt(lambda: socket.getaddrinfo(bytearray(b"a.invalid"), 80))
        out["gai_int"] = attempt(lambda: socket.getaddrinfo(5, 80))
        out["gai_none"] = attempt(lambda: socket.getaddrinfo(None, 80))
        """
    )
    for key in ("gai_bytes", "ghbn_bytes", "gai_array", "gai_int"):
        assert out[key].startswith("blocked: "), key
    assert out["gai_none"] == "passed"


def test_sendmsg_with_an_address_is_checked() -> None:
    out = run_child(
        """
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(udp, "sendmsg"):
            out["sendmsg"] = attempt(lambda: udp.sendmsg([b"x"], [], 0, ("203.0.113.1", 9)))
            out["kw"] = attempt(lambda: udp.sendmsg([b"x"], address=("203.0.113.1", 9)))
        else:
            out["sendmsg"] = out["kw"] = "blocked: not available"
        """
    )
    assert out["sendmsg"].startswith("blocked: ") and out["kw"].startswith("blocked: ")


def test_blocked_hosts_hide_credentials_and_control_characters() -> None:
    out = run_child(
        """
        msgs = [
            attempt(lambda: socket.getaddrinfo("user:pass@evil.invalid", 80)),
            attempt(lambda: socket.getaddrinfo("bad" + chr(10) + "host.invalid", 80)),
            attempt(lambda: socket.getaddrinfo("caf" + chr(233) + chr(8364) + ".invalid", 80)),
            attempt(lambda: socket.getaddrinfo("h" * 500 + ".invalid", 80)),
        ]
        out["msgs"] = msgs
        out["blocked"] = shield.blocked
        """
    )
    bs = chr(92)
    assert out["blocked"][0] == "evil.invalid"
    assert out["blocked"][1] == f"bad{bs}x0ahost.invalid"
    assert out["blocked"][2] == f"caf{bs}xe9{bs}u20ac.invalid"
    assert len(out["blocked"][3]) == 200
    assert "pass" not in out["msgs"][0]
    assert all(ord(c) < 127 and c.isprintable() for m in out["msgs"] for c in m)


def test_a_zone_is_accepted_only_on_ipv6() -> None:
    assert guard.parse_ip("127.0.0.1%x.evil.invalid") is None
    assert guard.parse_ip("127.0.0.1%1") is None
    assert guard.parse_ip("fe80::1%") is None
    assert guard.parse_ip("::1%lo") is not None


def test_blocked_list_is_capped_at_twenty() -> None:
    out = run_child(
        """
        for n in range(30):
            attempt(lambda n=n: socket.getaddrinfo(f"h{n}.invalid", 80))
        out["count"] = len(shield.blocked)
        out["first"] = shield.blocked[0]
        """
    )
    assert out == {"count": 20, "first": "h0.invalid"}


def test_asyncio_connections_are_blocked_quickly() -> None:
    out = run_child(
        """
        async def go():
            return await asyncio.wait_for(asyncio.open_connection("203.0.113.1", 80), 1)

        def under(loop_factory):
            loop = loop_factory()
            start = time.monotonic()
            try:
                result = attempt(lambda: loop.run_until_complete(go()))
            finally:
                loop.close()
            return [result, time.monotonic() - start < 1.0]

        out["selector"] = under(asyncio.SelectorEventLoop)
        if sys.platform == "win32":
            out["proactor"] = under(asyncio.ProactorEventLoop)
        out["default"] = [attempt(lambda: asyncio.run(go())), True]
        """
    )
    for key, (result, quick) in out.items():
        assert result.startswith("blocked: "), (key, result)
        assert quick, key


def test_loopback_and_localhost_stay_reachable() -> None:
    out = run_child(
        """
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        port = server.getsockname()[1]

        def serve():
            while True:
                conn, _ = server.accept()
                conn.sendall(b"hello")
                conn.close()

        threading.Thread(target=serve, daemon=True).start()

        def plain():
            with socket.create_connection(("127.0.0.1", port), 5) as c:
                return c.recv(5)

        out["plain"] = plain().decode()
        out["localhost"] = socket.create_connection(("localhost", port), 5).recv(5).decode()
        out["connect_ex"] = socket.socket().connect_ex(("127.0.0.1", port))

        async def aio():
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            data = await reader.read(5)
            writer.close()
            return data.decode()

        out["asyncio"] = asyncio.run(aio())
        out["blocked"] = shield.blocked
        """
    )
    assert out["plain"] == "hello" and out["localhost"] == "hello" and out["asyncio"] == "hello"
    assert out["connect_ex"] == 0
    assert out["blocked"] == []


def test_an_allowed_name_may_be_resolved() -> None:
    out = run_child(
        """
        out["allowed"] = attempt(lambda: socket.getaddrinfo("localhost", 80))
        out["other"] = attempt(lambda: socket.getaddrinfo("elsewhere.invalid", 80))
        """,
        allow=["Allowed.Example"],
    )
    assert out["allowed"] == "passed"
    assert out["other"].startswith("blocked: ")


def A(text: str) -> guard.IPAddress:
    ip = guard.parse_ip(text)
    assert ip is not None
    return ip


def test_addresses_are_compared_as_ip_objects() -> None:
    names = {"localhost"}
    ips = {A("2001:db8::1"), A("198.51.100.7")}
    ok = [
        "127.0.0.1",
        "127.9.9.9",
        "::1",
        "0:0:0:0:0:0:0:1",
        "::ffff:127.0.0.1",
        "LOCALHOST",
        "198.51.100.7",
        "::ffff:198.51.100.7",
        "2001:0DB8:0:0:0:0:0:1",
        "2001:db8::1%eth0",
        b"198.51.100.7",
    ]
    bad = [
        "198.51.100.8",
        "203.0.113.1",
        "::ffff:203.0.113.1",
        "2001:db8::2",
        "fe80::1%1",
        "not a host",
        "",
        "example.com",
        None,
        5,
    ]
    for host in ok:
        assert guard.permits(host, names, ips), host
    for host in bad:
        assert not guard.permits(host, names, ips), host


@pytest.mark.parametrize("name", ["localhost", "policy.example"])
def test_names_are_matched_in_lower_case(name: str) -> None:
    assert guard.permits(name.upper(), {"localhost", "policy.example"}, set())
