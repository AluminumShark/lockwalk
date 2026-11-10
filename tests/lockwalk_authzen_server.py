"""A fake AuthZEN PDP for tests: an HTTP server on 127.0.0.1 that the test controls.

pyproject.toml puts tests/ on sys.path, so test modules import this module by name.
"""

import json
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Any, Self

CRLF = bytes([13, 10])

# (path, parsed body or None, headers with lower-case names) -> (status, body, delay in seconds)
# A bytes body is sent as it is, a dict as JSON, and an iterator of bytes as a chunked body.
Responder = Callable[
    [str, Any, dict[str, str]], tuple[int, "bytes | dict[str, Any] | Iterator[bytes]", float]
]


def _no_content(path: str, body: Any, headers: dict[str, str]) -> tuple[int, bytes, float]:
    return 204, b"", 0.0


class FakePdp:
    """Runs a ThreadingHTTPServer on 127.0.0.1 in a daemon thread, as a context manager."""

    def __init__(self, respond: Responder | None = None) -> None:
        self.respond: Responder = respond or _no_content
        self.requests: list[tuple[str, Any, dict[str, str]]] = []
        # Sent with every response, for example a Location header.
        self.response_headers: dict[str, str] = {}
        pdp = self

        class Handler(BaseHTTPRequestHandler):
            wbufsize = 65536  # headers and body leave in one packet

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
                headers = {key.lower(): value for key, value in self.headers.items()}
                pdp.requests.append((self.path, body, headers))
                status, payload, delay = pdp.respond(self.path, body, headers)
                if delay:
                    time.sleep(delay)
                try:
                    if isinstance(payload, Iterator):
                        self._send_chunked(status, payload)
                    else:
                        self._send_whole(status, payload)
                except OSError:
                    pass  # the client gave up (a timeout test)

            def _send_whole(self, status: int, payload: bytes | dict[str, Any]) -> None:
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                if not isinstance(payload, bytes):
                    self.send_header("Content-Type", "application/json")
                for name, value in pdp.response_headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _send_chunked(self, status: int, chunks: Iterator[bytes]) -> None:
                self.send_response(status)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for chunk in chunks:
                    self.wfile.write(f"{len(chunk):x}".encode() + CRLF + chunk + CRLF)
                    self.wfile.flush()
                self.wfile.write(b"0" + CRLF + CRLF)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
