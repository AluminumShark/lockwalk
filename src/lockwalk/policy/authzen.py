"""The AuthZEN adapter: asks a PDP over HTTP.

Standard library only. The adapter fails closed: anything other than a clean JSON boolean
`decision` is an ERROR answer. Redirects are never followed, response bodies never appear in
an answer, and every message is scrubbed of header values and URL credentials.

Each request has one total deadline of `timeout` seconds, retry included, covering connect,
send, and reading the body. All answers of one request share its latency. Known limits: the
deadline does not cover the DNS lookup, nor a server that drips its header lines one by one.
http.client does not use HTTP_PROXY or HTTPS_PROXY, so a PDP behind a proxy is not reachable.
"""

import http.client
import json
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

from lockwalk import __version__
from lockwalk.config import PolicyConfig
from lockwalk.errors import StructuralError
from lockwalk.inventory.base import truncate
from lockwalk.inventory.normalize import describe_error
from lockwalk.masking import SecretValues, SetupError, expand_value, header_value_problem
from lockwalk.models import Verdict
from lockwalk.policy.base import REASON_KEYS, Decision, Query, error_decision
from lockwalk.urls import redact_urls

# The most a PDP answer may hold, read in chunks.
MAX_BODY_BYTES = 10 * 1024 * 1024
_CHUNK = 64 * 1024
_RETRY_STATUSES = (502, 503, 504)
_NO_BATCH_STATUSES = (404, 405)
_BATCH_PATH = "/access/v1/evaluations"
_SINGLE_PATH = "/access/v1/evaluation"
# Characters kept as they are when the configured path and query are percent-encoded, so
# input that is already encoded stays as it is.
_PATH_SAFE = "/:@!$&'()*+,;=-._~%"
_QUERY_SAFE = _PATH_SAFE + "?"
_SKIPPED = "skipped: the PDP timed out on an earlier question"
_PDP_ERROR = "the PDP reported an error for this question"


class _Failure(Exception):
    """A request that produced no usable answer. The message is not yet scrubbed."""

    def __init__(
        self, message: str, latency_ms: float | None = None, *, timed_out: bool = False
    ) -> None:
        super().__init__(message)
        self.message = message
        self.timed_out = timed_out
        self.latency_ms = latency_ms


@dataclass(frozen=True)
class _Reply:
    status: int
    body: bytes
    latency_ms: float


class AuthZenAdapter:
    def __init__(self, config: PolicyConfig) -> None:
        assert config.url is not None  # PolicyConfig guarantees it for adapter 'authzen'
        self._config = config
        self._timeout = config.timeout
        self._secrets, headers = self._prepare_headers(config)
        parts = urlsplit(config.url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or ""
        self._port = parts.port
        self._base = quote(parts.path.rstrip("/"), safe=_PATH_SAFE)
        query = quote(parts.query, safe=_QUERY_SAFE)
        self._query = f"?{query}" if query else ""
        self._context = ssl.create_default_context() if self._https else None
        defaults = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"lockwalk/{__version__}",
            "Connection": "close",
        }
        configured = {key.lower() for key in headers}
        self._headers = {k: v for k, v in defaults.items() if k.lower() not in configured}
        self._headers.update(headers)
        self._single_only = False
        self._notes: list[str] = []

    @staticmethod
    def _prepare_headers(config: PolicyConfig) -> tuple[SecretValues, dict[str, str]]:
        """Expand header values. Errors name the variable or the key, never a value."""
        values: list[tuple[str, str]] = []
        headers: dict[str, str] = {}
        # Header names were validated by config.check_headers.
        try:
            for key, template in config.headers.items():
                pieces: list[str] = []
                headers[key] = expand_value(template, pieces)
                what = f"header {key!r}"
                values.extend((what, text) for text in (headers[key], *pieces))
        except SetupError as exc:
            raise StructuralError("[policy]", [str(exc)]) from None
        for key, value in headers.items():
            problem = header_value_problem(key, value, template=False)
            if problem is not None:
                raise StructuralError("[policy]", [problem])
        return SecretValues(values), headers

    @property
    def label(self) -> str:
        return self._config.label

    @property
    def batch_size(self) -> int:
        return self._config.batch_size

    def notes(self) -> tuple[str, ...]:
        return tuple(self._notes)

    def close(self) -> None:
        """Nothing to do: every request uses its own connection."""

    def decide(self, queries: Sequence[Query]) -> list[Decision]:
        """Ask every question; the answers come back in the order of the questions.

        In batch mode the questions are first split into sub-batches in which each subject id
        belongs to one subject only (the same id with other properties, for example with an
        `act` chain, goes to another sub-batch). Cerbos 0.57 groups the items of a batch by
        subject id and uses the first item's principal for the whole group, so it would
        answer the later items with the wrong identity. Each sub-batch is one request with its
        own deadline, retry, and fallback, so a split chunk costs one request per sub-batch
        (max_queries still counts questions). After the first timeout, every remaining
        request of this call is skipped.
        """
        decisions: list[Decision | None] = [None] * len(queries)
        timed_out = False
        for positions in self._sub_batches(queries):
            found, timed_out = self._ask_group([queries[i] for i in positions], timed_out)
            for position, decision in zip(positions, found, strict=True):
                decisions[position] = decision
        result: list[Decision] = []
        for decision in decisions:
            assert decision is not None, "every question gets an answer"
            result.append(decision)
        return result

    @staticmethod
    def _sub_batches(queries: Sequence[Query]) -> list[list[int]]:
        """Positions of the questions in sub-batches with one subject per subject id.

        The k-th distinct form of a subject id goes to sub-batch k, and an equal form goes
        to the same sub-batch again. This is first-fit in question order, in linear time.
        """
        batches: list[list[int]] = []
        forms: dict[str, dict[str, int]] = {}
        for position, query in enumerate(queries):
            subject = query.subject
            key = json.dumps(subject.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
            known = forms.setdefault(subject.id, {})
            index = known.setdefault(key, len(known))
            if index == len(batches):
                batches.append([])
            batches[index].append(position)
        return batches

    def _ask_group(self, queries: Sequence[Query], timed_out: bool) -> tuple[list[Decision], bool]:
        """The answers for one sub-batch, and whether the call has timed out by now.

        One batch request when the PDP has a batch endpoint, otherwise one question at a time.
        Once timed_out is set, nothing is sent: a hanging PDP would otherwise cost one full
        timeout per request.
        """
        if timed_out:
            return [self._error(_SKIPPED, None) for _ in queries], True
        if not self._single_only:
            found, timed_out = self._ask_batch(queries)
            if found is not None:
                return found, timed_out
        decisions: list[Decision] = []
        for query in queries:
            if timed_out:
                decisions.append(self._error(_SKIPPED, None))
                continue
            decision, timed_out = self._ask_one(query)
            decisions.append(decision)
        return decisions, timed_out

    def _ask_batch(self, queries: Sequence[Query]) -> tuple[list[Decision] | None, bool]:
        """The answers of one batch request and whether it timed out.

        The answers are None when the PDP has no batch endpoint.
        """
        try:
            reply = self._post(_BATCH_PATH, {"evaluations": [q.to_authzen() for q in queries]})
        except _Failure as failure:
            return self._all_error(len(queries), failure), failure.timed_out
        if reply.status in _NO_BATCH_STATUSES:
            self._single_only = True
            self._notes.append(
                f"the PDP has no AuthZEN batch endpoint (HTTP {reply.status}); "
                "asked one question at a time"
            )
            return None, False
        return self._batch_decisions(reply, len(queries)), False

    def _ask_one(self, query: Query) -> tuple[Decision, bool]:
        """The answer to one question, and whether the request timed out."""
        try:
            reply = self._post(_SINGLE_PATH, query.to_authzen())
        except _Failure as failure:
            return self._error(failure.message, failure.latency_ms), failure.timed_out
        return self._single_decision(reply), False

    def _single_decision(self, reply: _Reply) -> Decision:
        parsed = self._parse_reply(reply)
        if isinstance(parsed, str):
            return self._error(parsed, reply.latency_ms)
        return self._answer(parsed, reply.latency_ms)

    def _batch_decisions(self, reply: _Reply, count: int) -> list[Decision]:
        parsed = self._parse_reply(reply)
        if isinstance(parsed, str):
            return [self._error(parsed, reply.latency_ms) for _ in range(count)]
        items = parsed.get("evaluations") if isinstance(parsed, dict) else None
        if not isinstance(items, list) or len(items) != count:
            got = len(items) if isinstance(items, list) else 0
            message = f"the PDP answered {got} evaluations for {count} questions"
            return [self._error(message, reply.latency_ms) for _ in range(count)]
        return [self._answer(item, reply.latency_ms) for item in items]

    def _parse_reply(self, reply: _Reply) -> Any:
        """The decoded JSON body, or an error message (a str) when there is no usable one."""
        if not 200 <= reply.status < 300:
            return f"the PDP answered HTTP {reply.status}"
        try:
            return json.loads(reply.body)
        except (ValueError, RecursionError):
            return "the PDP answer is not JSON"

    def _answer(self, answer: Any, latency_ms: float) -> Decision:
        """One answer object to a Decision; anything but a boolean decision is an error."""
        if not isinstance(answer, dict) or type(answer.get("decision")) is not bool:
            return self._error("the PDP answer has no boolean 'decision'", latency_ms)
        context = answer.get("context")
        if isinstance(context, dict) and context.get("error") is not None:
            # AuthZEN 1.0: a PDP reports an evaluation it could not perform as a false
            # decision with context.error. That is not a deny. Its content is never copied.
            return self._error(_PDP_ERROR, latency_ms)
        verdict = Verdict.ALLOW if answer["decision"] else Verdict.DENY
        return Decision(verdict=verdict, reason=self._reason(answer), latency_ms=latency_ms)

    def _reason(self, answer: dict[str, Any]) -> str | None:
        context = answer.get("context")
        if not isinstance(context, dict):
            return None
        for key in REASON_KEYS:
            value = context.get(key)
            if isinstance(value, str) and value.strip():
                cleaned = self._clean(value)
                if cleaned:
                    return cleaned
        return None

    def _clean(self, text: str) -> str:
        return truncate(redact_urls(self._secrets.scrub(text)))

    def _error(self, message: str, latency_ms: float | None) -> Decision:
        return error_decision(
            self._clean(message) or "the PDP answer could not be used", latency_ms=latency_ms
        )

    def _all_error(self, count: int, failure: _Failure) -> list[Decision]:
        return [self._error(failure.message, failure.latency_ms) for _ in range(count)]

    def _post(self, path: str, payload: Any) -> _Reply:
        """POST with one retry. Both attempts share one deadline of `timeout` seconds."""
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        target = f"{self._base}{path}{self._query}"
        started = time.perf_counter()
        deadline = time.monotonic() + self._timeout
        for attempt in (0, 1):
            try:
                status, body = self._once(target, data, deadline)
            except _Failure as failure:
                raise _Failure(
                    failure.message, self._elapsed(started), timed_out=failure.timed_out
                ) from None
            except OSError as exc:
                if attempt == 0 and self._is_retryable(exc):
                    continue
                message = f"cannot connect to the PDP: {describe_error(exc)}"
                raise _Failure(message, self._elapsed(started)) from None
            except ValueError:
                # UnicodeError (a host such as 'a..b') is a ValueError. Its text may quote the
                # input, so only a fixed message is shown. A bad URL is not retried.
                raise _Failure("the PDP URL cannot be used", self._elapsed(started)) from None
            except http.client.HTTPException:
                message = "the PDP answer is not valid HTTP"
                raise _Failure(message, self._elapsed(started)) from None
            if attempt == 0 and self._is_retryable(status):
                continue
            return _Reply(status, body, self._elapsed(started))
        raise AssertionError("unreachable")  # pragma: no cover

    @staticmethod
    def _is_retryable(failure: OSError | int) -> bool:
        """Whether one more attempt may help.

        Yes for a connection that failed before any answer, and for HTTP 502/503/504. No for
        timeouts and TLS failures (a bad certificate is deterministic).

        A POST may be resent after a reset; evaluations have no side effects.
        """
        if isinstance(failure, int):
            return failure in _RETRY_STATUSES
        return not isinstance(failure, (TimeoutError, ssl.SSLError))

    @staticmethod
    def _elapsed(started: float) -> float:
        return round(max(0.0, (time.perf_counter() - started) * 1000), 1)

    def _connect(
        self, left: Callable[[], float]
    ) -> tuple[http.client.HTTPConnection, socket.socket]:
        conn: http.client.HTTPConnection
        if self._context is not None:
            conn = http.client.HTTPSConnection(
                self._host, self._port, timeout=left(), context=self._context
            )
        else:
            conn = http.client.HTTPConnection(self._host, self._port, timeout=left())
        try:
            conn.connect()
            sock = conn.sock
            assert sock is not None
        except BaseException:
            conn.close()
            raise
        return conn, sock

    @staticmethod
    def _read_body(
        response: http.client.HTTPResponse, sock: socket.socket, left: Callable[[], float]
    ) -> bytes:
        chunks: list[bytes] = []
        size = 0
        # The response closes itself (and the socket) once its body is read.
        while not response.isclosed():
            sock.settimeout(left())
            chunk = response.read1(_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise _Failure("the PDP answer is larger than 10 MiB")
            chunks.append(chunk)
        return b"".join(chunks)

    def _once(self, target: str, data: bytes, deadline: float) -> tuple[int, bytes]:
        """One request on a new connection, before the deadline (a time.monotonic value).

        Raises _Failure on a timeout or an oversized body; other socket errors propagate.
        A non-2xx answer is returned with an empty body: its body is never read.
        """
        timed_out = _Failure(f"timed out after {self._timeout:g}s", timed_out=True)

        def left() -> float:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise timed_out
            return remaining

        conn: http.client.HTTPConnection | None = None
        try:
            conn, sock = self._connect(left)
            sock.settimeout(left())
            conn.request("POST", target, body=data, headers=self._headers)
            sock.settimeout(left())
            response = conn.getresponse()
            if not 200 <= response.status < 300:
                return response.status, b""
            return response.status, self._read_body(response, sock, left)
        except TimeoutError:
            raise timed_out from None
        finally:
            if conn is not None:
                conn.close()
