"""The AuthZEN adapter against a fake PDP on 127.0.0.1."""

import random
import ssl
import time
from typing import Any

import pytest
from lockwalk_authzen_server import FakePdp, Responder
from lockwalk_net_helpers import free_port

from lockwalk.config import PolicyConfig
from lockwalk.errors import StructuralError
from lockwalk.models import Verdict
from lockwalk.policy import authzen
from lockwalk.policy.authzen import AuthZenAdapter
from lockwalk.policy.base import Decision, Query

TOKEN = "tok-abcdef123456"
BATCH = "/access/v1/evaluations"
SINGLE = "/access/v1/evaluation"


def make_query(n: int = 1) -> Query:
    return Query.model_validate(
        {
            "subject": {"type": "agent", "id": f"a{n}"},
            "action": {"name": "tool:call"},
            "resource": {"type": "tool", "id": f"t{n}"},
        }
    )


def make_adapter(url: str, **kwargs: Any) -> AuthZenAdapter:
    fields: dict[str, Any] = {
        "adapter": "authzen",
        "url": url,
        "headers": {"Authorization": "Bearer ${PDP_TOKEN}"},
    }
    fields.update(kwargs)
    return AuthZenAdapter(PolicyConfig.model_validate(fields))


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDP_TOKEN", TOKEN)


def batch_ok(*decisions: object) -> Responder:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        return 200, {"evaluations": [{"decision": d} for d in decisions]}, 0.0

    return respond


def fixed(status: int, payload: Any, delay: float = 0.0) -> Responder:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        return status, payload, delay

    return respond


def assert_clean(adapter: AuthZenAdapter, decisions: list[Decision]) -> None:
    text = repr(decisions) + repr(adapter.notes()) + adapter.label
    assert TOKEN not in text
    assert "s3cret" not in text


def test_request_shape() -> None:
    with FakePdp(batch_ok(True, False)) as pdp:
        adapter = make_adapter(pdp.url + "?k=v")
        queries = [make_query(1), make_query(2)]
        result = adapter.decide(queries)
        adapter.close()
        (path, body, headers) = pdp.requests[0]
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.DENY]
    assert path == BATCH + "?k=v"
    assert body == {"evaluations": [q.to_authzen() for q in queries]}
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert headers["content-type"] == "application/json"
    assert headers["accept"] == "application/json"
    assert headers["user-agent"].startswith("lockwalk/")


def test_configured_headers_win_over_defaults() -> None:
    with FakePdp(batch_ok(True)) as pdp:
        adapter = make_adapter(pdp.url, headers={"accept": "application/x-test"})
        adapter.decide([make_query()])
        headers = pdp.requests[0][2]
    assert headers["accept"] == "application/x-test"


@pytest.mark.parametrize("status", [404, 405])
def test_fallback_to_single(status: int) -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return status, b"nope", 0.0
        return 200, {"decision": body["subject"]["id"] == "a1"}, 0.0

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url)
        first = adapter.decide([make_query(1), make_query(2)])
        second = adapter.decide([make_query(1)])
        paths = [r[0] for r in pdp.requests]
    assert [d.verdict for d in first] == [Verdict.ALLOW, Verdict.DENY]
    assert second[0].verdict is Verdict.ALLOW
    assert paths == [BATCH, SINGLE, SINGLE, SINGLE]
    assert adapter.notes() == (
        f"the PDP has no AuthZEN batch endpoint (HTTP {status}); asked one question at a time",
    )


def test_single_endpoint_errors_are_per_query() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return 404, b"", 0.0
        if body["subject"]["id"] == "a1":
            return 200, {"decision": "true"}, 0.0
        return 200, {"decision": False}, 0.0

    with FakePdp(respond) as pdp:
        result = make_adapter(pdp.url).decide([make_query(1), make_query(2)])
    assert result[0].verdict is Verdict.ERROR
    assert result[1].verdict is Verdict.DENY


@pytest.mark.parametrize("bad", ["true", 1, None, "missing"])
def test_bad_decisions_spoil_only_their_item(bad: object) -> None:
    item = {} if bad == "missing" else {"decision": bad}
    payload = {"evaluations": [{"decision": True}, item, {"decision": False}]}
    with FakePdp(fixed(200, payload)) as pdp:
        result = make_adapter(pdp.url).decide([make_query(i) for i in range(3)])
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.ERROR, Verdict.DENY]
    assert result[1].error == "the PDP answer has no boolean 'decision'"


def test_non_dict_item_is_error() -> None:
    payload = {"evaluations": [True, {"decision": True}]}
    with FakePdp(fixed(200, payload)) as pdp:
        result = make_adapter(pdp.url).decide([make_query(1), make_query(2)])
    assert [d.verdict for d in result] == [Verdict.ERROR, Verdict.ALLOW]


@pytest.mark.parametrize(
    "payload",
    [
        {"evaluations": [{"decision": True}]},
        {"evaluations": [{"decision": True}] * 3},
        {"evaluations": "x"},
        {"other": []},
        [{"decision": True}, {"decision": True}],
    ],
)
def test_wrong_count_spoils_the_batch(payload: Any) -> None:
    with FakePdp(fixed(200, payload)) as pdp:
        result = make_adapter(pdp.url).decide([make_query(1), make_query(2)])
    assert [d.verdict for d in result] == [Verdict.ERROR, Verdict.ERROR]
    assert result[0].error is not None
    assert result[0].error.startswith("the PDP answered ")
    assert result[0].error.endswith(" evaluations for 2 questions")


def test_http_500_is_error_without_retry() -> None:
    with FakePdp(fixed(500, b"internal s3cret")) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide([make_query()])
        assert len(pdp.requests) == 1
    assert result[0].error == "the PDP answered HTTP 500"
    assert_clean(adapter, result)


def test_503_twice_is_error_after_two_requests() -> None:
    with FakePdp(fixed(503, b"")) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
        assert len(pdp.requests) == 2
    assert result[0].error == "the PDP answered HTTP 503"


def test_503_then_200_succeeds() -> None:
    calls: list[str] = []

    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        calls.append(path)
        if len(calls) == 1:
            return 503, b"", 0.0
        return 200, {"evaluations": [{"decision": True}]}, 0.0

    with FakePdp(respond) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].verdict is Verdict.ALLOW
    assert len(calls) == 2


def test_refused_connection_is_retried_once_then_error(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[int] = []
    real = AuthZenAdapter._once

    def counting(self: AuthZenAdapter, *args: Any, **kwargs: Any) -> Any:
        attempts.append(1)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(AuthZenAdapter, "_once", counting)
    # Windows needs about 2 s to report a refused connection, so the shared budget is generous.
    adapter = make_adapter(f"http://127.0.0.1:{free_port()}", timeout_s=10)
    result = adapter.decide([make_query(1), make_query(2)])
    assert len(attempts) == 2
    assert all(d.verdict is Verdict.ERROR for d in result)
    assert result[0].error is not None
    assert result[0].error.startswith("cannot connect to the PDP: ")
    assert_clean(adapter, result)


def test_timeout_is_error_without_retry() -> None:
    payload = {"evaluations": [{"decision": True}]}
    with FakePdp(fixed(200, payload, delay=3.0)) as pdp:
        adapter = make_adapter(pdp.url, timeout_s=0.3)
        result = adapter.decide([make_query()])
        assert len(pdp.requests) == 1
    assert result[0].error == "timed out after 0.3s"
    assert_clean(adapter, result)


def test_redirect_is_error_and_not_followed() -> None:
    with FakePdp() as target, FakePdp(fixed(302, b"")) as pdp:
        pdp.response_headers["Location"] = target.url + BATCH
        result = make_adapter(pdp.url).decide([make_query()])
        assert len(pdp.requests) == 1
        assert target.requests == []
    assert result[0].error == "the PDP answered HTTP 302"


def test_non_json_body_is_error() -> None:
    with FakePdp(fixed(200, b"<html>s3cret</html>")) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide([make_query()])
    assert result[0].error == "the PDP answer is not JSON"
    assert_clean(adapter, result)


def test_empty_body_is_error() -> None:
    with FakePdp(fixed(200, b"")) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].error == "the PDP answer is not JSON"


def test_oversized_body_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authzen, "MAX_BODY_BYTES", 100)
    with FakePdp(fixed(200, b"[" + b" " * 1000 + b"]")) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].error == "the PDP answer is larger than 10 MiB"


def reason_server(context: Any) -> Responder:
    return fixed(200, {"evaluations": [{"decision": False, "context": context}]})


def test_reason_admin_becomes_the_reason() -> None:
    with FakePdp(reason_server({"reason_admin": "no role"})) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].verdict is Verdict.DENY
    assert result[0].reason == "no role"


def test_non_string_reason_is_ignored() -> None:
    with FakePdp(reason_server({"reason": 5, "reason_user": "second"})) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].reason == "second"
    with FakePdp(reason_server({"reason": {"a": 1}})) as pdp:
        assert make_adapter(pdp.url).decide([make_query()])[0].reason is None
    with FakePdp(reason_server("not a dict")) as pdp:
        assert make_adapter(pdp.url).decide([make_query()])[0].reason is None


def test_long_reason_is_truncated() -> None:
    with FakePdp(reason_server({"reason": "x" * 1000})) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].reason is not None
    assert len(result[0].reason) == 300


def test_url_credentials_in_a_reason_are_redacted() -> None:
    text = "see https://bob:s3cret@idp.example/p?token=abc for details"
    with FakePdp(reason_server({"reason": text})) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].reason is not None
    assert "s3cret" not in result[0].reason
    assert "token=abc" not in result[0].reason
    assert "https://idp.example/p" in result[0].reason


def test_echoed_authorization_header_is_scrubbed() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        context = {"reason": "got " + headers["authorization"]}
        return 200, {"evaluations": [{"decision": False, "context": context}]}, 0.0

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide([make_query()])
    assert result[0].reason is not None
    assert "<hidden header 'Authorization'>" in result[0].reason
    assert_clean(adapter, result)


def test_unset_variable_raises_structural_error() -> None:
    headers = {"Authorization": "Bearer ${NOPE_UNSET_VAR}"}
    with pytest.raises(StructuralError) as caught:
        make_adapter("http://127.0.0.1:1", headers=headers)
    assert "NOPE_UNSET_VAR" in str(caught.value)
    assert caught.value.source == "[policy]"


def test_bad_expanded_header_value_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDP_TOKEN", "bad\nvalue-s3cret")
    with pytest.raises(StructuralError) as caught:
        make_adapter("http://127.0.0.1:1")
    assert "s3cret" not in str(caught.value)
    assert "Authorization" in str(caught.value)


def test_base_path() -> None:
    with FakePdp(batch_ok(True)) as pdp:
        make_adapter(pdp.url + "/pdp/").decide([make_query()])
        assert pdp.requests[0][0] == "/pdp" + BATCH


def test_latency_is_set() -> None:
    with FakePdp(batch_ok(True, True)) as pdp:
        result = make_adapter(pdp.url).decide([make_query(1), make_query(2)])
    assert result[0].latency_ms is not None
    assert result[0].latency_ms >= 0
    assert result[0].latency_ms == result[1].latency_ms


def test_label_batch_size_and_empty_input() -> None:
    adapter = make_adapter("http://127.0.0.1:1/pdp?token=x", batch_size=7)
    assert adapter.label == "authzen:http://127.0.0.1:1/pdp"
    assert adapter.batch_size == 7
    assert adapter.decide([]) == []
    assert adapter.notes() == ()


def test_non_ascii_url_is_percent_encoded() -> None:
    with FakePdp(batch_ok(True)) as pdp:
        adapter = make_adapter(pdp.url + "/p?token=s" + chr(233) + "cret")
        result = adapter.decide([make_query()])
        path = pdp.requests[0][0]
    assert result[0].verdict is Verdict.ALLOW
    assert path == "/p" + BATCH + "?token=s%C3%A9cret"


def test_already_encoded_url_is_kept() -> None:
    with FakePdp(batch_ok(True)) as pdp:
        make_adapter(pdp.url + "/a%20b?q=x%2Fy&r=1").decide([make_query()])
        path = pdp.requests[0][0]
    assert path == "/a%20b" + BATCH + "?q=x%2Fy&r=1"


def test_unusable_host_is_error_without_crash() -> None:
    adapter = make_adapter("http://a..b/")
    result = adapter.decide([make_query(1), make_query(2)])
    assert [d.error for d in result] == ["the PDP URL cannot be used"] * 2


def test_retry_shares_the_first_attempts_deadline() -> None:
    calls: list[str] = []

    # This used to assert elapsed < 1.5 s, which is fragile under load. Now the outcome
    # shows the shared deadline: the first attempt uses 0.8 s of the 1.0 s budget and the
    # retry's answer needs 0.5 s. With a fresh deadline the retry would get 1.0 s and the
    # answer would arrive (no error); with the shared one only 0.2 s is left, so it times
    # out. Only the order of the delays matters, not the total wall time.
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        calls.append(path)
        if len(calls) == 1:
            return 503, b"", 0.8
        return 200, {"evaluations": [{"decision": True}]}, 0.5

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url, timeout_s=1.0)
        started = time.monotonic()
        result = adapter.decide([make_query()])
        elapsed = time.monotonic() - started
        assert len(pdp.requests) == 2
    assert result[0].error == "timed out after 1s"
    # Loose sanity bound only (the real check is the timeout error above).
    assert elapsed < 5.0


def test_single_mode_skips_questions_after_a_timeout() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return 404, b"", 0.0
        return 200, {"decision": True}, 3.0

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url, timeout_s=0.3)
        result = adapter.decide([make_query(1), make_query(2), make_query(3)])
        assert [r[0] for r in pdp.requests] == [BATCH, SINGLE]
    assert [d.error for d in result] == [
        "timed out after 0.3s",
        "skipped: the PDP timed out on an earlier question",
        "skipped: the PDP timed out on an earlier question",
    ]


def test_tls_failure_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts: list[int] = []

    def failing_connect(self: object) -> None:
        attempts.append(1)
        raise ssl.SSLCertVerificationError("certificate verify failed")

    monkeypatch.setattr("http.client.HTTPSConnection.connect", failing_connect)
    result = make_adapter("https://127.0.0.1:1").decide([make_query()])
    assert len(attempts) == 1
    assert result[0].error is not None
    assert result[0].error.startswith("cannot connect to the PDP: ")


def test_blank_reasons_are_skipped() -> None:
    context = {"reason": "   ", "reason_admin": "", "reason_user": "real"}
    with FakePdp(reason_server(context)) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].reason == "real"


def test_deeply_nested_body_is_error() -> None:
    with FakePdp(fixed(200, b"[" * 100000)) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].error == "the PDP answer is not JSON"


def test_invalid_utf8_body_is_error() -> None:
    with FakePdp(fixed(200, bytes([255, 254, 0, 1]))) as pdp:
        result = make_adapter(pdp.url).decide([make_query()])
    assert result[0].error == "the PDP answer is not JSON"


def test_endless_chunked_body_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authzen, "MAX_BODY_BYTES", 100_000)

    def endless() -> Any:
        while True:
            yield b"x" * 1000

    with FakePdp(lambda p, b, h: (200, endless(), 0.0)) as pdp:
        result = make_adapter(pdp.url, timeout_s=3).decide([make_query()])
    assert result[0].error == "the PDP answer is larger than 10 MiB"


def test_pieces_of_an_expanded_header_are_hidden(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("A", "piece-aaaaaa")
    monkeypatch.setenv("B", "piece-bbbbbb")

    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        reason = f"one {headers['x-k']} two piece-aaaaaa three piece-bbbbbb"
        return 200, {"evaluations": [{"decision": False, "context": {"reason": reason}}]}, 0.0

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url, headers={"X-K": "a-${A}-b-${B}"})
        result = adapter.decide([make_query()])
    assert result[0].reason is not None
    assert "piece-aaaaaa" not in result[0].reason
    assert "piece-bbbbbb" not in result[0].reason
    assert "<hidden header 'X-K'>" in result[0].reason


def test_fallback_persists_even_when_single_endpoint_fails() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return 404, b"", 0.0
        return 500, b"", 0.0

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url)
        adapter.decide([make_query()])
        second = adapter.decide([make_query()])
        paths = [r[0] for r in pdp.requests]
    assert paths == [BATCH, SINGLE, SINGLE]
    assert second[0].error == "the PDP answered HTTP 500"


def subject_query(subject: dict[str, Any], n: int) -> Query:
    return Query.model_validate(
        {
            "subject": subject,
            "action": {"name": "tool:call"},
            "resource": {"type": "tool", "id": f"t{n}"},
        }
    )


def echo_resource() -> Responder:
    """Allow when the resource id is odd, so each answer shows which question it answers."""

    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        items = body["evaluations"]
        return (
            200,
            {"evaluations": [{"decision": int(i["resource"]["id"][1:]) % 2 == 1} for i in items]},
            0.0,
        )

    return respond


def test_same_subject_id_with_different_forms_is_split() -> None:
    plain = {"type": "user", "id": "alice", "properties": {"roles": ["r"]}}
    acting = {**plain, "properties": {"roles": ["r"], "act": {"type": "agent", "id": "a"}}}
    bob = {"type": "user", "id": "bob"}
    queries = [
        subject_query(plain, 1),
        subject_query(acting, 2),
        subject_query(bob, 3),
        subject_query(plain, 4),
    ]
    with FakePdp(echo_resource()) as pdp:
        result = make_adapter(pdp.url).decide(queries)
        bodies = [r[1] for r in pdp.requests]
    sent = [[i["resource"]["id"] for i in b["evaluations"]] for b in bodies]
    assert sent == [["t1", "t3", "t4"], ["t2"]]
    assert [d.verdict for d in result] == [
        Verdict.ALLOW,
        Verdict.DENY,
        Verdict.ALLOW,
        Verdict.DENY,
    ]


def test_batch_without_id_conflicts_is_one_request() -> None:
    with FakePdp(echo_resource()) as pdp:
        result = make_adapter(pdp.url).decide([make_query(1), make_query(2), make_query(1)])
        count = len(pdp.requests)
    assert count == 1
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.DENY, Verdict.ALLOW]


def test_split_fallback_to_single_keeps_order() -> None:
    plain = {"type": "user", "id": "alice"}
    acting = {**plain, "properties": {"act": {"type": "agent", "id": "a"}}}

    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return 404, b"nope", 0.0
        return 200, {"decision": int(body["resource"]["id"][1:]) % 2 == 1}, 0.0

    queries = [subject_query(plain, 1), subject_query(acting, 2), subject_query(plain, 3)]
    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide(queries)
        paths = [r[0] for r in pdp.requests]
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.DENY, Verdict.ALLOW]
    assert paths == [BATCH, SINGLE, SINGLE, SINGLE]
    assert len(adapter.notes()) == 1


_SKIPPED_TEXT = "skipped: the PDP timed out on an earlier question"


def form(n: int, ident: str = "alice") -> dict[str, Any]:
    """The n-th form of a subject id: forms differ in their properties."""
    return {"type": "user", "id": ident, "properties": {"form": n}}


def test_three_forms_of_one_id_give_three_sub_batches() -> None:
    queries = [subject_query(form(n), n) for n in (1, 2, 3, 1)]
    assert AuthZenAdapter._sub_batches(queries) == [[0, 3], [1], [2]]


def test_interleaved_ids_with_two_forms_each() -> None:
    queries = [
        subject_query(form(1, "a"), 1),
        subject_query(form(1, "b"), 2),
        subject_query(form(2, "b"), 3),
        subject_query(form(2, "a"), 4),
        subject_query(form(1, "b"), 5),
        subject_query(form(1, "a"), 6),
    ]
    assert AuthZenAdapter._sub_batches(queries) == [[0, 1, 4, 5], [2, 3]]


def first_fit(queries: list[Query]) -> list[list[int]]:
    batches: list[list[int]] = []
    seen: list[dict[str, Any]] = []
    for position, query in enumerate(queries):
        for batch, subjects in zip(batches, seen, strict=True):
            known = subjects.get(query.subject.id)
            if known is None:
                subjects[query.subject.id] = query.subject
            elif known != query.subject:
                continue
            batch.append(position)
            break
        else:
            batches.append([position])
            seen.append({query.subject.id: query.subject})
    return batches


def test_sub_batches_equal_greedy_first_fit() -> None:
    rng = random.Random(20261107)
    for _ in range(200):
        queries = [
            subject_query(form(rng.randrange(3), rng.choice("abc")), i)
            for i in range(rng.randrange(1, 25))
        ]
        assert AuthZenAdapter._sub_batches(queries) == first_fit(queries)


def split_queries() -> list[Query]:
    return [subject_query(form(n), n) for n in (1, 2, 3)]


def test_batch_timeout_skips_the_remaining_sub_batches() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        return 200, {"evaluations": [{"decision": True}]}, 1.0

    with FakePdp(respond) as pdp:
        result = make_adapter(pdp.url, timeout_s=0.2).decide(split_queries())
        count = len(pdp.requests)
    assert count == 1
    assert result[0].error is not None and "timed out" in result[0].error
    assert [d.error for d in result[1:]] == [_SKIPPED_TEXT, _SKIPPED_TEXT]


def test_timeout_in_single_mode_after_a_404_skips_the_rest() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return 404, b"nope", 0.0
        return 200, {"decision": True}, 1.0

    with FakePdp(respond) as pdp:
        result = make_adapter(pdp.url, timeout_s=0.2).decide([*split_queries(), make_query(9)])
        paths = [r[0] for r in pdp.requests]
    assert paths == [BATCH, SINGLE]
    assert result[0].error is not None and "timed out" in result[0].error
    assert [d.error for d in result[1:]] == [_SKIPPED_TEXT] * 3


def test_http_error_in_one_sub_batch_does_not_touch_the_next() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if body["evaluations"][0]["subject"]["properties"]["form"] == 1:
            return 500, b"boom", 0.0
        return 200, {"evaluations": [{"decision": True}]}, 0.0

    queries = [subject_query(form(n), n) for n in (1, 2)]
    with FakePdp(respond) as pdp:
        result = make_adapter(pdp.url).decide(queries)
    assert result[0].verdict is Verdict.ERROR
    assert result[1].verdict is Verdict.ALLOW


def test_404_on_the_second_sub_batch_keeps_the_first_answers() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            if body["evaluations"][0]["subject"]["properties"]["form"] == 1:
                return 200, {"evaluations": [{"decision": True}]}, 0.0
            return 404, b"nope", 0.0
        return 200, {"decision": False}, 0.0

    queries = [subject_query(form(n), n) for n in (1, 2, 3)]
    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide(queries)
        paths = [r[0] for r in pdp.requests]
    assert paths == [BATCH, BATCH, SINGLE, SINGLE]
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.DENY, Verdict.DENY]
    assert len(adapter.notes()) == 1


PDP_ERROR = "the PDP reported an error for this question"
ERROR_ITEM = {"decision": False, "context": {"error": {"status": 500, "message": "s3cret boom"}}}


def test_batch_item_with_context_error_is_error_not_deny() -> None:
    payload = {"evaluations": [{"decision": True}, ERROR_ITEM, {"decision": False}]}
    with FakePdp(fixed(200, payload)) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide([make_query(i) for i in range(3)])
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.ERROR, Verdict.DENY]
    assert result[1].error == PDP_ERROR
    assert_clean(adapter, result)


def test_single_endpoint_context_error_is_error_not_deny() -> None:
    def respond(path: str, body: Any, headers: dict[str, str]) -> tuple[int, Any, float]:
        if path == BATCH:
            return 404, b"", 0.0
        if body["subject"]["id"] == "a1":
            return 200, ERROR_ITEM, 0.0
        return 200, {"decision": False}, 0.0

    with FakePdp(respond) as pdp:
        adapter = make_adapter(pdp.url)
        result = adapter.decide([make_query(1), make_query(2)])
    assert [d.verdict for d in result] == [Verdict.ERROR, Verdict.DENY]
    assert result[0].error == PDP_ERROR
    assert_clean(adapter, result)


def test_null_context_error_is_a_normal_answer() -> None:
    payload = {
        "evaluations": [
            {"decision": True, "context": {"error": None}},
            {"decision": False, "context": {"error": None}},
        ]
    }
    with FakePdp(fixed(200, payload)) as pdp:
        result = make_adapter(pdp.url).decide([make_query(1), make_query(2)])
    assert [d.verdict for d in result] == [Verdict.ALLOW, Verdict.DENY]
