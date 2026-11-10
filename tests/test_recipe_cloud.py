"""Cloud decide() recipes, run against fake clients. No SDK and no network."""

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

RECIPES = Path(__file__).resolve().parent.parent / "examples" / "recipes"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"recipe_{name}", RECIPES / name / "decide.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def user(**props: Any) -> dict:
    return {"type": "user", "id": "alice", "properties": props}


def order(**props: Any) -> dict:
    return {"type": "order", "id": "o1", "properties": props}


ACT = {"name": "read"}


class FakeAvp:
    def __init__(self, decisions: list[str] | None = None, short: bool = False) -> None:
        self.single_response: dict | None = None
        self.single: list[dict] = []
        self.batches: list[dict] = []
        self.decisions = decisions
        self.short = short

    def is_authorized(self, **kwargs: Any) -> dict:
        self.single.append(kwargs)
        if self.single_response is not None:
            return self.single_response
        return {"decision": (self.decisions or ["ALLOW"])[0]}

    def batch_is_authorized(self, **kwargs: Any) -> dict:
        self.batches.append(kwargs)
        reqs = kwargs["requests"]
        results = [
            {"request": r, "decision": "ALLOW" if r["resource"]["entityId"] != "deny" else "DENY"}
            for r in reqs
        ]
        return {"results": results[:-1] if self.short else results}


@pytest.fixture
def avp(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, FakeAvp]:
    module = load("verified_permissions")
    fake = FakeAvp()
    monkeypatch.setattr(module, "_client", lambda: fake)
    monkeypatch.setenv("AVP_POLICY_STORE_ID", "store-1")
    monkeypatch.setenv("AVP_NAMESPACE", "Desk")
    return module, fake


def test_avp_decide_request_shape(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    assert module.decide(user(), ACT, order(), {"hour": 9, "ok": True, "tag": "x"}) is True
    assert fake.single == [
        {
            "policyStoreId": "store-1",
            "principal": {"entityType": "Desk::User", "entityId": "alice"},
            "action": {"actionType": "Desk::Action", "actionId": "read"},
            "resource": {"entityType": "Desk::Order", "entityId": "o1"},
            "context": {
                "contextMap": {"hour": {"long": 9}, "ok": {"boolean": True}, "tag": {"string": "x"}}
            },
        }
    ]


def test_avp_deny_and_unknown_decision(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    fake.decisions = ["DENY"]
    assert module.decide(user(), ACT, order(), {}) is False
    fake.decisions = ["MAYBE"]
    with pytest.raises(ValueError, match="unknown"):
        module.decide(user(), ACT, order(), {})


def test_avp_fail_closed_inputs(
    avp: tuple[ModuleType, FakeAvp], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, _ = avp
    with pytest.raises(ValueError, match="TYPES"):
        module.decide({"type": "robot", "id": "r"}, ACT, order(), {})
    with pytest.raises(ValueError, match="context"):
        module.decide(user(), ACT, order(), {"bad": [1]})
    monkeypatch.delenv("AVP_POLICY_STORE_ID")
    with pytest.raises(RuntimeError):
        module.decide(user(), ACT, order(), {})


def queries(n: int) -> list[dict]:
    return [
        {
            "subject": user(),
            "action": ACT,
            "resource": {"type": "order", "id": "deny" if i % 7 == 0 else f"o{i}"},
            "context": {},
        }
        for i in range(n)
    ]


def test_avp_batch_chunks_of_30_in_order(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    qs = queries(65)
    answers = module.decide_many(qs)
    assert [len(b["requests"]) for b in fake.batches] == [30, 30, 5]
    assert all(b["policyStoreId"] == "store-1" for b in fake.batches)
    assert answers == [i % 7 != 0 for i in range(65)]
    assert all(type(a) is bool for a in answers)


def test_avp_batch_wrong_count_raises(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    fake.short = True
    with pytest.raises(ValueError, match="results"):
        module.decide_many(queries(3))


def test_avp_batch_one_principal_per_call_and_order_kept(
    avp: tuple[ModuleType, FakeAvp],
) -> None:
    module, fake = avp
    qs = []
    for i in range(10):
        who = "alice" if i % 2 == 0 else "bob"
        qs.append(
            {
                "subject": {"type": "user", "id": who},
                "action": ACT,
                "resource": {"type": "order", "id": "deny" if i in (3, 4) else f"o{i}"},
                "context": {},
            }
        )
    answers = module.decide_many(qs)
    assert len(fake.batches) == 2
    for batch in fake.batches:
        assert len({r["principal"]["entityId"] for r in batch["requests"]}) == 1
    assert answers == [i not in (3, 4) for i in range(10)]


def test_avp_batch_65_for_one_principal_is_30_30_5(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    qs = [
        {"subject": user(), "action": ACT, "resource": {"type": "order", "id": f"o{i}"}}
        for i in range(65)
    ]
    assert module.decide_many(qs) == [True] * 65
    assert [len(b["requests"]) for b in fake.batches] == [30, 30, 5]


def test_avp_missing_or_none_decision_raises(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    fake.single_response = {}
    with pytest.raises(ValueError, match="unknown"):
        module.decide(user(), ACT, order(), {})
    fake.single_response = {"decision": None}
    with pytest.raises(ValueError, match="unknown"):
        module.decide(user(), ACT, order(), {})


@pytest.mark.parametrize("response", [{}, {"results": None}, {"results": "x"}, {"results": {}}])
def test_avp_batch_bad_results_raise(avp: tuple[ModuleType, FakeAvp], response: dict) -> None:
    module, fake = avp
    fake.batch_is_authorized = lambda **kwargs: response  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="results"):
        module.decide_many(queries(2))


def test_avp_batch_too_many_results_raise(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    fake.batch_is_authorized = lambda **kwargs: {  # type: ignore[method-assign]
        "results": [{"decision": "ALLOW"}] * 3
    }
    with pytest.raises(ValueError, match="3 results for 2"):
        module.decide_many(queries(2))


def test_avp_empty_namespace_and_empty_batch(
    avp: tuple[ModuleType, FakeAvp], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, fake = avp
    monkeypatch.delenv("AVP_NAMESPACE")
    module.decide(user(), ACT, order(), {})
    assert fake.single[0]["principal"]["entityType"] == "User"
    assert fake.single[0]["action"]["actionType"] == "Action"
    assert module.decide_many([]) == []
    assert fake.batches == []


def test_avp_batch_ignores_echo_casing(avp: tuple[ModuleType, FakeAvp]) -> None:
    module, fake = avp
    original = fake.batch_is_authorized

    def lowercase_echo(**kwargs: Any) -> dict:
        response = original(**kwargs)
        for result in response["results"]:
            result["request"]["principal"]["entityId"] = "ALICE"
        return response

    fake.batch_is_authorized = lowercase_echo  # type: ignore[method-assign]
    assert module.decide_many(queries(3)) == [False, True, True]


class FakeIam:
    def __init__(self, response: dict) -> None:
        self.calls: list[dict] = []
        self.response = response

    def simulate_principal_policy(self, **kwargs: Any) -> dict:
        self.calls.append(kwargs)
        return self.response


def iam_with(monkeypatch: pytest.MonkeyPatch, response: dict) -> tuple[ModuleType, FakeIam]:
    module = load("aws_iam_simulator")
    fake = FakeIam(response)
    monkeypatch.setattr(module, "_client", lambda: fake)
    return module, fake


ROLE = "arn:aws:iam::123456789012:role/trader"
BUCKET = "arn:aws:s3:::desk/orders"
ACT_S3 = {"name": "s3:GetObject"}


@pytest.mark.parametrize(
    ("eval_decision", "expected"),
    [("allowed", True), ("explicitDeny", False), ("implicitDeny", False)],
)
def test_iam_decisions(monkeypatch: pytest.MonkeyPatch, eval_decision: str, expected: bool) -> None:
    module, fake = iam_with(monkeypatch, {"EvaluationResults": [{"EvalDecision": eval_decision}]})
    got = module.decide(user(arn=ROLE), ACT_S3, order(arn=BUCKET), {})
    assert got is expected
    assert fake.calls == [
        {"PolicySourceArn": ROLE, "ActionNames": ["s3:GetObject"], "ResourceArns": [BUCKET]}
    ]


@pytest.mark.parametrize(
    "response",
    [
        {"EvaluationResults": [{"EvalDecision": "somethingNew"}]},
        {"EvaluationResults": []},
        {"EvaluationResults": [{"EvalDecision": "allowed"}, {"EvalDecision": "allowed"}]},
        {},
    ],
)
def test_iam_unexpected_response_raises(monkeypatch: pytest.MonkeyPatch, response: dict) -> None:
    module, _ = iam_with(monkeypatch, response)
    with pytest.raises(ValueError):
        module.decide(user(arn=ROLE), ACT_S3, order(arn=BUCKET), {})


MISSING = "the simulation needs context values that the recipe does not send"


@pytest.mark.parametrize(
    "result",
    [
        {"EvalDecision": "implicitDeny", "MissingContextValues": ["aws:SecretKey", "b"]},
        {
            "EvalDecision": "implicitDeny",
            "ResourceSpecificResults": [{"MissingContextValues": ["aws:SecretKey", "b"]}],
        },
        {"EvalDecision": "allowed", "MissingContextValues": ["aws:SecretKey", "b"]},
    ],
)
def test_iam_missing_context_raises_with_count_only(
    monkeypatch: pytest.MonkeyPatch, result: dict
) -> None:
    module, _ = iam_with(monkeypatch, {"EvaluationResults": [result]})
    with pytest.raises(ValueError, match=MISSING) as info:
        module.decide(user(arn=ROLE), ACT_S3, order(arn=BUCKET), {})
    assert "2 keys" in str(info.value)
    assert "aws:SecretKey" not in str(info.value)


def test_iam_errors_never_contain_an_arn(monkeypatch: pytest.MonkeyPatch) -> None:
    for response in (
        {"EvaluationResults": [{"EvalDecision": "weird"}]},
        {"EvaluationResults": []},
        {"EvaluationResults": [{"EvalDecision": "implicitDeny", "MissingContextValues": ["k"]}]},
    ):
        module, _ = iam_with(monkeypatch, response)
        with pytest.raises(ValueError) as info:
            module.decide(user(arn=ROLE), ACT_S3, order(arn=BUCKET), {})
        assert ROLE not in str(info.value)
        assert BUCKET not in str(info.value)
        assert "123456789012" not in str(info.value)


def test_iam_missing_arn_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    module, fake = iam_with(monkeypatch, {"EvaluationResults": [{"EvalDecision": "allowed"}]})
    with pytest.raises(ValueError, match="subject"):
        module.decide(user(), ACT_S3, order(arn=BUCKET), {})
    with pytest.raises(ValueError, match="resource"):
        module.decide(user(arn=ROLE), ACT_S3, order(), {})
    assert fake.calls == []


class State:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeGcp:
    def __init__(self, access: object) -> None:
        self.requests: list[dict] = []
        self.access = access

    def troubleshoot_iam_policy(self, request: dict) -> Any:
        self.requests.append(request)
        return type("Response", (), {"access": self.access})()


PROJECT = "//cloudresourcemanager.googleapis.com/projects/p"


def gcp_with(monkeypatch: pytest.MonkeyPatch, access: object) -> tuple[ModuleType, FakeGcp]:
    module = load("gcp_troubleshooter")
    fake = FakeGcp(access)
    monkeypatch.setattr(module, "_client", lambda: fake)
    return module, fake


def call_gcp(module: ModuleType) -> bool:
    return module.decide(
        user(principal="a@example.com"),
        {"name": "storage.objects.get"},
        order(full_resource_name=PROJECT),
        {},
    )


@pytest.mark.parametrize(
    ("access", "expected"),
    [(State("GRANTED"), True), (State("NOT_GRANTED"), False), (1, True), (2, False)],
)
def test_gcp_decisions(monkeypatch: pytest.MonkeyPatch, access: object, expected: bool) -> None:
    module, fake = gcp_with(monkeypatch, access)
    assert call_gcp(module) is expected
    assert fake.requests == [
        {
            "access_tuple": {
                "principal": "a@example.com",
                "full_resource_name": PROJECT,
                "permission": "storage.objects.get",
            }
        }
    ]


@pytest.mark.parametrize(
    "access",
    [
        State("UNKNOWN_CONDITIONAL"),
        State("UNKNOWN_INFO_DENIED"),
        0,
        3,
        4,
        99,
        None,
        True,
        "GRANTED",
    ],
)
def test_gcp_unknown_states_raise(monkeypatch: pytest.MonkeyPatch, access: object) -> None:
    module, _ = gcp_with(monkeypatch, access)
    with pytest.raises(ValueError, match="could not decide"):
        call_gcp(module)


def test_gcp_missing_property_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    module, fake = gcp_with(monkeypatch, State("GRANTED"))
    with pytest.raises(ValueError, match="principal"):
        module.decide(user(), ACT, order(full_resource_name=PROJECT), {})
    assert fake.requests == []


def test_recipes_import_without_sdks() -> None:
    for name in ("verified_permissions", "aws_iam_simulator", "gcp_troubleshooter"):
        assert callable(load(name).decide)
