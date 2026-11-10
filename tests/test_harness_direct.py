"""Reading and calling tools the framework's way."""

from typing import ClassVar

import pytest
from harness_apps import direct_tools as t

from lockwalk.harness.direct import call, tool_info


@pytest.fixture(autouse=True)
def _reset():
    t.reset()


CASES = [
    ("function", t.plain_function, "function"),
    ("function_async", t.plain_async, "function"),
    ("openai", t.openai_sync, "openai_agents"),
    ("openai_async", t.openai_async, "openai_agents"),
    ("langchain", t.lc_sync, "langchain"),
    ("langchain_async", t.lc_async, "langchain"),
    ("agno", t.agno_sync, "agno"),
    ("agno_async", t.agno_async, "agno"),
    ("pydantic", t.pydantic_tool("pydantic_plain"), "pydantic_ai"),
    ("pydantic_async", t.pydantic_tool("pydantic_async"), "pydantic_ai"),
]

SWALLOWED = {"openai", "openai_async", "agno", "agno_async"}


@pytest.mark.parametrize(("label", "obj", "kind"), CASES)
def test_kind_schema_and_one_call(label, obj, kind):
    info = tool_info("x", obj)
    assert info.kind == kind
    assert info.callable
    if kind == "function":
        assert info.input_schema is None
    else:
        assert info.input_schema is not None
        assert "order_id" in info.input_schema["properties"]
    outcome = call(obj, {"order_id": "o-1"})
    assert outcome.exception is None
    assert list(t.CALLS) == [(label, {"order_id": "o-1"})]


@pytest.mark.parametrize(("label", "obj", "kind"), CASES)
def test_permission_error(label, obj, kind):
    outcome = call(obj, {"order_id": "deny"})
    assert len(t.CALLS) == 1
    if label in SWALLOWED:
        assert outcome.exception is None
    else:
        assert outcome.exception == "PermissionError"
        assert outcome.message == "denied by the door"


def test_langchain_bad_argument_type_is_a_validation_error():
    outcome = call(t.lc_sync, {"order_id": {"not": "a string"}})
    assert outcome.exception == "ValidationError"
    assert t.CALLS == []


def test_pydantic_tool_with_run_context_is_not_callable():
    info = tool_info("pydantic_ctx", t.pydantic_tool("pydantic_ctx"))
    assert info.kind == "pydantic_ai"
    assert not info.callable
    assert info.why_not is not None and "RunContext" in info.why_not
    assert info.input_schema is not None
    assert "order_id" in info.input_schema["properties"]


def test_unknown_object_is_not_callable():
    info = tool_info("u", t.Unknown())
    assert not info.callable
    assert info.why_not == "lockwalk does not know how to call a Unknown"
    assert call(t.Unknown(), {}).exception == "TypeError"


def test_call_never_raises_on_missing_argument():
    assert call(t.plain_function, {}).exception == "TypeError"


def test_non_json_schema_becomes_none():
    class Weird:
        name = "w"
        params_json_schema: ClassVar = {"x": float("nan")}

        async def on_invoke_tool(self, ctx, args):
            return ""

    info = tool_info("w", Weird())
    assert info.kind == "openai_agents"
    assert info.input_schema is None


def test_tool_info_never_raises():
    class Hostile:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    assert not tool_info("h", Hostile()).callable


def test_generator_tools_are_closed_not_run():
    ran = []

    def gen(order_id: str):
        ran.append(order_id)
        yield 1

    async def agen(order_id: str):
        ran.append(order_id)
        yield 1

    for tool in (gen, agen):
        outcome = call(tool, {"order_id": "o"})
        assert outcome.exception == "TypeError"
        assert outcome.message is not None and "generator" in outcome.message
    assert ran == []


def test_call_inside_a_running_loop_is_refused():
    import asyncio

    async def inside():
        return call(t.plain_function, {"order_id": "o"})

    outcome = asyncio.run(inside())
    assert outcome.exception == "RuntimeError"
    assert "running event loop" in (outcome.message or "")
    assert t.CALLS == []


def test_huge_schema_becomes_none():
    class Big:
        name = "big"
        params_json_schema: ClassVar = {"properties": {"a" * 300_000: {"type": "string"}}}

        async def on_invoke_tool(self, ctx, args):
            return ""

    assert tool_info("big", Big()).input_schema is None
