"""Scripted fake model for Pydantic AI, run in-process."""

import contextlib
from collections.abc import Iterator

import pytest

pytest.importorskip("pydantic_ai")

from harness_apps import pydantic_app as app
from harness_apps.network_guard import block_network

from lockwalk.harness import fake_pydantic
from lockwalk.harness.events import EventLog
from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import ScriptedJob, Step
from lockwalk.harness.script import Script

USER = {"type": "user", "id": "alice"}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    block_network(monkeypatch)
    monkeypatch.setenv("PYDANTIC_AI_NO_BANNER", "1")
    app.CALLS.clear()
    yield


def run(steps: tuple[Step, ...], route: tuple[str, ...]) -> Script:
    agents: dict[str, object] = {"finance-agent": app.finance, "pricing-agent": app.pricing}
    f = Found(agents=agents, frameworks=dict.fromkeys(agents, "pydantic_ai"))
    j = ScriptedJob(
        case_id="C",
        route=route,
        tool="get_stock_price",
        args={"symbol": "AAPL"},
        subject=USER,
        steps=steps,
    )
    script = Script(j, EventLog())
    with contextlib.ExitStack() as stack:
        fake_pydantic.install(script, f, stack)
        fake_pydantic.start(j, f)
    return script


PRICE = Step(
    agent="pricing-agent",
    kind="tool",
    target="get_stock_price",
    tool="get_stock_price",
    args={"symbol": "AAPL"},
)


def test_agent_without_model_runs_tool() -> None:
    token = app.IDENT.set("alice")
    try:
        script = run((PRICE,), ("pricing-agent",))
    finally:
        app.IDENT.reset(token)
    assert app.CALLS == [("AAPL", "alice")]
    assert script.window_start is not None
    assert script.window_end is not None


def test_nested_agents_and_undo() -> None:
    steps = (
        Step(
            agent="finance-agent",
            kind="agent_tool",
            target="pricing-agent",
            tool="ask_pricing",
            args={"symbol": "AAPL"},
        ),
        PRICE,
    )
    script = run(steps, ("finance-agent", "pricing-agent"))
    assert app.CALLS == [("AAPL", "NONE")]
    assert script.problems == []
    # The overrides are gone: with no model, a run fails before reaching any fake.
    with pytest.raises(Exception, match="model"):
        app.pricing.run_sync("x")


def test_handoff_noted() -> None:
    steps = (Step(agent="finance-agent", kind="handoff", target="pricing-agent"),)
    script = run(steps, ("finance-agent", "pricing-agent"))
    assert any("no handoffs" in p for p in script.problems)
    assert app.CALLS == []


def test_tool_not_offered() -> None:
    steps = (PRICE.model_copy(update={"agent": "finance-agent"}),)
    script = run(steps, ("finance-agent",))
    assert any("was not offered tool 'get_stock_price'" in p for p in script.problems)
    assert app.CALLS == []
    assert script.window_start is None
    assert script.observation(door_configured=False).not_run is not None


def test_real_model_requests_are_blocked_and_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    import pydantic_ai.models as models
    from pydantic_ai import Agent

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    ghost = Agent("openai:gpt-4o", name="ghost")
    job = ScriptedJob(case_id="C", route=("x",), tool="t", args={}, subject=USER)
    script = Script(job, EventLog())
    before = models.ALLOW_MODEL_REQUESTS
    with contextlib.ExitStack() as stack:
        fake_pydantic.install(script, Found(), stack)
        assert models.ALLOW_MODEL_REQUESTS is False
        with pytest.raises(RuntimeError, match="not allowed"):
            ghost.run_sync("hi")
    assert models.ALLOW_MODEL_REQUESTS is before


def test_structured_output_retry_gets_final_again() -> None:
    step = PRICE.model_copy(update={"agent": "structured-agent"})
    j = ScriptedJob(
        case_id="C",
        route=("structured-agent",),
        tool="get_stock_price",
        args={"symbol": "AAPL"},
        subject=USER,
        steps=(step,),
    )
    f = Found(
        agents={"structured-agent": app.structured},
        frameworks={"structured-agent": "pydantic_ai"},
    )
    script = Script(j, EventLog())
    with contextlib.ExitStack() as stack:
        fake_pydantic.install(script, f, stack)
        with pytest.raises(Exception):  # noqa: B017 - text never satisfies output_type
            fake_pydantic.start(j, f)
    assert app.CALLS == [("AAPL", "NONE")]
    assert any("structured output type" in p for p in script.problems)
