"""Scripted fake model for the OpenAI Agents SDK, run in-process."""

import contextlib
import sys
from collections.abc import Iterator
from typing import Any, cast

import pytest

pytest.importorskip("agents")

from harness_apps import openai_app as app
from harness_apps.network_guard import block_network

from lockwalk.harness import fake_openai
from lockwalk.harness.events import EventLog
from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import SCRIPTED_TEXT, ScriptedJob, Step
from lockwalk.harness.script import NotRun, Script

USER = {"type": "user", "id": "alice"}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    block_network(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_AGENTS_DISABLE_TRACING", "1")
    app.CALLS.clear()
    yield


def found() -> Found:
    agents = {
        "supervisor": app.supervisor,
        "finance-agent": app.finance_agent,
        "trade-agent": app.trade_agent,
    }
    return Found(agents=agents, frameworks=dict.fromkeys(agents, "openai_agents"))


def job(steps: tuple[Step, ...], route: tuple[str, ...]) -> ScriptedJob:
    return ScriptedJob(
        case_id="C",
        route=route,
        tool="execute_trade",
        args={"order_id": "o-1"},
        subject=USER,
        steps=steps,
    )


FULL = (
    Step(agent="supervisor", kind="handoff", target="finance-agent"),
    Step(
        agent="finance-agent",
        kind="agent_tool",
        target="trade-agent",
        tool="ask_trade_agent",
        args={"input": SCRIPTED_TEXT},
    ),
    Step(
        agent="trade-agent",
        kind="tool",
        target="execute_trade",
        tool="execute_trade",
        args={"order_id": "o-1"},
    ),
)
ROUTE = ("supervisor", "finance-agent", "trade-agent")


def run(j: ScriptedJob) -> Script:
    script = Script(j, EventLog())
    f = found()
    with contextlib.ExitStack() as stack:
        fake_openai.install(script, f, stack)
        fake_openai.start(j, f)
    return script


def test_full_route_reaches_tool_and_restores_models() -> None:
    before = {k: cast(Any, v).model for k, v in found().agents.items()}
    token = app.IDENT.set("alice")
    try:
        script = run(job(FULL, ROUTE))
    finally:
        app.IDENT.reset(token)
    assert app.CALLS == [("o-1", "alice")]
    assert script.window_start is not None
    assert script.window_end is not None
    assert script.problems == []
    after = {k: cast(Any, v).model for k, v in found().agents.items()}
    assert after == before


def test_handoff_to_agent_not_offered() -> None:
    steps = (Step(agent="supervisor", kind="handoff", target="trade-agent"),)
    script = run(job(steps, ("supervisor", "trade-agent")))
    assert app.CALLS == []
    assert script.window_start is None
    assert any("was not offered a handoff to 'trade-agent'" in p for p in script.problems)


def test_tool_not_offered() -> None:
    steps = (
        Step(
            agent="supervisor",
            kind="tool",
            target="execute_trade",
            tool="execute_trade",
            args={"order_id": "o-1"},
        ),
    )
    script = run(job(steps, ("supervisor",)))
    assert app.CALLS == []
    assert any("was not offered tool 'execute_trade'" in p for p in script.problems)
    assert script.window_start is None
    assert script.observation(door_configured=False).not_run is not None


def test_install_does_nothing_without_framework(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "agents")
    before = {k: cast(Any, v).model for k, v in found().agents.items()}
    with contextlib.ExitStack() as stack:
        fake_openai.install(Script(job(FULL, ROUTE), EventLog()), found(), stack)
        assert {k: cast(Any, v).model for k, v in found().agents.items()} == before


def test_start_without_install_fails_closed() -> None:
    with pytest.raises(NotRun, match="not installed"):
        fake_openai.start(job(FULL, ROUTE), found())
    assert app.CALLS == []


def test_agent_not_found_never_reaches_a_real_model() -> None:
    agents: dict[str, object] = {"ghost-supervisor": app.ghost_supervisor}
    f = Found(agents=agents, frameworks={"ghost-supervisor": "openai_agents"})
    steps = (Step(agent="ghost-supervisor", kind="handoff", target="ghost"),)
    j = job(steps, ("ghost-supervisor", "ghost"))
    script = Script(j, EventLog())
    assert app.ghost_agent.model is None
    with contextlib.ExitStack() as stack:
        fake_openai.install(script, f, stack)
        fake_openai.start(j, f)
    assert any("did not find asked for a model" in p for p in script.problems)
    assert app.ghost_agent.model is None
