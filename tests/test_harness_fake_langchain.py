"""The scripted fake model for LangChain / LangGraph."""

import asyncio
import contextlib
import socket
import warnings
from typing import Any

import pytest
from harness_apps import langchain_apps
from langchain_core.language_models.chat_models import BaseChatModel

from lockwalk.harness import fake_langchain
from lockwalk.harness.events import EventLog
from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import ScriptedJob, Step
from lockwalk.harness.script import NotRun, Script

USER = {"type": "user", "id": "alice"}
PATCHED = ("_generate_with_cache", "_agenerate_with_cache", "_should_stream")


@pytest.fixture(autouse=True)
def isolate(monkeypatch: pytest.MonkeyPatch) -> None:
    real_connect = socket.socket.connect

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise OSError("network is off in this test")

    def connect(self: socket.socket, address: Any) -> Any:
        # asyncio's Windows socketpair fallback connects to loopback; nothing else may.
        if isinstance(address, tuple) and address[0] == "127.0.0.1":
            return real_connect(self, address)
        raise OSError("network is off in this test")

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(fake_langchain, "_reason", None)
    langchain_apps.CALLS.clear()


def make_job(route: tuple[str, ...], steps: tuple[Step, ...]) -> ScriptedJob:
    return ScriptedJob(
        case_id="CASE-1",
        route=route,
        tool="execute_trade",
        args={"order_id": "o-1"},
        subject=USER,
        steps=steps,
    )


def tool_step(agent: str, name: str = "execute_trade", args: dict[str, Any] | None = None) -> Step:
    return Step(
        agent=agent,
        kind="tool",
        target=name,
        tool=name,
        args=args or {"order_id": "o-1"},
    )


def setup(job: ScriptedJob, graph: Any) -> tuple[Script, Found]:
    script = Script(job, EventLog())
    found = Found(agents={job.route[0]: graph}, frameworks={job.route[0]: "langgraph"})
    return script, found


def run(job: ScriptedJob, graph: Any) -> Script:
    script, found = setup(job, graph)
    with contextlib.ExitStack() as stack:
        fake_langchain.install(script, found, stack)
        fake_langchain.start(job, found)
    return script


def test_top_level_react_agent_calls_the_tool() -> None:
    job = make_job(("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent"),))
    script = run(job, langchain_apps.react("finance-agent", [langchain_apps.execute_trade]))
    assert langchain_apps.CALLS == [("execute_trade", {"order_id": "o-1"}, "none")]
    assert script.window_start is not None
    assert script.window_end is not None
    assert script.problems == []


def test_react_agent_as_a_node_of_a_named_graph() -> None:
    job = make_job(
        ("boss", "boss:researcher", "boss:researcher:agent"),
        (
            Step(agent="boss", kind="pass", target="boss:researcher"),
            Step(agent="boss:researcher", kind="pass", target="boss:researcher:agent"),
            tool_step("boss:researcher:agent"),
        ),
    )
    script = run(job, langchain_apps.boss_graph([langchain_apps.execute_trade]))
    assert [c[0] for c in langchain_apps.CALLS] == ["execute_trade"]
    assert script.called == ["boss:researcher:agent"]


@pytest.mark.parametrize("name", ["execute_trade", "aexecute_trade"])
def test_contextvar_is_visible_in_sync_and_async_tools(name: str) -> None:
    job = make_job(
        ("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent", name),)
    )
    agent = langchain_apps.react(
        "finance-agent", [langchain_apps.execute_trade, langchain_apps.aexecute_trade]
    )
    token = langchain_apps.IDENT.set("alice")
    try:
        run(job, agent)
    finally:
        langchain_apps.IDENT.reset(token)
    calls = list(langchain_apps.CALLS)
    assert calls == [(name, {"order_id": "o-1"}, "alice")]


def test_agent_invoked_inside_a_tool_body_is_not_a_wrong_agent() -> None:
    job = make_job(
        ("outer", "outer:agent", "inner"),
        (
            tool_step("outer:agent", "ask_inner", {"question": "go"}),
            tool_step("inner"),
        ),
    )
    script = run(job, langchain_apps.react("outer", [langchain_apps.ask_inner]))
    assert langchain_apps.CALLS == []
    assert script.called[0] == "outer:agent"
    assert "inner" not in script.called
    assert script.problems == []
    assert script.observation(door_configured=False).side_effect_calls == 0


def test_graph_without_messages_input_is_not_run() -> None:
    job = make_job(("plain", "plain:n"), (tool_step("plain:n"),))
    with pytest.raises(NotRun, match="does not take a 'messages' input"):
        run(job, langchain_apps.plain_graph())


def test_missing_patch_point_is_not_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(BaseChatModel, "_should_stream")
    job = make_job(("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent"),))
    script, found = setup(
        job, langchain_apps.react("finance-agent", [langchain_apps.execute_trade])
    )
    with contextlib.ExitStack() as stack:
        fake_langchain.install(script, found, stack)
        assert "changed how chat models are called" in str(fake_langchain._reason)
        assert not hasattr(BaseChatModel, "_should_stream")
        with pytest.raises(NotRun, match="changed how chat models are called"):
            fake_langchain.start(job, found)
    assert langchain_apps.CALLS == []


def test_methods_are_restored_after_the_stack_closes() -> None:
    before = {name: BaseChatModel.__dict__[name] for name in PATCHED}
    job = make_job(("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent"),))
    script, found = setup(job, None)
    with contextlib.ExitStack() as stack:
        fake_langchain.install(script, found, stack)
        assert all(BaseChatModel.__dict__[name] is not before[name] for name in PATCHED)
    assert all(BaseChatModel.__dict__[name] is before[name] for name in PATCHED)


def test_a_call_with_no_namespace_notes_and_ends() -> None:
    job = make_job(("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent"),))
    script, found = setup(job, None)
    with contextlib.ExitStack() as stack:
        fake_langchain.install(script, found, stack)
        result = langchain_apps.RealModel().invoke("hi")
    assert result.content == "lockwalk scripted run"
    assert script.problems == ["lockwalk could not tell which LangGraph agent called the model"]


def installed(job: ScriptedJob | None = None) -> tuple[Script, contextlib.ExitStack]:
    job = job or make_job(("a", "a:agent"), (tool_step("a:agent"),))
    script, found = setup(job, None)
    stack = contextlib.ExitStack()
    fake_langchain.install(script, found, stack)
    return script, stack


def test_every_plain_entry_point_stays_scripted() -> None:
    model = langchain_apps.RealModel()
    script, stack = installed()
    with stack:
        assert model.invoke("hi").content == "lockwalk scripted run"
        assert [c.content for c in model.stream("hi")] == ["lockwalk scripted run"]
        assert [m.content for m in model.batch(["a", "b"])] == ["lockwalk scripted run"] * 2

        async def go() -> None:
            assert [c.content async for c in model.astream("hi")] == ["lockwalk scripted run"]
            assert [m.content for m in await model.abatch(["a"])] == ["lockwalk scripted run"]

        asyncio.run(go())
    assert script.problems == ["lockwalk could not tell which LangGraph agent called the model"]


def test_v3_protocol_streaming_is_blocked_and_noted() -> None:
    model = langchain_apps.RealModel()
    script, stack = installed()
    with stack, pytest.raises(RuntimeError, match="does not support v3 protocol streaming"):
        model.stream_events("hi", version="v3")
    assert any("v3 protocol streaming" in p for p in script.problems)


def test_v3_methods_are_restored() -> None:
    names = [
        n
        for n in ("_chat_model_stream_v3", "_achat_model_stream_v3")
        if n in BaseChatModel.__dict__
    ]
    before = {n: BaseChatModel.__dict__[n] for n in names}
    _, stack = installed()
    with stack:
        assert all(BaseChatModel.__dict__[n] is not before[n] for n in names)
    assert all(BaseChatModel.__dict__[n] is before[n] for n in names)


def test_handoff_is_noted(monkeypatch: pytest.MonkeyPatch) -> None:
    job = make_job(("a", "a:agent"), (Step(agent="a:agent", kind="handoff", target="b"),))
    script, stack = installed(job)
    monkeypatch.setattr(fake_langchain, "_agent_id", lambda script, run_manager: "a:agent")
    with stack:
        langchain_apps.RealModel().invoke("hi")
    assert script.problems == [
        "LangGraph routes are decided by the graph; scripted mode does not hand off"
    ]


def test_a_second_install_starts_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fake_langchain, "_reason", "stale reason")
    _, stack = installed()
    with stack:
        assert fake_langchain._reason is None


class BindingModel(langchain_apps.RealModel):
    """Like a real provider model: bind_tools puts the tools into the call kwargs."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        from langchain_core.utils.function_calling import convert_to_openai_tool

        return self.bind(tools=[convert_to_openai_tool(t) for t in tools], **kwargs)


def binding_react(name: str, tools: list[Any]) -> Any:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # create_react_agent is deprecated in LangGraph 1.x
        from langgraph.prebuilt import create_react_agent  # ty: ignore[deprecated]

        return create_react_agent(BindingModel(), tools, name=name)  # ty: ignore[deprecated]


def test_a_bound_tool_is_offered_and_called() -> None:
    job = make_job(("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent"),))
    script = run(job, binding_react("finance-agent", [langchain_apps.execute_trade]))
    assert langchain_apps.CALLS == [("execute_trade", {"order_id": "o-1"}, "none")]
    assert script.problems == []


def test_a_tool_that_is_not_bound_is_not_offered_and_not_run() -> None:
    # The model binds real tools, so _bound_tool_names returns names (not None) and the
    # step's tool, which is not among them, ends the turn with a note.
    job = make_job(("finance-agent", "finance-agent:agent"), (tool_step("finance-agent:agent"),))
    script = run(job, binding_react("finance-agent", [langchain_apps.ask_inner]))
    assert langchain_apps.CALLS == []
    assert any("was not offered tool 'execute_trade'" in p for p in script.problems)
    assert script.window_start is None
    assert script.observation(door_configured=False).not_run is not None
