"""Script: what each fake model answers, and the tool's window."""

from lockwalk.harness.events import EventLog
from lockwalk.harness.protocol import SCRIPTED_TEXT, ScriptedJob, Step
from lockwalk.harness.script import Final, Handoff, Script, ToolCall

USER = {"type": "user", "id": "alice"}


def job(**extra: object) -> ScriptedJob:
    data: dict[str, object] = {
        "case_id": "CASE-1",
        "route": ("supervisor", "finance-agent", "trade-agent"),
        "tool": "execute_trade",
        "args": {"order_id": "o-1"},
        "subject": USER,
        "steps": (
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
        ),
    }
    data.update(extra)
    return ScriptedJob.model_validate(data)


def test_tool_not_offered_ends_the_turn_and_never_opens_the_window() -> None:
    script = Script(job(), EventLog())
    script.act("supervisor")
    script.act("finance-agent", {"ask_trade_agent"})
    assert script.act("trade-agent", {"other_tool"}) == Final()
    assert script.window_start is None
    assert script.problems == ["agent 'trade-agent' was not offered tool 'execute_trade'"]
    not_run = script.observation(door_configured=False).not_run
    assert not_run is not None and "was not offered tool 'execute_trade'" in not_run
    assert script.act("trade-agent", {"execute_trade"}) == Final()  # it already acted


def test_offered_tool_opens_the_window() -> None:
    script = Script(job(), EventLog())
    script.act("supervisor")
    script.act("finance-agent")
    assert script.act("trade-agent", ["execute_trade"]) == ToolCall(
        "execute_trade", {"order_id": "o-1"}
    )
    assert script.window_start is not None


def test_each_agent_takes_its_step_once_then_ends() -> None:
    log = EventLog()
    script = Script(job(), log)
    assert script.act("supervisor") == Handoff("finance-agent")
    assert script.act("finance-agent") == ToolCall("ask_trade_agent", {"input": SCRIPTED_TEXT})
    assert script.act("trade-agent") == ToolCall("execute_trade", {"order_id": "o-1"})
    assert script.window_start is not None and script.window_end is None
    log.door({"subject": USER, "decision": True})
    log.side_effect("execute_trade")
    assert script.act("trade-agent") == Final()  # the tool returned
    assert script.window_end is not None
    assert script.act("finance-agent") == Final()
    assert script.act("someone-else") == Final()
    seen = script.observation(door_configured=True)
    assert seen.not_run is None
    assert seen.side_effect_calls == 1
    assert seen.door_calls == ({"subject": USER, "decision": True},)
    assert seen.bypass is False
    assert script.called == ["supervisor", "finance-agent", "trade-agent", "someone-else"]


def test_a_run_that_never_asks_for_the_tool_is_not_run() -> None:
    script = Script(job(), EventLog())
    script.act("supervisor")
    script.note("agent 'supervisor' was not offered a handoff to 'finance-agent'")
    seen = script.observation(door_configured=True)
    assert seen.not_run is not None
    assert "did not reach 'execute_trade'" in seen.not_run
    assert "supervisor" in seen.not_run and "not offered a handoff" in seen.not_run


def test_a_pass_step_ends_the_turn() -> None:
    script = Script(
        job(
            route=("boss", "boss:agent"),
            steps=(
                Step(agent="boss", kind="pass", target="boss:agent"),
                Step(agent="boss:agent", kind="tool", target="execute_trade", tool="execute_trade"),
            ),
        ),
        EventLog(),
    )
    assert script.act("boss") == Final()
    assert script.act("boss:agent") == ToolCall("execute_trade", {})


def test_run_path_uses_the_whole_run_as_the_window() -> None:
    log = EventLog()
    script = Script(job(use_run_path=True, steps=()), log)
    script.open_whole_run()
    assert script.observation(door_configured=True).not_run is not None  # nothing happened
    log.door({"subject": USER, "decision": False})
    seen = script.observation(door_configured=True)
    assert seen.not_run is None and seen.side_effect_calls == 0


def test_open_whole_run_starts_after_earlier_door_calls() -> None:
    log = EventLog()
    script = Script(job(use_run_path=True, steps=()), log)
    log.door({"subject": USER, "decision": True})  # e.g. made while entering set_identity
    script.open_whole_run()
    log.side_effect("execute_trade")
    assert script.observation(door_configured=True).bypass is True
