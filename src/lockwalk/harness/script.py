"""What the fake models answer in scripted mode.

One Script drives one run. Every fake model, whatever its framework, calls Script.act()
with the inventory id of the agent it serves. The first time, the answer is that agent's step;
after that, it is a fixed final text, so each agent ends its turn once its call returned.
"""

import threading
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from lockwalk.harness.events import EventLog
from lockwalk.harness.protocol import MAX_DOOR_CALLS, SCRIPTED_TEXT, Observation, ScriptedJob


class NotRun(Exception):
    """lockwalk cannot run this route in scripted mode; the message says why."""


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Handoff:
    target: str  # the agent id to hand the conversation to


@dataclass(frozen=True)
class Final:
    text: str = SCRIPTED_TEXT


Action = ToolCall | Handoff | Final


class Script:
    def __init__(self, job: ScriptedJob, log: EventLog) -> None:
        self.job = job
        self._log = log
        self._steps = {step.agent: step for step in job.steps}
        self._acted: set[str] = set()
        self._lock = threading.Lock()
        self.start = log.mark()
        self.window_start: int | None = None  # set when the last agent asks for the tool
        self.window_end: int | None = None  # set when its model is asked again
        self.called: list[str] = []  # agents whose model was asked, in first-call order
        self.problems: list[str] = []

    def act(self, agent_id: str, offered: Collection[str] | None = None) -> Action:
        """The next answer of agent_id's model.

        offered is the set of tool names the framework offers this agent, or None when the
        fake cannot tell. A tool step whose tool is not offered ends the turn with a note and
        does not open the tool's window, so the run reads as not reached, never as a clean one.
        """
        with self._lock:
            if agent_id not in self.called:
                self.called.append(agent_id)
            last = self.job.route[-1]
            if agent_id == last and self.window_start is not None and self.window_end is None:
                self.window_end = self._log.mark()  # the tool has returned
            step = self._steps.get(agent_id)
            if step is None or agent_id in self._acted:
                return Final()
            self._acted.add(agent_id)
            if step.kind == "pass":
                return Final()
            if step.kind == "handoff":
                return Handoff(step.target)
            name = step.tool or step.target
            if offered is not None and name not in offered:
                problem = f"agent {agent_id!r} was not offered tool {name!r}"
                if problem not in self.problems:
                    self.problems.append(problem)
                return Final()
            if step.kind == "tool":
                self.window_start = self._log.mark()
            return ToolCall(name, dict(step.args or {}))

    def note(self, problem: str) -> None:
        """A fake model could not take its step, for example the tool was not offered."""
        with self._lock:
            if problem not in self.problems:
                self.problems.append(problem)

    def open_whole_run(self) -> None:
        """run_path drives the route itself, so the whole run is the tool's window."""
        with self._lock:
            self.window_start = self._log.mark()

    def observation(self, *, door_configured: bool) -> Observation:
        if self.window_start is None:
            called = ", ".join(self.called) if self.called else "none"
            text = (
                f"the scripted run did not reach {self.job.tool!r} "
                f"(agents whose model was asked: {called})"
            )
            if self.problems:
                text = f"{text}: {'; '.join(self.problems)}"
            return Observation(not_run=text)
        window = self._log.window(
            self.job.tool,
            self.window_start,
            self.window_end,
            door_configured=door_configured,
            keep=MAX_DOOR_CALLS,
        )
        if self.job.use_run_path and window.side_effect_calls == 0 and not window.door_calls:
            return Observation(not_run="run_path did not reach the door or the tool's side effect")
        return Observation(
            side_effect_calls=window.side_effect_calls,
            door_calls=window.door_calls,
            door_calls_dropped=window.door_calls_dropped,
            bypass=window.bypass,
        )
