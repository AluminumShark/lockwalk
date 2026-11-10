"""Scripted fake model for the OpenAI Agents SDK.

Known limit: an agent lockwalk did not find (for example, one built inside a tool) that
already holds a real Model instance, not None or a string, is not covered by the fallback
provider. The network guard is then the only protection. The equivalent case for Pydantic AI
is covered by ALLOW_MODEL_REQUESTS (see fake_pydantic).
"""

import asyncio
import contextlib
import itertools
import json
import sys
from typing import Any, cast

from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import SCRIPTED_TEXT, ScriptedJob
from lockwalk.harness.script import Final, Handoff, NotRun, Script, ToolCall

_model_class: type | None = None
_provider_class: type | None = None
_current_script: Script | None = None  # set by install, cleared by the stack
_ids = itertools.count(1)


def _build_model_class() -> type:
    """The Model subclass, built once so the SDK is imported lazily."""
    global _model_class
    if _model_class is not None:
        return _model_class

    from agents.items import ModelResponse
    from agents.models.interface import Model, ModelProvider
    from agents.usage import Usage
    from openai.types.responses import (
        ResponseFunctionToolCall,
        ResponseOutputMessage,
        ResponseOutputText,
    )

    def final(text: str) -> list[Any]:
        return [
            ResponseOutputMessage(
                id=f"msg_lockwalk_{next(_ids)}",
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text=text, annotations=[])],
            )
        ]

    def call(name: str, arguments: str) -> list[Any]:
        return [
            ResponseFunctionToolCall(
                type="function_call",
                call_id=f"call_lockwalk_{next(_ids)}",
                name=name,
                arguments=arguments,
            )
        ]

    class ScriptedModel(Model):  # type: ignore[misc]
        def __init__(self, script: Script, agent_id: str) -> None:
            self._script = script
            self._agent_id = agent_id

        async def get_response(
            self,
            system_instructions: Any,
            input: Any,
            model_settings: Any,
            tools: Any,
            output_schema: Any,
            handoffs: Any,
            tracing: Any,
            **_kwargs: Any,
        ) -> Any:
            output = self._answer(
                [getattr(t, "name", None) for t in tools or ()], list(handoffs or ())
            )
            return ModelResponse(output=output, usage=Usage(), response_id=None)

        def _answer(self, tool_names: list[Any], handoffs: list[Any]) -> list[Any]:
            script, agent_id = self._script, self._agent_id
            action = script.act(agent_id, {n for n in tool_names if isinstance(n, str)})
            if isinstance(action, ToolCall):
                return call(action.name, json.dumps(action.args))
            if isinstance(action, Handoff):
                for handoff in handoffs:
                    if getattr(handoff, "agent_name", None) == action.target:
                        return call(str(handoff.tool_name), "{}")
                script.note(f"agent {agent_id!r} was not offered a handoff to {action.target!r}")
                return final(SCRIPTED_TEXT)
            assert isinstance(action, Final)
            return final(action.text)

        def stream_response(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("lockwalk scripted mode does not stream")

    class FallbackModel(ScriptedModel):
        """For an agent lockwalk did not find: it never reaches a real model."""

        def __init__(self, script: Script) -> None:
            super().__init__(script, "")

        def _answer(self, tool_names: list[Any], handoffs: list[Any]) -> list[Any]:
            self._script.note(
                "an agent lockwalk did not find asked for a model; it got the final answer"
            )
            return final(SCRIPTED_TEXT)

    class ScriptedProvider(ModelProvider):  # type: ignore[misc]
        def __init__(self, script: Script) -> None:
            self._script = script

        def get_model(self, model_name: str | None) -> Any:
            return FallbackModel(self._script)

    global _provider_class
    _provider_class = ScriptedProvider
    _model_class = ScriptedModel
    return ScriptedModel


def _clear_script() -> None:
    global _current_script
    _current_script = None


def install(script: Script, found: Found, stack: contextlib.ExitStack) -> None:
    """Replace the model of every agent of this framework with one that answers from script.

    Does nothing when the framework was never imported (it is not in sys.modules).
    Undo goes on the stack.
    """
    if "agents" not in sys.modules:
        return
    import agents

    # Read the SDK's manual switch (private, so guarded) to put it back afterwards.
    provider = agents.tracing.get_trace_provider()
    old_tracing = getattr(provider, "_manual_disabled", None)
    if isinstance(old_tracing, bool):
        stack.callback(agents.set_tracing_disabled, old_tracing)
    agents.set_tracing_disabled(True)
    global _current_script
    _current_script = script
    stack.callback(_clear_script)
    model_class = _build_model_class()
    for agent_id, obj in found.agents.items():
        if found.frameworks.get(agent_id) != "openai_agents":
            continue
        holder = cast(Any, obj)
        old = holder.model
        holder.model = model_class(script, agent_id)
        stack.callback(setattr, holder, "model", old)


def start(job: ScriptedJob, found: Found) -> None:
    """Run job.route[0] to the end. NotRun when this framework cannot run the route."""
    from agents import RunConfig, Runner

    _build_model_class()
    if _provider_class is None or _current_script is None:
        raise NotRun("the OpenAI Agents SDK fake model was not installed")
    # Agents lockwalk did not find (model None or a string) get a fake, not a real client.
    config = RunConfig(tracing_disabled=True, model_provider=_provider_class(_current_script))
    agent = found.agents[job.route[0]]
    max_turns = 4 * len(job.route) + 4
    asyncio.run(
        Runner.run(
            cast(Any, agent),
            SCRIPTED_TEXT,
            max_turns=max_turns,
            run_config=config,
        )
    )
