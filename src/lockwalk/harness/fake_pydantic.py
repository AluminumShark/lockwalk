"""Scripted fake model for Pydantic AI."""

import asyncio
import contextlib
import sys
from typing import Any, cast

from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import SCRIPTED_TEXT, ScriptedJob
from lockwalk.harness.script import Final, Handoff, Script, ToolCall


def _make_fn(script: Script, agent_id: str) -> Any:
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

    def fn(messages: Any, info: Any) -> Any:
        action = script.act(agent_id, {t.name for t in info.function_tools})
        if isinstance(action, ToolCall):
            part = ToolCallPart(tool_name=action.name, args=action.args)
            return ModelResponse(parts=[part])
        elif isinstance(action, Handoff):
            script.note("Pydantic AI agents have no handoffs")
        else:
            assert isinstance(action, Final)
            if not info.allow_text_output:
                script.note(
                    f"agent {agent_id!r} has a structured output type; "
                    "lockwalk ends its turn with text anyway"
                )
            return ModelResponse(parts=[TextPart(action.text)])
        return ModelResponse(parts=[TextPart(SCRIPTED_TEXT)])

    return fn


def install(script: Script, found: Found, stack: contextlib.ExitStack) -> None:
    """Replace the model of every agent of this framework with one that answers from script.

    Does nothing when the framework was never imported (it is not in sys.modules).
    Undo goes on the stack.
    """
    if "pydantic_ai" not in sys.modules:
        return
    import pydantic_ai.models as models
    from pydantic_ai.models.function import FunctionModel

    # Real models check this flag; FunctionModel does not. It covers agents that were not
    # found, and runs in plain threads that the per-agent override does not reach.
    stack.callback(setattr, models, "ALLOW_MODEL_REQUESTS", models.ALLOW_MODEL_REQUESTS)
    models.ALLOW_MODEL_REQUESTS = False

    for agent_id, obj in found.agents.items():
        if found.frameworks.get(agent_id) != "pydantic_ai":
            continue
        model = FunctionModel(_make_fn(script, agent_id))
        stack.enter_context(cast(Any, obj).override(model=model))


def start(job: ScriptedJob, found: Found) -> None:
    """Run job.route[0] to the end. NotRun when this framework cannot run the route."""
    agent = found.agents[job.route[0]]
    asyncio.run(cast(Any, agent).run(SCRIPTED_TEXT))
