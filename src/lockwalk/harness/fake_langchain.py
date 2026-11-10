"""Scripted fake model for the LangChain / LangGraph.

One class-level patch of BaseChatModel covers every chat model, so no agent can reach a
real provider. The calling agent is read from the LangGraph checkpoint namespace, which
is "<graph>:<uuid>|<node>:<uuid>|..." at model-call time; the names alone give the same
ids as lockwalk's static discovery ("<graph>:<node>:<inner node>"). When the namespace is
missing or does not name a node on the route, the answer is final, so the run ends
without the tool (NOT_RUN), never with a wrong agent.

Only the entry points listed in _PATCHED and _V3 are covered. A later langchain-core may add
other ways to call a model; the network guard is the second line of defense.
"""

import asyncio
import contextlib
import importlib.metadata
import itertools
import sys
from typing import Any

from lockwalk.harness.objects import Found
from lockwalk.harness.protocol import SCRIPTED_TEXT, ScriptedJob
from lockwalk.harness.script import Final, Handoff, NotRun, Script, ToolCall

_PATCHED = ("_generate_with_cache", "_agenerate_with_cache", "_should_stream")
_V3 = ("_chat_model_stream_v3", "_achat_model_stream_v3")  # patched only when present
_V3_NOTE = (
    "a chat model was called through LangChain's v3 protocol streaming, "
    "which scripted mode does not support"
)
_reason: str | None = None  # set by install() when the patch points are gone
_ids = itertools.count(1)


def _version() -> str:
    try:
        return importlib.metadata.version("langchain-core")
    except Exception:
        return "(unknown version)"


def _agent_id(script: Script, run_manager: Any) -> str | None:
    """The inventory id of the agent whose model is being called, or None when unknown."""
    try:
        metadata = getattr(run_manager, "metadata", None)
        if not isinstance(metadata, dict):
            return None
        ns = metadata.get("langgraph_checkpoint_ns") or metadata.get("checkpoint_ns")
        if not isinstance(ns, str) or not ns:
            return None
        # A node name containing ":" or "|" gives an id that matches no route agent, so the
        # run ends NOT_RUN and is never mislabeled.
        names = [part.split(":", 1)[0] for part in ns.split("|")]
        if not all(names):
            return None
        return ":".join([script.job.route[0], *names])
    except Exception:
        return None


def _bound_tool_names(kwargs: Any) -> set[str] | None:
    """Names of the tools bound to the model, or None when they cannot be read."""
    try:
        tools = kwargs.get("tools")
        if tools is None:
            return None
        names: set[str] = set()
        for tool in tools:
            if isinstance(tool, dict):
                function = tool.get("function")
                name = tool.get("name")
                if name is None and isinstance(function, dict):
                    name = function.get("name")
            else:
                name = getattr(tool, "name", None)
            if not isinstance(name, str):
                return None
            names.add(name)
        return names
    except Exception:
        return None


def _result(script: Script, run_manager: Any, kwargs: Any = None) -> Any:
    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, ChatResult

    agent_id = _agent_id(script, run_manager)
    if agent_id is None:
        script.note("lockwalk could not tell which LangGraph agent called the model")
        action: Any = Final()
    else:
        action = script.act(agent_id, _bound_tool_names(kwargs))
    if isinstance(action, ToolCall):
        message = AIMessage(
            content="",
            tool_calls=[
                {
                    "name": action.name,
                    "args": action.args,
                    "id": f"lockwalk-call-{next(_ids)}",
                    "type": "tool_call",
                }
            ],
        )
    else:
        if isinstance(action, Handoff):
            script.note(
                "LangGraph routes are decided by the graph; scripted mode does not hand off"
            )
        message = AIMessage(content=getattr(action, "text", SCRIPTED_TEXT))
    return ChatResult(generations=[ChatGeneration(message=message)])


def install(script: Script, found: Found, stack: contextlib.ExitStack) -> None:
    """Replace the model of every agent of this framework with one that answers from script.

    Does nothing when the framework was never imported (it is not in sys.modules).
    Undo goes on the stack.
    """
    global _reason
    _reason = None
    if "langchain_core" not in sys.modules:
        return
    from langchain_core.language_models.chat_models import BaseChatModel

    if not all(hasattr(BaseChatModel, name) for name in _PATCHED):
        _reason = (
            f"langchain-core {_version()} changed how chat models are called; "
            "scripted mode cannot replace the model"
        )
        return

    def scripted(
        self: Any, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> Any:
        return _result(script, run_manager, kwargs)

    async def ascripted(
        self: Any, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> Any:
        return _result(script, run_manager, kwargs)

    def no_stream(self: Any, *args: Any, **kwargs: Any) -> bool:
        return False

    def v3_blocked(self: Any, *args: Any, **kwargs: Any) -> Any:
        script.note(_V3_NOTE)
        raise RuntimeError("lockwalk scripted mode does not support v3 protocol streaming")

    async def av3_blocked(self: Any, *args: Any, **kwargs: Any) -> Any:
        script.note(_V3_NOTE)
        raise RuntimeError("lockwalk scripted mode does not support v3 protocol streaming")

    for name, blocked in (
        ("_chat_model_stream_v3", v3_blocked),
        ("_achat_model_stream_v3", av3_blocked),
    ):
        if name in BaseChatModel.__dict__:
            stack.callback(setattr, BaseChatModel, name, BaseChatModel.__dict__[name])
            setattr(BaseChatModel, name, blocked)

    # Read the originals from the class dict, so restoring puts back exactly what was there.
    originals = {name: BaseChatModel.__dict__[name] for name in _PATCHED}
    for name, value in (
        ("_generate_with_cache", scripted),
        ("_agenerate_with_cache", ascripted),
        ("_should_stream", no_stream),
    ):
        stack.callback(setattr, BaseChatModel, name, originals[name])
        setattr(BaseChatModel, name, value)


def start(job: ScriptedJob, found: Found) -> None:
    """Run job.route[0] to the end. NotRun when this framework cannot run the route."""
    if _reason is not None:
        raise NotRun(_reason)
    from langchain_core.messages import HumanMessage

    entry = job.route[0]
    graph: Any = found.agents[entry]
    try:
        properties = graph.get_input_jsonschema().get("properties", {})
    except Exception:
        properties = {}
    if "messages" not in properties:
        raise NotRun(
            f"LangGraph graph {entry!r} does not take a 'messages' input; "
            "provide run_path in the hooks file"
        )
    asyncio.run(
        graph.ainvoke(
            {"messages": [HumanMessage(SCRIPTED_TEXT)]},
            config={"recursion_limit": 4 * len(job.route) + 10},
        )
    )
