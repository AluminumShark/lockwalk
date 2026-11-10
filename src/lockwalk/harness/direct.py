"""Read a tool's kind and schema, and call it the framework's way.

Direct mode calls the public entry point each framework offers, with no model involved.
The OpenAI Agents SDK and Agno swallow tool exceptions by design; what comes back is
reported as it is, and no private attribute is read to undo that.
"""

import asyncio
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from lockwalk.harness.protocol import ToolInfo, ToolKind
from lockwalk.jsonvalues import check_json_value
from lockwalk.models import MAX_QUERY_DEPTH

MAX_SCHEMA_BYTES = 256 * 1024


@dataclass(frozen=True)
class CallOutcome:
    exception: str | None = None  # type name of what the call raised
    message: str | None = None  # str() of it; the parent masks and truncates it


def tool_info(name: str, obj: object) -> ToolInfo:
    """Never raises."""
    try:
        return _tool_info(name, obj)
    except BaseException:
        return ToolInfo(
            name=name,
            kind="function",
            callable=False,
            why_not=f"lockwalk could not read tool {name!r}",
        )


def _tool_info(name: str, obj: Any) -> ToolInfo:
    kind = _kind_of(obj)
    if kind is None:
        return ToolInfo(
            name=name,
            kind="function",
            callable=False,
            why_not=f"lockwalk does not know how to call a {type(obj).__name__}",
        )
    schema = _safe(lambda: _schema(kind, obj))
    if kind == "pydantic_ai" and getattr(obj, "takes_ctx", False):
        return ToolInfo(
            name=name,
            kind=kind,
            input_schema=schema,
            callable=False,
            why_not=(
                f"Pydantic AI tool {name!r} takes a RunContext, which exists only inside a "
                "run; scripted mode tests it"
            ),
        )
    return ToolInfo(name=name, kind=kind, input_schema=schema)


def _has(obj: object, *names: str) -> bool:
    return all(hasattr(obj, n) for n in names)


def _kind_of(obj: object) -> ToolKind | None:
    if _has(obj, "on_invoke_tool", "params_json_schema"):
        return "openai_agents"
    if _has(obj, "entrypoint", "process_entrypoint"):
        return "agno"
    if _has(obj, "function", "takes_ctx", "function_schema"):
        return "pydantic_ai"
    if _has(obj, "invoke", "ainvoke", "args_schema"):
        return "langchain"
    if _has(obj, "run", "_run", "args_schema"):
        return "crewai"
    if callable(obj):
        return "function"
    return None


def _safe(read: Callable[[], Any]) -> dict[str, Any] | None:
    """Run read(); keep the result only when it is a JSON-safe dict."""
    try:
        schema = read()
        if not isinstance(schema, dict):
            return None
        check_json_value(schema, "schema", allow_null=True, max_depth=MAX_QUERY_DEPTH)
        if len(json.dumps(schema)) > MAX_SCHEMA_BYTES:
            return None
        return schema
    except BaseException:
        return None


def _schema(kind: ToolKind, obj: Any) -> Any:
    if kind == "openai_agents":
        return obj.params_json_schema
    if kind == "agno":
        obj.process_entrypoint()
        return obj.parameters
    if kind == "pydantic_ai":
        return obj.function_schema.json_schema
    if kind in ("langchain", "crewai"):
        args_schema = obj.args_schema
        if isinstance(args_schema, dict):
            return args_schema
        if args_schema is not None and hasattr(args_schema, "model_json_schema"):
            return args_schema.model_json_schema()
        if kind == "langchain":
            return obj.get_input_schema().model_json_schema()
    return None


def call(obj: object, args: Mapping[str, Any]) -> CallOutcome:
    """Call the tool once with args. Never raises: what the tool raises is returned.

    Must run with no running event loop: each call uses a fresh one (asyncio.run).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return CallOutcome(
            "RuntimeError", "lockwalk cannot call a tool from inside a running event loop"
        )
    try:
        _call(obj, args)
    except BaseException as exc:
        # KeyboardInterrupt and SystemExit become outcomes on purpose: the worker is a
        # throwaway process that the parent kills on timeout.
        if isinstance(exc, _GeneratorTool):
            return CallOutcome("TypeError", GENERATOR_MESSAGE)
        try:
            message: str | None = str(exc)
        except BaseException:
            message = None
        return CallOutcome(type(exc).__name__, message)
    return CallOutcome()


async def _await(awaitable: Any) -> Any:
    return await awaitable


GENERATOR_MESSAGE = (
    "the tool returned a generator; lockwalk does not iterate it, so the tool body did not run"
)


class _GeneratorTool(Exception):
    pass


def _reject_generator(result: Any) -> None:
    """Close a generator without iterating it and report that the body did not run."""
    if inspect.isgenerator(result):
        result.close()
        raise _GeneratorTool
    if inspect.isasyncgen(result):
        asyncio.run(_await(result.aclose()))
        raise _GeneratorTool


def _run(result: Any) -> Any:
    """Await a result on a fresh event loop when it is awaitable."""
    _reject_generator(result)
    if inspect.isawaitable(result):
        return asyncio.run(_await(result))
    return result


def _call(obj: Any, args: Mapping[str, Any]) -> None:
    kind = _kind_of(obj)
    if kind == "openai_agents":
        from agents.tool_context import ToolContext

        json_args = json.dumps(dict(args))
        context = ToolContext(
            context=None,
            tool_name=obj.name,
            tool_call_id="lockwalk-direct",
            tool_arguments=json_args,
        )
        asyncio.run(_await(obj.on_invoke_tool(context, json_args)))
    elif kind == "agno":
        from agno.tools.function import FunctionCall

        function_call = FunctionCall(function=obj, arguments=dict(args))
        if inspect.iscoroutinefunction(obj.entrypoint):
            asyncio.run(_await(function_call.aexecute()))
        else:
            function_call.execute()
    elif kind == "pydantic_ai":
        _run(obj.function(**args))
    elif kind == "langchain":
        if getattr(obj, "func", None) is None and getattr(obj, "coroutine", None) is not None:
            asyncio.run(_await(obj.ainvoke(dict(args))))
        else:
            obj.invoke(dict(args))
    elif kind == "crewai":
        obj.run(**args)
    elif kind == "function":
        _run(obj(**args))
    else:
        raise TypeError(f"lockwalk does not know how to call a {type(obj).__name__}")
