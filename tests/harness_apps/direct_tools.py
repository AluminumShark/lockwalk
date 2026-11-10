"""Tiny tools of every kind for the harness direct-call tests."""

from agents import function_tool
from agno.tools import tool as agno_tool
from langchain_core.tools import tool as lc_tool
from pydantic_ai import Agent, RunContext

CALLS: list[tuple[str, dict]] = []


def reset() -> None:
    CALLS.clear()


def _work(label: str, **args) -> str:
    CALLS.append((label, args))
    if args.get("order_id") == "deny":
        raise PermissionError("denied by the door")
    return "ok"


def plain_function(order_id: str) -> str:
    """Place an order."""
    return _work("function", order_id=order_id)


async def plain_async(order_id: str) -> str:
    """Place an order, async."""
    return _work("function_async", order_id=order_id)


@function_tool
def openai_sync(order_id: str) -> str:
    """Place an order."""
    return _work("openai", order_id=order_id)


@function_tool
async def openai_async(order_id: str) -> str:
    """Place an order, async."""
    return _work("openai_async", order_id=order_id)


@lc_tool
def lc_sync(order_id: str) -> str:
    """Place an order."""
    return _work("langchain", order_id=order_id)


@lc_tool
async def lc_async(order_id: str) -> str:
    """Place an order, async."""
    return _work("langchain_async", order_id=order_id)


@agno_tool
def agno_sync(order_id: str) -> str:
    """Place an order."""
    return _work("agno", order_id=order_id)


@agno_tool
async def agno_async(order_id: str) -> str:
    """Place an order, async."""
    return _work("agno_async", order_id=order_id)


_agent = Agent(None)


@_agent.tool_plain
def pydantic_plain(order_id: str) -> str:
    """Place an order."""
    return _work("pydantic", order_id=order_id)


@_agent.tool_plain
async def pydantic_async(order_id: str) -> str:
    """Place an order, async."""
    return _work("pydantic_async", order_id=order_id)


@_agent.tool
def pydantic_ctx(ctx: RunContext[object], order_id: str) -> str:
    """Place an order, with a run context."""
    return _work("pydantic_ctx", order_id=order_id)


def pydantic_tool(name: str):
    return _agent._function_toolset.tools[name]


class Unknown:
    """Neither callable nor shaped like a tool."""
