"""LangGraph apps for the scripted fake model tests."""

import contextvars
import warnings
from typing import Any, TypedDict

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langgraph.graph import START, MessagesState, StateGraph

IDENT: contextvars.ContextVar[str] = contextvars.ContextVar("ident", default="none")
CALLS: list[tuple[str, dict[str, Any], str]] = []  # (tool, args, identity seen)


class RealModel(BaseChatModel):
    """Stands in for a real provider model: every way to reach the network raises."""

    @property
    def _llm_type(self) -> str:
        return "real-model"

    def _generate(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the real model was called")

    async def _agenerate(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the real model was called")

    def _stream(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the real model was called (_stream)")

    async def _astream(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the real model was called (_astream)")
        yield  # pragma: no cover

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self


@tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    CALLS.append(("execute_trade", {"order_id": order_id}, IDENT.get()))
    return "done"


@tool
async def aexecute_trade(order_id: str) -> str:
    """Execute a trade, async."""
    CALLS.append(("aexecute_trade", {"order_id": order_id}, IDENT.get()))
    return "done"


def react(name: str | None, tools: list[Any]) -> Any:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # create_react_agent is deprecated in LangGraph 1.x
        from langgraph.prebuilt import create_react_agent  # ty: ignore[deprecated]

        return create_react_agent(RealModel(), tools, name=name)  # ty: ignore[deprecated]


def boss_graph(tools: list[Any]) -> Any:
    """A StateGraph named boss with the react agent as node researcher."""
    graph = StateGraph(MessagesState)  # ty: ignore[invalid-argument-type]
    graph.add_node("researcher", react(None, tools))
    graph.add_edge(START, "researcher")
    return graph.compile(name="boss")


@tool
def ask_inner(question: str) -> str:
    """Delegate to a react agent from inside a tool body."""
    inner = react("inner", [execute_trade])
    result = inner.invoke({"messages": [HumanMessage(question)]})
    return str(result["messages"][-1].content)


class _PlainState(TypedDict):
    x: int


def _bump(state: _PlainState) -> dict[str, int]:
    return {"x": 1}


def plain_graph() -> Any:
    """A graph whose state has no messages."""
    graph = StateGraph(_PlainState)  # ty: ignore[invalid-argument-type]
    graph.add_node("n", _bump)
    graph.add_edge(START, "n")
    return graph.compile(name="plain")
