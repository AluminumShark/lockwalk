"""Agents of several frameworks for the harness object-finding tests."""

import warnings
from dataclasses import dataclass

from agents import Agent as OpenAIAgent
from agents import function_tool
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.tools import tool as lc_tool
from langgraph.graph import END, START, StateGraph
from pydantic_ai import Agent as PydanticAgent


@function_tool
def execute_trade(order_id: str) -> str:
    """Execute a trade."""
    return order_id


@function_tool
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio."""
    return portfolio_id


trade_agent = OpenAIAgent(name="trade-agent", tools=[execute_trade])
finance_agent = OpenAIAgent(
    name="finance-agent",
    tools=[
        read_portfolio,
        trade_agent.as_tool(tool_name="ask_trade_agent", tool_description="Ask trade"),
    ],
)
supervisor = OpenAIAgent(name="supervisor", handoffs=[finance_agent])

pydantic_agent = PydanticAgent(None, name="research-agent")


@pydantic_agent.tool_plain
def search_notes(query: str) -> str:
    """Search notes."""
    return query


@lc_tool
def lookup_account(account_id: str) -> str:
    """Look up an account."""
    return account_id


class FakeModel(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def react_agent(name: str):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from langgraph.prebuilt import create_react_agent  # ty: ignore[deprecated]

        return create_react_agent(  # ty: ignore[deprecated]
            FakeModel(responses=[]), [lookup_account], name=name
        )


@dataclass
class State:
    x: int


react = react_agent("lg-agent")

parent_builder = StateGraph(State)
parent_builder.add_node("worker", react)
parent_builder.add_edge(START, "worker")
parent_builder.add_edge("worker", END)
parent_graph = parent_builder.compile(name="desk")
