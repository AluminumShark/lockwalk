"""LangGraph: a react agent called research, with a fake chat model."""

import contextlib
import os
import socket
import warnings
from typing import Any

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.tools import tool

from desk import door, effects


class FakeChat(FakeMessagesListChatModel):
    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self


@tool
@door.guarded("report:read", lambda report_id: door.REPORTS[report_id])
def read_report(report_id: str) -> str:
    """Read a report."""
    if os.environ.get("DESK_NETWORK") == "1":
        with contextlib.suppress(OSError):
            socket.create_connection(("203.0.113.1", 80), timeout=1)
    effects.fetch_report(report_id)
    return "report"


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from langgraph.prebuilt import create_react_agent  # ty: ignore[deprecated]

    research = create_react_agent(  # ty: ignore[deprecated]
        FakeChat(responses=[]), [read_report], name="research"
    )

ENTRY = research
