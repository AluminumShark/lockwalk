"""Minimal MCP server for the finance demo.

It exposes four stub tools. delete_portfolio is deliberately missing from registry.yaml and
security-spec.yaml, so lockwalk should flag it. lockwalk only ever calls tools/list. If any
tool is called anyway, the server writes the tool name to the --marker file (when given)
and raises, so tests can prove that no call happened.

Run over stdio:            python mcp_server.py [--marker PATH]
Run over streamable HTTP:  python mcp_server.py --http PORT [--marker PATH]
"""

import argparse
from pathlib import Path
from typing import NoReturn

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

server = MCPServer("finance-tools", log_level="WARNING")
call_marker: Path | None = None


def _refuse(tool_name: str) -> NoReturn:
    if call_marker is not None:
        call_marker.write_text(tool_name, encoding="utf-8")
    raise RuntimeError(f"demo tool {tool_name!r} must never be called")


@server.tool(annotations=ToolAnnotations(read_only_hint=True))
def get_stock_price(symbol: str) -> str:
    """Return the price of a stock symbol (demo stub)."""
    _refuse("get_stock_price")


@server.tool(annotations=ToolAnnotations(read_only_hint=True))
def read_portfolio(portfolio_id: str) -> str:
    """Read a portfolio (demo stub)."""
    _refuse("read_portfolio")


@server.tool(annotations=ToolAnnotations(destructive_hint=True, open_world_hint=True))
def execute_trade(order_id: str) -> str:
    """Execute a trade order (demo stub)."""
    _refuse("execute_trade")


# Deliberately missing from registry.yaml and security-spec.yaml, so lockwalk flags it.
@server.tool(annotations=ToolAnnotations(destructive_hint=True))
def delete_portfolio(portfolio_id: str) -> str:
    """Delete a portfolio (demo stub)."""
    _refuse("delete_portfolio")


def main() -> None:
    global call_marker
    parser = argparse.ArgumentParser(description="Finance demo MCP server (stub tools).")
    parser.add_argument("--http", type=int, metavar="PORT", help="serve streamable HTTP")
    parser.add_argument("--marker", type=Path, help="file written if any tool is ever called")
    args = parser.parse_args()
    call_marker = args.marker
    if args.http is not None:
        # Loopback only: this server exposes destructive (stub) tools.
        server.run("streamable-http", host="127.0.0.1", port=args.http)
    else:
        server.run()


if __name__ == "__main__":
    main()
