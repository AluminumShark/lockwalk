"""A tiny MCP server for tests/test_mcp_options.py. Its tools are stubs that refuse to run.

Run over stdio:            python options_server.py [options]
Run over streamable HTTP:  python options_server.py --http PORT [options]

Options:
  --report-env NAME      add a tool env_<NAME> whose description is the SHA-256 of that
                         variable's value ("unset" when it is not set). Tests can check what
                         arrived, and the value itself never shows up anywhere. The names in
                         the variable LW_REPORT_ENV (comma-separated) are reported too, for
                         stdio:// targets, which cannot pass arguments.
  --echo-env NAME        act like a careless server: copy the raw value of variable NAME into
                         the server name and a tool description.
  --leak-tool-name       with --echo-env, also add a tool named after that value.
  --require-header NAME  HTTP only: answer 401 unless header NAME equals the variable
                         LW_EXPECTED_HEADER. The 401 body is a JSON-RPC error that echoes
                         the value it received.
  --noise                print a line that is not JSON to stdout before serving (stdio).
  --server-name NAME     the name the server reports (default: options-test).
  --token VALUE          accepted and ignored, like the API token a real server may take.
"""

import argparse
import hashlib
import json
import os
from typing import NoReturn

from mcp.server.mcpserver import MCPServer
from starlette.types import ASGIApp, Receive, Scope, Send


def _refuse() -> NoReturn:
    raise RuntimeError("test tools must never be called")


def stub() -> str:
    """A stub tool."""
    _refuse()


def digest(value: str | None) -> str:
    """What --report-env puts in a description."""
    if value is None:
        return "unset"
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_server(args: argparse.Namespace) -> MCPServer:
    echoed = os.environ.get(args.echo_env, "") if args.echo_env else ""
    server = MCPServer(f"echo-{echoed}" if echoed else args.server_name, log_level="WARNING")
    server.add_tool(stub, name="stub")
    listed = [name for name in os.environ.get("LW_REPORT_ENV", "").split(",") if name]
    for name in [*args.report_env, *listed]:
        server.add_tool(stub, name=f"env_{name}", description=digest(os.environ.get(name)))
    if echoed:
        server.add_tool(stub, name="whoami", description=f"token is {echoed}")
        if args.leak_tool_name:
            server.add_tool(stub, name=f"leak_{echoed}", description="named after a secret")
    return server


class RequireHeader:
    """ASGI middleware: reject every HTTP request whose header does not match."""

    def __init__(self, app: ASGIApp, header: str, expected: str) -> None:
        self._app = app
        self._header = header.lower().encode("ascii")
        self._expected = expected.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            received = dict(scope["headers"]).get(self._header)
            if received != self._expected:
                shown = "nothing" if received is None else received.decode("latin-1")
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32001, "message": f"unauthorized: got {shown}"},
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode("ascii")),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self._app(scope, receive, send)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP test server for lockwalk.")
    parser.add_argument("--http", type=int, metavar="PORT")
    parser.add_argument("--report-env", action="append", default=[], metavar="NAME")
    parser.add_argument("--echo-env", metavar="NAME")
    parser.add_argument("--leak-tool-name", action="store_true")
    parser.add_argument("--require-header", metavar="NAME")
    parser.add_argument("--noise", action="store_true")
    parser.add_argument("--server-name", default="options-test", metavar="NAME")
    parser.add_argument("--token", metavar="VALUE")
    args = parser.parse_args()
    server = build_server(args)
    if args.http is None:
        if args.noise:
            print("this line is not JSON-RPC", flush=True)
        server.run()
        return
    import uvicorn

    app: ASGIApp = server.streamable_http_app()
    if args.require_header:
        app = RequireHeader(app, args.require_header, os.environ["LW_EXPECTED_HEADER"])
    # Loopback only.
    uvicorn.run(app, host="127.0.0.1", port=args.http, log_level="warning")


if __name__ == "__main__":
    main()
