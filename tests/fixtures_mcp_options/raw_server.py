"""A bare JSON-RPC stdio MCP server whose tools/list reply can be made unusable.

Usage: python raw_server.py MODE [N]

Modes:
  bad-schema   answer tools/list with a reply the SDK's schema rejects.
  pages N      serve N pages of one tool each, then end the list (N pages in total).
  endless      always return a next cursor.
  page2-fails  a valid first page with a next cursor, then a schema-breaking second page.
  list-error   answer tools/list with a JSON-RPC error.
  list-hangs   never answer tools/list.
"""

import json
import sys
import time


def reply(message_id: object, result: object) -> None:
    print(json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}), flush=True)


def refuse(message_id: object) -> None:
    error = {"code": -32601, "message": "method not found"}
    print(json.dumps({"jsonrpc": "2.0", "id": message_id, "error": error}), flush=True)


def tool(name: str) -> dict[str, object]:
    return {"name": name, "inputSchema": {"type": "object"}}


def main() -> None:
    mode = sys.argv[1]
    total = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    for line in sys.stdin:
        message = json.loads(line)
        method = message.get("method")
        if method == "initialize":
            version = message["params"]["protocolVersion"]
            reply(
                message["id"],
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "raw", "version": "1"},
                },
            )
        elif method not in ("tools/list", "ping") and "id" in message:
            refuse(message["id"])  # for example server/discover: answer fast, do not stall
        elif method == "tools/list":
            cursor = (message.get("params") or {}).get("cursor")
            page = int(cursor) if cursor else 1
            if mode == "bad-schema":
                reply(message["id"], {"tools": "not a list"})
            elif mode == "list-error":
                print(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "error": {"code": -32603, "message": "boom"},
                        }
                    ),
                    flush=True,
                )
            elif mode == "list-hangs":
                time.sleep(60)
            elif mode == "endless":
                reply(message["id"], {"tools": [tool(f"t{page}")], "nextCursor": str(page + 1)})
            elif mode == "page2-fails":
                if page == 1:
                    reply(message["id"], {"tools": [tool("t1")], "nextCursor": "2"})
                else:
                    reply(message["id"], {"tools": "not a list"})
            else:  # pages
                last = page >= total
                payload: dict[str, object] = {"tools": [tool(f"t{page}")]}
                if not last:
                    payload["nextCursor"] = str(page + 1)
                reply(message["id"], payload)


main()
