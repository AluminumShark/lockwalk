"""Scripted OpenAI-compatible model server for the Hermes recorder (stdlib only).

Usage: python fake_model.py PORT SCRATCH_DIR
Binds 127.0.0.1 only. There is no real model: the reply is chosen by a marker in the first
user message and by the number of tool messages already in the conversation.

  [DELEGATE]      main agent: delegate_task once, then a final text
  [DELEGATE-SUB]  sub-agent : one harmless terminal command, then a final text
  [DANGER]        terminal: remove a directory inside SCRATCH_DIR, then a final text

Served paths: POST /v1/chat/completions (stream and non-stream) and GET /v1/models. Anything
else gets 404. The log (env FAKE_LOG) holds roles and tool names only, never message content.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("FAKE_LOG", "fake_model.log")
MARKER = "lockwalk-fake-model"  # owned_by in /v1/models; record.sh probes for it
USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


def checked_scratch(argv: list[str]) -> str:
    """The scratch folder the dangerous command removes, or exit. It must be a real, absolute
    folder whose resolved path contains "lockwalk", and never "/"."""
    if len(argv) < 3 or not argv[2]:
        sys.exit("usage: python fake_model.py PORT SCRATCH_DIR (SCRATCH_DIR is required)")
    path = argv[2]
    resolved = os.path.realpath(path)
    if not os.path.isabs(path) or resolved == "/" or "lockwalk" not in resolved:
        sys.exit("SCRATCH_DIR must be absolute, not /, and its real path must contain 'lockwalk'")
    return resolved


SCRATCH = ""  # set from the command line at startup, after checked_scratch()


def log(entry: dict) -> None:
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def text_of(message: dict) -> str:
    content = message.get("content")
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content or ""


def decide(body: dict) -> tuple[dict, str]:
    """Return (reply, tag). A reply is {"text": ...} or {"call": (name, arguments)}."""
    messages = body.get("messages", [])
    if not body.get("tools"):
        return {"text": "ok"}, "aux"  # auxiliary calls (titles and so on) offer no tools
    first_user = next((text_of(m) for m in messages if m.get("role") == "user"), "")
    steps = sum(1 for m in messages if m.get("role") == "tool")
    for marker in ("[DELEGATE-SUB]", "[DELEGATE]", "[DANGER]"):
        if marker in first_user:
            break
    else:
        return {"text": "done"}, "unknown"
    if steps > 0:
        return {"text": "finished"}, marker
    if marker == "[DELEGATE]":
        task = {"goal": "[DELEGATE-SUB] run one harmless echo and report", "context": "demo"}
        return {"call": ("delegate_task", {"tasks": [task]})}, marker
    if marker == "[DELEGATE-SUB]":
        return {"call": ("terminal", {"command": "echo hello"})}, marker
    victim = shlex.quote(os.path.join(SCRATCH, "victim"))
    return {"call": ("terminal", {"command": f"rm -rf {victim}"})}, marker


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        log({"get": self.path})
        if self.path.split("?")[0].rstrip("/").endswith("/v1/models"):
            model = {"id": "fake-model", "object": "model", "owned_by": MARKER}
            return self._send(200, {"object": "list", "data": [model]})
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length < 0 or length > 10_000_000:
                raise ValueError("bad Content-Length")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body is not an object")
        except ValueError:
            return self._send(400, {"error": "bad request"})
        if self.path.split("?")[0] != "/v1/chat/completions":
            log({"post_unhandled": self.path})
            return self._send(404, {"error": "not found"})
        reply, tag = decide(body)
        log(
            {
                "tag": tag,
                "stream": bool(body.get("stream")),
                "roles": [m.get("role") for m in body.get("messages", [])],
                "tools_offered": len(body.get("tools") or []),
                "reply": ("call:" + reply["call"][0]) if "call" in reply else "text",
            }
        )
        cid = "chatcmpl-" + uuid.uuid4().hex[:12]
        if "call" in reply:
            name, args = reply["call"]
            call = {
                "id": "call_" + uuid.uuid4().hex[:10],
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)},
            }
            message = {"role": "assistant", "content": None, "tool_calls": [call]}
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": reply["text"]}
            finish = "stop"
        if not body.get("stream"):
            choice = {"index": 0, "message": message, "finish_reason": finish}
            return self._send(
                200,
                {
                    "id": cid,
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": "fake-model",
                    "choices": [choice],
                    "usage": USAGE,
                },
            )
        self._stream(cid, message, finish)

    def _stream(self, cid: str, message: dict, finish: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def write(data: bytes) -> None:
            self.wfile.write(b"%x\r\n" % len(data) + data + b"\r\n")
            self.wfile.flush()

        def chunk(delta: dict, fin: str | None = None, usage: dict | None = None) -> None:
            obj = {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": "fake-model",
                "choices": [{"index": 0, "delta": delta, "finish_reason": fin}],
            }
            if usage:
                obj["usage"] = usage
            write(("data: " + json.dumps(obj) + "\n\n").encode())

        chunk({"role": "assistant", "content": ""})
        if "tool_calls" in message:
            call = message["tool_calls"][0]
            head = {"name": call["function"]["name"], "arguments": ""}
            chunk(
                {
                    "tool_calls": [
                        {"index": 0, "id": call["id"], "type": "function", "function": head}
                    ]
                }
            )
            chunk(
                {
                    "tool_calls": [
                        {"index": 0, "function": {"arguments": call["function"]["arguments"]}}
                    ]
                }
            )
        else:
            chunk({"content": message["content"]})
        chunk({}, finish, USAGE)
        write(b"data: [DONE]\n\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


if __name__ == "__main__":
    SCRATCH = checked_scratch(sys.argv)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
