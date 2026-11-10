"""Subprocess side of the python policy adapter.

Run as: python -P -m lockwalk.policy._decide_worker <target>

The worker imports the user's decide() once and then answers JSON lines on stdin with JSON
lines on stdout. The user's code may print, so the real stdout is kept for the protocol and
fd 1 is pointed at stderr; the user's code also cannot read the protocol from stdin.
"""

import asyncio
import inspect
import json
import os
import sys
from collections.abc import Callable
from typing import Any, TextIO

from lockwalk.inventory._python_worker import load_module
from lockwalk.inventory.normalize import describe_error
from lockwalk.inventory.targets import TargetError, parse_target

BAD_RETURN = (
    "decide returned {name}; it must return True, False, or {{'decision': bool, 'reason': str}}"
)


def answer_for(value: object) -> dict[str, Any]:
    """Turn what decide() returned into one answer, or an error answer.

    Nothing is truncated here: the parent masks URL credentials first and then truncates, and
    the 1 MiB line cap bounds the size.
    """
    if type(value) is bool:
        return {"decision": value}
    if type(value) is dict and set(value) <= {"decision", "reason"}:
        decision = value.get("decision")
        reason = value.get("reason")
        if type(decision) is bool and (reason is None or type(reason) is str):
            return {"decision": decision, "reason": reason}
    return {"error": BAD_RETURN.format(name=type(value).__name__)}


async def _await(awaitable: Any) -> Any:
    return await awaitable


class Server:
    def __init__(self, decide: Callable[..., Any], decide_many: Callable[..., Any] | None) -> None:
        self._decide = decide
        self._decide_many = decide_many
        # One loop for the whole run, so state tied to a loop survives between questions.
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

    def _resolve(self, value: Any) -> Any:
        return self._loop.run_until_complete(_await(value)) if inspect.isawaitable(value) else value

    def _one(self, query: dict[str, Any]) -> dict[str, Any]:
        try:
            value = self._resolve(
                self._decide(query["subject"], query["action"], query["resource"], query["context"])
            )
            return answer_for(value)
        except BaseException as exc:  # the user's code may raise anything, even SystemExit
            return {"error": describe_error(exc)}

    def answers(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if self._decide_many is None:
            return [self._one(query) for query in queries]
        try:
            result = self._resolve(self._decide_many(queries))
        except BaseException as exc:
            return [{"error": describe_error(exc)} for _ in queries]
        if not isinstance(result, list) or len(result) != len(queries):
            count = len(result) if isinstance(result, list) else type(result).__name__
            message = f"decide_many returned {count} answers for {len(queries)} questions"
            return [{"error": message} for _ in queries]
        return [answer_for(item) for item in result]


def resolve(target: str) -> tuple[Callable[..., Any], Callable[..., Any] | None]:
    module_part, parts, _ = parse_target(target)
    module = load_module(module_part)
    value: Any = module
    for part in parts:
        try:
            value = getattr(value, part)
        except AttributeError as exc:
            raise TargetError(f"{module_part!r} has no attribute {'.'.join(parts)!r}") from exc
    if not callable(value):
        raise TargetError(f"{'.'.join(parts)!r} is not callable")
    many = getattr(module, "decide_many", None) if len(parts) == 1 else None
    return value, many if callable(many) else None


def send(proto: TextIO, message: dict[str, Any]) -> None:
    proto.write(json.dumps(message) + "\n")
    proto.flush()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m lockwalk.policy._decide_worker <target>", file=sys.stderr)
        return 2
    # Keep the real stdout and stdin for the protocol. Anything the user's code prints, at
    # Python or C level, goes to stderr; anything it reads from stdin gets end-of-file.
    proto = os.fdopen(os.dup(1), "w", encoding="utf-8")
    requests = os.fdopen(os.dup(0), "r", encoding="utf-8")
    os.dup2(2, 1)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    sys.path.insert(0, os.getcwd())
    try:
        try:
            decide, decide_many = resolve(argv[1])
        except TargetError as exc:
            send(proto, {"fatal": str(exc)})
            return 0
        except BaseException as exc:  # importing runs the user's code
            send(proto, {"fatal": f"importing the target raised {describe_error(exc)}"})
            return 0
        server = Server(decide, decide_many)
        send(proto, {"ready": True, "batch": decide_many is not None})
        for line in requests:
            send(proto, {"answers": server.answers(json.loads(line)["queries"])})
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    code = main(sys.argv)
    sys.stdout.flush()
    sys.stderr.flush()
    # Skip interpreter shutdown: a non-daemon thread started by the user's code would
    # otherwise keep the process alive after the parent is done with it.
    os._exit(code)
