"""Side effects and doors for the patching tests."""

import asyncio
from typing import Any

REAL_CALLS: list[str] = []


def place_order(symbol: str) -> str:
    REAL_CALLS.append(symbol)
    return "real order"


async def send_alert(text: str) -> str:
    REAL_CALLS.append(text)
    return "real alert"


def shared(value: str) -> str:
    REAL_CALLS.append(value)
    return "real shared"


class Broker:
    def submit(self, symbol: str) -> str:
        REAL_CALLS.append(symbol)
        return "real submit"

    @staticmethod
    def static_submit(symbol: str) -> str:
        REAL_CALLS.append(symbol)
        return "real static"


def check_access(subject: dict[str, Any], tool: str) -> bool:
    return subject.get("id") == "alice"


def check_raising(subject: dict[str, Any], tool: str) -> bool:
    raise PermissionError("secret-detail-from-the-door")


async def check_async(subject: dict[str, Any], tool: str) -> bool:
    await asyncio.sleep(0)
    return True


def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
    """Describe a call of check_access / check_async; an exception result means deny."""
    subject = dict(args[0])
    decision = False if isinstance(result, BaseException) else bool(result)
    return {"subject": subject, "decision": decision}


def check_exit(subject: dict[str, Any], tool: str) -> bool:
    raise SystemExit(3)
