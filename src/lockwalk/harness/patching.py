"""Replace SIDE_EFFECTS with counters and record DOOR calls.

Each SIDE_EFFECTS function becomes a counter that records the call and returns None. The
reference scan then replaces every other module-level name that points at the same
function. When the path goes through an instance, the method is replaced on its class so
every instance is counted. Class attributes, containers, closures, functools.partial, and
default arguments are not scanned. A class that captures the function at def time (for
example `def __init__(self, fn=real_send): self.send = fn`) runs the REAL function on an
instance created after install(); this cannot be found by scanning, so it is documented
here. An instance whose __init__ reads the module global instead is covered, because the
scan already replaced that name. `Installed.replaced` counts only the places that were
actually replaced, so its number does not reveal a reference the scan could not reach.

A subclass that overrides the door method is not recorded. This is loud, not silent: a side
effect that then runs without a recorded door call is reported as a bypass, and a denied
case whose door was never asked is an ERROR.

The DOOR is wrapped in a recorder: it calls the real door, then
read_door_call(args, kwargs, result). If the door raises, read_door_call receives the
exception as `result` (so it can report "denied"), and the exception is re-raised.
Door answers are stored reduced (type, id, act chain), and errors by type name only.
"""

import functools
import importlib
import inspect
import sys
import threading
import types
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from lockwalk.harness.events import EventLog
from lockwalk.harness.hooks import Hooks
from lockwalk.harness.protocol import reduce_subject


@dataclass(frozen=True)
class Installed:
    replaced: dict[str, int]  # tool name -> places (objects or classes) its function was replaced
    problems: tuple[str, ...]  # a path that cannot be resolved; every door test is then ERROR


@dataclass
class _Found:
    owner: object
    attr: str
    raw: object  # what the owner holds: a function, staticmethod, or classmethod
    func: Callable[..., Any]
    # The class that really holds `attr` when `owner` is an instance that only inherits it
    # (getattr_static then returns the class's raw object, not something bound to the instance).
    holder: type | None = None


_reading: ContextVar[bool] = ContextVar("lockwalk_reading_door", default=False)
_local = threading.local()  # fallback for threads that do not copy the context


def _busy() -> bool:
    return _reading.get() or getattr(_local, "busy", False)


def _resolve(path: str) -> tuple[_Found | None, str | None]:
    """The function at 'module.attr[.attr]' and the object that holds it.

    The longest importable module prefix is tried first, then getattr down the rest.
    """
    parts = path.split(".")
    reason: str | None = None
    for cut in range(len(parts) - 1, 0, -1):
        try:
            module = importlib.import_module(".".join(parts[:cut]))
        except KeyboardInterrupt:
            raise
        except BaseException as exc:  # importing runs the user's code
            reason = reason or f"importing it raised {type(exc).__name__}"
            continue
        owner: object = module
        try:
            for name in parts[cut:-1]:
                owner = getattr(owner, name)
            attr = parts[-1]
            try:
                raw = inspect.getattr_static(owner, attr)
            except AttributeError:
                raw = getattr(owner, attr)
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            reason = reason or f"looking it up raised {type(exc).__name__}"
            continue
        func = raw.__func__ if isinstance(raw, (staticmethod, classmethod)) else raw
        if callable(func):
            return _Found(owner, attr, raw, func, _class_holder(owner, attr)), None
    return None, reason


def _class_holder(owner: object, attr: str) -> type | None:
    """The class that holds `attr` for an instance owner, or None when setattr on the owner
    itself is correct (a module, a class, or an instance with its own entry for `attr`).

    Limit: an attribute a class owner only gets from its metaclass is not detected here.
    """
    if isinstance(owner, (types.ModuleType, type)):
        return None
    try:
        if attr in vars(owner):
            return None
    except TypeError:  # no __dict__ (slots): the attribute can only live on the class
        pass
    for klass in type(owner).__mro__:
        if attr in vars(klass):
            return klass
    return None


def _missing(label: str, path: str, reason: str | None) -> str:
    note = f" ({reason})" if reason else ""
    return f"{label}: cannot find a function at {path!r}{note}"


def _rewrap(raw: object, replacement: Callable[..., Any]) -> object:
    if isinstance(raw, staticmethod):
        return staticmethod(replacement)
    if isinstance(raw, classmethod):
        return classmethod(replacement)
    return replacement


def _class_door(found: _Found, hooks: Hooks, log: EventLog) -> object:
    """The replacement for a door that is reached through an instance, stored on the class.

    The wrapper absorbs `self` (or `cls`) and builds the recorder over the method bound to
    whichever object is calling, so the recorded arguments are what a caller of the configured
    path passes (no `self`) and every instance is recorded. A recorder only closes over its
    original, the hooks and the log, so building one per call keeps no state.
    """
    func = found.func
    if isinstance(found.raw, staticmethod):
        return staticmethod(_recorder(func, hooks, log))
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def abound(owner: Any, *args: Any, **kwargs: Any) -> Any:
            return await _recorder(types.MethodType(func, owner), hooks, log)(*args, **kwargs)

        return classmethod(abound) if isinstance(found.raw, classmethod) else abound

    @functools.wraps(func)
    def bound(owner: Any, *args: Any, **kwargs: Any) -> Any:
        return _recorder(types.MethodType(func, owner), hooks, log)(*args, **kwargs)

    return classmethod(bound) if isinstance(found.raw, classmethod) else bound


def _counter(original: Callable[..., Any], tools: list[str], log: EventLog) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def acount(*args: Any, **kwargs: Any) -> None:
            for tool in tools:
                log.side_effect(tool)

        return acount

    @functools.wraps(original)
    def count(*args: Any, **kwargs: Any) -> None:
        for tool in tools:
            log.side_effect(tool)

    return count


def _scan(original: object, replacement: object) -> int:
    """Replace module-level names that are `original`; returns how many."""
    replaced = 0
    for name, module in list(sys.modules.items()):
        if module is None or name == "lockwalk" or name.startswith("lockwalk."):
            continue
        namespace = getattr(module, "__dict__", None)
        if not isinstance(namespace, dict):
            continue
        for key, value in list(namespace.items()):
            if value is original:
                namespace[key] = replacement
                replaced += 1
    return replaced


def _answer_to_call(answer: object) -> dict[str, Any]:
    if isinstance(answer, dict) and type(answer.get("decision")) is bool:
        subject = reduce_subject(answer.get("subject"))
        if subject is not None:
            return {"subject": subject, "decision": answer["decision"]}
    return {
        "error": "read_door_call must return {'subject': {...}, 'decision': bool}; "
        f"it returned {type(answer).__name__}"
    }


def _record(hooks: Hooks, log: EventLog, args: Any, kwargs: Any, result: object) -> None:
    reader = hooks.read_door_call
    if reader is None:
        return
    token = _reading.set(True)
    _local.busy = True
    try:
        answer = reader(args, kwargs, result)
    except BaseException as exc:  # never let the reader replace the door's own exception
        log.door({"error": f"read_door_call raised {type(exc).__name__}"})
        return
    finally:
        _local.busy = False
        _reading.reset(token)
    log.door(_answer_to_call(answer))


def _recorder(original: Callable[..., Any], hooks: Hooks, log: EventLog) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def adoor(*args: Any, **kwargs: Any) -> Any:
            if _busy():
                return await original(*args, **kwargs)
            try:
                result = await original(*args, **kwargs)
            except Exception as exc:  # BaseException-only types pass through unrecorded
                _record(hooks, log, args, kwargs, exc)
                raise
            _record(hooks, log, args, kwargs, result)
            return result

        return adoor

    @functools.wraps(original)
    def door(*args: Any, **kwargs: Any) -> Any:
        if _busy():
            return original(*args, **kwargs)
        try:
            result = original(*args, **kwargs)
        except Exception as exc:  # BaseException-only types pass through unrecorded
            _record(hooks, log, args, kwargs, exc)
            raise
        _record(hooks, log, args, kwargs, result)
        return result

    return door


def install(hooks: Hooks, log: EventLog) -> Installed:
    problems: list[str] = []
    groups: dict[int, tuple[list[str], list[_Found]]] = {}
    for tool, path in hooks.side_effects.items():
        found, reason = _resolve(path)
        if found is None:
            problems.append(_missing(f"SIDE_EFFECTS[{tool!r}]", path, reason))
            continue
        tools, places = groups.setdefault(id(found.func), ([], []))
        tools.append(tool)
        places.append(found)
    door_found: _Found | None = None
    if hooks.door is not None:
        door_found, reason = _resolve(hooks.door)
        if door_found is None:
            problems.append(_missing("DOOR", hooks.door, reason))
    replaced: dict[str, int] = {}
    for tools, places in groups.values():
        original = places[0].func
        counter = _counter(original, tools, log)
        seen: set[tuple[int, str]] = set()
        total = 0
        for place in places:
            # An instance that only inherits the method is patched through its class: the goal
            # is that no real side effect runs from ANY instance, and a counter ignores `self`.
            target = place.holder if place.holder is not None else place.owner
            key = (id(target), place.attr)
            if key in seen:
                continue
            seen.add(key)
            try:
                setattr(target, place.attr, _rewrap(place.raw, counter))
            except BaseException:
                problems.append(f"SIDE_EFFECTS[{tools[0]!r}]: cannot replace {place.attr!r}")
                continue
            total += 1
        total += _scan(original, counter)
        for tool in tools:
            replaced[tool] = total
    if door_found is not None:
        # A door reached through an instance is wrapped on the class that holds it, so every
        # instance is recorded; the recorded arguments are the caller's, without `self`.
        # A callable object that does not bind is wrapped on the instance itself.
        holder = door_found.holder
        scan_with: Callable[..., Any] | None = None
        if holder is not None and isinstance(
            door_found.raw, (types.FunctionType, staticmethod, classmethod)
        ):
            target: object = holder
            replacement: object = _class_door(door_found, hooks, log)
        elif holder is not None:
            target = door_found.owner
            replacement = _recorder(door_found.func, hooks, log)
        else:
            recorder = _recorder(door_found.func, hooks, log)
            target = door_found.owner
            replacement = _rewrap(door_found.raw, recorder)
            scan_with = recorder
        try:
            setattr(target, door_found.attr, replacement)
        except BaseException:
            problems.append("DOOR: cannot replace the door function")
        else:
            if scan_with is not None:
                _scan(door_found.func, scan_with)
    return Installed(replaced=replaced, problems=tuple(problems))
