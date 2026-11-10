import asyncio
import importlib
import inspect
import sys
from collections.abc import Callable, Iterator
from types import ModuleType
from typing import Any

import pytest

from lockwalk.harness import patching
from lockwalk.harness.events import EventLog
from lockwalk.harness.hooks import Hooks

PREFIX = "harness_apps"


def _purge() -> None:
    for name in [n for n in sys.modules if n == PREFIX or n.startswith(PREFIX + ".")]:
        del sys.modules[name]


@pytest.fixture
def apps() -> Iterator[tuple[ModuleType, ModuleType]]:
    _purge()
    trading = importlib.import_module("harness_apps.trading_app")
    consumer = importlib.import_module("harness_apps.trading_consumer")
    yield trading, consumer
    _purge()


def make_hooks(
    side_effects: dict[str, str],
    door: str | None = None,
    reader: Callable[..., Any] | None = None,
) -> Hooks:
    return Hooks(
        set_identity=lambda subject: None,
        side_effects=side_effects,
        door=door,
        read_door_call=reader if door is not None else None,
        run_path=None,
    )


T = "harness_apps.trading_app"


def test_a_side_effect_becomes_a_counter_and_references_follow(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, consumer = apps
    log = EventLog()
    installed = patching.install(make_hooks({"execute_trade": f"{T}.place_order"}), log)
    assert installed.problems == ()
    # owner + consumer.place_order + consumer.ALIAS + consumer.DIRECT; the list is not scanned
    assert installed.replaced == {"execute_trade": 4}
    assert trading.place_order("AAPL") is None
    assert consumer.place_order("AAPL") is None
    assert consumer.DIRECT("AAPL") is None
    assert log.count("execute_trade") == 3
    assert trading.REAL_CALLS == []
    assert trading.place_order.__name__ == "place_order"
    # the container still holds the real function: it is what the door control finds
    assert consumer.HELD[0]("AAPL") == "real order"


def test_two_tools_sharing_one_function_are_both_counted(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps
    log = EventLog()
    hooks = make_hooks({"buy": f"{T}.shared", "sell": f"{T}.shared"})
    installed = patching.install(hooks, log)
    assert installed.replaced == {"buy": 1, "sell": 1}
    trading.shared("x")
    assert (log.count("buy"), log.count("sell")) == (1, 1)


def test_an_async_side_effect_can_still_be_awaited(apps: tuple[ModuleType, ModuleType]) -> None:
    trading, _ = apps
    log = EventLog()
    patching.install(make_hooks({"alert": f"{T}.send_alert"}), log)
    assert inspect.iscoroutinefunction(trading.send_alert)
    assert asyncio.run(trading.send_alert("hi")) is None
    assert log.count("alert") == 1


def test_a_method_is_replaced_for_every_instance(apps: tuple[ModuleType, ModuleType]) -> None:
    trading, _ = apps
    broker = trading.Broker()
    log = EventLog()
    installed = patching.install(
        make_hooks({"submit": f"{T}.Broker.submit", "static": f"{T}.Broker.static_submit"}), log
    )
    assert installed.problems == ()
    assert broker.submit("AAPL") is None
    assert trading.Broker.static_submit("AAPL") is None
    assert trading.Broker().static_submit("AAPL") is None
    assert (log.count("submit"), log.count("static")) == (1, 2)


def test_an_unresolvable_path_is_a_problem_not_an_exception(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    log = EventLog()
    hooks = make_hooks(
        {
            "a": "no_such_module_here.func",
            "b": f"{T}.missing_function",
            "c": f"{T}.REAL_CALLS",
            "d": f"{T}.place_order",
        }
    )
    installed = patching.install(hooks, log)
    assert installed.replaced == {"d": 4}
    assert len(installed.problems) == 3
    assert (
        "SIDE_EFFECTS['a']: cannot find a function at 'no_such_module_here.func' "
        "(importing it raised ModuleNotFoundError)"
    ) in installed.problems
    assert all(p.startswith("SIDE_EFFECTS[") for p in installed.problems)


def test_an_unresolvable_door_is_a_problem(apps: tuple[ModuleType, ModuleType]) -> None:
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.nope", reader=lambda *a: {})
    installed = patching.install(hooks, EventLog())
    assert installed.problems == (
        f"DOOR: cannot find a function at '{T}.nope' (looking it up raised AttributeError)",
    )


def _door_log(log: EventLog) -> tuple[dict[str, Any], ...]:
    return log.window("t", 0, None, door_configured=True, keep=20).door_calls


def test_the_door_recorder_records_a_reduced_answer(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, consumer = apps
    log = EventLog()
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_access", reader=trading.reader)
    installed = patching.install(hooks, log)
    assert installed.problems == ()
    subject = {"type": "user", "id": "alice", "properties": {"token": "s3cret", "act": None}}
    assert consumer.DOOR_ALIAS(subject, "t") is True
    (call,) = _door_log(log)
    assert call == {"subject": {"type": "user", "id": "alice"}, "decision": True}
    assert "s3cret" not in repr(call)


def test_a_door_that_raises_is_recorded_and_still_raises(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps
    seen: list[object] = []

    def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
        seen.append(result)
        return {"subject": {"type": "user", "id": "bob"}, "decision": False}

    log = EventLog()
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_raising", reader=reader)
    patching.install(hooks, log)
    with pytest.raises(PermissionError, match="secret-detail"):
        trading.check_raising({"type": "user", "id": "bob"}, "t")
    assert isinstance(seen[0], PermissionError)
    assert _door_log(log) == ({"subject": {"type": "user", "id": "bob"}, "decision": False},)


def test_an_async_door_is_awaited_and_recorded(apps: tuple[ModuleType, ModuleType]) -> None:
    trading, _ = apps
    log = EventLog()
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_async", reader=trading.reader)
    patching.install(hooks, log)
    assert inspect.iscoroutinefunction(trading.check_async)
    assert asyncio.run(trading.check_async({"type": "user", "id": "alice"}, "t")) is True
    assert _door_log(log) == ({"subject": {"type": "user", "id": "alice"}, "decision": True},)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        "yes",
        {"subject": {"type": "user", "id": "a"}, "decision": 1},
        {"subject": {"type": "user", "id": "a"}},
        {"subject": "alice", "decision": True},
        {"subject": {"type": "user"}, "decision": True},
    ],
)
def test_a_malformed_read_door_call_answer_is_an_error_entry(
    apps: tuple[ModuleType, ModuleType], answer: object
) -> None:
    trading, _ = apps
    log = EventLog()
    hooks = make_hooks(
        {"t": f"{T}.place_order"}, door=f"{T}.check_access", reader=lambda *a: answer
    )
    patching.install(hooks, log)
    trading.check_access({"type": "user", "id": "alice"}, "t")
    (call,) = _door_log(log)
    assert call == {
        "error": "read_door_call must return {'subject': {...}, 'decision': bool}; "
        f"it returned {type(answer).__name__}"
    }


def test_a_raising_read_door_call_gives_the_type_name_only(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps

    def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
        raise ValueError("token=hunter2")

    log = EventLog()
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_access", reader=reader)
    patching.install(hooks, log)
    assert trading.check_access({"type": "user", "id": "alice"}, "t") is True
    assert _door_log(log) == ({"error": "read_door_call raised ValueError"},)


def test_no_door_means_no_recorder(apps: tuple[ModuleType, ModuleType]) -> None:
    trading, _ = apps
    original = trading.check_access
    log = EventLog()
    patching.install(make_hooks({"t": f"{T}.place_order"}), log)
    assert trading.check_access is original
    assert _door_log(log) == ()


def test_a_reader_that_calls_the_door_records_once(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps

    def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
        trading.check_access(args[0], "inner")  # the patched door again
        return {"subject": {"type": "user", "id": "alice"}, "decision": bool(result)}

    log = EventLog()
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_access", reader=reader)
    patching.install(hooks, log)
    assert trading.check_access({"type": "user", "id": "alice"}, "t") is True
    assert len(_door_log(log)) == 1
    # the flag is released afterwards: the next call records again
    trading.check_access({"type": "user", "id": "alice"}, "t")
    assert len(_door_log(log)) == 2


def test_a_reader_that_calls_the_async_door_records_once(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps

    def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
        inner = trading.check_async(args[0], "inner")  # the patched async door
        while True:  # drive it by hand: a loop is already running in this thread
            try:
                inner.send(None)
            except StopIteration:
                break
        return {"subject": {"type": "user", "id": "alice"}, "decision": True}

    log = EventLog()
    hooks = make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_async", reader=reader)
    patching.install(hooks, log)
    assert asyncio.run(trading.check_async({"type": "user", "id": "alice"}, "t")) is True
    assert len(_door_log(log)) == 1


def test_a_base_exception_only_door_error_is_not_recorded(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps
    seen: list[object] = []

    def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
        seen.append(result)
        return {"subject": {"type": "user", "id": "a"}, "decision": False}

    log = EventLog()
    patching.install(
        make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_exit", reader=reader), log
    )
    with pytest.raises(SystemExit):
        trading.check_exit({"type": "user", "id": "a"}, "t")
    assert seen == [] and _door_log(log) == ()


def test_a_reader_raising_a_base_exception_cannot_replace_the_door_error(
    apps: tuple[ModuleType, ModuleType],
) -> None:
    trading, _ = apps

    def reader(args: Any, kwargs: Any, result: Any) -> dict[str, Any]:
        raise KeyboardInterrupt("secret")

    log = EventLog()
    patching.install(
        make_hooks({"t": f"{T}.place_order"}, door=f"{T}.check_raising", reader=reader), log
    )
    with pytest.raises(PermissionError):
        trading.check_raising({"type": "user", "id": "a"}, "t")
    assert _door_log(log) == ({"error": "read_door_call raised KeyboardInterrupt"},)


def test_the_scan_skips_lockwalk_modules_but_not_lookalikes(
    apps: tuple[ModuleType, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    trading, _ = apps
    original = trading.place_order
    own = ModuleType("lockwalk.probe")
    own.__dict__["held"] = original
    lookalike = ModuleType("lockwalk_demo")
    lookalike.__dict__["held"] = original
    monkeypatch.setitem(sys.modules, "lockwalk.probe", own)
    monkeypatch.setitem(sys.modules, "lockwalk_demo", lookalike)
    installed = patching.install(make_hooks({"t": f"{T}.place_order"}), EventLog())
    assert own.__dict__["held"] is original
    assert lookalike.__dict__["held"] is trading.place_order
    assert installed.replaced == {"t": 5}


def _instance_app() -> ModuleType:
    _purge()
    return importlib.import_module("harness_apps.trading_instance")


def test_a_path_through_an_instance_keeps_self_and_counts_every_instance() -> None:
    app = _instance_app()
    try:
        log = EventLog()
        calls: list[Any] = []

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            calls.append((args, kwargs, result))
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        hooks = make_hooks(
            {"send_mail": f"{base}.mailer.send"}, door=f"{base}.authorizer.check", reader=reader
        )
        installed = patching.install(hooks, log)
        assert installed.problems == ()
        assert installed.replaced == {"send_mail": 1}
        # door: callable (no TypeError) and recorded with the arguments the caller passed
        assert app.authorizer.check("alice", "x") is True
        assert calls == [(("alice", "x"), {}, True)]
        # side effect: counted on the configured instance and on one made after install()
        assert app.mailer.send(1) is None
        assert app.Mailer().send(2) is None
        assert log.count("send_mail") == 2
        assert app.REAL_CALLS == []
    finally:
        _purge()


def test_instance_paths_to_static_and_class_methods_still_work() -> None:
    app = _instance_app()
    try:
        log = EventLog()
        seen: list[Any] = []

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            seen.append(args)
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        hooks = make_hooks({}, door=f"{base}.authorizer.static_check", reader=reader)
        assert patching.install(hooks, log).problems == ()
        assert app.authorizer.static_check("alice") is True
        hooks = make_hooks({}, door=f"{base}.authorizer.class_check", reader=reader)
        assert patching.install(hooks, log).problems == ()
        assert app.authorizer.class_check("alice") is True
        assert seen == [("alice",), ("alice",)]
    finally:
        _purge()


def test_a_second_instance_of_the_door_class_is_recorded_without_self() -> None:
    app = _instance_app()
    try:
        log = EventLog()
        calls: list[Any] = []

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            calls.append((args, kwargs, result))
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        hooks = make_hooks(
            {"send_mail": f"{base}.mailer.send"}, door=f"{base}.authorizer.check", reader=reader
        )
        assert patching.install(hooks, log).problems == ()
        other = app.Authz()
        assert other.check("alice", "x") is True
        assert other.check(who="bob", what="y") is False
        assert app.authorizer.check("alice", "z") is True
        assert calls == [
            (("alice", "x"), {}, True),
            ((), {"who": "bob", "what": "y"}, False),
            (("alice", "z"), {}, True),
        ]
    finally:
        _purge()


def test_a_door_used_only_on_a_second_instance_is_not_a_bypass() -> None:
    app = _instance_app()
    try:
        log = EventLog()

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        hooks = make_hooks(
            {"send_mail": f"{base}.mailer.send"}, door=f"{base}.authorizer.check", reader=reader
        )
        assert patching.install(hooks, log).problems == ()
        # the app asks the door through its own instance, then runs the side effect
        start = log.mark()
        assert app.Authz().check("alice", "x") is True
        app.Mailer().send(1)
        observed = log.window("send_mail", start, None, door_configured=True, keep=10)
        assert observed.bypass is False
        assert len(observed.door_calls) == 1
        assert log.count("send_mail") == 1
    finally:
        _purge()


def test_static_and_class_doors_are_recorded_on_a_second_instance() -> None:
    app = _instance_app()
    try:
        log = EventLog()
        seen: list[Any] = []

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            seen.append(args)
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        for attr in ("static_check", "class_check"):
            hooks = make_hooks({}, door=f"{base}.authorizer.{attr}", reader=reader)
            assert patching.install(hooks, log).problems == ()
            assert getattr(app.Authz(), attr)("alice") is True
        assert seen == [("alice",), ("alice",)]
    finally:
        _purge()


def test_an_async_door_through_an_instance_is_recorded_on_a_second_instance() -> None:
    app = _instance_app()
    try:
        log = EventLog()
        calls: list[Any] = []

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            calls.append((args, kwargs, result))
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        hooks = make_hooks(
            {"send_mail": f"{base}.mailer.send"}, door=f"{base}.authorizer.acheck", reader=reader
        )
        assert patching.install(hooks, log).problems == ()
        assert inspect.iscoroutinefunction(app.Authz.acheck)
        other = app.Authz()
        assert asyncio.run(other.acheck("alice", "x")) is True
        assert asyncio.run(other.acheck(who="bob", what="y")) is False
        assert calls == [
            (("alice", "x"), {}, True),
            ((), {"who": "bob", "what": "y"}, False),
        ]
    finally:
        _purge()


def test_an_async_class_door_through_an_instance_is_recorded_on_a_second_instance() -> None:
    app = _instance_app()
    try:
        log = EventLog()
        calls: list[Any] = []

        def reader(args: Any, kwargs: Any, result: object) -> dict[str, Any]:
            calls.append((args, kwargs, result))
            return {"subject": {"type": "user", "id": "alice"}, "decision": result is True}

        base = "harness_apps.trading_instance"
        hooks = make_hooks(
            {"send_mail": f"{base}.mailer.send"},
            door=f"{base}.authorizer.aclass_check",
            reader=reader,
        )
        assert patching.install(hooks, log).problems == ()
        assert inspect.iscoroutinefunction(app.Authz.aclass_check)
        other = app.Authz()
        assert asyncio.run(other.aclass_check("alice")) is True
        assert asyncio.run(other.aclass_check(who="bob")) is False
        assert calls == [(("alice",), {}, True), ((), {"who": "bob"}, False)]
    finally:
        _purge()
