import time

import pytest

from lockwalk.jsonvalues import check_json_value


def check(value: object, *, allow_null: bool = True, max_depth: int = 8) -> None:
    check_json_value(value, "v", allow_null=allow_null, max_depth=max_depth)


def test_plain_json_values_pass() -> None:
    check({"a": [1, 2.5, True, "x", None, (1, {"b": []})]})


def test_depth_message_and_boundary() -> None:
    def nest(levels: int) -> object:
        value: object = 1
        for _ in range(levels):
            value = [value]
        return value

    check(nest(7), max_depth=8)  # the scalar sits at depth 8
    with pytest.raises(ValueError, match="more than 3 levels deep"):
        check(nest(4), max_depth=3)
    check(nest(3), max_depth=3)


def test_non_finite_float_message() -> None:
    with pytest.raises(ValueError, match=r"^v\[2\].k must be a finite number$"):
        check([0, 1, {"k": float("nan")}])
    with pytest.raises(ValueError, match="finite"):
        check([float("inf")])


def test_bad_key_message() -> None:
    with pytest.raises(ValueError, match=r"^v\[0\] keys must be non-empty strings$"):
        check([{1: "a"}])
    with pytest.raises(ValueError, match="keys must be non-empty strings"):
        check({"": "a"})


def test_other_type_message() -> None:
    with pytest.raises(
        ValueError,
        match=r"^v.k must be a string, number, boolean, null, list, or mapping \(not set\)$",
    ):
        check({"k": {1}})
    with pytest.raises(ValueError, match="not bytes"):
        check(b"x")


def test_null_depends_on_allow_null() -> None:
    check({"a": None}, allow_null=True)
    with pytest.raises(ValueError, match="must be a string, number, boolean, list, or mapping"):
        check({"a": None}, allow_null=False)


def test_shared_container_is_rejected_quickly() -> None:
    value: object = [1]
    for _ in range(25):
        value = [value, value]
    start = time.perf_counter()
    with pytest.raises(ValueError, match="more than once"):
        check(value, max_depth=100)
    assert time.perf_counter() - start < 1


def test_self_reference_is_rejected() -> None:
    loop: list[object] = []
    loop.append(loop)
    with pytest.raises(ValueError, match="more than once"):
        check(loop)


def test_same_list_in_two_separate_calls_is_fine() -> None:
    shared = [1, 2]
    check({"a": shared})
    check({"b": shared})


def test_long_keys_nested_deep_stay_linear() -> None:
    leaves = {f"leaf{i}": i for i in range(70)}
    value: object = leaves
    for level in range(60):
        value = {"k" * 10_000 + str(level): value, **{f"x{j}": j for j in range(70)}}
    start = time.perf_counter()
    check(value, max_depth=100)
    assert time.perf_counter() - start < 0.5


def test_error_paths_are_capped() -> None:
    value: object = float("nan")
    for level in range(5):
        value = {"k" * 5_000 + str(level): value}
    with pytest.raises(ValueError) as info:
        check(value, max_depth=100)
    message = str(info.value)
    path = message.removesuffix(" must be a finite number")
    assert path.startswith("v")
    assert len(path) <= 200
    assert "..." in path


def test_empty_containers_may_repeat() -> None:
    empty: list[object] = []
    check({"a": empty, "b": empty, "c": (), "d": (), "e": {}})
