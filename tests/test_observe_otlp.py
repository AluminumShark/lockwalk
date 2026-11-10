import gzip
import json
import time
from pathlib import Path

import pytest
from observe_helpers import DATA, loose_raw_spans

from lockwalk.observe.keys import BUILTIN_KEYS
from lockwalk.observe.otlp import read_otlp
from lockwalk.observe.spans import Limits

BIG = Limits(max_spans=1_000_000, max_line_bytes=50 * 1024 * 1024, max_total_bytes=10**10)
TID = "a" * 32
SID = "b" * 16
FIXTURES = sorted(p.name for p in DATA.iterdir() if p.suffix in (".json", ".jsonl"))


def attr(key: str, **value: object) -> dict:
    return {"key": key, "value": value}


def span(**over: object) -> dict:
    base: dict = {"traceId": TID, "spanId": SID, "name": "s"}
    base.update(over)
    return base


def doc(*spans: dict) -> str:
    return json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]})


def write(tmp_path: Path, name: str, text: str | bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return path


def read(*paths: Path, keys: frozenset[str] = BUILTIN_KEYS, limits: Limits = BIG, **kw):
    return read_otlp(list(paths), keys=keys, limits=limits, **kw)


def messages(result) -> str:
    return "\n".join(f"{p.where} {p.message}" for p in result.problems)


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_reads_clean(name):
    result = read(DATA / name, keys=frozenset({"gen_ai.tool.name"}))
    assert result.problems == ()
    assert len(result.raw) == len(loose_raw_spans(name))
    assert len(result.raw) > 0


def test_fixture_span_counts_are_known():
    counts = {n: len(read(DATA / n).raw) for n in FIXTURES}
    assert counts["jaeger_v3_trace.json"] == 1
    assert counts["collector.jsonl"] == 9
    assert counts["jaeger_v3_search.json"] == 8
    assert len({s.trace_id for s in read(DATA / "jaeger_v3_search.json").raw}) > 1


def test_content_attributes_never_kept():
    banned = {"input.value", "pydantic_ai.all_messages", "gen_ai.tool.call.arguments"}
    seen_in_source = set()
    for name in FIXTURES:
        seen_in_source |= {k for s in loose_raw_spans(name) for k in s.attributes} & banned
        for s in read(DATA / name).raw:
            assert not banned & set(s.attributes)
    assert seen_in_source  # the fixtures do carry them


def test_gzip_same_as_plain(tmp_path):
    for name in ("collector.jsonl", "pydantic_delegation.json"):
        raw = (DATA / name).read_bytes()
        gz = write(tmp_path, name + ".gz", gzip.compress(raw))
        plain = read(DATA / name).raw
        zipped = read(gz).raw
        assert [(s.trace_id, s.span_id, s.attributes) for s in zipped] == [
            (s.trace_id, s.span_id, s.attributes) for s in plain
        ]


def test_bom_accepted(tmp_path):
    path = write(tmp_path, "a.json", b"\xef\xbb\xbf" + doc(span()).encode())
    result = read(path)
    assert result.problems == () and len(result.raw) == 1


@pytest.mark.parametrize(
    "content",
    [
        b"\x00\x00\x00\x2a\x28\xb5\x2f\xfd" + b"x" * 40,
        b"\x12\x00\x0a\x10abc",
        b"\xff\xfe{abc",
    ],
)
def test_binary_formats(tmp_path, content):
    for name in ("a.json", "b.jsonl"):
        result = read(write(tmp_path, name, content))
        assert result.raw == ()
        assert len(result.problems) == 1
        assert "not OTLP JSON" in result.problems[0].message
        assert "format: json" in result.problems[0].message


def test_ids(tmp_path):
    bad = [
        span(traceId="a" * 31),
        span(traceId="z" * 32),
        span(traceId="0" * 32),
        span(spanId="0" * 16),
        span(spanId="b" * 15),
        span(parentSpanId="xyz"),
        span(spanId=None),
    ]
    path = write(tmp_path, "a.jsonl", "\n".join(doc(s) for s in bad) + "\n")
    result = read(path)
    assert result.raw == ()
    assert len(result.problems) == len(bad)
    assert [p.where for p in result.problems] == [f"a.jsonl:{i}" for i in range(1, 8)]


def test_ids_lowercased_and_roots(tmp_path):
    spans = [
        span(traceId="AB" * 16, spanId="CD" * 8, parentSpanId="EF" * 8),
        span(spanId="1" * 16, parentSpanId=""),
        span(spanId="2" * 16),
    ]
    result = read(write(tmp_path, "a.json", doc(*spans)))
    first, second, third = result.raw
    assert (first.trace_id, first.span_id, first.parent_id) == ("ab" * 16, "cd" * 8, "ef" * 8)
    assert second.parent_id is None and third.parent_id is None


def test_attribute_values(tmp_path):
    attrs = [
        attr("gen_ai.operation.name", stringValue="x"),
        attr("gen_ai.agent.name", intValue="42"),
        attr("gen_ai.agent.id", intValue=42),
        attr("gen_ai.tool.name", doubleValue="NaN"),
        attr("agent.name", arrayValue={"values": []}),
        attr("tool.name", **{}),
        attr("openinference.span.kind", kvlistValue={"values": []}),
        attr("enduser.id", bytesValue="AA=="),
        attr("lockwalk.effect", boolValue=True),
        attr("user.id", doubleValue=1.5),
        attr("input.value", stringValue="secret"),
        attr("graph.node.parent_id", intValue="-7"),
    ]
    s = read(write(tmp_path, "a.json", doc(span(attributes=attrs)))).raw[0]
    a = s.attributes
    assert a["gen_ai.operation.name"] == "x"
    assert a["gen_ai.agent.name"] == 42 and a["gen_ai.agent.id"] == 42
    assert a["gen_ai.tool.name"] != a["gen_ai.tool.name"]  # NaN
    assert a["lockwalk.effect"] is True and a["user.id"] == 1.5
    assert a["graph.node.parent_id"] == -7
    for key in ("agent.name", "tool.name", "openinference.span.kind", "enduser.id", "input.value"):
        assert key not in a


def test_malformed_allowlisted_value_is_problem_but_others_ignored(tmp_path):
    good_ignored = attr("other.key", stringValue=5)
    bad = attr("gen_ai.tool.name", stringValue=5)
    result = read(
        write(
            tmp_path,
            "a.jsonl",
            doc(span(attributes=[good_ignored])) + "\n" + doc(span(attributes=[bad])) + "\n",
        )
    )
    assert len(result.raw) == 1 and len(result.problems) == 1
    assert result.problems[0].where == "a.jsonl:2"


def test_times(tmp_path):
    ok = read(
        write(tmp_path, "a.json", doc(span(startTimeUnixNano="123", endTimeUnixNano=456)))
    ).raw[0]
    assert (ok.start_ns, ok.end_ns) == (123, 456)
    none = read(write(tmp_path, "b.json", doc(span()))).raw[0]
    assert none.start_ns is None and none.end_ns is None
    for bad in ("-1", -1, "12x", 1.5, True, "1" * 30):
        result = read(write(tmp_path, "c.json", doc(span(startTimeUnixNano=bad))))
        assert result.raw == () and len(result.problems) == 1


def test_duplicate_keys_only_that_line(tmp_path):
    dup = '{"resourceSpans": [], "resourceSpans": []}'
    text = doc(span()) + "\n" + dup + "\n" + doc(span(spanId="c" * 16)) + "\n"
    result = read(write(tmp_path, "a.jsonl", text))
    assert len(result.raw) == 2
    assert [p.where for p in result.problems] == ["a.jsonl:2"]


def test_invalid_json_and_deep_nesting(tmp_path):
    deep = "{" * 100000
    text = "{bad\n" + deep + "\n" + doc(span()) + "\n"
    result = read(write(tmp_path, "a.jsonl", text))
    assert len(result.raw) == 1 and len(result.problems) == 2


def test_too_long_line_skipped(tmp_path):
    small = Limits(max_spans=100, max_line_bytes=2000, max_total_bytes=10**9)
    long_line = doc(span(name="n" * 100000))
    text = doc(span()) + "\n" + long_line + "\n" + doc(span(spanId="c" * 16)) + "\n"
    result = read(write(tmp_path, "a.jsonl", text), limits=small)
    assert len(result.raw) == 2
    assert [p.where for p in result.problems] == ["a.jsonl:2"]
    assert not result.truncated


def test_too_large_json_file(tmp_path):
    small = Limits(max_spans=100, max_line_bytes=500, max_total_bytes=10**9)
    result = read(write(tmp_path, "a.json", doc(span(name="n" * 2000))), limits=small)
    assert result.raw == () and "is larger than" in result.problems[0].message


def test_max_spans(tmp_path):
    limits = Limits(max_spans=3, max_line_bytes=10**6, max_total_bytes=10**9)
    lines = [doc(span(spanId=f"{i:016x}")) for i in range(1, 10)]
    first = write(tmp_path, "a.jsonl", "\n".join(lines) + "\n")
    second = write(tmp_path, "b.jsonl", doc(span(spanId="f" * 16)) + "\n")
    result = read(first, second, limits=limits)
    assert len(result.raw) == 3 and result.truncated
    assert "more than 3 spans" in result.problems[-1].message
    assert result.sources == (str(first),)


def test_max_total_bytes(tmp_path):
    line = doc(span())
    limits = Limits(max_spans=100, max_line_bytes=10**6, max_total_bytes=len(line) * 2 + 5)
    text = "\n".join([line] * 10) + "\n"
    result = read(write(tmp_path, "a.jsonl", text), limits=limits)
    assert result.truncated
    assert len(result.raw) == 2
    assert "MiB of trace data" in result.problems[-1].message


def test_directory(tmp_path):
    d = tmp_path / "traces"
    d.mkdir()
    (d / "b.jsonl").write_text(doc(span(spanId="2" * 16)) + "\n")
    (d / "a.json").write_text(doc(span(spanId="1" * 16)))
    (d / "c.json.gz").write_bytes(gzip.compress(doc(span(spanId="3" * 16)).encode()))
    (d / "notes.txt").write_text("hi")
    (d / "sub").mkdir()
    (d / "sub" / "x.json").write_text(doc(span()))
    result = read(d)
    assert [s.span_id[0] for s in result.raw] == ["1", "2", "3"]
    assert result.sources == (f"{d} (3 files)",)
    assert result.warnings == (
        f"{d}: 1 file(s) skipped (not .json, .jsonl, .json.gz or .jsonl.gz)",
        f"{d}: 1 sub-folder(s) skipped (the scan does not descend)",
    )
    assert result.problems == ()


def test_explicit_bad_suffix_and_missing(tmp_path):
    txt = write(tmp_path, "a.txt", doc(span()))
    result = read(txt, tmp_path / "nope.json")
    assert result.raw == () and len(result.problems) == 2


def test_only_trace(tmp_path):
    other = span(traceId="c" * 32, spanId="9" * 16)
    junk = span(traceId="c" * 32, spanId="bad", name=5)  # other trace: only id format matters
    path = write(tmp_path, "a.json", doc(span(), other, junk))
    result = read(path, only_trace=("A" * 32))
    assert [s.trace_id for s in result.raw] == [TID]
    assert result.problems == ()


def test_problems_never_quote_content(tmp_path):
    secret = "sk-SECRET-TOKEN-12345"
    lines = [
        f'{{"resourceSpans": [{{"scopeSpans": [{{"spans": [{{"traceId": "{secret}"}}]}}]}}]}}',
        f'{{"{secret}": 1, "{secret}": 2}}',
        f'{{"oops": "{secret}"',
        doc(span(attributes=[attr("gen_ai.tool.name", stringValue=7), {"key": secret}])),
        doc(span(name=secret, startTimeUnixNano=secret)),
        f'{{"resourceSpans": "{secret}"}}',
    ]
    result = read(write(tmp_path, "a.jsonl", "\n".join(lines) + "\n"))
    assert len(result.problems) == len(lines)
    assert secret not in messages(result)


def test_result_wrapper_and_old_format(tmp_path):
    wrapped = json.dumps({"result": json.loads(doc(span()))})
    assert len(read(write(tmp_path, "a.json", wrapped)).raw) == 1
    old = json.dumps({"resourceSpans": [{"instrumentationLibrarySpans": [{"spans": []}]}]})
    result = read(write(tmp_path, "b.json", old))
    assert "instrumentationLibrarySpans" in result.problems[0].message


def test_problem_cap(tmp_path):
    text = "{bad\n" * 250
    result = read(write(tmp_path, "a.jsonl", text))
    assert len(result.problems) == 101
    assert result.problems[-1].message == "... and 150 more problems"


def test_one_problem_per_line(tmp_path):
    result = read(write(tmp_path, "a.json", doc(span(traceId="x"), span(spanId="y"))))
    assert len(result.problems) == 1


def test_whitespace_lines_and_empty_file(tmp_path):
    text = "\n   \n" + doc(span()) + "\n\n"
    result = read(write(tmp_path, "a.jsonl", text), write(tmp_path, "e.jsonl", ""))
    assert len(result.raw) == 1 and result.problems == ()


def test_corrupt_gzip(tmp_path):
    good = gzip.compress((doc(span()) + "\n").encode() * 50)
    result = read(write(tmp_path, "a.jsonl.gz", good[: len(good) // 2]))
    assert result.problems
    assert read(write(tmp_path, "b.json.gz", b"notgzip")).problems


def test_linear_time(tmp_path):
    lines = []
    n = 0
    for _ in range(1000):
        spans = []
        for _ in range(100):
            n += 1
            spans.append(
                span(
                    spanId=f"{n:016x}",
                    attributes=[attr("gen_ai.tool.name", stringValue="t")],
                )
            )
        lines.append(doc(*spans))
    path = write(tmp_path, "big.jsonl", "\n".join(lines) + "\n")
    start = time.perf_counter()
    result = read(path)
    assert time.perf_counter() - start < 60
    assert len(result.raw) == 100_000 and result.problems == ()


def test_huge_numbers_are_problems_not_crashes(tmp_path):
    huge = "1" + "0" * 400
    first = doc(span(attributes=[attr("gen_ai.tool.name", doubleValue="HUGE")]))
    text = first.replace('"HUGE"', huge) + "\n"
    text += doc(span(startTimeUnixNano=int(huge), attributes=[attr("user.id", intValue=huge)]))
    result = read(write(tmp_path, "a.jsonl", text))
    assert [p.where for p in result.problems] == ["a.jsonl:1", "a.jsonl:2"]
    assert result.raw == ()


def test_one_problem_per_line_even_with_structural_error(tmp_path):
    bad = {"resourceSpans": [{"scopeSpans": [{"spans": [span(traceId="x")]}, "oops"]}]}
    result = read(write(tmp_path, "a.json", json.dumps(bad)))
    assert len(result.problems) == 1


def test_jsonl_detected_by_suffix_only(tmp_path):
    text = doc(span()) + "\n" + doc(span(spanId="c" * 16)) + "\n"
    result = read(write(tmp_path, "x.jsonl.bak.json", text))
    assert len(result.problems) == 1  # read as one .json document
    assert len(read(write(tmp_path, "y.jsonl", text)).raw) == 2


def test_listing_errors_become_problems(tmp_path, monkeypatch):
    d = tmp_path / "t"
    d.mkdir()
    (d / "a.json").write_text(doc(span()))
    real = Path.is_dir

    def boom(self):
        if self.name == "a.json":
            raise PermissionError
        return real(self)

    monkeypatch.setattr(Path, "is_dir", boom)
    result = read(d)
    assert len(result.problems) == 1 and result.raw == ()


def test_fatal_file_problem_uses_bare_name(tmp_path):
    result = read(write(tmp_path, "b.json.gz", b"notgzip"))
    assert result.problems[0].where == "b.json.gz"
    assert result.problems[0].message == "this file could not be read"


def test_blank_line_flood_is_cheap(tmp_path):
    path = write(tmp_path, "a.jsonl.gz", gzip.compress(b"\n" * 5_000_000))
    start = time.perf_counter()
    result = read(path)
    assert time.perf_counter() - start < 5
    assert [(p.where, p.message) for p in result.problems] == [
        ("a.jsonl.gz", "more than 1000 blank lines in a row")
    ]
    ok = write(tmp_path, "b.jsonl", "\n" * 1000 + doc(span()) + "\n" + " \n" * 1000 + doc(span()))
    assert len(read(ok).raw) == 2


def test_line_limit_boundary(tmp_path):
    line = doc(span())
    limits = Limits(max_spans=10, max_line_bytes=len(line), max_total_bytes=10**9)
    for ending in ("\n", "\r\n", ""):
        result = read(write(tmp_path, "a.jsonl", line + ending), limits=limits)
        assert len(result.raw) == 1 and result.problems == ()
    longer = line[:-1] + " }"
    result = read(write(tmp_path, "b.jsonl", longer + "\n" + line + "\n"), limits=limits)
    assert [p.where for p in result.problems] == ["b.jsonl:1"]
    assert len(result.raw) == 1
    assert read(write(tmp_path, "c.json", line), limits=limits).problems == ()
    assert read(write(tmp_path, "d.json", longer), limits=limits).problems


def test_not_otlp_message_for_text(tmp_path):
    for name, content in (("a.json", "[1, 2]"), ("b.json", "   \n"), ("c.jsonl", "[1]\n")):
        result = read(write(tmp_path, name, content))
        assert result.problems[0].message == "this is not an OTLP JSON document"


def test_int_time_cap_and_null_spans(tmp_path):
    result = read(write(tmp_path, "a.json", doc(span(startTimeUnixNano=10**20))))
    assert result.raw == () and len(result.problems) == 1
    null = json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": None}]}]})
    result = read(write(tmp_path, "b.json", null))
    assert result.raw == () and result.problems == ()


def test_gz_over_limits(tmp_path):
    body = doc(span(name="n" * 5000)).encode()
    small = Limits(max_spans=10, max_line_bytes=1000, max_total_bytes=10**9)
    result = read(write(tmp_path, "a.json.gz", gzip.compress(body)), limits=small)
    assert result.raw == () and "larger than" in result.problems[0].message
    tiny = Limits(max_spans=10, max_line_bytes=10**6, max_total_bytes=100)
    result = read(write(tmp_path, "b.json.gz", gzip.compress(body)), limits=tiny)
    assert result.truncated and "MiB of trace data" in result.problems[-1].message


def test_truncated_gzip_and_mid_read_oserror(tmp_path, monkeypatch):
    good = gzip.compress((doc(span()) + "\n").encode() * 5000)
    result = read(write(tmp_path, "a.jsonl.gz", good[:-200]))
    assert result.problems[-1].where == "a.jsonl.gz"
    assert result.problems[-1].message == "this file could not be read"

    def boom(*args, **kwargs):
        raise OSError("disk")

    path = write(tmp_path, "b.jsonl", doc(span()) + "\n")
    monkeypatch.setattr(gzip, "open", boom)
    monkeypatch.setattr("builtins.open", boom)
    result = read_otlp([path], keys=BUILTIN_KEYS, limits=BIG)
    assert [(p.where, p.message) for p in result.problems] == [
        ("b.jsonl", "this file could not be read")
    ]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"resourceSpans": 5}, "this is not an OTLP document (no resourceSpans list)"),
        ({"resourceSpans": [5]}, "a resourceSpans entry is not an object"),
        ({"resourceSpans": [{"scopeSpans": 5}]}, "scopeSpans is not a list"),
        ({"resourceSpans": [{"scopeSpans": [5]}]}, "a scopeSpans entry is not an object"),
        ({"resourceSpans": [{"scopeSpans": [{"spans": 5}]}]}, "spans is not a list"),
        ({"resourceSpans": [{"scopeSpans": [{"spans": [5]}]}]}, "a span is not an object"),
        (
            {"resourceSpans": [{"scopeSpans": [{"spans": [span(attributes=[5])]}]}]},
            "an attribute is not an object with a string key",
        ),
        (
            {"resourceSpans": [{"scopeSpans": [{"spans": [span(attributes=[{"key": 5}])]}]}]},
            "an attribute is not an object with a string key",
        ),
    ],
)
def test_structural_errors(tmp_path, document, message):
    result = read(write(tmp_path, "a.json", json.dumps(document)))
    assert result.raw == ()
    assert [(p.where, p.message) for p in result.problems] == [("a.json:1", message)]


def test_many_attributes_keep_only_allowlisted(tmp_path):
    attrs = [attr(f"k{i}", stringValue="v") for i in range(100_000)]
    attrs.append(attr("gen_ai.tool.name", stringValue="t"))
    result = read(write(tmp_path, "a.json", doc(span(attributes=attrs))))
    assert result.problems == ()
    assert dict(result.raw[0].attributes) == {"gen_ai.tool.name": "t"}


def test_labels_name_the_sources_instead_of_the_paths(tmp_path: Path) -> None:
    first = write(tmp_path, "one.json", doc(span()))
    folder = tmp_path / "dir"
    folder.mkdir()
    write(folder, "two.json", doc(span(spanId="c" * 16)))
    result = read(first, folder, tmp_path / "nope.json", labels=["a.json", "dir", "nope.json"])
    assert result.sources == ("a.json", "dir (1 file)")
    assert [problem.where for problem in result.problems] == ["nope.json"]
    assert str(tmp_path) not in repr(result.problems)


def test_messages_do_not_repeat_the_file_name(tmp_path: Path) -> None:
    result = read(write(tmp_path, "x.jsonl", "[1]\n"), tmp_path / "missing.json")
    for problem in result.problems:
        assert problem.where.split(":")[0] not in problem.message


def test_only_regular_files_are_opened(tmp_path: Path, monkeypatch) -> None:
    path = write(tmp_path, "a.jsonl", doc(span()) + "\n")
    monkeypatch.setattr("lockwalk.observe.otlp._is_regular", lambda file: False)
    result = read(path)
    assert result.raw == ()
    assert [(p.where, p.message) for p in result.problems] == [
        ("a.jsonl", "this is not a regular file")
    ]
    monkeypatch.undo()
    assert len(read(path).raw) == 1


def test_sub_folders_are_skipped_with_a_warning(tmp_path: Path) -> None:
    d = tmp_path / "traces"
    (d / "2026-11-08").mkdir(parents=True)
    (d / "empty").mkdir()
    (d / "a.json").write_text(doc(span(spanId="1" * 16)))
    (d / "2026-11-08" / "b.jsonl").write_text(doc(span(spanId="2" * 16)) + "\n")
    result = read(d)
    assert [s.span_id[0] for s in result.raw] == ["1"]
    assert result.warnings == (f"{d}: 2 sub-folder(s) skipped (the scan does not descend)",)


def test_only_sub_folders_still_warn(tmp_path: Path) -> None:
    d = tmp_path / "traces"
    (d / "day1").mkdir(parents=True)
    (d / "day1" / "b.json").write_text(doc(span()))
    result = read(d)
    assert result.raw == ()
    assert result.sources == (f"{d} (0 files)",)
    assert result.warnings == (f"{d}: 1 sub-folder(s) skipped (the scan does not descend)",)


def test_sub_folder_names_never_reach_the_warning(tmp_path: Path) -> None:
    d = tmp_path / "traces"
    names = ["alice@example.com", "tenant-secret-token", *(f"day{n}" for n in range(5))]
    for name in names:
        (d / name).mkdir(parents=True)
    (warning,) = read(d).warnings
    assert warning == f"{d}: 7 sub-folder(s) skipped (the scan does not descend)"
    assert not any(name in warning for name in names)


def test_a_symlinked_folder_counts_as_a_sub_folder(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "b.json").write_text(doc(span()))
    d = tmp_path / "traces"
    d.mkdir()
    try:
        (d / "link").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available here")
    result = read(d)
    assert result.raw == ()
    assert result.warnings == (f"{d}: 1 sub-folder(s) skipped (the scan does not descend)",)


def test_a_folder_without_sub_folders_has_no_such_warning(tmp_path: Path) -> None:
    d = tmp_path / "traces"
    d.mkdir()
    (d / "a.json").write_text(doc(span()))
    assert read(d).warnings == ()
