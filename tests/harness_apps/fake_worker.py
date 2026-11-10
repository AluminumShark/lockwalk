"""Stand-in for lockwalk.harness._worker, used by the runner tests.

Parses argv like the real worker and acts on the job's case_id. A survey job has no
case_id; its case comes from the environment variable LOCKWALK_FAKE_SURVEY (ok, fatal, none).
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

SECRET_URL = "https://user:pass@example.com/path"


def write(out: Path, name: str, text: str) -> None:
    temp = out / f"{name}.tmp"
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, out / name)


def observation(**fields: Any) -> str:
    return json.dumps({"observation": fields})


def main(argv: list[str]) -> int:
    request = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    out = Path(argv[2])
    job = request["job"]
    if job["mode"] == "survey":
        case = "survey-" + os.environ.get("LOCKWALK_FAKE_SURVEY", "ok")
    else:
        case = job["case_id"]
    if case == "hang-import":
        time.sleep(600)
    write(out, "imported", "")
    if case == "survey-fatal":
        write(out, "result.json", json.dumps({"fatal": f"cannot load {SECRET_URL}"}))
    elif case == "survey-ok":
        survey = {
            "side_effects": {},
            "door": True,
            "run_path": False,
            "tools": {},
            "agents": {},
            "replaced": {},
            "problems": [f"bad {SECRET_URL}"],
            "warnings": [f"warn {SECRET_URL}"],
        }
        write(out, "result.json", json.dumps({"survey": survey}))
    elif case == "survey-none":
        write(out, "result.json", observation())
    elif case == "hang-run":
        time.sleep(600)
    elif case == "crash":
        return 3
    elif case == "write-fails":
        raise OSError("No space left on device")
    elif case == "junk":
        write(out, "result.json", "{")
    elif case == "big":
        write(out, "result.json", " " * (9 * 1024 * 1024))
    elif case == "bad-door":
        bad = {"subject": {"type": "user", "id": "a", "properties": {"secret": "x"}}}
        bad["decision"] = True
        write(out, "result.json", observation(door_calls=[bad]))
    elif case == "dropped":
        write(out, "result.json", observation(door_calls_dropped=3))
    elif case == "reduced-chain":
        chain = {
            "type": "user",
            "id": "u",
            "act": {"type": "agent", "id": "b", "act": {"type": "agent", "id": "a"}},
        }
        calls = [{"subject": chain, "decision": True}]
        write(out, "result.json", observation(door_calls=calls))
    elif case == "dir-result":
        (out / "result.json").mkdir()
    elif case == "symlink-result":
        os.symlink(argv[1], out / "result.json")
    elif case == "long-exception":
        write(out, "result.json", observation(exception="E" * 300))
    elif case == "grandchild":
        import subprocess

        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        write(out, "result.json", observation(exception_message=str(child.pid)))
    elif case == "empty-error":
        write(out, "result.json", observation(error="", exception_message=""))
    elif case == "empty-not-run":
        write(out, "result.json", observation(not_run=""))
    elif case == "timeline":
        write(
            out,
            "result.json",
            observation(
                side_effect_calls=1,
                timeline=[
                    {
                        "seq": 1,
                        "at_ms": 0.0,
                        "kind": "identity",
                        "data": {"type": "user", "id": "a"},
                    },
                    {
                        "seq": 2,
                        "at_ms": 1.0,
                        "kind": "door",
                        "data": {"subject": {"type": "user", "id": "a"}, "decision": True},
                    },
                    {"seq": 3, "at_ms": 2.0, "kind": "effect", "tool": "t"},
                ],
                timeline_dropped=4,
                elapsed_ms=3.0,
            ),
        )
    elif case == "timeline-junk":
        write(
            out,
            "result.json",
            observation(
                timeline=[
                    {"seq": 1, "at_ms": 0.0, "kind": "identity", "data": {"type": "user"}},
                    {"seq": 2, "at_ms": 1.0, "kind": "door", "data": {"surprise": 1}},
                    {"seq": 3, "at_ms": 2.0, "kind": "effect", "tool": SECRET_URL},
                ],
                elapsed_ms=3.0,
            ),
        )
    elif case == "timeline-too-long":
        write(
            out,
            "result.json",
            observation(
                timeline=[
                    {"seq": n, "at_ms": 0.0, "kind": "effect", "tool": "t"} for n in range(1, 202)
                ],
            ),
        )
    elif case == "timeline-big":
        big = "x" * 600
        write(
            out,
            "result.json",
            observation(
                timeline=[
                    {
                        "seq": 1,
                        "at_ms": 0.0,
                        "kind": "identity",
                        "data": {"type": "user", "id": big},
                    },
                    {
                        "seq": 2,
                        "at_ms": 1.0,
                        "kind": "door",
                        "data": {"subject": {"type": "user", "id": big}, "decision": True},
                    },
                    {"seq": 3, "at_ms": 2.0, "kind": "effect", "tool": "t"},
                ],
            ),
        )
    elif case == "timeline-shapes":
        write(
            out,
            "result.json",
            observation(
                timeline=[
                    {"seq": 1, "at_ms": 0.0, "kind": "door", "data": {}},
                    {
                        "seq": 2,
                        "at_ms": 1.0,
                        "kind": "identity",
                        "data": {"type": "user", "id": "a", "properties": {"k": "v"}},
                    },
                    {
                        "seq": 3,
                        "at_ms": 2.0,
                        "kind": "identity",
                        "data": {"type": "user", "id": f"u{SECRET_URL}"},
                    },
                    {"seq": 4, "at_ms": 3.0, "kind": "effect", "tool": ""},
                ],
            ),
        )
    elif case == "bad-exception":
        write(out, "result.json", observation(exception="not an identifier!"))
    else:  # "ok" and "prints"
        if case == "prints":
            for _ in range(2000):
                print("x" * 200)
                print("y" * 200, file=sys.stderr)
        calls = [
            {"subject": {"type": "user", "id": "a"}, "decision": True},
            {"error": f"door failed at {SECRET_URL}"},
        ]
        fields: dict[str, Any] = {"side_effect_calls": 1, "door_calls": calls}
        if case == "ok":
            fields.update(
                exception="ValueError",
                exception_message=f"boom {SECRET_URL}",
                not_run=f"skipped {SECRET_URL}",
                error=f"err {SECRET_URL}",
                blocked_hosts=[SECRET_URL],
            )
        write(out, "result.json", observation(**fields))
    return 0


if __name__ == "__main__":
    os._exit(main(sys.argv))
