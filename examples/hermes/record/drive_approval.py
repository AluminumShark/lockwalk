"""Run `hermes chat -q` on a pty and answer the dangerous-command approval menu.

Usage: python drive_approval.py MARKER allow|deny PORT
Linux only (stdlib pty). Approval spans exist only on the interactive path, so the menu is
answered like a person would: "allow once" is the first entry, "deny" is the fourth. PORT is
the fake model's port; record.sh passes it, so the two can never disagree.

Env: TRANSCRIPT (optional path). The file holds the RAW pty output, only stripped of ANSI
escapes: it contains the command text and local paths. Keep it out of the repository.

Exit code: 0 when the menu was answered, 1 when it never appeared, 2 on bad arguments.
"""

from __future__ import annotations

import contextlib
import os
import re
import select
import signal
import sys
import time

if sys.platform != "linux":
    sys.exit("drive_approval.py needs a Linux pty; run it in WSL or on Linux")

import pty

ANSI = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]")
DOWN = b"\x1b[B"
DEADLINE = 90  # seconds for the whole drive


def stop_child(pid: int) -> None:
    """SIGTERM, then SIGKILL after a few seconds, and always reap the child."""
    for sig, wait in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 5.0)):
        with contextlib.suppress(OSError):
            os.kill(pid, sig)
        end = time.time() + wait
        while time.time() < end:
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                return
            if done:
                return
            time.sleep(0.1)


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[2] not in ("allow", "deny") or not sys.argv[3].isdigit():
        print("usage: python drive_approval.py MARKER allow|deny PORT", file=sys.stderr)
        return 2
    marker, answer, port = sys.argv[1], sys.argv[2], sys.argv[3]
    args = [
        "hermes", "chat", "-q", f"{marker} go",
        "--provider", "custom", "--base-url", f"http://127.0.0.1:{port}/v1",
        "--api-key", "dummy-key", "-m", "fake-model",
    ]  # fmt: skip
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.environ.update(TERM="xterm", COLUMNS="120", LINES="40")
            os.execvp(args[0], args)
        finally:
            os._exit(127)  # only reached when exec failed
    buf = b""
    answered = False
    sent_exit = False
    started = time.time()
    answered_at = exit_at = 0.0
    while time.time() - started < DEADLINE:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            buf += data
        text = ANSI.sub(b"", buf).decode("utf-8", "replace")
        if not answered and "to select, Enter to confirm" in text and "Dangerous Command" in text:
            time.sleep(0.5)
            if answer == "deny":
                for _ in range(3):
                    os.write(fd, DOWN)
                    time.sleep(0.3)
            os.write(fd, b"\r")
            answered, answered_at = True, time.time()
        if answered and not sent_exit and time.time() - answered_at > 6:
            os.write(fd, b"/exit\r")
            sent_exit, exit_at = True, time.time()
        if sent_exit and time.time() - exit_at > 10:
            break
    stop_child(pid)
    with contextlib.suppress(OSError):
        os.close(fd)
    transcript = os.environ.get("TRANSCRIPT")
    if transcript:
        with open(transcript, "w", encoding="utf-8") as out:
            out.write(ANSI.sub(b"", buf).decode("utf-8", "replace"))
    print(f"answered={answered} exited_cleanly={sent_exit}")
    return 0 if answered else 1


if __name__ == "__main__":
    sys.exit(main())
