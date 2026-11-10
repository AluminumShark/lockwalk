"""A reader that never finishes; it also leaves a grandchild behind."""

import os
import subprocess
import sys
import time


def read(paths):
    pid_file = paths[0]
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    with open(pid_file + ".child", "w") as handle:
        handle.write(str(child.pid))
    with open(pid_file, "w") as handle:
        handle.write(str(os.getpid()))
    time.sleep(120)
    yield {"trace_id": "T", "span_id": "S", "kind": "other"}
