"""A decide() used by the adapter tests. It decides by subject id and prints a lot."""

import os
import time

print("printing at import time")


def decide(subject, action, resource, context):
    print("printing inside decide")
    os.write(1, b"raw write to fd 1\n")
    who = subject["id"]
    if who == "alice":
        return True
    if who == "bob":
        return False
    if who == "carol":
        return {"decision": True, "reason": "owner"}
    if who == "dave":
        raise ValueError("bad at https://u:pw@h/x")
    if who == "erin":
        return 1
    if who == "frank":
        time.sleep(5)
        return True
    if who == "gina":
        os._exit(3)
    if who == "hank":
        return {"decision": True, "extra": 1}
    if who == "ivy":
        raise SystemExit(4)
    return False
