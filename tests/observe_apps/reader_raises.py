"""Readers that fail, one with a message that holds URL credentials."""


def read(paths):
    raise RuntimeError("token https://u:p@x/y")


def read_long(paths):
    raise ValueError("x" * 5000)


def read_huge_message(paths):
    raise ValueError("y" * 100_000)


def read_exit(paths):
    raise SystemExit(3)
