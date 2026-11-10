"""A hooks file that raises on import, with a secret in the message."""

raise RuntimeError("cannot connect to https://user:pass@db.internal/x")
