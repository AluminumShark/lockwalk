"""Pick the policy adapter that [policy] names."""

from pathlib import Path

from lockwalk.config import PolicyConfig
from lockwalk.policy.authzen import AuthZenAdapter
from lockwalk.policy.base import PolicyAdapter
from lockwalk.policy.python import PythonAdapter


def make_adapter(policy: PolicyConfig, base_dir: Path) -> PolicyAdapter:
    """The adapter [policy] names. Raises StructuralError for a header that cannot be set.

    A direct caller who passes a python config without a target gets ValueError. PolicyConfig
    prevents that, so the command line can never reach it.
    """
    if policy.adapter == "authzen":
        return AuthZenAdapter(policy)
    return PythonAdapter(policy, base_dir)
