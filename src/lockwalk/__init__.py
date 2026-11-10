"""lockwalk: authorization test coverage for AI agent tools."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lockwalk")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0"

__all__ = ["__version__"]
