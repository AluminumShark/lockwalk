"""Check what the built packages hold, before anyone can publish them.

Usage: python scripts/check_package.py DIST_DIR [--tag v1.2.3] [--changelog CHANGELOG.md]

Checks the names inside the archives against an exact list of what may ship, that the wheel
and the sdist hold the same package files, and the version in METADATA and PKG-INFO. It does
not read any other file's contents, so a secret inside a module is not found.
Exits 1 and lists every problem.
"""

import argparse
import re
import stat
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path

PACKAGE = "lockwalk"
# Newer uv versions keep the original pyproject.toml next to the rewritten one.
SDIST_FILES = frozenset(
    {"LICENSE", "PKG-INFO", "README.md", "pyproject.toml", "pyproject.toml.orig"}
)
# Inside the package folder a file is a module (name ends in .py) or this one data file.
PACKAGE_DATA = "py.typed"
DIST_INFO_FILES = frozenset({"METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE"})
WHEEL_REQUIRED = ("METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE")
WHEEL_PACKAGE_REQUIRED = ("__init__.py", "cli.py", PACKAGE_DATA)
SDIST_REQUIRED = (
    "README.md",
    "LICENSE",
    "PKG-INFO",
    "pyproject.toml",
    f"src/{PACKAGE}/__init__.py",
    f"src/{PACKAGE}/cli.py",
    f"src/{PACKAGE}/{PACKAGE_DATA}",
)
MAX_METADATA = 1_000_000  # bytes; a real METADATA holds the README and stays well below this
MAX_NAMED = 20
_WHEEL_NAME = re.compile(rf"^{PACKAGE}-(?P<version>[^-]+)-py3-none-any\.whl$")
_SDIST_NAME = re.compile(rf"^{PACKAGE}-(?P<version>.+)\.tar\.gz$")


_SAFE_NAME = re.compile(r"[A-Za-z0-9_./-]+")
_SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_SECRET_NAMES = frozenset(
    {
        ".env",
        ".ds_store",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".pypirc",
        ".netrc",
        ".npmrc",
        ".git-credentials",
        "credentials",
        "credentials.json",
    }
)
_DATED_HEADING = r"^## \[{version}\] - \d{{4}}-\d{{2}}-\d{{2}}[ \t\r]*$"


def _bad_name(name: str) -> bool:
    """True for a name that must never ship, whatever folder it sits in."""
    if _SAFE_NAME.fullmatch(name) is None:
        return True
    parts = name.rstrip("/").split("/")
    return (
        name.startswith("/")
        or ".." in parts
        or "__pycache__" in parts
        or parts[-1].lower().endswith(".pyc")
        or any(_secret_component(part) for part in parts)
    )


def _secret_component(part: str) -> bool:
    """True for a file or folder name that looks like a secret, in any letter case."""
    low = part.lower()
    return low in _SECRET_NAMES or low.startswith(".env.") or low.endswith(_SECRET_SUFFIXES)


def _package_file_ok(path: str) -> bool:
    """True for a file the package folder may hold: a module or py.typed."""
    return path.endswith(".py") or path == PACKAGE_DATA


def _repeated(names: Sequence[str], where: str) -> list[str]:
    seen = set()
    problems = []
    for name in names:
        if name in seen:
            problems.append(f"{where}: entry {name!r} appears more than once")
        seen.add(name)
    return problems


def _version_problem(text: bytes, label: str, where: str, version: str) -> str | None:
    """Check the one `Version:` header of METADATA or PKG-INFO against `version`."""
    if len(text) > MAX_METADATA:
        return f"{where}: {label} is larger than {MAX_METADATA} bytes"
    try:
        decoded = text.decode("utf-8")
    except UnicodeDecodeError:
        return f"{where}: {label} is not UTF-8"
    header = decoded.replace("\r\n", "\n").split("\n\n", 1)[0]
    prefix = "Version:"
    versions = [
        line[len(prefix) :].strip() for line in header.split("\n") if line.startswith(prefix)
    ]
    if len(versions) != 1:
        return f"{where}: {label} must hold exactly one Version header, found {len(versions)}"
    if versions[0] != version:
        return f"{where}: {label} says version {versions[0]!r}, the file name says {version!r}"
    return None


def _check_wheel(path: Path, version: str) -> tuple[list[str], set[str]]:
    """Return the problems and the package files (names relative to the package folder)."""
    where = repr(path.name)
    dist_info = f"{PACKAGE}-{version}.dist-info"
    metadata = f"{dist_info}/METADATA"
    raw = b""
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            for info in infos:
                if info.filename == metadata and not info.is_dir():
                    with archive.open(info) as handle:
                        raw = handle.read(MAX_METADATA + 1)
                    break
    except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError) as error:
        return [f"{where}: cannot read the wheel ({error})"], set()
    problems = _repeated([info.filename for info in infos], where)
    files = set()
    for info in infos:
        name = info.filename
        bare = name.rstrip("/")
        if _bad_name(name):
            problems.append(f"{where}: unsafe entry {name!r}")
        elif stat.S_ISLNK(info.external_attr >> 16):
            problems.append(f"{where}: entry {name!r} is a symbolic link")
        elif name.startswith(f"{PACKAGE}/"):
            if info.is_dir():
                continue
            if _package_file_ok(bare[len(PACKAGE) + 1 :]):
                files.add(bare[len(PACKAGE) + 1 :])
            else:
                problems.append(f"{where}: unexpected entry {name!r}")
        elif name.startswith(f"{dist_info}/"):
            if not (info.is_dir() or bare[len(dist_info) + 1 :] in DIST_INFO_FILES):
                problems.append(f"{where}: unexpected entry {name!r}")
        else:
            problems.append(f"{where}: unexpected entry {name!r}")
    present = {info.filename for info in infos}
    for needed in (
        *(f"{PACKAGE}/{n}" for n in WHEEL_PACKAGE_REQUIRED),
        *(f"{dist_info}/{n}" for n in WHEEL_REQUIRED),
    ):
        if needed not in present:
            problems.append(f"{where}: required entry {needed!r} is missing")
    if metadata in present and (found := _version_problem(raw, "METADATA", where, version)):
        problems.append(found)
    return problems, files


def _check_sdist(path: Path, version: str) -> tuple[list[str], set[str]]:
    """Return the problems and the package files (names relative to the package folder)."""
    where = repr(path.name)
    top = f"{PACKAGE}-{version}"
    package_dir = f"src/{PACKAGE}"
    raw = b""
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                if member.name == f"{top}/PKG-INFO" and member.isreg():
                    handle = archive.extractfile(member)
                    if handle is not None:
                        raw = handle.read(MAX_METADATA + 1)
                    break
    except (tarfile.TarError, OSError, EOFError) as error:
        return [f"{where}: cannot read the sdist ({error})"], set()
    problems = _repeated([member.name for member in members], where)
    present = set()
    files = set()
    for member in members:
        name = member.name
        if _bad_name(name):
            problems.append(f"{where}: unsafe entry {name!r}")
            continue
        if not (member.isreg() or member.isdir()):
            problems.append(f"{where}: entry {name!r} is not a regular file or a directory")
            continue
        bare = name.rstrip("/")
        if bare == top:
            if not member.isdir():
                problems.append(f"{where}: entry {name!r} must be a directory")
            continue
        if not name.startswith(top + "/"):
            problems.append(f"{where}: entry {name!r} is outside {top}/")
            continue
        rest = bare[len(top) + 1 :]
        in_package = rest.startswith(package_dir + "/")
        if member.isreg():
            present.add(rest)
        if member.isdir():
            if rest in ("src", package_dir) or in_package:
                continue
        elif in_package:
            inside = rest[len(package_dir) + 1 :]
            if _package_file_ok(inside):
                files.add(inside)
                continue
        elif rest in SDIST_FILES:
            continue
        problems.append(f"{where}: unexpected entry {name!r}")
    for needed in SDIST_REQUIRED:
        if needed not in present:
            problems.append(f"{where}: required entry '{top}/{needed}' is missing")
    if "PKG-INFO" in present and (found := _version_problem(raw, "PKG-INFO", where, version)):
        problems.append(found)
    return problems, files


def _named(files: set[str]) -> str:
    shown = sorted(files)[:MAX_NAMED]
    more = len(files) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more else "")


def _compare(wheel_files: set[str], sdist_files: set[str]) -> list[str]:
    """Report package files that only one of the two archives holds."""
    problems = []
    if only := wheel_files - sdist_files:
        problems.append(f"files only in the wheel, not in the sdist: {_named(only)}")
    if only := sdist_files - wheel_files:
        problems.append(f"files only in the sdist, not in the wheel: {_named(only)}")
    return problems


def _check_tag(tag: str, version: str, changelog: Path | None) -> list[str]:
    problems = []
    if tag != f"v{version}":
        problems.append(f"tag {tag!r} does not match the built version (expected 'v{version}')")
    if ".dev" in version:
        problems.append(f"version {version!r} is a development version and cannot be released")
    if "+" in version:
        problems.append(f"version {version!r} is a local version and cannot be released")
    if changelog is None:
        problems.append("a tag check needs --changelog")
        return problems
    try:
        text = changelog.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        problems.append(f"cannot read {str(changelog)!r} ({error})")
        return problems
    escaped = re.escape(version)
    if re.search(_DATED_HEADING.format(version=escaped), text, re.MULTILINE):
        return problems
    found = re.search(rf"^## \[{escaped}\](.*)$", text, re.MULTILINE)
    if found is None:
        problems.append(f"{str(changelog)!r} has no '## [{version}]' heading")
    elif "unreleased" in found[1].lower():
        problems.append(
            f"{str(changelog)!r}: the heading for {version!r} says Unreleased; "
            "give it a date (## [X.Y.Z] - YYYY-MM-DD)"
        )
    else:
        problems.append(
            f"{str(changelog)!r}: the heading for {version!r} has no date (## [X.Y.Z] - YYYY-MM-DD)"
        )
    return problems


def check(dist: Path, *, tag: str | None = None, changelog: Path | None = None) -> list[str]:
    """Return a list of problems with the packages in `dist`; empty means fine."""
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    problems = []
    if len(wheels) != 1:
        problems.append(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    if len(sdists) != 1:
        problems.append(f"expected exactly one sdist in {dist}, found {len(sdists)}")
    if problems:
        return problems
    wheel, sdist = wheels[0], sdists[0]
    wheel_match = _WHEEL_NAME.match(wheel.name)
    sdist_match = _SDIST_NAME.match(sdist.name)
    if wheel_match is None:
        problems.append(f"{wheel.name!r}: not a {PACKAGE} wheel name")
    if sdist_match is None:
        problems.append(f"{sdist.name!r}: not a {PACKAGE} sdist name")
    if wheel_match is None or sdist_match is None:
        return problems
    version = wheel_match["version"]
    if sdist_match["version"] != version:
        problems.append(f"version mismatch: wheel {version!r}, sdist {sdist_match['version']!r}")
        return problems
    wheel_problems, wheel_files = _check_wheel(wheel, version)
    sdist_problems, sdist_files = _check_sdist(sdist, version)
    problems += wheel_problems + sdist_problems
    problems += _compare(wheel_files, sdist_files)
    if tag is not None:
        problems += _check_tag(tag, version, changelog)
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the built wheel and sdist.")
    parser.add_argument("dist", type=Path, help="folder with the built packages")
    parser.add_argument("--tag", help="release tag, for example v1.2.3")
    parser.add_argument("--changelog", type=Path, help="CHANGELOG.md, needed with --tag")
    args = parser.parse_args(argv)
    problems = check(args.dist, tag=args.tag, changelog=args.changelog)
    for problem in problems:
        print(f"PROBLEM: {problem}", file=sys.stderr)
    if problems:
        print(f"{len(problems)} problem(s) found", file=sys.stderr)
        return 1
    note = "names and versions checked; other contents not read"
    print(f"OK: packages in {args.dist} hold only the expected files ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
