"""The package check script: what the built wheel and sdist may hold."""

import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_package.py"
_spec = importlib.util.spec_from_file_location("check_package", SCRIPT)
assert _spec is not None and _spec.loader is not None
check_package = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_package)
check = check_package.check
main = check_package.main


def wheel_members(version):
    return (
        "lockwalk/__init__.py",
        "lockwalk/cli.py",
        "lockwalk/py.typed",
        f"lockwalk-{version}.dist-info/METADATA",
        f"lockwalk-{version}.dist-info/WHEEL",
        f"lockwalk-{version}.dist-info/RECORD",
        f"lockwalk-{version}.dist-info/entry_points.txt",
        f"lockwalk-{version}.dist-info/licenses/LICENSE",
    )


SDIST_MEMBERS = (
    "LICENSE",
    "PKG-INFO",
    "README.md",
    "pyproject.toml",
    "src/lockwalk/__init__.py",
    "src/lockwalk/cli.py",
    "src/lockwalk/py.typed",
)


def content(name, version):
    if name.endswith(("METADATA", "PKG-INFO")):
        return f"Metadata-Version: 2.4\nName: lockwalk\nVersion: {version}\n\nbody\n"
    return "x"


def make_wheel(folder, version="1.2.3", extra=(), omit=(), meta_version=None):
    path = folder / f"lockwalk-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name in (*wheel_members(version), *extra):
            if name not in omit:
                archive.writestr(name, content(name, meta_version or version))
    return path


def make_sdist(folder, version="1.2.3", extra=(), omit=(), meta_version=None):
    path = folder / f"lockwalk-{version}.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name in (*SDIST_MEMBERS, *extra):
            if name in omit:
                continue
            data = content(name, meta_version or version).encode()
            info = tarfile.TarInfo(f"lockwalk-{version}/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def make_dist(folder, **kw):
    make_wheel(folder, extra=kw.get("wheel", ()), omit=kw.get("omit_wheel", ()))
    make_sdist(folder, extra=kw.get("sdist", ()), omit=kw.get("omit_sdist", ()))
    return folder


def test_a_good_package_has_no_problems(tmp_path):
    assert check(make_dist(tmp_path)) == []


def test_the_original_pyproject_copy_is_allowed_in_the_sdist(tmp_path):
    assert check(make_dist(tmp_path, sdist=("pyproject.toml.orig",))) == []


def test_directory_entries_are_fine(tmp_path):
    make_wheel(tmp_path)
    path = tmp_path / "lockwalk-1.2.3.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name in ("lockwalk-1.2.3", "lockwalk-1.2.3/src", "lockwalk-1.2.3/src/lockwalk"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for name in SDIST_MEMBERS:
            data = content(name, "1.2.3").encode()
            info = tarfile.TarInfo(f"lockwalk-1.2.3/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    assert check(tmp_path) == []


@pytest.mark.parametrize(
    "entry",
    [
        "tests/test_x.py",
        "examples/a.py",
        "docs/" + "superpowers/plans/x.md",
        "lockwalk/__pycache__/a.pyc",
        "lockwalk/a.PYC",
        "lockwalk/.env",
        "lockwalk/cert.pem",
        "lockwalk/id.KEY",
        "lockwalk/.DS_Store",
        "lockwalk-9.9.9.dist-info/x",
        "evil.py",
        "./lockwalk/x.py",
        "Lockwalk/x.py",
    ],
)
def test_a_wheel_with_a_stray_entry_is_a_problem(tmp_path, entry):
    problems = check(make_dist(tmp_path, wheel=(entry,)))
    assert any(entry in problem for problem in problems)


@pytest.mark.parametrize(
    "entry",
    [
        "docs/" + "superpowers/specs/x.md",
        "PROJECT_" + "SPEC_x.md",
        ".claude/x",
        "tests/x.py",
        "src/other/x.py",
        "src/lockwalk/.env",
        "src/lockwalk/a.pem",
        "src/lockwalk/a.pyc",
    ],
)
def test_an_sdist_with_a_stray_entry_is_a_problem(tmp_path, entry):
    problems = check(make_dist(tmp_path, sdist=(entry,)))
    assert any(entry in problem for problem in problems)


def test_a_file_named_like_the_package_folder_is_a_problem(tmp_path):
    # A regular file called src/lockwalk instead of a folder.
    make_wheel(tmp_path)
    make_sdist(tmp_path, extra=("src/lockwalk",), omit=("src/lockwalk/__init__.py",))
    assert any("src/lockwalk" in problem for problem in check(tmp_path))


def _sdist_with(folder, build):
    make_wheel(folder)
    with tarfile.open(folder / "lockwalk-1.2.3.tar.gz", "w:gz") as archive:
        build(archive)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE])
def test_an_sdist_member_that_is_not_a_file_is_a_problem(tmp_path, kind):
    def build(archive):
        info = tarfile.TarInfo("lockwalk-1.2.3/src/lockwalk/link")
        info.type = kind
        info.linkname = "/etc/passwd"
        archive.addfile(info)

    _sdist_with(tmp_path, build)
    problems = check(tmp_path)
    assert any("src/lockwalk/link" in problem for problem in problems)


def test_the_sdist_top_name_must_be_a_directory(tmp_path):
    def build(archive):
        info = tarfile.TarInfo("lockwalk-1.2.3")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))

    _sdist_with(tmp_path, build)
    assert any("must be a directory" in problem for problem in check(tmp_path))


def test_a_wheel_symlink_is_a_problem(tmp_path):
    path = tmp_path / "lockwalk-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name in wheel_members("1.2.3"):
            archive.writestr(name, content(name, "1.2.3"))
        info = zipfile.ZipInfo("lockwalk/link")
        info.external_attr = 0o120777 << 16
        archive.writestr(info, "/etc/passwd")
    make_sdist(tmp_path)
    assert any("lockwalk/link" in problem for problem in check(tmp_path))


@pytest.mark.parametrize("name", wheel_members("1.2.3"))
def test_a_wheel_missing_a_required_member_is_a_problem(tmp_path, name):
    problems = check(make_dist(tmp_path, omit_wheel=(name,)))
    assert any("required" in problem and name in problem for problem in problems)


@pytest.mark.parametrize(
    "name",
    [
        "PKG-INFO",
        "pyproject.toml",
        "LICENSE",
        "src/lockwalk/__init__.py",
        "src/lockwalk/cli.py",
        "src/lockwalk/py.typed",
    ],
)
def test_an_sdist_missing_a_required_member_is_a_problem(tmp_path, name):
    problems = check(make_dist(tmp_path, omit_sdist=(name,)))
    assert any("required" in problem and name in problem for problem in problems)


def test_no_wheel_is_a_problem(tmp_path):
    make_sdist(tmp_path)
    assert any("wheel" in problem for problem in check(tmp_path))


def test_no_sdist_is_a_problem(tmp_path):
    make_wheel(tmp_path)
    assert any("sdist" in problem for problem in check(tmp_path))


def test_two_wheels_are_a_problem(tmp_path):
    make_dist(tmp_path)
    make_wheel(tmp_path, version="1.2.4")
    assert any("wheel" in problem for problem in check(tmp_path))


def test_different_versions_are_a_problem(tmp_path):
    make_wheel(tmp_path, version="1.2.3")
    make_sdist(tmp_path, version="1.2.4")
    assert any("version" in problem for problem in check(tmp_path))


def test_unsafe_names_are_a_problem_and_nothing_is_extracted(tmp_path):
    make_wheel(tmp_path, extra=("lockwalk/../evil.py", "/abs.py"))
    make_sdist(tmp_path, extra=("src/lockwalk/../../evil.py",))
    problems = check(tmp_path)
    assert any("lockwalk/../evil.py" in problem for problem in problems)
    assert any("/abs.py" in problem for problem in problems)
    assert any(".tar.gz" in problem and "../../evil.py" in problem for problem in problems)
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "lockwalk-1.2.3-py3-none-any.whl",
        "lockwalk-1.2.3.tar.gz",
    ]


def test_a_hostile_name_stays_on_one_line(tmp_path):
    problems = check(make_dist(tmp_path, wheel=("lockwalk/a\nPROBLEM: fake\x1b[31m.py",)))
    assert problems
    assert all("\n" not in problem and "\x1b" not in problem for problem in problems)


def test_a_broken_archive_is_a_problem_not_a_crash(tmp_path):
    (tmp_path / "lockwalk-1.2.3-py3-none-any.whl").write_bytes(b"not a zip")
    make_sdist(tmp_path)
    assert check(tmp_path)
    (tmp_path / "lockwalk-1.2.3.tar.gz").write_bytes(b"not a tar")
    assert check(tmp_path)


@pytest.mark.parametrize(
    "entry",
    [
        "lockwalk/id_rsa",
        "lockwalk/.env.production",
        "lockwalk/credentials.json",
        "lockwalk/_scratch/plan.md",
        "lockwalk/tests/data.txt",
        "lockwalk/docs/x.md",
        "lockwalk/x.PY",
        "lockwalk/py.typed.bak",
        "lockwalk/sub/py.typed",
        "lockwalk-1.2.3.dist-info/extra.txt",
        "lockwalk-1.2.3.dist-info/licenses/NOTICE",
        "lockwalk-1.2.3.dist-info/sub/METADATA",
    ],
)
def test_a_wheel_holds_an_exact_list_of_files(tmp_path, entry):
    problems = check(make_dist(tmp_path, wheel=(entry,)))
    assert any(entry in problem for problem in problems), problems


def test_a_py_file_in_a_nested_subpackage_is_allowed(tmp_path):
    dist = make_dist(
        tmp_path,
        wheel=("lockwalk/a/b/c.py", "lockwalk/tests/x.py"),
        sdist=("src/lockwalk/a/b/c.py", "src/lockwalk/tests/x.py"),
    )
    assert check(dist) == []


def test_directory_entries_in_a_wheel_are_fine(tmp_path):
    path = make_wheel(tmp_path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("lockwalk-1.2.3.dist-info/licenses/", "")
        archive.writestr("lockwalk/sub/", "")
    make_sdist(tmp_path)
    assert check(tmp_path) == []


@pytest.mark.parametrize("entry", ["lockwalk/.env/", "lockwalk/id_rsa/", "lockwalk/key.pem/"])
def test_a_directory_with_a_secret_name_is_a_problem(tmp_path, entry):
    path = make_wheel(tmp_path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr(entry, "")
    make_sdist(tmp_path)
    assert any(entry in problem for problem in check(tmp_path))


def test_a_repeated_wheel_entry_is_a_problem(tmp_path):
    path = make_wheel(tmp_path)
    with zipfile.ZipFile(path, "a") as archive, pytest.warns(UserWarning, match="Duplicate"):
        archive.writestr("lockwalk/cli.py", "evil")
    make_sdist(tmp_path)
    assert any("more than once" in problem for problem in check(tmp_path))


def test_a_repeated_sdist_entry_is_a_problem(tmp_path):
    make_wheel(tmp_path)
    with tarfile.open(tmp_path / "lockwalk-1.2.3.tar.gz", "w:gz") as archive:
        for name in (*SDIST_MEMBERS, "src/lockwalk/cli.py"):
            data = content(name, "1.2.3").encode()
            info = tarfile.TarInfo(f"lockwalk-1.2.3/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    assert any("more than once" in problem for problem in check(tmp_path))


@pytest.mark.parametrize(
    "name",
    [
        "lockwalk/py.typed",
        "lockwalk/cli.py",
        "lockwalk-1.2.3.dist-info/entry_points.txt",
        "lockwalk-1.2.3.dist-info/licenses/LICENSE",
    ],
)
def test_a_wheel_missing_a_package_file_is_a_problem(tmp_path, name):
    problems = check(make_dist(tmp_path, omit_wheel=(name,)))
    assert any("required" in problem and name in problem for problem in problems), problems


def test_an_sdist_needs_the_readme(tmp_path):
    problems = check(make_dist(tmp_path, omit_sdist=("README.md",)))
    assert any("README.md" in problem for problem in problems)


@pytest.mark.parametrize(
    "entry",
    [
        "src/lockwalk/id_rsa",
        "src/lockwalk/data.txt",
        "src/lockwalk/sub/notes.md",
        "src/lockwalk/X.PY",
    ],
)
def test_the_sdist_package_folder_holds_only_py_and_py_typed(tmp_path, entry):
    problems = check(make_dist(tmp_path, sdist=(entry,)))
    assert any(entry in problem for problem in problems), problems


def test_a_module_missing_from_the_wheel_is_a_problem(tmp_path):
    problems = check(make_dist(tmp_path, sdist=("src/lockwalk/extra.py",)))
    assert any("extra.py" in problem and "only in the sdist" in problem for problem in problems)


def test_a_module_missing_from_the_sdist_is_a_problem(tmp_path):
    problems = check(make_dist(tmp_path, wheel=("lockwalk/extra.py",)))
    assert any("extra.py" in problem and "only in the wheel" in problem for problem in problems)


def test_at_most_20_differences_are_named(tmp_path):
    names = tuple(f"lockwalk/m{i:02}.py" for i in range(30))
    problems = check(make_dist(tmp_path, wheel=names))
    text = " ".join(problems)
    assert "m19.py" in text
    assert "m20.py" not in text
    assert "10 more" in text


def test_a_wheel_metadata_version_that_differs_is_a_problem(tmp_path):
    make_wheel(tmp_path, meta_version="9.9.9")
    make_sdist(tmp_path)
    problems = check(tmp_path)
    assert any("METADATA" in problem and "9.9.9" in problem for problem in problems)


def test_an_sdist_pkg_info_version_that_differs_is_a_problem(tmp_path):
    make_wheel(tmp_path)
    make_sdist(tmp_path, meta_version="9.9.9")
    problems = check(tmp_path)
    assert any("PKG-INFO" in problem and "9.9.9" in problem for problem in problems)


def wheel_with_metadata(folder, data):
    path = folder / "lockwalk-1.2.3-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for name in wheel_members("1.2.3"):
            archive.writestr(name, data if name.endswith("METADATA") else b"x")
    make_sdist(folder)


@pytest.mark.parametrize(
    "text",
    [
        b"Name: lockwalk\n",
        b"Name: lockwalk\nVersion: 1.2.3\nVersion: 1.2.3\n",
        b"Name: lockwalk\n\nVersion: 1.2.3\n",
        b"",
    ],
)
def test_metadata_must_hold_exactly_one_version_header(tmp_path, text):
    wheel_with_metadata(tmp_path, text)
    assert any("METADATA" in problem for problem in check(tmp_path))


def test_metadata_that_is_not_utf8_is_a_problem_not_a_crash(tmp_path):
    wheel_with_metadata(tmp_path, b"Version: 1.2.3\n\xff\xfe")
    assert any("METADATA" in problem for problem in check(tmp_path))


def test_huge_metadata_is_a_problem_not_a_crash(tmp_path):
    wheel_with_metadata(tmp_path, b"Version: 1.2.3\n" + b"a" * 3_000_000)
    assert any("METADATA" in problem for problem in check(tmp_path))


@pytest.mark.parametrize(
    "base",
    [
        ".env",
        ".ENV",
        ".env.local",
        ".Env.Production",
        "id_rsa",
        "ID_RSA",
        "id_dsa",
        "id_ecdsa",
        "Id_Ed25519",
        ".pypirc",
        ".netrc",
        ".NPMRC",
        ".git-credentials",
        "credentials",
        "Credentials.JSON",
        "a.pem",
        "a.KEY",
        "a.p12",
        "a.PFX",
        ".DS_Store",
    ],
)
@pytest.mark.parametrize("folder", ["", "a/", "a/b/c/"])
def test_secret_looking_names_are_refused_in_the_sdist_at_any_depth(tmp_path, base, folder):
    entry = f"{folder}{base}"
    problems = check(make_dist(tmp_path, sdist=(entry,)))
    assert any("unsafe entry" in problem and base in problem for problem in problems), problems


@pytest.mark.parametrize(
    "base", [".env.production", "id_ed25519", ".NETRC", "x.p12", "credentials"]
)
def test_secret_looking_names_are_refused_in_the_wheel(tmp_path, base):
    problems = check(make_dist(tmp_path, wheel=(f"lockwalk/{base}",)))
    assert any("unsafe entry" in problem and base in problem for problem in problems), problems


def test_the_ok_line_says_what_it_checked(tmp_path, capsys):
    assert main([str(make_dist(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "hold only the expected files" in out
    assert "names and versions checked; other contents not read" in out


def write_changelog(folder, heading="## [1.2.3] - 2026-11-09"):
    path = folder / "CHANGELOG.md"
    path.write_text(f"# Changelog\n\n{heading}\n\n- something\n", encoding="utf-8")
    return path


def test_a_matching_tag_is_fine(tmp_path):
    dist = make_dist(tmp_path)
    assert check(dist, tag="v1.2.3", changelog=write_changelog(tmp_path)) == []


def test_a_changelog_with_windows_line_endings_is_fine(tmp_path):
    dist = make_dist(tmp_path)
    path = tmp_path / "CHANGELOG.md"
    path.write_bytes(b"# Changelog\r\n\r\n## [1.2.3] - 2026-11-09\r\n\r\n- x\r\n")
    assert check(dist, tag="v1.2.3", changelog=path) == []


@pytest.mark.parametrize("tag", ["v1.2.4", "1.2.3", "V1.2.3", "v1.2.3 "])
def test_a_wrong_tag_is_a_problem(tmp_path, tag):
    dist = make_dist(tmp_path)
    problems = check(dist, tag=tag, changelog=write_changelog(tmp_path))
    assert any("does not match the built version" in problem for problem in problems)


@pytest.mark.parametrize(
    ("version", "word"),
    [("1.2.3.dev0", "development"), ("1.2.3+local", "local")],
)
def test_a_dev_or_local_version_cannot_be_tagged(tmp_path, version, word):
    make_wheel(tmp_path, version=version)
    make_sdist(tmp_path, version=version)
    changelog = write_changelog(tmp_path, f"## [{version}] - 2026-11-09")
    problems = check(tmp_path, tag=f"v{version}", changelog=changelog)
    assert any(word in problem for problem in problems)


@pytest.mark.parametrize("version", ["1.2.3rc1", "1.2.3.post1"])
def test_rc_and_post_versions_can_be_tagged(tmp_path, version):
    make_wheel(tmp_path, version=version)
    make_sdist(tmp_path, version=version)
    changelog = write_changelog(tmp_path, f"## [{version}] - 2026-11-09")
    assert check(tmp_path, tag=f"v{version}", changelog=changelog) == []


@pytest.mark.parametrize(
    ("heading", "message"),
    [
        ("## [1.2.2] - 2026-11-01", "no '## [1.2.3]' heading"),
        ("## [1.2.3] - Unreleased", "says Unreleased"),
        ("## [1.2.3] - unreleased", "says Unreleased"),
        ("## [1.2.3]", "has no date"),
        ("## [1.2.3] - soon", "has no date"),
        ("## [1.2.3] - 2026-11", "has no date"),
        ("## [1.2.3] - 2026-11-09 extra", "has no date"),
    ],
)
def test_the_changelog_heading_needs_a_date(tmp_path, heading, message):
    dist = make_dist(tmp_path)
    problems = check(dist, tag="v1.2.3", changelog=write_changelog(tmp_path, heading))
    assert any(message in problem for problem in problems), problems


def test_a_missing_changelog_is_a_problem(tmp_path):
    dist = make_dist(tmp_path)
    problems = check(dist, tag="v1.2.3", changelog=tmp_path / "missing.md")
    assert any("cannot read" in problem for problem in problems)


def test_a_tag_without_a_changelog_option_is_a_problem(tmp_path):
    problems = check(make_dist(tmp_path), tag="v1.2.3")
    assert any("--changelog" in problem for problem in problems)


def test_a_changelog_that_is_not_utf8_is_a_problem_not_a_crash(tmp_path):
    dist = make_dist(tmp_path)
    path = tmp_path / "CHANGELOG.md"
    path.write_bytes(b"## [1.2.3] - 2026-11-09 \xff\xfe\n")
    problems = check(dist, tag="v1.2.3", changelog=path)
    assert any("cannot read" in problem for problem in problems)


def test_main_returns_0_for_a_good_package(tmp_path, capsys):
    assert main([str(make_dist(tmp_path))]) == 0
    assert capsys.readouterr().err == ""


def test_main_returns_1_and_prints_each_problem(tmp_path, capsys):
    dist = make_dist(tmp_path, wheel=("tests/a.py", "examples/b.py"))
    assert main([str(dist)]) == 1
    output = capsys.readouterr()
    text = output.out + output.err
    assert "tests/a.py" in text
    assert "examples/b.py" in text


def test_main_checks_the_tag(tmp_path, capsys):
    dist = make_dist(tmp_path)
    changelog = write_changelog(tmp_path)
    assert main([str(dist), "--tag", "v1.2.3", "--changelog", str(changelog)]) == 0
    assert main([str(dist), "--tag", "v9.9.9", "--changelog", str(changelog)]) == 1


@pytest.mark.parametrize(
    "folder",
    [
        "id_rsa",
        ".env",
        "credentials",
        "x.pem",
        "ID_RSA",
        ".Env.Production",
        "Credentials.JSON",
        "a.P12",
    ],
)
@pytest.mark.parametrize("prefix", ["", "a/", "a/b/"])
def test_a_secret_name_as_a_folder_is_refused_in_both_archives(tmp_path, folder, prefix):
    wheel_entry = f"lockwalk/{prefix}{folder}/x.py"
    sdist_entry = f"src/lockwalk/{prefix}{folder}/x.py"
    problems = check(make_dist(tmp_path, wheel=(wheel_entry,), sdist=(sdist_entry,)))
    assert any("unsafe entry" in p and wheel_entry in p for p in problems), problems
    assert any("unsafe entry" in p and sdist_entry in p for p in problems), problems
