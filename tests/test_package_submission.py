"""Tests for the submission packager: what goes in, what stays out."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from scripts import package_submission
from scripts.package_submission import PackagingError, build, collect

PRIVATE_PEM = b"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"
PUBLIC_PEM = b"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"


def _write(root: Path, relative: str, data: bytes = b"x") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@pytest.fixture()
def repository(tmp_path):
    """A small tree with every included root, plus everything that must stay out."""
    root = tmp_path / "repo"
    files = {"main.py", "requirements.txt", "pyproject.toml", "pytest.ini", "README.md",
             ".gitignore", ".gitattributes", "AGENTS.md"}
    for entry in package_submission.INCLUDED:
        _write(root, entry if entry in files else f"{entry}/placeholder.txt")
    _write(root, "keys/public/samples_public.pem", PUBLIC_PEM)
    _write(root, "keys/public/demo_public.pem", PUBLIC_PEM)
    _write(root, "keys/demo_private/demo_private.pem", PRIVATE_PEM)
    _write(root, ".venv/Lib/site-packages/numpy/big.dll")
    _write(root, "app/__pycache__/module.cpython-311.pyc")
    _write(root, "tests/.hypothesis/examples/a")
    _write(root, ".pytest_out.txt")
    _write(root, "evidence/logs/application.log")
    _write(root, "evidence/results/e2e_results.md")
    _write(root, "samples/r11/unrelated.txt")
    _write(root, "samples/t07/party-b/sender-public.pem", PUBLIC_PEM)
    return root


def _names(root: Path, **options) -> set[str]:
    return {path.as_posix() for path in collect(root, **options)}


class TestCollect:
    def test_the_included_content_is_packaged(self, repository):
        names = _names(repository)
        assert "main.py" in names
        assert "keys/public/samples_public.pem" in names
        assert "evidence/results/e2e_results.md" in names
        assert "samples/t07/party-b/sender-public.pem" in names
        assert ".gitattributes" in names

    @pytest.mark.parametrize(
        "excluded",
        [
            "keys/demo_private/demo_private.pem",
            "keys/public/demo_public.pem",
            ".venv/Lib/site-packages/numpy/big.dll",
            "app/__pycache__/module.cpython-311.pyc",
            "tests/.hypothesis/examples/a",
            ".pytest_out.txt",
            "evidence/logs/application.log",
            "samples/r11/unrelated.txt",
        ],
    )
    def test_everything_else_stays_out(self, repository, excluded):
        assert excluded not in _names(repository)

    def test_logs_only_on_request(self, repository):
        assert "evidence/logs/application.log" in _names(repository, include_logs=True)

    def test_a_missing_root_is_an_error(self, repository):
        (repository / "pytest.ini").unlink()
        with pytest.raises(PackagingError, match=r"pytest.ini"):
            collect(repository)


class TestBuild:
    def test_it_writes_a_zip_of_exactly_the_collected_files(self, repository, tmp_path):
        output = tmp_path / "out" / "submission.zip"
        count, size = build(output, root=repository)

        with zipfile.ZipFile(output) as archive:
            names = set(archive.namelist())
        assert names == _names(repository)
        assert count == len(names)
        assert size == output.stat().st_size

    def test_a_private_key_anywhere_stops_the_build(self, repository, tmp_path):
        _write(repository, "docs/leaked.pem", PRIVATE_PEM)
        output = tmp_path / "submission.zip"

        with pytest.raises(PackagingError, match=r"docs/leaked.pem"):
            build(output, root=repository)
        assert not output.exists()

    def test_the_output_cannot_be_inside_a_packaged_directory(self, repository):
        with pytest.raises(PackagingError, match="include itself"):
            build(repository / "docs" / "submission.zip", root=repository)


def test_the_real_repository_packages_without_private_keys():
    """The actual tree: collectable, and no private key would be shipped."""
    files = collect(package_submission.REPOSITORY_ROOT)
    package_submission.check_no_private_keys(package_submission.REPOSITORY_ROOT, files)
    names = {path.as_posix() for path in files}
    assert not any(name.startswith(("keys/demo_private", ".venv", ".git/")) for name in names)
    assert "keys/public/samples_public.pem" in names
