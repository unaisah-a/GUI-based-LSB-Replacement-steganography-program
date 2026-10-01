"""Release checks reject unsafe, stale or incomplete archives before extraction."""

import zipfile

import pytest

from scripts.check_release_package import check, inspect_archive


@pytest.mark.parametrize("name,data,error", [
    ("../escape", b"x", "Unsafe"),
    ("/absolute", b"x", "Unsafe"),
    ("C:/absolute", b"x", "Unsafe"),
    ("samples/practice.png", b"x", "Excluded"),
    (".venv-x/secret", b"x", "Excluded"),
    ("docs/key", b"-----BEGIN RSA PRIVATE KEY-----", "Private key"),
    ("main.py", b"stale", "differs"),
])
def test_reject_unsafe_members(tmp_path, name, data, error):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/release_samples.txt").write_text("")
    (tmp_path / "main.py").write_bytes(b"current")
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(name, data)
    with pytest.raises(ValueError, match=error):
        inspect_archive(archive, tmp_path)


def test_missing_bundle_rejected(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/release_samples.txt").write_text("")
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w"):
        pass
    with pytest.raises(ValueError, match="Missing release"):
        inspect_archive(archive, tmp_path)


def test_existing_output_not_overwritten(tmp_path):
    with pytest.raises(ValueError, match="new output"):
        check(tmp_path / "unused.zip", tmp_path)
