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
    ("app/key", b"-----BEGIN RSA PRIVATE KEY-----", "Private key"),
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


def test_missing_required_files_rejected(tmp_path):
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


def test_empty_sample_archive_passes_source_checks_but_is_not_submission_ready(tmp_path):
    import json
    import shutil

    from scripts.package_submission import REPOSITORY_ROOT, build, collect

    # Copy application inputs but construct empty samples independently of real samples.
    source = tmp_path / "source"
    for relative in collect(REPOSITORY_ROOT):
        if relative.parts[0] == "samples":
            continue
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY_ROOT / relative, destination)
    inventory = []
    for name in ("original", "protected", "tampered"):
        relative = f"samples/{name}/.gitkeep"
        placeholder = source / relative
        placeholder.parent.mkdir(parents=True)
        placeholder.touch()
        inventory.append(relative)
    (source / "scripts/release_samples.txt").write_text("\n".join(inventory) + "\n")
    archive = tmp_path / "cleanup.zip"
    build(archive, root=source)
    report = check(archive, tmp_path / "checked", source=source)
    assert report["passed"] is True
    assert report["submission_ready"] is False
    assert report["sample_validation"]["status"] == "PENDING"
    assert report["sample_validation"]["files"] == 0
    assert json.loads(report["commands"][0]["stdout"])["startup"] == "PASS"
    with zipfile.ZipFile(archive) as handle:
        assert not any(name.startswith("docs/") for name in handle.namelist())
        assert {name for name in handle.namelist() if name.startswith("samples/")} == {
            "samples/original/.gitkeep", "samples/protected/.gitkeep",
            "samples/tampered/.gitkeep",
        }
