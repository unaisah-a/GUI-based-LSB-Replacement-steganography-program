import hashlib
import json
import zipfile

import pytest

from scripts.package_release import build_package, ROOT_FILES


def fixture_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    for name in ROOT_FILES:
        (root / name).write_text("fixture\n", encoding="utf-8")
    for name in ("app", "docs", "samples", ".venv", "output"):
        (root / name).mkdir()
    (root / "app/new.py").write_text("print('untracked work')\n", encoding="utf-8")
    (root / ".venv/private.pem").write_text("not a release input", encoding="utf-8")
    return root


def test_package_is_deterministic_and_inventory_covers_untracked_source(tmp_path):
    root = fixture_root(tmp_path)
    first, second = root / "output/first.zip", root / "output/second.zip"
    build_package(root, first)
    build_package(root, second)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        inventory = json.loads(archive.read("RELEASE_INVENTORY.json"))
        assert "app/new.py" in archive.namelist()
        assert not any(n.startswith((".venv/", "output/")) for n in archive.namelist())
        assert len(archive.namelist()) == len(inventory["files"]) + 1
        for row in inventory["files"]:
            raw = archive.read(row["path"])
            assert len(raw) == row["bytes"]
            assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    with pytest.raises(FileExistsError):
        build_package(root, first)


def test_package_rejects_private_material_before_creating_archive(tmp_path):
    root = fixture_root(tmp_path)
    (root / "samples/leak.txt").write_text("-----BEGIN PRIVATE KEY-----\nsecret\n", encoding="utf-8")
    destination = root / "output/release.zip"
    with pytest.raises(ValueError, match="Private key"):
        build_package(root, destination)
    assert not destination.exists()
