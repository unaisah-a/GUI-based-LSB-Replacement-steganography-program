"""Tests for the cryptography layer.

Import smoke tests for every module in the package, plus the hashing helpers.
Behavioural tests for each module live in their own test files.
"""

from __future__ import annotations

import importlib
import os

import pytest

CRYPTO_MODULES = [
    "app.crypto.encryption",
    "app.crypto.envelope",
    "app.crypto.errors",
    "app.crypto.hashing",
    "app.crypto.key_manager",
    "app.crypto.manifest",
    "app.crypto.payload",
    "app.crypto.signatures",
    "app.crypto.start_location",
]


@pytest.mark.parametrize("module_name", CRYPTO_MODULES)
def test_module_imports(module_name):
    assert importlib.import_module(module_name) is not None


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestHashing:
    def test_known_digest(self):
        from app.crypto.hashing import sha256_hex

        # The SHA-256 of the empty string is a well-known constant, so this pins
        # the algorithm rather than merely checking self-consistency.
        assert sha256_hex(b"") == EMPTY_SHA256

    def test_digest_length(self):
        from app.crypto.hashing import SHA256_HEX_LENGTH, sha256_hex

        assert len(sha256_hex(b"x")) == SHA256_HEX_LENGTH

    def test_non_bytes_rejected(self):
        from app.crypto.hashing import sha256_hex

        with pytest.raises(TypeError):
            sha256_hex("a string is not bytes")

    def test_empty_file_matches_the_known_constant(self, tmp_path):
        from app.crypto.hashing import file_sha256

        path = tmp_path / "empty.bin"
        path.write_bytes(b"")
        assert file_sha256(str(path)) == EMPTY_SHA256

    def test_file_and_bytes_digests_agree(self, tmp_path):
        from app.crypto.hashing import file_sha256, sha256_hex

        data = b"INF2005 media integrity"
        path = tmp_path / "data.bin"
        path.write_bytes(data)
        assert file_sha256(str(path)) == sha256_hex(data)

    def test_chunking_does_not_change_the_digest(self, tmp_path):
        from app.crypto.hashing import file_sha256, sha256_hex

        data = os.urandom(70_000)
        path = tmp_path / "big.bin"
        path.write_bytes(data)
        assert file_sha256(str(path), chunk_bytes=7) == sha256_hex(data)

    def test_hashes_equal_is_case_insensitive_for_hex(self):
        from app.crypto.hashing import hashes_equal, sha256_hex

        digest = sha256_hex(b"payload")
        assert hashes_equal(digest, digest.upper())

    def test_hashes_equal_rejects_mixed_forms(self):
        from app.crypto.hashing import hashes_equal

        with pytest.raises(TypeError):
            hashes_equal("abc", b"abc")

    def test_hashes_equal_detects_difference(self):
        from app.crypto.hashing import hashes_equal, sha256_hex

        assert not hashes_equal(sha256_hex(b"a"), sha256_hex(b"b"))
