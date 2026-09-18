"""Tests for the cryptography layer.

Import smoke tests for every module in the package, plus the hashing helpers.
Behavioural tests for each module live in their own test files.
"""

from __future__ import annotations

import importlib

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


class TestHashing:
    def test_known_digest(self):
        from app.crypto.hashing import compute_media_hash

        # The SHA-256 of the empty string is a well-known constant, so this pins
        # the algorithm rather than merely checking self-consistency.
        assert compute_media_hash(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_hex_and_raw_agree(self):
        from app.crypto.hashing import compute_media_hash, compute_raw_sha256

        data = b"INF2005"
        assert compute_raw_sha256(data).hex() == compute_media_hash(data)

    def test_digest_length(self):
        from app.crypto.hashing import (
            SHA256_DIGEST_BYTES,
            SHA256_HEX_LENGTH,
            compute_media_hash,
            compute_raw_sha256,
        )

        assert len(compute_raw_sha256(b"x")) == SHA256_DIGEST_BYTES
        assert len(compute_media_hash(b"x")) == SHA256_HEX_LENGTH

    def test_non_bytes_rejected(self):
        from app.crypto.hashing import compute_media_hash

        with pytest.raises(TypeError):
            compute_media_hash("a string is not bytes")

    def test_hashes_equal_is_case_insensitive_for_hex(self):
        from app.crypto.hashing import compute_media_hash, hashes_equal

        digest = compute_media_hash(b"payload")
        assert hashes_equal(digest, digest.upper())

    def test_hashes_equal_rejects_mixed_forms(self):
        from app.crypto.hashing import hashes_equal

        with pytest.raises(TypeError):
            hashes_equal("abc", b"abc")

    def test_hashes_equal_detects_difference(self):
        from app.crypto.hashing import compute_media_hash, hashes_equal

        assert not hashes_equal(compute_media_hash(b"a"), compute_media_hash(b"b"))
