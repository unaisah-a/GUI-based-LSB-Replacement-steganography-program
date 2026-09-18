import json
import struct

import numpy as np
import pytest
import soundfile as sf

from app.crypto.key_manager import generate_rsa_keys
from app.services.protection import ProtectionOptions, protect_media
from app.services.size_preservation import (
    MAX_PNG_TARGET_SIZE,
    export_size_preservation_result,
    pad_png_to_size,
)
from app.stego import image_io
from app.verification.verdicts import Verdict
from app.verification.verifier import verify_media


@pytest.fixture(scope="module")
def signer():
    return generate_rsa_keys()


def _options(media_id):
    return ProtectionOptions(
        media_id=media_id,
        lsb_count=2,
        start_method="manual",
        start_location=0,
        preserve_size=True,
    )


def _bmp_sample_mask(raw):
    width, height_raw = struct.unpack_from("<ii", raw, 18)
    height = abs(height_raw)
    bits = struct.unpack_from("<H", raw, 28)[0]
    channels = bits // 8
    stride = ((bits * width + 31) // 32) * 4
    offset = struct.unpack_from("<I", raw, 10)[0]
    mask = np.ones(len(raw), dtype=bool)
    for row in range(height):
        start = offset + row * stride
        mask[start : start + width * channels] = False
    return mask


def _wav_data_region(raw):
    cursor = 12
    while cursor < len(raw):
        size = struct.unpack_from("<I", raw, cursor + 4)[0]
        if raw[cursor : cursor + 4] == b"data":
            return cursor + 8, size
        cursor += 8 + size + (size & 1)
    raise AssertionError("data chunk missing")


def test_bmp_preserves_length_and_every_non_sample_byte(tmp_path, signer):
    private_key, public_key = signer
    source = tmp_path / "layout.bmp"
    output = tmp_path / "protected.bmp"
    manifest = tmp_path / "protected.json"
    pixels = np.arange(120 * 121 * 3, dtype=np.uint8).reshape(120, 121, 3)
    image_io.save_image(pixels, source, image_io.BMP)
    raw = bytearray(source.read_bytes())
    raw[6:10] = b"LAB!"
    raw.extend(b"preserved-bmp-trailer")
    struct.pack_into("<I", raw, 2, len(raw))
    source.write_bytes(raw)
    before = source.read_bytes()

    result = protect_media(
        source,
        output,
        manifest,
        b"BMP layout preservation",
        private_key,
        _options("SIZE-BMP"),
    )

    after = output.read_bytes()
    mask = _bmp_sample_mask(before)
    assert len(after) == len(before)
    assert after[6:10] == b"LAB!"
    assert after[-21:] == b"preserved-bmp-trailer"
    assert np.array_equal(np.frombuffer(before, dtype=np.uint8)[mask], np.frombuffer(after, dtype=np.uint8)[mask])
    assert result.size_preservation.exact
    assert result.size_preservation.method == "bmp-layout-preserved"
    assert verify_media(output, manifest, public_key).verdict is Verdict.AUTHENTIC


def test_wav_preserves_length_chunks_and_all_non_sample_bytes(tmp_path, signer):
    private_key, public_key = signer
    source = tmp_path / "layout.wav"
    output = tmp_path / "protected.wav"
    manifest = tmp_path / "protected.json"
    samples = np.arange(30_000 * 2, dtype=np.int16).reshape(30_000, 2)
    sf.write(source, samples, 16_000, subtype="PCM_16")
    raw = bytearray(source.read_bytes())
    data_header = raw.find(b"data", 12)
    junk = b"JUNK" + struct.pack("<I", 5) + b"abcde" + b"\x00"
    raw[data_header:data_header] = junk
    struct.pack_into("<I", raw, 4, len(raw) - 8)
    source.write_bytes(raw)
    before = source.read_bytes()

    result = protect_media(
        source,
        output,
        manifest,
        b"WAV layout preservation",
        private_key,
        _options("SIZE-WAV"),
    )

    after = output.read_bytes()
    start, size = _wav_data_region(before)
    assert len(after) == len(before)
    assert after[12:data_header + len(junk)] == before[12:data_header + len(junk)]
    assert after[:start] == before[:start]
    assert after[start + size :] == before[start + size :]
    assert result.size_preservation.exact
    assert result.size_preservation.method == "wav-layout-preserved"
    assert verify_media(output, manifest, public_key).verdict is Verdict.AUTHENTIC


def test_png_search_and_padding_preserve_pixels_payload_and_exact_size(tmp_path, signer):
    private_key, public_key = signer
    source = tmp_path / "cover.png"
    output = tmp_path / "protected.png"
    manifest = tmp_path / "protected.json"
    pixels = np.arange(128 * 128 * 3, dtype=np.uint8).reshape(128, 128, 3)
    image_io.save_image(pixels, source, image_io.PNG)
    pad_png_to_size(source, source.stat().st_size + 8_000)

    result = protect_media(
        source,
        output,
        manifest,
        b"PNG bounded compression search",
        private_key,
        _options("SIZE-PNG"),
    )

    decoded, _ = image_io.load_image(output)
    assert result.size_preservation.exact
    assert result.size_preservation.attempts == 10
    assert output.stat().st_size == source.stat().st_size
    assert decoded.shape == pixels.shape
    assert verify_media(output, manifest, public_key).verdict is Verdict.AUTHENTIC


def test_png_larger_output_reports_failure_without_false_exact_claim(tmp_path, signer):
    private_key, public_key = signer
    source = tmp_path / "small.png"
    output = tmp_path / "protected.png"
    manifest = tmp_path / "protected.json"
    image_io.save_image(np.zeros((128, 128, 3), dtype=np.uint8), source, image_io.PNG)

    result = protect_media(
        source,
        output,
        manifest,
        b"A" * 1_000,
        private_key,
        _options("SIZE-PNG-LARGER"),
    )

    size = result.size_preservation
    assert not size.exact
    assert size.method.startswith("unavailable:")
    assert size.failure_reason
    assert size.final_size == output.stat().st_size
    assert verify_media(output, manifest, public_key).verdict is Verdict.AUTHENTIC


def test_png_padding_rejects_small_gap_and_bounded_large_target(tmp_path):
    source = tmp_path / "source.png"
    image_io.save_image(np.zeros((8, 8, 3), dtype=np.uint8), source, image_io.PNG)
    with pytest.raises(ValueError, match="below the 12-byte"):
        pad_png_to_size(source, source.stat().st_size + 11)
    with pytest.raises(ValueError, match="safety limit"):
        pad_png_to_size(source, MAX_PNG_TARGET_SIZE + 1)


def test_size_result_export_records_method_sizes_and_failure(tmp_path, signer):
    private_key, _public_key = signer
    source = tmp_path / "source.png"
    output = tmp_path / "protected.png"
    manifest = tmp_path / "protected.json"
    report = tmp_path / "size-report.json"
    image_io.save_image(np.zeros((96, 96, 3), dtype=np.uint8), source, image_io.PNG)
    result = protect_media(
        source,
        output,
        manifest,
        b"report",
        private_key,
        _options("SIZE-REPORT"),
    ).size_preservation
    export_size_preservation_result(result, report)
    saved = json.loads(report.read_text(encoding="utf-8"))
    assert saved == result.to_dict()
    assert {"original_size", "initial_stego_size", "final_size", "method", "failure_reason"} <= saved.keys()
    with pytest.raises(FileExistsError):
        export_size_preservation_result(result, report)


def test_protection_transaction_publishes_size_report_with_bundle(tmp_path, signer):
    private_key, public_key = signer
    source = tmp_path / "source.bmp"
    output = tmp_path / "protected.bmp"
    manifest = tmp_path / "protected.json"
    report = tmp_path / "size-report.json"
    pixels = np.arange(96 * 96 * 3, dtype=np.uint8).reshape(96, 96, 3)
    image_io.save_image(pixels, source, image_io.BMP)
    options = _options("SIZE-BUNDLE")
    options = options.__class__(**{**options.__dict__, "size_report_path": report})

    result = protect_media(
        source, output, manifest, b"transaction report", private_key, options
    )

    saved = json.loads(report.read_text(encoding="utf-8"))
    assert result.size_report_path == str(report.resolve())
    assert saved == result.size_preservation.to_dict()
    assert verify_media(output, manifest, public_key).verdict is Verdict.AUTHENTIC


def test_unsupported_wav_layout_is_rejected_without_partial_bundle(tmp_path, signer):
    private_key, _public_key = signer
    source = tmp_path / "unsupported.wav"
    output = tmp_path / "protected.wav"
    manifest = tmp_path / "protected.json"
    sf.write(source, np.arange(20_000, dtype=np.int16), 8_000, subtype="PCM_16")
    source.write_bytes(source.read_bytes() + b"trailing-byte")

    with pytest.raises(ValueError, match="RIFF size is not exact"):
        protect_media(
            source,
            output,
            manifest,
            b"unsupported layout",
            private_key,
            _options("SIZE-UNSUPPORTED"),
        )
    assert not output.exists()
    assert not manifest.exists()
