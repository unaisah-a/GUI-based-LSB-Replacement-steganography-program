import hashlib
import json

import numpy as np

from app.stego import image_io
from scripts.evaluate_extensions import build_report, image_evaluation, noise_evaluation


def test_evaluation_records_false_alarms_misses_and_inconclusive_controls():
    first = build_report()
    assert first == build_report()
    analysis = first["steganalysis"]
    counts = analysis["counts"]
    assert counts["false_positives"] > 0
    assert counts["false_negatives"] > 0
    assert counts["inconclusive_clean"] > 0
    assert counts["clean"] == sum(counts[k] for k in (
        "false_positives", "true_negatives", "inconclusive_clean"))
    assert counts["embedded"] == sum(counts[k] for k in (
        "true_positives", "false_negatives", "inconclusive_embedded"))
    json.dumps(first, allow_nan=False)
    assert "Synthetic" in analysis["provenance"]


def test_supplied_cover_is_preserved_and_identified_by_hash(tmp_path):
    path = tmp_path / "my-cover.png"
    image_io.save_image(np.random.default_rng(8).integers(
        0, 256, (96, 96, 3), dtype=np.uint8), path, image_io.PNG)
    original = path.read_bytes()
    report = image_evaluation([path], 2005, "Test fixture")
    assert path.read_bytes() == original
    assert report["cases"][0]["input_sha256"] == hashlib.sha256(original).hexdigest()
    assert report["counts"]["embedded"] == 3
    assert str(tmp_path) not in json.dumps(report)


def test_noise_evaluation_includes_multicopy_failures_and_storage_cost():
    report = noise_evaluation(2005)
    for row in report["cases"]:
        assert row["stored_bytes"] == report["message_bytes"] * (
            3 if row["mode"] == "repetition-3" else 1)
        if row["bit_flip_probability"] == 0:
            assert row["exact_recoveries"] == row["trials"]
            assert row["recovered_bit_errors"] == 0
        if row["bit_flip_probability"] == 0.1:
            assert row["exact_recoveries"] < row["trials"]
            assert row["recovered_bit_errors"] > 0
    assert report == noise_evaluation(2005)
