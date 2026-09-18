import json
import math

import numpy as np
import pytest
import soundfile as sf

from app.analysis.experiments import export_analysis_evidence, prepare_analysis
from app.stego import image_io
from app.stego.audio_stego import embed_audio_lsb
from app.stego.image_stego import embed_image


def _image_pair(tmp_path):
    original = tmp_path / "original.png"
    modified = tmp_path / "modified.png"
    pixels = np.arange(96 * 96 * 4, dtype=np.uint8).reshape(96, 96, 4)
    image_io.save_image(pixels, original, image_io.PNG)
    embed_image(original, modified, b"analysis comparison", 2, 17)
    return original, modified


def _audio_pair(tmp_path, sample_rate=16_000):
    original = tmp_path / "original.wav"
    modified = tmp_path / "modified.wav"
    samples = ((np.arange(8_000 * 2) * 43) % 50_000 - 25_000).astype(np.int16)
    sf.write(original, samples.reshape(8_000, 2), sample_rate, subtype="PCM_16")
    embed_audio_lsb(original, modified, b"analysis comparison", 2, 17)
    return original, modified


def test_image_analysis_bundle_contains_views_indicators_depths_and_export(tmp_path):
    original, modified = _image_pair(tmp_path)
    bundle = prepare_analysis(original, modified, 2, 24)

    assert bundle.media_type == "image"
    assert bundle.image_original_lsb.shape == (96, 96)
    assert bundle.image_modified_lsb.shape == (96, 96)
    assert bundle.image_difference.shape == (96, 96, 4)
    assert bundle.histogram_original.shape == (3, 256)
    assert bundle.evidence["original"]["sha256"] != bundle.evidence["modified"]["sha256"]
    assert {
        result["indicator"] for result in bundle.evidence["indicators"]["original"]
    } == {
        "lsb_distribution",
        "bit0_uniformity_chi_square",
        "pair_of_values_chi_square",
        "pair_of_values_neighbour",
    }
    assert [row.lsb_count for row in bundle.experiment.rows] == list(range(1, 9))
    assert all(row.message_bytes == 24 for row in bundle.experiment.rows)
    assert all(row.encoded_bytes == 28 for row in bundle.experiment.rows)
    assert all(0 < row.embedding_density <= 1 for row in bundle.experiment.rows)

    destination = tmp_path / "analysis.json"
    export_analysis_evidence(bundle, destination)
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["format"] == "SMIV-ANALYSIS-EVIDENCE"
    assert document["quality"]["colour_mse"] == bundle.evidence["quality"]["colour_mse"]
    assert len(document["depth_experiment"]["rows"]) == 8
    assert "Infinity" not in destination.read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        export_analysis_evidence(bundle, destination)


def test_alpha_only_change_distinguishes_colour_and_whole_image_equality(tmp_path):
    original = tmp_path / "first.png"
    modified = tmp_path / "second.png"
    pixels = np.full((64, 64, 4), 127, dtype=np.uint8)
    changed = pixels.copy()
    changed[:, :, 3] = 128
    image_io.save_image(pixels, original, image_io.PNG)
    image_io.save_image(changed, modified, image_io.PNG)

    bundle = prepare_analysis(original, modified, 1, 8)
    quality = bundle.evidence["quality"]
    assert quality["colour_mse"] == 0
    assert quality["colour_psnr_db"] is None
    assert quality["colour_psnr_unbounded"] is True
    assert quality["colour_samples_identical"] is True
    assert quality["all_samples_identical"] is False
    assert quality["channels"][3]["mse"] == 1


def test_audio_analysis_bundle_contains_waveforms_metrics_and_depths(tmp_path):
    original, modified = _audio_pair(tmp_path)
    bundle = prepare_analysis(
        original,
        modified,
        2,
        24,
        listening_observation="No audible difference on reference headphones.",
    )

    assert bundle.media_type == "audio"
    assert 0 < bundle.audio_original.size <= 2_000
    assert bundle.audio_original.shape == bundle.audio_modified.shape
    assert bundle.audio_difference.shape == bundle.audio_original.shape
    assert bundle.evidence["quality"]["sample_rate"] == 16_000
    assert bundle.evidence["quality"]["channels"] == 2
    assert len(bundle.experiment.rows) == 8
    assert bundle.evidence["listening_observation"].startswith("No audible difference")
    assert all(row.snr_db is not None or row.snr_unbounded for row in bundle.experiment.rows)
    assert "human listener" in bundle.experiment.interpretation


def test_analysis_rejects_mismatched_media_and_rates_clearly(tmp_path):
    image, modified_image = _image_pair(tmp_path)
    audio, modified_audio = _audio_pair(tmp_path)
    with pytest.raises(ValueError, match="same media type"):
        prepare_analysis(image, modified_audio, 1, 8)

    other = tmp_path / "other-rate.wav"
    sf.write(other, np.zeros((8_000, 2), dtype=np.int16), 8_000, subtype="PCM_16")
    with pytest.raises(ValueError, match="Sample rates differ"):
        prepare_analysis(audio, other, 1, 8)


def test_identical_audio_exports_unbounded_metrics_without_nonstandard_json(tmp_path):
    original, _modified = _audio_pair(tmp_path)
    bundle = prepare_analysis(original, original, 1, 8)
    assert bundle.evidence["quality"]["mse"] == 0
    assert bundle.evidence["quality"]["snr_db"] is None
    assert bundle.evidence["quality"]["snr_unbounded"] is True
    assert bundle.evidence["quality"]["psnr_db"] is None
    destination = tmp_path / "identical.json"
    export_analysis_evidence(bundle, destination)
    assert math.isfinite(float(json.loads(destination.read_text())["depth_experiment"]["rows"][0]["mse"]))
