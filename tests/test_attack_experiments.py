import json

import numpy as np
import pytest
import soundfile as sf

from app.attacks import export_attack_evidence, run_attack_experiment
from app.crypto.key_manager import generate_rsa_keys
from app.services.protection import ProtectionOptions, protect_media
from app.stego import image_io


@pytest.fixture(scope="module")
def signer():
    return generate_rsa_keys()


def _bundle(tmp_path, signer, media_type="image", *, name="one", derived=False, robust=False):
    private_key, public_key = signer
    suffix = ".png" if media_type == "image" else ".wav"
    cover = tmp_path / f"{name}-cover{suffix}"
    protected = tmp_path / f"{name}-protected{suffix}"
    manifest = tmp_path / f"{name}.json"
    if media_type == "image":
        pixels = np.arange(180 * 180 * 3, dtype=np.uint8).reshape(180, 180, 3)
        image_io.save_image(pixels, cover, image_io.PNG)
    else:
        samples = np.arange(50_000 * 2, dtype=np.int16).reshape(50_000, 2)
        sf.write(cover, samples, 16_000, subtype="PCM_16")
    options = ProtectionOptions(
        media_id=f"ATTACK-{name}",
        lsb_count=3,
        start_method="hmac-sha256" if derived else "manual",
        start_secret="correct start secret" if derived else None,
        start_location=None if derived else 0,
        robustness="repetition-3" if robust else "none",
    )
    protect_media(
        cover,
        protected,
        manifest,
        f"attack evidence {name}".encode(),
        private_key,
        options,
    )
    return protected, manifest, public_key


@pytest.mark.parametrize("media_type", ["image", "audio"])
@pytest.mark.parametrize(
    "scenario", ["record-corruption", "message-corruption", "signature-corruption"]
)
def test_targeted_regions_produce_rejected_paired_evidence(
    tmp_path, signer, media_type, scenario
):
    protected, manifest, public_key = _bundle(tmp_path, signer, media_type)
    output = tmp_path / f"{scenario}{protected.suffix}"
    before = protected.read_bytes()

    evidence = run_attack_experiment(
        protected,
        manifest,
        public_key,
        scenario,
        output_path=output,
    )

    assert evidence.baseline.verdict == "AUTHENTIC"
    assert evidence.outcome.verdict != "AUTHENTIC"
    assert evidence.mutation is not None
    assert evidence.mutation.attack == f"corrupt-{scenario.removesuffix('-corruption')}"
    assert output.is_file()
    assert protected.read_bytes() == before


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_seeded_noise_is_reproducible_and_report_is_safe(
    tmp_path, signer, media_type
):
    protected, manifest, public_key = _bundle(tmp_path, signer, media_type)
    first_path = tmp_path / f"noise-one{protected.suffix}"
    second_path = tmp_path / f"noise-two{protected.suffix}"
    first = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "seeded-noise",
        output_path=first_path,
        seed=44,
        severity=32,
    )
    second = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "seeded-noise",
        output_path=second_path,
        seed=44,
        severity=32,
    )
    assert first.outcome.verdict != "AUTHENTIC"
    assert second.outcome.verdict == first.outcome.verdict
    if media_type == "image":
        first_array, _ = image_io.load_image(first_path)
        second_array, _ = image_io.load_image(second_path)
        assert np.array_equal(first_array, second_array)
    else:
        first_samples, _ = sf.read(first_path, dtype="int16")
        second_samples, _ = sf.read(second_path, dtype="int16")
        assert np.array_equal(first_samples, second_samples)

    report = tmp_path / f"{media_type}-evidence.json"
    export_attack_evidence(first, report)
    saved = json.loads(report.read_text(encoding="utf-8"))
    assert saved == first.to_dict()
    assert saved["format"] == "SMIV-ATTACK-EVIDENCE"
    assert "secret" not in report.read_text(encoding="utf-8").lower()
    with pytest.raises(FileExistsError):
        export_attack_evidence(first, report)


def test_wrong_key_and_wrong_secret_change_inputs_without_mutating_media(
    tmp_path, signer
):
    protected, manifest, public_key = _bundle(
        tmp_path, signer, derived=True
    )
    original = protected.read_bytes()
    _, wrong_key = generate_rsa_keys()

    wrong_key_evidence = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "wrong-public-key",
        start_secret="correct start secret",
        alternate_public_key=wrong_key,
    )
    wrong_secret_evidence = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "wrong-start-secret",
        start_secret="correct start secret",
        wrong_start_secret="incorrect start secret",
    )

    assert wrong_key_evidence.outcome.verdict == "SIGNATURE_INVALID"
    assert wrong_secret_evidence.outcome.verdict != "AUTHENTIC"
    assert wrong_key_evidence.mutation is None
    assert wrong_secret_evidence.mutation is None
    assert protected.read_bytes() == original


def test_replay_outside_and_substitution_report_verification_boundaries(
    tmp_path, signer
):
    protected, manifest, public_key = _bundle(tmp_path, signer, name="original")
    _other_media, other_manifest, _ = _bundle(tmp_path, signer, name="substitute")
    replay = tmp_path / "replay.png"
    outside = tmp_path / "outside.png"

    replay_evidence = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "replay",
        output_path=replay,
    )
    outside_evidence = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "outside-payload",
        output_path=outside,
    )
    substitution = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "substitution",
        substitute_manifest_path=other_manifest,
    )

    assert replay.read_bytes() == protected.read_bytes()
    assert replay_evidence.outcome.verdict == "AUTHENTIC"
    assert outside_evidence.outcome.verdict == "AUTHENTIC"
    assert substitution.outcome.verdict != "AUTHENTIC"
    assert "replay" in replay_evidence.limitation.lower()
    assert "not every" in outside_evidence.limitation.lower()
    assert "whole-cover" in substitution.limitation.lower()


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_robust_attack_distinguishes_corrected_and_rejected_faults(
    tmp_path, signer, media_type
):
    protected, manifest, public_key = _bundle(
        tmp_path, signer, media_type, robust=True
    )
    corrected = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "message-corruption",
        output_path=tmp_path / f"corrected{protected.suffix}",
        fault_copies=1,
    )
    rejected = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "message-corruption",
        output_path=tmp_path / f"rejected{protected.suffix}",
        fault_copies=2,
    )
    assert corrected.outcome.verdict == "AUTHENTIC"
    assert rejected.outcome.verdict != "AUTHENTIC"


@pytest.mark.parametrize("media_type", ["image", "audio"])
def test_payload_truncation_simulation_rejects_both_media(tmp_path, signer, media_type):
    protected, manifest, public_key = _bundle(tmp_path, signer, media_type)
    evidence = run_attack_experiment(
        protected,
        manifest,
        public_key,
        "payload-truncation",
        output_path=tmp_path / f"truncated{protected.suffix}",
        severity=16,
    )
    assert evidence.baseline.verdict == "AUTHENTIC"
    assert evidence.outcome.verdict != "AUTHENTIC"
