# Requirement and test-case matrix

This document maps the assignment requirements to implemented behavior and reproducible evidence. The authoritative generated case list is `samples/r11/receiver/case-index.json`; the R12 release result is `evidence/results/r12-validation-summary.json`.

## Reproduction commands

From the repository root on Windows:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\verify_sample_bundle.py samples\r11\receiver
.\.venv\Scripts\python.exe -m pytest tests\test_release_checks.py -q
```

Reviewed release results:

- Complete suite: **578 passed in 100.02 seconds** in the recorded clean-environment log.
- Receiver bundle: **10 of 10 indexed cases passed**, plus capacity rejection.
- Native desktop audit: **3 of 3 cases passed** on Qt `windows`.
- Clean environment: Python 3.14.3, pinned installation successful, `pip check` successful, and `main.py --smoke-test` successful.

## Functional requirements

| Requirement | Implemented behavior | Evidence |
| --- | --- | --- |
| FR1–FR2: image and audio covers | PNG, supported BMP, and PCM-16 WAV inspection, embedding, extraction, preview/playback, and property preservation. | `tests/test_carrier_integration.py`, `tests/test_image_stego.py`, `tests/test_audio_stego.py`; image/audio R11 cases. |
| FR3: verification payload | Canonical signed record contains media ID, timezone-aware timestamp, random nonce, SHA-256 message digest, content type, signer fingerprint, extraction settings, and metadata. | `tests/test_crypto.py`, `tests/test_security_boundaries.py`; manifests and expected messages under `samples/r11/receiver/cases/`. |
| FR4: digital signature | RSA-PSS/SHA-256 signs the record and stored message; receiver verifies against a separately trusted RSA public key and fingerprint. | `tests/test_crypto.py`, `tests/test_verification.py`; `demo-public-key.pem`; wrong-key attack coverage. |
| FR5–FR6: LSB replacement | Image and audio use selectable depths 1–8 with continuous bit ordering and exact capacity calculations. | `tests/test_carrier_integration.py`, `tests/test_capacity.py`, `tests/test_bit_utils.py`; GUI capacity tests. |
| FR7: start location | Manual zero-based scalar index or HMAC-SHA256-derived start using a separate secret and signed context; derived location is omitted from the manifest. | `tests/test_crypto.py`, `tests/test_verification.py`, `tests/test_carrier_integration.py`; `audio-long-positive`. |
| FR8–FR10: extraction and verification | Bounded extraction, manifest/signed-setting comparison, signature check, optional authenticated decryption, plaintext digest check, and structured verdict/check list. | `tests/test_verification.py`, `tests/test_security_boundaries.py`, native desktop audit screenshots. |
| FR11: positive/negative cases | Six indexed authentic outcomes and four indexed rejected outcomes span image, audio, robustness, and video. Mandatory image/audio each have a positive and negative case. | `case-index.json`, `verification-report.json`, case table below. |
| FR12: reproducibility | Pinned setup, deterministic cover/message generator, fresh cryptographic material, standalone receiver verifier, test logs, hashes, and screenshots. | Root README; `scripts/generate_samples.py`; `scripts/verify_sample_bundle.py`; R12 evidence. |
| FR13: innovation | Derived starts, AES-GCM, repetition-3, Attack Lab, statistical analysis, size experiments, encrypted restoration sidecars, and FFV1 selected-frame video are implemented and bounded. | Relevant tests plus sender evidence JSON; limitations are documented in `limitations.md`. |
| Capacity and usability | Exact signed-envelope estimate precedes writing; GUI previews images/video, plays audio, runs work off the UI thread, supports cancellation, and saves recovered bytes only after authenticity. | `tests/test_protect_tab.py`, `tests/test_gui_workflows.py`, `tests/test_operation_controls.py`, desktop audit. |
| Required messages | Bundle contains whitespace-normalized Learning Outcome and Project Overview text plus a fictional custom confidentiality/integrity message. | `samples/r11/messages/` and the corresponding indexed cases. |
| A-to-B transfer | Receiver directory works without sender state or private signing key; it contains protected media, manifests, expected bytes, public key, and labelled demo-only secrets. | `tests/test_sample_bundle.py`, `scripts/verify_sample_bundle.py`; real human transfer remains on the submission checklist. |
| Demo and accountability | A timed five-member plan, truthful contribution template, originality/AI-use record, evidence index, and unfilled human declarations are provided. | `demo_plan.md`, `contribution_statement.md`, `originality_and_ai_use.md`, `submission_checklist.md`. |

## Indexed receiver cases

| ID | Medium | Expected result | Purpose |
| --- | --- | --- | --- |
| `image-short-positive` | Image | `AUTHENTIC` | Required positive image using the brief-derived short message. |
| `image-message-corruption-negative` | Image | `SIGNATURE_INVALID` | Embedded message mutation demonstrates an actual verification failure. |
| `audio-long-positive` | Audio | `AUTHENTIC` | Required positive mono WAV using the longer Project Overview message and derived start. |
| `audio-signature-corruption-negative` | Audio | `SIGNATURE_INVALID` | Signature-region mutation demonstrates an actual audio failure. |
| `image-confidential-positive` | Image | `AUTHENTIC` | AES-256-GCM confidentiality and signed plaintext-integrity demonstration. |
| `audio-robust-stereo-positive` | Audio | `AUTHENTIC` | Stereo PCM repetition-3 baseline. |
| `audio-robust-one-copy-corrected` | Audio | `AUTHENTIC` | One repetition copy is corrupted and majority recovery succeeds. |
| `audio-robust-two-copy-negative` | Audio | `SIGNATURE_INVALID` | Two-copy corruption exceeds the demonstrated correction boundary. |
| `video-short-positive` | Video | `AUTHENTIC` | Selected-frame FFV1 Matroska with compatible PCM audio remuxing. |
| `video-h264-lossy-negative` | Video | `CANNOT_VERIFY` | Measured payload loss after the recorded H.264 transcode. |

The separate `capacity-rejection.json` case confirms an oversized request is rejected before an output file is created. It is input-validation evidence and is not counted as one of the required verification-negative cases.

The three mandatory image/audio negatives are `image-message-corruption-negative`, `audio-signature-corruption-negative`, and `audio-robust-two-copy-negative`. Video is optional and cannot replace the third required image/audio negative.

## Review follow-up coverage

`tests/test_protect_tab.py` checks asynchronous capacity estimates, a responsive event loop during slow work, coalescing rapid edits, suppression of stale success/error results, current failures, and safe worker shutdown. `tests/test_extension_evaluation.py` checks reproducible false-alarm/miss/inconclusive accounting, preservation of user-supplied cover files, and repetition failures under independent noise. `tests/test_release_package.py` checks deterministic packaging, inventory hashes, inclusion of untracked deliverables, exclusion of environments, overwrite refusal, and private-key rejection. See [extension evaluation](extension_evaluation.md) for measured outcomes and limits.

## Native desktop cases

| Case | Expected | Screenshot |
| --- | --- | --- |
| Image positive verification | `AUTHENTIC` | `evidence/screenshots/r12-image-authentic.png` |
| Audio positive verification | `AUTHENTIC` | `evidence/screenshots/r12-audio-authentic.png` |
| Corrupted image verification | `SIGNATURE_INVALID` | `evidence/screenshots/r12-image-rejected.png` |

`evidence/results/r12-desktop-audit.json` records the native Qt platform, window/display geometry, verdicts, screenshot sizes, and SHA-256 hashes.

## Security and malformed-input coverage

The automated suite covers:

- missing, extra, duplicate, non-canonical, wrongly typed, and unsupported manifest/record fields;
- truncated, oversized, inconsistent, and trailing envelope data;
- encryption flag/metadata disagreement and AES-GCM authentication failure;
- unsuitable RSA key types/sizes, wrong trusted keys, and fingerprint mismatches;
- wrong start secrets, invalid manual starts, unavailable capacity, and malformed carrier lengths;
- signed robustness, carrier-payload-length, media-type, depth, and video-frame mismatches;
- output aliases, overwrite rules, staged-publication failures, cleanup, and rollback;
- recovery-sidecar corruption, wrong protected file, wrong key, overwrite behavior, and exact restoration;
- absent FFmpeg with image/audio inspection still usable.

No malformed case is accepted as `AUTHENTIC`.

## Rubric evidence map

| Criterion | Demonstration and evidence |
| --- | --- |
| Security design and framing | Explain the architecture protection/verification flows, version-1 envelope, companion manifest, trusted key, signed extraction controls, and conservative verdicts. Use the confidential image case. |
| Image workflow and cases | Run `image-short-positive`, show before/after preview, then run `image-message-corruption-negative`. |
| Audio workflow and cases | Run `audio-long-positive`, play/compare WAV files, then run `audio-signature-corruption-negative`. |
| Hash/signature and failures | Show the Verify check list and explain the separate signature, decryption, signed-setting, and message-hash decisions. |
| Innovation | Demonstrate one-copy repetition recovery followed by two-copy failure; briefly show Attack Lab/Analysis or FFV1 video as additional implemented work. |
| Individual explanation | The demo plan assigns every member a technical section and requires each to answer questions about the complete flow. |
| Limitations, ethics, and AI reflection | Present whole-cover, replay, hash-leakage, lossy-media, and sidecar limits; complete the human originality and AI-use record before submission. |

## Manual observations still required

The team must complete these as real observations rather than copying expected text:

- [ ] Party A transfers protected media and manifest to Party B's separate folder/device.
- [ ] Party B obtains the trusted public key and required secrets through the chosen separate channel.
- [ ] Party B verifies without access to Party A's private key or process state.
- [ ] A team member records image visibility and audio listening observations on the actual demo equipment.
- [ ] The full demo is rehearsed and its actual duration is recorded.
- [ ] All screenshots shown in the final presentation are checked against the current build.
