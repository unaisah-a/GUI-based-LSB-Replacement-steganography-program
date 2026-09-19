# Contribution Statement

Module: **INF2005 Assignment 1** — GUI-based LSB Replacement Steganography Program.

---

## How to complete this document

**This file needs each member's real name, student number and signed agreement before
submission.** The role columns below match the ownership agreed in the project plan and
the code as it stands, so they should need no editing; the identity columns are
placeholders and must be filled in.

Replace every `<...>` placeholder. Do not submit with placeholders left in.

---

## 1. Members

| # | Name | Student number | Primary area |
|---|---|---|---|
| 1 | `<name>` | `<number>` | Cryptography and payload security |
| 2 | `<name>` | `<number>` | Image steganography and image steganalysis |
| 3 | `<name>` | `<number>` | Audio steganography and robust embedding |
| 4 | `<name>` | `<number>` | GUI and system integration |
| 5 | `<name>` | `<number>` | Verification, attack simulation, video and media comparison |

---

## 2. Ownership by area

The mapping from role to code, so that a marker can find each member's work directly.
The test counts are per file as collected by `pytest --collect-only`. The five areas
account for 1,714 tests. The remaining 14, in `test_package_submission.py`, cover the
packaging script, which belongs to no single area. The full suite was 1,728 tests on
19 September 2026.

### Member 1 — Cryptography and payload security

```text
app/crypto/envelope.py          the payload envelope and verification record
app/crypto/signatures.py        RSA-PSS signing and verification
app/crypto/hashing.py           SHA-256 over the message
app/crypto/key_manager.py       key generation, loading, demo key pair
app/crypto/encryption.py        AES-256-GCM, scrypt key derivation
app/crypto/start_location.py    the keyed HMAC start-location derivation
app/crypto/manifest.py          the companion manifest and its cross-check
app/crypto/payload.py           assembling and recovering a signed payload
app/crypto/errors.py            the crypto error hierarchy
```

Tests: `test_envelope.py`, `test_signatures.py`, `test_encryption.py`,
`test_start_location.py`, `test_manifest.py`, `test_crypto.py` — 408 tests.

Also responsible for the written justification of why the verification payload can be
trusted, which is [`architecture.md`](architecture.md) §2, §4 and §5.

### Member 2 — Image steganography and image steganalysis

```text
app/stego/image_io.py           container sniffing, decode, encode, lossy rejection
app/stego/image_stego.py        LSB embed and extract, depths 1 to 8
app/stego/bit_utils.py          shared bit packing and masking
app/stego/capacity.py           shared capacity arithmetic
app/analysis/image_analysis.py  indicators, bit planes, difference images, histograms
```

Tests: `test_image_stego.py`, `test_image_io.py`, `test_image_analysis.py`,
`test_bit_utils.py`, `test_capacity.py`, and the image, dispatch and honesty tests in
`test_steganalysis.py` — 380 tests.

`bit_utils.py` and `capacity.py` began as part of the image layer and were promoted to
shared modules when the audio and video layers were built on them. That is why they are
listed here.

### Member 3 — Audio steganography and robust embedding

```text
app/stego/audio_stego.py            16-bit PCM WAV embed and extract
app/analysis/audio_analysis.py      MSE, PSNR, SNR, distortion bounds
app/robustness/redundancy.py        repetition encode, decode, factor validation
app/robustness/error_correction.py  majority vote, correction reporting
```

Tests: `test_audio_stego.py`, `test_audio_quality.py`, `test_robustness.py`,
and the audio indicators in `test_steganalysis.py` — 163 tests.

Also responsible for the measured robustness figures in
[`architecture.md`](architecture.md) §8 and the audio round-trip evidence in
[`evidence/results/audio_lsb_round_trip.md`](../evidence/results/audio_lsb_round_trip.md).

### Member 4 — GUI and system integration

```text
main.py                         application entry point
app/gui/main_window.py          the window, tabs, menus, status bar
app/gui/protect_tab.py          the sender workflow
app/gui/verify_tab.py           the receiver workflow
app/gui/attack_tab.py           the Attack Lab
app/gui/steganalysis_tab.py     the Steganalysis view
app/gui/video_tab.py            clip inspection and payload frame location
app/gui/workers.py              background execution off the interface thread
app/gui/widgets/                drop zone, media preview, info panel, result panel
assets/styles/app.qss           styling
app/utils/                      constants, file utilities, logging
```

Tests: `test_gui_shell.py`, `test_gui_tabs.py`, `test_gui_lab_tabs.py`,
`test_utils.py`, `test_payload_files.py` — 328 tests.

Also responsible for the integration decision that no layer below the GUI imports Qt,
which is what makes every workflow testable without a window.

### Member 5 — Verification, attack simulation, video and media comparison

```text
app/verification/protect.py       the sender-side orchestration
app/verification/verifier.py      the receiver-side orchestration and verdict rules
app/verification/verdicts.py      the verdict vocabulary
app/verification/media_compare.py property comparison for all three media
app/attacks/                      the attack catalogue and every attack
app/stego/video_stego.py          the video layer
app/stego/media.py                the one-interface facade over all three media
app/analysis/quality_metrics.py   one quality report for every medium
app/analysis/size_preservation.py the file-size experiment
app/utils/media_utils.py          video property inspection
```

Tests: `test_verification.py`, `test_attacks.py`, `test_video_stego.py`,
`test_media_compare.py`, `test_media_facade.py`, `test_size_preservation.py`,
`test_e2e.py` — 435 tests.

Also responsible for the end-to-end evidence artefacts and the
[`test_cases.md`](test_cases.md) mapping.

---

## 3. Shared work

Some things were decided jointly and belong to no single member. Recording them here
rather than assigning them to someone is the accurate account.

| Item | Nature of the decision |
|---|---|
| The layering rule that the stego layer carries opaque bytes | Agreed across members 1, 2, 3 and 5; it constrains all four areas |
| Putting the envelope magic inside the payload rather than in the stego framing | Agreed between members 1, 2 and 3 after the audio layer's private marker was removed |
| The one flat sample domain per medium | Members 2, 3 and 5, so that one start-location derivation serves all three |
| Treating video as a flat domain rather than selected frames | Members 1 and 5, because a frame-selection scheme would have pushed key material into the stego layer |
| The verdict vocabulary and the rule that failures are verdicts, not exceptions | Members 4 and 5 |
| Applying the error-correcting code to the whole signed envelope | Members 1 and 3 |
| The honesty notices shown verbatim in the interface | All members; the wording lives in `app/utils/constants.py` so it cannot drift |

---

## 4. Effort declaration

| # | Name | Approximate share | Notes |
|---|---|---|---|
| 1 | `<name>` | `<%>` | `<any adjustment and why>` |
| 2 | `<name>` | `<%>` | |
| 3 | `<name>` | `<%>` | |
| 4 | `<name>` | `<%>` | |
| 5 | `<name>` | `<%>` | |

Total must be 100 %. If the shares are not equal, state the reason in the notes column
rather than leaving the difference unexplained.

---

## 5. Demonstration responsibilities

From [`demo_plan.md`](demo_plan.md). Every member should understand the complete
workflow even though each presents their own segment.

| Segment | Time | Presented by |
|---|---|---|
| Architecture and security design | 0–3 | `<name>` |
| Image positive case, party A to party B | 3–7 | `<name>` |
| Image attack and negative case | 7–10 | `<name>` |
| Audio positive case and depth distortion | 10–15 | `<name>` |
| Audio negative case | 15–18 | `<name>` |
| Signature and start-location security | 18–21 | `<name>` |
| Innovation, robustness, video, size preservation | 21–23 | `<name>` |
| Limitations and conclusion | 23–25 | `<name>` |

---

## 6. Declaration

Each member confirms that the work attributed to them above is their own, that the
effort shares in §4 are an accurate account, and that any external sources or
libraries used are acknowledged in `requirements.txt` and in the module docstrings
where they are used.

| # | Name | Signature | Date |
|---|---|---|---|
| 1 | `<name>` | | |
| 2 | `<name>` | | |
| 3 | `<name>` | | |
| 4 | `<name>` | | |
| 5 | `<name>` | | |

---

## 7. Third-party dependencies

Declared in full, with the reason each is present. Versions are pinned in
`requirements.txt`.

| Package | Version | Used for |
|---|---|---|
| `numpy` | 2.1.3 | vectorised bit manipulation and all sample arithmetic |
| `Pillow` | 11.0.0 | PNG and BMP encode and decode |
| `soundfile` | 0.12.1 | WAV read and write |
| `scipy` | 1.14.1 | chi-square p-values for the steganalysis indicators |
| `cryptography` | 43.0.1 | RSA-PSS, AES-256-GCM, scrypt, SHA-256 |
| `opencv-python` | 4.10.0.84 | video decode and encode, including the bundled FFV1 encoder |
| `PySide6` | 6.8.0 | the interface, and QtMultimedia for playback |
| `pytest` | 8.3.3 | test runner |
| `hypothesis` | 6.115.5 | property-based tests |
| `pytest-qt` | 4.4.0 | testing Qt widgets without a display |
| `pytest-cov` | 7.1.0 | coverage measurement through pytest |
| `coverage` | 7.16.1 | the coverage engine behind `pytest-cov` |
| `ruff` | 0.16.8 | linting |

No external binary is required. In particular there is no dependency on a separately
installed `ffmpeg`: the video layer uses the FFmpeg build bundled inside
`opencv-python`, which was a deliberate choice recorded in
[`architecture.md`](architecture.md) §3.
