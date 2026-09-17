# Test Cases

The assignment requires at least **two positive** and **three negative**
verification cases, with at least one of each for image and for audio. This document
records what is actually implemented, where, and what each case is meant to establish.

Insufficient capacity is kept **separate** as input validation rather than counted as
a verification failure, because it is refused before anything is written and never
produces a verdict.

Run everything with:

```powershell
.venv\Scripts\python -m pytest -q
```

Total: **1 641 tests**, all passing, as of 17 September 2026. Suite runtime is about a minute.

---

## 1. Required cases, and where they live

The end-to-end cases are in [`tests/test_e2e.py`](../tests/test_e2e.py), which also
writes [`evidence/results/e2e_results.md`](../evidence/results/e2e_results.md) and
`e2e_results.json` as it runs. Those artefacts are generated, not written by hand, so
the table below and the evidence cannot drift apart.

### Positive

| # | Case | Media | Message sizes | Expected |
|---|---|---|---|---|
| 1 | PNG protected and verified | image | short, long, custom | `AUTHENTIC` |
| 2 | WAV protected and verified | audio | short, long, custom | `AUTHENTIC` |
| 3 | PNG with an encrypted message | image | custom | `AUTHENTIC` |
| 4 | BMP with a manual start location | image | short | `AUTHENTIC` |
| 5 | MKV video protected and verified | video | short | `AUTHENTIC` |

Case 5 exists to show that nothing in the workflow is video-specific: the same three
files cross, the same secret is shared out of band, and the same call verifies them.

### Negative

| # | Case | Media | Expected | Mechanism it demonstrates |
|---|---|---|---|---|
| 1 | Corrupted embedded message | image | `SIGNATURE_INVALID` | The signature covers the message, so this is *not* `TAMPERED` |
| 2a | Corrupted verification record | audio | `SIGNATURE_INVALID` | The record is signed |
| 2b | Corrupted signature | audio | `SIGNATURE_INVALID` | |
| 3 | Wrong public key | image | `SIGNATURE_INVALID` | Public/private key binding |
| 4 | Wrong start secret | image | not `AUTHENTIC` | Verdict deliberately not pinned; see §3 |
| 5 | Unprotected cover, no payload | image | `PAYLOAD_MISSING` | |
| 6 | Video re-encoded lossily | video | not `AUTHENTIC` | The default fate of a clip, not just an attack |
| 7 | Tampered manifest, `message_length` | image | `TAMPERED` | The **cross-check** against the signed record |
| 8 | Tampered manifest, `media_id` | image | `PAYLOAD_MISSING` | The **derivation** breaking |
| 9 | Wrong message passphrase | image | `CANNOT_VERIFY` | Signature verified first, so the record is known genuine |

Cases 7 and 8 are separated on purpose. The manifest is unsigned, and an edit to it is
caught by one of two different routes depending on whether the field feeds the
start-location derivation. Showing only one would leave the other mechanism
undemonstrated.

### Input validation, kept separate

| Case | Expected | Note |
|---|---|---|
| Payload exceeds capacity | refused before writing, with the size that would fit | No file is created |
| Same message fits at a greater depth | `AUTHENTIC` at depth 6, refused at depth 1 | The capacity/depth trade-off, demonstrated |

---

## 2. The three required message sizes

All three are used against both mandatory media, in
`TestPositiveCases::test_png_at_three_message_sizes` and
`test_wav_at_three_message_sizes`.

| Size | Source | Length |
|---|---|---|
| Short | one Learning Objective | 57 bytes |
| Long | the Project Overview paragraph | 711 bytes |
| Custom | confidentiality and integrity together | 359 bytes |

The custom message is also the one used for the encrypted case, since it is the
message that describes what encryption adds.

---

## 3. Cases where the verdict is deliberately not pinned

Three cases assert "not `AUTHENTIC`" rather than a specific verdict. This is a
correctness decision, not laziness.

**Wrong start secret.** A wrong secret puts the reader at an unpredictable offset, and
what is found there is not predictable either. The test asserts that verification does
not succeed and, additionally, that it does **not** claim
`WRONG_START_LOCATION` — because that would be an unprovable claim.

**Lossy video re-encode.** Depending on the codec chosen, the output may not even be a
container this build can read, so the honest expectation covers `PAYLOAD_MISSING`,
`SIGNATURE_INVALID` and `CANNOT_VERIFY`.

**Random bit corruption.** Where the flips land decides the outcome. The attack's
declared `expected_verdicts` is a set with several members, and when an
error-correcting code is active `AUTHENTIC` joins it — surviving is a legitimate
outcome, not a failure of the attack.

---

## 4. The A-to-B transfer simulation

`tests/test_e2e.py` models the transfer physically rather than notionally. Party A
works in a sender directory, party B in a receiver directory, and only the files a
real transfer would carry are copied across.

Asserted:

- the receiver's directory contains **exactly three** files: the stego object, its
  manifest, and the sender's public key
- the private key never leaves the sender, and no transferred file contains
  `PRIVATE KEY`
- **neither shared secret appears in any transferred file** — the start secret and the
  passphrase are both checked
- the receiver can verify from its own directory with nothing but those three files
  plus the out-of-band secrets
- deleting the manifest makes verification impossible (`CANNOT_VERIFY`) rather than
  silently degrading
- the sender's cover is byte-for-byte unchanged afterwards
- for the encrypted case, the plaintext appears in none of the transferred files

---

## 5. Coverage beyond the required cases

| File | Tests | Establishes |
|---|---|---|
| `test_image_stego.py` | 133 | Image embed/extract, all depths, all patterns, property-based round trips |
| `test_envelope.py` | 120 | Envelope framing, canonical JSON, record validation, malformed input |
| `test_manifest.py` | 105 | Manifest schema, cross-check, tamper detection per field |
| `test_image_analysis.py` | 89 | Indicators, bit planes, difference images, histograms |
| `test_gui_shell.py` | 86 | Window, tabs, widgets, workers, error surfacing |
| `test_audio_stego.py` | 84 | Audio embed/extract, signed-sample handling, all depths |
| `test_utils.py` | 83 | Content sniffing, atomic writes, constants agreeing with their sources |
| `test_video_stego.py` | 73 | Video layer, its attacks, quality, the Video tab |
| `test_media_compare.py` | 71 | Property comparison for all three media |
| `test_attacks.py` | 63 | Attack catalogue, expectation pairing, per-attack behaviour |
| `test_robustness.py` | 63 | Repetition coding, recovery, and where it stops working |
| `test_verification.py` | 61 | Verdict rules and the order of operations |
| `test_gui_tabs.py` | 59 | Protect and Verify tab behaviour without a window |
| `test_start_location.py` | 58 | Derivation, determinism, domain separation, bounds |
| `test_signatures.py` | 56 | Signing, verification, wrong keys, malformed signatures |
| `test_encryption.py` | 55 | AES-GCM, scrypt, wrong passphrase, parameter validation |
| `test_media_facade.py` | 50 | Dispatch by content, unified result shapes |
| `test_capacity.py` | 49 | Capacity arithmetic, the three distinct quantities |
| `test_image_io.py` | 48 | Container sniffing, decode, encode, rejection of lossy input |
| `test_gui_lab_tabs.py` | 48 | Attack Lab and Steganalysis tabs |
| `test_size_preservation.py` | 44 | The file-size experiment and its wiring into protect |
| `test_e2e.py` | 40 | The cases in §1 |
| `test_bit_utils.py` | 39 | Bit packing, masking, depth and width validation |
| `test_steganalysis.py` | 30 | The analysis facade and the audio indicators |
| `test_audio_quality.py` | 17 | MSE, PSNR, SNR, distortion bounds |
| `test_crypto.py` | 16 | Hashing and payload preparation |

---

## 6. Limitations asserted rather than avoided

These tests exist to prove a limitation is real. They would fail if the application
quietly started claiming more than it can establish.

| Test | Limitation asserted |
|---|---|
| `test_attacks.py` — outside-payload attacks | Modifying the cover outside the payload leaves the verdict `AUTHENTIC` |
| `test_video_stego.py::test_corruption_outside_the_payload_still_verifies` | Same, on video, where the intuition is strongest |
| `test_robustness.py::TestWhatCodingCannotFix` | Coding does not survive amplitude scaling or lossy recompression |
| `test_robustness.py::test_heavy_corruption_defeats_the_code` | There is a threshold |
| `test_robustness.py::test_a_wrong_signature_is_not_something_coding_repairs` | Coding repairs damage, not forgery |
| `test_size_preservation.py::test_an_impossible_case_is_reported_rather_than_forced` | PNG size matching cannot always succeed |
| `test_size_preservation.py::test_a_coincidental_size_match_is_not_counted` | Two FFV1 encodings landing on the same length is not preservation |
| `test_verification.py` — missing-secret mapping | A missing secret is `CANNOT_VERIFY`, not `WRONG_START_LOCATION` |
| `test_steganalysis.py` — insufficient sample | Indicators report "insufficient sample" rather than a fabricated number |
| `test_video_stego.py::test_a_lossy_encoder_would_be_caught_rather_than_trusted` | A codec that does not preserve pixels is caught at embed time, not at verification |

---

## 7. Property-based testing

Hypothesis is used where a property should hold for every input rather than for a
chosen example: round trips, capacity arithmetic, bit packing, and repetition coding.

The generators **derive** each value from the previous draws rather than filtering:
the depth fixes a minimum image size, the size fixes the payload bound, and the
payload length fixes the start-location bound. Nothing is ever discarded, so
Hypothesis's `filter_too_much` health check is never triggered and every generated
example is valid by construction.

Bounds are kept small — images to 64×64, payloads to 256 bytes — so the property suite
finishes inside its time budget. A faster profile is available for iteration:

```powershell
$env:HYPOTHESIS_PROFILE="fast"; .venv\Scripts\python -m pytest -q
```

---

## 8. Generated evidence

Four artefacts are produced by running the suite, so they always describe the current
code:

| Artefact | Written by | Records |
|---|---|---|
| [`e2e_results.md`](../evidence/results/e2e_results.md) and `.json` | `tests/test_e2e.py` | Every positive, negative and validation case with expected against observed |
| [`size_preservation.md`](../evidence/results/size_preservation.md) and `.json` | `tests/test_size_preservation.py` | The file-size experiment, including the cases that cannot be matched |
| [`audio_lsb_round_trip.md`](../evidence/results/audio_lsb_round_trip.md) and `.json` | `tests/test_audio_stego.py` | Round trip at all eight depths, with the observed distortion against its bound |
| [`audio_quality_by_depth.md`](../evidence/results/audio_quality_by_depth.md) and `.json` | `tests/test_audio_quality.py` | MSE, PSNR and SNR against depth at full occupancy |

All four include the failures and the limits. That is the point of them.

None of these files should be edited by hand. Two earlier hand-maintained artefacts had
gone stale — one described a payload format the code no longer uses, the other was a
pasted terminal capture from a different machine — and both were replaced by generated
versions for that reason.
