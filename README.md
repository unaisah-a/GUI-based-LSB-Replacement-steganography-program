# Media Integrity & Steganography Tool

> Consolidation work: read the [implementation plan and task tracker](docs/IMPLEMENTATION_PLAN.md) for agreed scope, task status, verification evidence and handoff notes.

The [T07 sender/receiver bundle guide](docs/sample_bundle.md) covers fresh required
messages, positive/negative cases, all five challenges and independent verification.

INF2005 Assignment 1 — a desktop application that hides a **signed** message inside an
image, audio or video file using LSB replacement, and lets a receiver prove whether that
message is authentic.

- **Media:** PNG and BMP images, 16-bit PCM WAV audio, and video (output is lossless
  FFV1 in Matroska).
- **LSB depth:** 1 to 8 bits per sample.
- **Security:** RSA-PSS signatures, SHA-256 message digests, optional AES-256-GCM
  encryption with a scrypt-derived key, and an HMAC-derived secret start location.
- **Extras:** repetition error correction, an attack simulator, steganalysis views, and
  a file-size preservation experiment.

Design and limits are documented in [`docs/`](docs/): start with
[`architecture.md`](docs/architecture.md) and [`limitations.md`](docs/limitations.md).
Responsible use, originality and AI use are covered in
[`ethics_and_ai_use.md`](docs/ethics_and_ai_use.md).

---

## Install

Python 3.11 is required. Install into a virtual environment rather than the system
interpreter.

```bash
python -m venv .venv

# Windows
.venv\Scripts\python -m pip install -r requirements.txt

# macOS / Linux
.venv/bin/python -m pip install -r requirements.txt
```

Every dependency is a wheel, including the FFV1 video codec bundled inside
`opencv-python`, so no separate `ffmpeg` install is needed.

## Run

```bash
.venv\Scripts\python main.py        # Windows
.venv/bin/python main.py            # macOS / Linux
```

The window has five tabs: **Protect**, **Verify**, **Attack Lab**, **Steganalysis** and
**Video**. Log output goes to the terminal and to `evidence/logs/application.log`.

## Test

```bash
.venv\Scripts\python -m pytest
```

Configuration is in [`pytest.ini`](pytest.ini): tests are collected from `tests/`, and
warnings are treated as errors. The GUI tests use `pytest-qt` and need no visible window.

```bash
.venv\Scripts\python -m pytest --cov              # with a coverage report
.venv\Scripts\python -m pytest --write-evidence   # also regenerate evidence/results/
.venv\Scripts\ruff check .                        # lint, configured in pyproject.toml
```

GitHub Actions runs the linter and the full suite on every push and pull request.

## Package for submission

```bash
.venv\Scripts\python scripts/package_submission.py
```

This writes `dist/INF2005_ACW1_submission.zip` (choose another path with `--output`).
It contains the source, tests, docs, samples, evidence and configuration. It leaves
out the virtual environment, caches, the local demo key pair and the local
application logs, and it refuses to build if any packaged file holds a private key.

---

## Demo walkthrough

For the consolidated presentation use the [T09 timed script](docs/demo_plan.md),
[evidence index](docs/evidence_index.md) and [submission/human checklist](docs/submission_handoff.md).
The walkthrough below uses **legacy samples only**; T07 fixtures have a different
key and demonstration inputs, documented in the bundle guide.


Legacy sample files live under `samples/images`, `samples/audio` and `samples/video`. Each stego file has a
`.manifest.json` beside it and was signed with the sample key in
[`keys/public/samples_public.pem`](keys/public/). The start-location secret for all of
them is `demo-start-secret`. When you verify, attack or inspect a committed sample,
select that key in the public-key field (the tabs default to your own demo key).
Regenerate the samples with `python scripts/generate_samples.py`.

1. **Create a key pair.** Open *Keys → Generate demo key pair*. This writes a private
   key to `keys/demo_private/` (git-ignored, unencrypted, demo use only) and a public
   key to `keys/public/`. The Protect and Verify tabs pick them up automatically. No
   private key is shipped with the project: every user generates their own. The
   committed samples need only their public key; the private key that signed them
   was discarded when they were generated.

2. **Protect (party A).** On the **Protect** tab, drop in
   `samples/images/original/cover.png`, type a message (or switch the payload to
   *A file* and choose any text, image or audio file), pick an LSB depth, keep the
   *derived* start method and enter a start secret. Optionally tick *Encrypt* and
   enter a passphrase. Click **Protect**. You get a stego PNG and its
   `.manifest.json`, and the tab lists which secrets the receiver needs.

3. **Verify (party B).** On the **Verify** tab, load the stego file. The manifest is
   found beside it and the demo public key is filled in. Enter the same start secret
   (and passphrase, if you used one) and click **Verify**. The verdict should be
   `AUTHENTIC`, with the recovered message. A recovered image or audio file is shown
   or played in the tab, and **Save recovered payload...** writes it out under its
   original name. Preview and save require an `AUTHENTIC` verdict. Compare the displayed
   public-key SHA-256 fingerprint through an independently trusted channel. A wrong secret gives `PAYLOAD_MISSING`,
   and a different public key gives `SIGNATURE_INVALID`.

4. **Attack it.** On **Attack Lab**, load the protected file and select payload
   corruption, signature corruption, or an edit outside the payload. Run one attack
   to compare its expected and observed verdicts. Outside-payload edits can still
   verify because the signature does not authenticate every cover byte. The bulk
   runner and extra GUI attack variants have been removed; backend experiments remain.
   Dedicated wrong-key and wrong-start actions reverify the unchanged file with a substituted receiver input. Wrong-start requires HMAC-derived protection.

5. **Inspect it.** **Steganalysis** shows bit planes with fixed display scaling,
   a reference difference, distortion figures and experimental statistical indicators.
   **Video** provides playback, clip properties and the claimed payload frame range
   from the manifest. Use **Verify** to authenticate those claims. Video protection
   creates video-only FFV1/MKV output: source audio is omitted. Capacity is measured
   in **Protect**, including the selected manual start, on a background worker.


## Repository layout

```text
app/
  stego/          LSB embedding and extraction for image, audio and video
  crypto/         envelope, signatures, encryption, start location, manifest
  verification/   the protect (sender) and verify (receiver) workflows
  robustness/     repetition error correction
  attacks/        the attack catalogue used by the Attack Lab
  analysis/       quality metrics, steganalysis, file-size experiment
  gui/            the PySide6 interface; nothing below this layer imports Qt
  utils/          constants, file helpers, logging
assets/styles/    the Qt stylesheet
docs/             architecture, limitations, test cases, demo plan, contributions
evidence/         generated test results and logs for submission
samples/          committed demo media with manifests
scripts/          sample generation and submission packaging
tests/            the pytest suite
main.py           entry point
```

[`docs/planning_reference.md`](docs/planning_reference.md) (the team's original
planning brief) and [`docs/image_layer_requirements.md`](docs/image_layer_requirements.md)
(the image layer's working specification, cited by requirement number in the code) are
internal working documents, not deliverables.

Challenge demonstrations and reproducible evaluation: [T05 guide](docs/challenge_workflows.md).
