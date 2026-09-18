# Media Integrity & Steganography Tool

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

---

## Demo walkthrough

Committed sample files live in [`samples/`](samples/). Each stego file has a
`.manifest.json` beside it and was signed with the sample key in
[`keys/public/samples_public.pem`](keys/public/). The start-location secret for all of
them is `demo-start-secret`. When you verify, attack or inspect a committed sample,
select that key in the public-key field (the tabs default to your own demo key).
Regenerate the samples with `python scripts/generate_samples.py`.

1. **Create a key pair.** Open *Keys → Generate demo key pair*. This writes a private
   key to `keys/demo_private/` (git-ignored, unencrypted, demo use only) and a public
   key to `keys/public/`. The Protect and Verify tabs pick them up automatically.

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
   original name. A wrong secret gives `PAYLOAD_MISSING`,
   and a different public key gives `SIGNATURE_INVALID`.

4. **Attack it.** On the **Attack Lab** tab, load the same stego file, choose an attack
   (for example *Modify pixels inside the payload*) and run it. The tampered copy is
   verified straight away and should no longer be `AUTHENTIC`. An attack *outside* the
   payload region is shown to still verify, which is the limit of what the signature
   covers. Audio attacks work the same way with `samples/audio/stego/stego.wav`.

5. **Analyse it.** On the **Steganalysis** tab, load the stego file and give the
   original cover as the reference. You see the bit planes, an amplified difference
   image, distortion figures (MSE, PSNR) and statistical indicators. On the **Video**
   tab, load `samples/video/stego/cover_stego.mkv` with its manifest and secret to see
   which frames carry the payload.

---

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
scripts/          sample-generation utilities
tests/            the pytest suite
main.py           entry point
```

[`docs/planning_reference.md`](docs/planning_reference.md) is the team's original
planning brief (requirements, roles, Git workflow), kept for reference.
