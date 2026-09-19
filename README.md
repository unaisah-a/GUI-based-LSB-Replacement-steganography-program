# Steganographic Media Integrity Lab

A PySide6 desktop application that hides signed messages or files in image, PCM audio, and lossless video carriers. The receiver extracts the payload, verifies an RSA-PSS signature, checks the signed SHA-256 digest, and receives a structured verdict.

Successful verification authenticates the hidden message and signed record relative to a separately trusted public key. It does not authenticate every byte of the cover media or automatically reject replay.

## Features

- PNG, supported BMP, and PCM-16 WAV LSB replacement at depths 1–8.
- FFV1 Matroska video embedding in one selected RGB frame when FFmpeg is installed.
- Manual or HMAC-SHA256-derived start locations.
- RSA-PSS/SHA-256 signatures and public-key fingerprint checks.
- Optional AES-256-GCM message encryption.
- Optional three-copy repetition coding with majority recovery.
- Transactional publication of protected media and its companion manifest.
- Optional exact-size experiments for supported PNG, BMP, and WAV files.
- Optional encrypted sidecar for byte-exact restoration of the original file.
- Protect, Verify, Attack Lab, Analysis, and Video GUI workflows.
- Reproducible positive, negative, confidentiality, robustness, and video samples.

## Requirements

- Python 3.14 (release evidence used Python 3.14.3).
- A desktop environment supported by PySide6.
- FFmpeg and ffprobe on `PATH` only for video workflows. Image and audio workflows remain available without them.

Direct Python dependencies are pinned in `requirements.txt`. The application does not require network access after dependencies are installed.

## Install

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

macOS or Linux:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m pip check
```

For video support, install FFmpeg separately and confirm both commands are available:

```text
ffmpeg -version
ffprobe -version
```

## Run

Windows:

```powershell
.\.venv\Scripts\python.exe main.py
```

macOS or Linux:

```bash
./.venv/bin/python main.py
```

A non-interactive startup check is also available:

```powershell
.\.venv\Scripts\python.exe main.py --smoke-test
```

## Protect media

1. Open **Protect** and choose a PNG, BMP, PCM-16 WAV, or supported video cover.
2. Choose output media, manifest, and an RSA private signing key. **Generate demo key pair…** creates matching private/public keys. Enter a non-empty **Key password** before generating to encrypt the private-key file; leaving it blank saves an unencrypted private key.
3. Enter a media ID and select LSB depth, start method, and optional robustness.
4. Supply a start secret for HMAC-SHA256 mode, or a non-negative scalar-sample index for manual mode.
5. Enter text or choose a payload file. Enable encryption only when a separately shared AES key is available.
6. Review the exact capacity estimate, then select **Protect and sign**.
7. Transfer the protected media and companion manifest. Transfer the trusted public key and any start/encryption secrets through an independently trusted channel.

The manifest is required extraction metadata, but it is untrusted until its settings and signer fingerprint agree with the signed record. Derived start locations and secret values are deliberately omitted from it.

### Location, bits, and unchanged files

Protect and Verify accept one local media file at a time in their drag-and-drop zones. Other inputs use file pickers. A manual start is a numeric, zero-based eligible-sample index, not an image click or audio timeline selection. Image indices traverse color channels with alpha excluded; audio indices traverse interleaved PCM samples. Video also has a frame selector.

**LSB depth** chooses the number of consecutive lowest bits to replace: depth 1 replaces bit 0, depth 3 replaces bits 0–2, and depth 8 replaces bits 0–7. It does not select arbitrary individual bit positions. The GUI illustrates the affected bits. AES encryption is a separate option applied to the message before embedding.

The original input is kept and a separate protected output is written. Embedding changes output bits, and higher depths can increase visual or audible distortion. **Attempt exact original file size** preserves size for supported BMP/WAV layouts and attempts it conditionally for PNG; video size preservation is unsupported. The result reports measured byte counts. Manifests and recovery sidecars add storage and are excluded from that comparison. Byte-exact restoration needs the encrypted recovery sidecar and its separate key.

Capacity estimates run in a background worker after a short typing pause. Outdated results are discarded when inputs change. The final protection operation checks capacity again; a derived-start preview can differ because protection generates a fresh nonce.

## Verify media

1. Open **Verify** and choose the received protected media, its manifest, and the trusted RSA public key.
2. Supply the start secret when the manifest uses a derived start. Supply the AES key when the payload is encrypted.
3. Select **Extract and verify**.
4. Inspect every check and the final verdict. Save recovered bytes only after an `AUTHENTIC` result enables **Save trusted recovered payload…**.

`AUTHENTIC` means the signature, signed settings, plaintext hash, and required extraction relationships passed. Extraction failures with an uncertain cause are reported conservatively as `CANNOT_VERIFY`.

## Reproduce the receiver bundle

The checked-in receiver bundle contains no signing private key and needs no sender process state:

```powershell
.\.venv\Scripts\python.exe scripts\verify_sample_bundle.py samples\r11\receiver
```

It verifies ten indexed image, audio, robustness, confidentiality, and video cases plus a separate capacity-rejection case. The AES and start values in that bundle are clearly labelled evidence-only demonstration values.

To generate a new bundle with deterministic covers and messages but fresh RSA keys, AES keys, start secrets, and nonces:

```powershell
.\.venv\Scripts\python.exe scripts\generate_samples.py --output samples\r11 --overwrite
.\.venv\Scripts\python.exe scripts\verify_sample_bundle.py samples\r11\receiver
```

Generating over the checked-in bundle changes its cryptographic artifacts. Use a different output directory when the committed evidence must remain unchanged.

## Test and release evidence

Run the complete suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The reviewed R12 release candidate passed 578 tests. Its validation summary records a clean Python 3.14 installation, successful startup, ten receiver cases, three native Windows Qt workflows, optional-tool behavior, screenshot hashes, and secret-exclusion checks:

- `evidence/results/r12-validation-summary.json`
- `evidence/results/r12-release-audit.json`
- `evidence/results/r12-desktop-audit.json`
- `evidence/logs/r12-clean-install.txt`
- `evidence/logs/r12-full-suite.txt`
- `evidence/screenshots/`

Focused release checks can be rerun with:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_release_checks.py -q
```

The native desktop evidence script controls the real GUI and should be run from an interactive desktop session:

```powershell
.\.venv\Scripts\python.exe scripts\run_desktop_release_check.py
```

## Security and key handling

- Never commit or transfer a real private signing key.
- Verify the public-key fingerprint through a trusted channel before accepting it.
- Share start secrets, AES keys, and recovery keys separately from protected media and manifests.
- Use newly generated AES keys/nonces for real data. Checked-in demonstration secrets are public and provide no confidentiality.
- Treat extracted file bytes as data. The application does not execute recovered content automatically.
- A timestamp and nonce provide signed context but require an external freshness database or policy to reject replay.

See [limitations](docs/limitations.md) for the complete claim boundary and [architecture](docs/architecture.md) for the wire format and trust flow.

For measured steganalysis false alarms and repetition recovery under independent bit noise, see [extension evaluation](docs/extension_evaluation.md). The bundled controls are synthetic; natural-image evaluation requires team-supplied photographs with recorded provenance.

## Documentation

- [Architecture and wire format](docs/architecture.md)
- [Compatibility boundaries](docs/compatibility.md)
- [Limitations and security assumptions](docs/limitations.md)
- [Requirement and test-case matrix](docs/test_cases.md)
- [25-minute demonstration plan](docs/demo_plan.md)
- [Contribution statement template](docs/contribution_statement.md)
- [Originality and AI-use record](docs/originality_and_ai_use.md)
- [Submission checklist and evidence index](docs/submission_checklist.md)
- [Implementation plan and acceptance history](docs/IMPLEMENTATION_PLAN.md)
- [Preserved original planning README](docs/planning_reference.md)

Team identifiers, member names, contribution percentages, acknowledgements, actual transfer/rehearsal results, and signatures are intentionally left for the team to complete truthfully before submission.
