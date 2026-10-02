# Media Integrity & Steganography Tool

A desktop app for hiding signed text or files inside images, audio and video using
LSB replacement. It verifies signatures and SHA-256 payload hashes, with optional
password-based encryption.

Supported cover formats are PNG/BMP images, 16-bit PCM WAV audio and video readable
by OpenCV. Protected video is saved as lossless FFV1 in an MKV container.

## Installation

Use **Python 3.11**. Run these commands from the project folder.

Windows:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python main.py
```

macOS / Linux:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

[requirements.txt](requirements.txt) contains the pinned dependencies: PySide6 for
the interface, NumPy and Pillow for image processing, SoundFile for audio,
OpenCV for video, cryptography for signing/encryption, and SciPy for evaluation.
It also installs the testing and linting tools. No separate FFmpeg installation
is required for FFV1 encoding.

## Keys

Choose **Keys → Generate demo key pair**. The app creates a pair or loads the existing
pair, displays its paths and fills the relevant key fields:

- `keys/demo_private/demo_private.pem`: private key used by **Protect** to sign.
- `keys/public/demo_public.pem`: matching public key used by **Verify**.

Keep the private key with the sender. Give the receiver the public key belonging
to the key pair that signed the file; generating a different pair will not verify
an existing file. Check the displayed public-key fingerprint with the sender.
Generated demo private keys are stored without password protection.

## Protect a file

1. Open **Protect** and select or drop an original image, WAV or video.
2. Enter text or select a file payload. Select the signing private key.
3. Choose the LSB depth (1–8) and a manual or secret-derived start location.
   For a derived location, enter a start secret and keep it for the receiver.
4. Optionally enable encryption and enter a passphrase. The receiver needs the
   same passphrase. Review capacity before protecting; a larger depth changes more
   cover data. Repetition error correction uses additional capacity.
5. Choose an output under `samples/protected/` and click **Protect**.

Keep both the protected media and its `.manifest.json` companion. Send both to the
receiver, together with the matching public key. Share any required start secret
and encryption passphrase securely.

## Verify and recover

1. Open **Verify** and select the protected file.
2. Check the manifest path (automatically detected beside the file) and select
   the sender's public key.
3. Enter the start secret and passphrase when required, then click **Verify**.
4. Read the verdict, signature result and payload hash comparisons. An
   **AUTHENTIC** result enables recovered-payload preview and saving.

The app requires version 2 manifests. Regenerate older protected files and their
manifests using this version of the app. Missing files, incorrect inputs and
damaged payloads produce a failure explanation; some failures have more than one
possible cause.

## Attack Lab and video

In **Attack Lab**, load a protected file with its manifest and verification inputs,
select an attack and click **Run Attack**. The app shows verification before and
after the attack. **Save as evidence...** exports the attack log.

Corruption attacks save a separate `attacked_...` file beside the protected file.
The protected file is unchanged, and repeated attacks use numbered filenames.
Move the resulting file into `samples/tampered/` if desired, then explicitly select
the matching original manifest when verifying it. Wrong-key and wrong-start
attacks change verification inputs and do not create modified media.

Use **Video** for playback, clip properties and payload-frame information from the
manifest. Use **Protect** and **Verify** for video signing and verification.
Protected video contains no source audio.

## Sample files

Sample files are in the `samples/` folder, organised as follows:

```text
samples/
  original/    Original cover files
  protected/   Protected media and matching .manifest.json files
  tampered/    Modified copies for verification tests
```

Use **`keys/public/submission_public.pem`** for all supplied samples. The separate
`unrelated_public.pem` is deliberately incorrect and is used only for the wrong-key
test. You do not need the private key to verify or recover these payloads.

These are **public demonstration inputs**, not passwords for real information:

- Derived start secret: `sample-start-2026`.
- Encryption passphrase: `sample-encryption-2026` (only `image-encrypted`).
- Manual-start examples use location 37, recorded in their manifests.

Each protected file has a same-named `.manifest.json` beside it. All rows below
should return **AUTHENTIC**, with matching payload hashes:

| Protected filename (without extension) | Original cover | Payload | Settings |
| --- | --- | --- | --- |
| `image-short-depth1` through `image-short-depth8` | `image_cover.png` | `short_text_payload.txt` | Depth 1–8, manual start |
| `image-long` | `image_cover.png` | `text_payload.txt` | Depth 1, derived start, size matching requested |
| `image-file` | `image_cover.png` | `image_payload.png` | Depth 2, derived start, image file recovery |
| `image-encrypted` | `encryption_cover.png` | `custom_text_payload.txt` | Depth 2, derived start, encrypted text |
| `image-audio-file` | `encryption_cover.png` | `audio_cover.wav` | Depth 3, derived start, audio file recovery |
| `audio-long` | `audio_cover.wav` | `text_payload.txt` | Depth 1, manual start |
| `audio-large-file` | `audio_cover.wav` | `huge_text_payload .txt` | Depth 2, derived start, exact file recovery |
| `audio-robust` | `audio_cover.wav` | `text_payload.txt` | Depth 1, manual start, repetition-3 |
| `video-text` | `forest-cover.mkv` | `text_payload.txt` | Depth 1, derived start |

Image outputs use `.png`, audio outputs `.wav` and video output `.mkv`. The space
before `.txt` in `huge_text_payload .txt` is intentional: the supplied filename is
preserved. Payload source files and cover files are both under `samples/original/`.
Size matching is a request, not a guarantee; actual sizes are in the evidence.

### Tampered examples

Choose the original protected file's manifest explicitly after selecting a tampered
media file. Use the same public key and demonstration inputs as the protected source.

| Tampered filename (without extension) | Protected source / manifest | Expected result |
| --- | --- | --- |
| `image-message-corrupt` | `image-short-depth1` | SIGNATURE_INVALID |
| `audio-signature-corrupt` | `audio-long` | SIGNATURE_INVALID |
| `audio-repetition1-damage1` | `audio-long` | SIGNATURE_INVALID |
| `audio-repetition3-damage1` | `audio-robust` | AUTHENTIC, one corrected bit |
| `audio-repetition3-damage2` | `audio-robust` | SIGNATURE_INVALID |
| `image-outside-payload` | `image-short-depth1` | AUTHENTIC; edit is outside the signed payload |

The two `*-hash-mismatch.manifest.json` files in `samples/tampered/` are modified
manifests. Pair each with its named, unchanged protected media file. Both produce
**TAMPERED** and withhold recovery, even though the embedded signature remains valid.

Additional cases verify unchanged media with an unrelated key, a wrong derived-start
secret (`sample-wrong-start-0`) or a wrong encryption passphrase
(`sample-wrong-passphrase`). See the case index for the exact settings and recorded
failure verdicts. For capacity rejection at depth 1 and manual start 37, select
`image_payload.png` as a file payload in `image_cover.png`, or select
`huge_text_payload .txt` as a file payload in `audio_cover.wav`. Neither attempt
fits; no protected output is created. The same huge text fits the audio cover at
depth 2, as demonstrated by `audio-large-file`.

### Check all samples

From the project folder, using the installed environment:

```powershell
.venv/Scripts/python -m scripts.verify_submission_samples --report tmp/sample-check.json --recovered tmp/recovered-samples
```

On macOS/Linux, use `.venv/bin/python`. Choose new report and recovery paths on each
run. Expected: **27 verification cases and two capacity checks pass**, with 18
exact recovered payloads and no private-key use.

[evidence/verification-results.csv](evidence/verification-results.csv) lists each
expected and actual result. [evidence/case-index.json](evidence/case-index.json)
maps files, manifests, keys and inputs. Detailed logs and screenshots are under
`evidence/logs/` and `evidence/screenshots/`. Screenshots are fresh automated
captures of the real app; they do not document the earlier demo or establish native
media playback. File checksums detect changed submission inputs; key trust still
requires checking the sender's fingerprint.

## Verification limits

The signature and hash checks authenticate the embedded payload and its signed
record, not every byte of the cover. Changes outside the payload can still return
**AUTHENTIC**. A start secret hides the embedding location; enable encryption when
the payload needs confidentiality. Lossy conversion or media editing can destroy
the embedded data.
