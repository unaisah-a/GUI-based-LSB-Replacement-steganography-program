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

Use the matching public key from `keys/public/` when verifying a sample. Select
the protected file's matching `.manifest.json` when verifying a tampered copy.

## Verification limits

The signature and hash checks authenticate the embedded payload and its signed
record, not every byte of the cover. Changes outside the payload can still return
**AUTHENTIC**. A start secret hides the embedding location; enable encryption when
the payload needs confidentiality. Lossy conversion or media editing can destroy
the embedded data.
