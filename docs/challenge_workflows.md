# T05 challenge workflows

Run from the repository root with Python 3.11 and the pinned dependencies:

```powershell
.venv-t05/Scripts/python.exe -m scripts.evaluate_challenges --output tmp/t05-demo-new
.venv-t05/Scripts/python.exe main.py
```

Use a new output directory each run. The script refuses to overwrite a directory.
It creates synthetic PNG, PCM-16 WAV and ten-frame FFV1/MKV inputs, protected files,
attack outputs, analysis pairs, a public key and results.json. Private keys remain
in memory. RSA signatures, timestamps and nonces change each run; fixed generators,
damage positions and evaluation rules reproduce the experiment, not identical bytes.
This is a development experiment, not the T07 sender/receiver sample bundle.

All files use the **public demonstration start value** `t05-public-demo-start`.
This value is only for generated demonstration files. Select the generated public.pem
in Verify and Attack Lab. No encryption passphrase is needed for these cases.

## 1. Advanced starts

Load protected_coverpng.png and its automatic companion manifest in Verify.
Enter the demonstration start value and verify: AUTHENTIC. The script repeats this
for WAV and MKV. In Attack Lab select **Verify with the wrong start secret**. The
before verdict must be AUTHENTIC; the after verdict must reject verification.
The action finds a genuinely different derived location, handling finite-space
collisions with a bounded search. A manual-start input is explicitly refused.
Start hiding is not encryption. Wrong secrets, absent payloads and damaged framing
can have indistinguishable failure symptoms.

## 2. Focused attacks

For any generated protected file, supply its public key and original start value.
Run the five actions individually: message corruption, signature corruption,
wrong public key, wrong start secret and outside-payload edit. Read before, after,
expected and observed verdicts. Save the log using **Save as evidence...**.
Wrong-key and wrong-start actions write no file and require an AUTHENTIC baseline.
Outside-payload edits remain AUTHENTIC because the signature authenticates the
payload and signed settings, not every cover byte. Public-key trust is external.
The evaluation runs all five actions on each of the three media.

## 3. Repetition-3 robustness

The script compares uncoded and repetition-3 image/audio files at depth 1 using
the same cover and message. It flips the last signature bit in the first stored
copy in each case: uncoded fails, repetition-3 recovers and reports a correction.
It then flips that logical bit in two of the three copies: verification fails.
The framing is deliberately untouched. This is matched logical damage, not an
equal bit-error-rate comparison; the coded envelope consumes approximately three
times the payload storage. Existing seeded random-damage tests provide additional
coverage. Neither experiment establishes resistance to arbitrary lossy processing.

Open damage_wav_3_1.wav in Verify, explicitly select robust_wav_3.wav.manifest.json,
and verify with the generated public key/start value. Read the correction report.
Then select damage_wav_3_2.wav with the same manifest: SIGNATURE_INVALID. This is the
unrecoverable audio negative. For the uncoded comparison use damage_wav_1_1.wav
with robust_wav_1.wav.manifest.json. Equivalent PNG cases are generated too.
Damage files deliberately reuse their original manifest; select it explicitly.

## 4. Video

Open cover.mkv and protected_covermkv.mkv in Video to preview them, then verify the
protected file in Verify. The Video tab shows the manifest-claimed payload frame
span; authenticate it using Verify. results.json records actual changed frame
indices and checks that they lie within that span. Output is video-only FFV1/MKV:
source audio is omitted. This synthetic source has no audio track. Codec/property
measurements belong to T06; native playback validation belongs to T08.

## 5. Steganalysis

Open analysis_noise_0_stego.png in Steganalysis with analysis_noise_0.png as its
reference. Inspect bit plane 0, amplified reference difference and distortion
metrics; export the report. Repeat with an even-valued or gradient case.

The evaluation has three synthetic families (uniform random bytes, even-valued
random bytes and an even-valued gradient), three seed entries and paired
cover/stego labels: 9 covers and 9 stegos. Gradient seeds intentionally produce
the same cover; these are fixtures, not independent population samples.
The fixed rule flags channel-0 bit-0 uniformity p >= 0.05. Other reported indicators
are not combined into a classifier. Counts of false positives and misses are
recorded along with every case and its indicators/quality metrics in results.json.
A p-value is not a probability that steganography is present. These small,
synthetic fixtures do not estimate natural-media detection accuracy.

Recorded execution and limitations: [T05 evidence](../evidence/t05/README.md).
