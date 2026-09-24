# T07 sender/receiver sample bundle

This is a local demonstration bundle, not a submitted release. Party A and Party B
are separate folders. No private signing key is saved in either folder. The signing
key is generated in memory and discarded; the corresponding public key travels
with Party B. The unchanged application uses the Tristan envelope/manifest format.

## Reproduce or verify

From the repository root, using Python 3.11 with `requirements.txt` installed:

```powershell
# Existing bundle: receiver verification and optional authenticated payload export.
.venv-t05/Scripts/python.exe -m scripts.verify_sample_bundle samples/t07/party-b --report tmp/t07-receiver.json --recovered tmp/t07-recovered

# New bundle: the destination must not already exist.
.venv-t05/Scripts/python.exe -m scripts.build_sample_bundle --output tmp/t07-new

# Open the application for the live steps below.
.venv-t05/Scripts/python.exe main.py
```

Use your own environment path if it is named `.venv`. Reports and recovered folders
must be new: the commands refuse to overwrite them. The verifier returns exit code
0 only when every indexed expectation and capacity check passes. It compares exact
recovered message hashes/lengths and verifies signatures; a nonzero exit is a failed
check. The checksum inventory detects transfer damage, not malicious replacement
of the bundle or substitution of a trusted key.

For another machine, install the same dependencies and copy the application code,
the receiver verifier script and **only `party-b/`**. Run the same command with its
new folder path. Party A, original source messages and private keys are unnecessary.
The recorded isolation test is a local copy into a new directory and fresh process;
it is not evidence of an email transfer or a second person's demonstration.

## Files and credentials

- `party-a/original/`: source PNG/BMP, mono/stereo PCM-16 WAV and a short FFV1 clip.
- `party-a/messages/`: exact short/long message inputs, fictional encrypted custom
  text, PNG and WAV payload files, and source attribution.
- `party-a/protected/` and `party-a/tampered/`: sender outputs and deliberate changes.
- `party-a/generation-report.json`: measured sizes, separate manifests, quality,
  attack outcomes and capacity rejection. No private key is included.
- `party-b/case-index.json`: authoritative paths, settings and expected verdicts.
  The bundle root's `CASE_INDEX.md` gives a readable table.
- `party-b/sender-public.pem`: the public key for normal verification;
  `unrelated-public.pem` is deliberately wrong.
- `party-b/demo-only-secrets.json`: public demonstration start/passphrase values,
  including intentionally wrong values. **These protect no real information.**
- `party-b/original/` and `analysis/`: optional reference media for comparison.
  Positive verification itself needs only media, manifest, public key and any
  relevant demo secret.

The normal start value is `t07-public-demo-start`. The encrypted case uses
`t07-public-demo-passphrase`. Manual-start cases need no start secret. Read the
case index for exceptions. Real secrets must use a separate secure channel.
Confirm the sender fingerprint through a trusted channel; a supplied key alone
does not establish who owns it.

The short message is Learning Outcome 1. The long message contains both Project
Overview paragraphs, with PDF layout whitespace normalised. Both were checked
against page 1 of `INF2005-ACW1-spec_v5-f2f.pdf`. The custom message is fictional.
Image/video generators and audio tones are deterministic; keys, nonces, timestamps
and signatures are fresh, so regenerated protected files differ byte-for-byte.

## GUI walkthrough and expected results

In **Verify**, select the indexed file under Party B, its listed companion manifest
and public key. Enter the relevant start value/passphrase. Select the corresponding
original as the optional comparison. Damaged files deliberately reuse the original
manifest: select that path explicitly. Use **Save recovered payload...** for authenticated bytes. Attack Lab supplies
**Save as evidence...** for attack results; receiver scripts produce JSON reports.

| Demonstration | Case / action | Expected observation |
| --- | --- | --- |
| Image short message, manual start | `image-short`, depth 2, start 37 | AUTHENTIC; exact Learning Outcome text; original/stego comparison |
| Audio long message, advanced start | `audio-long`, depth 2, HMAC start | AUTHENTIC; both Project Overview paragraphs; cover/stego playback |
| Confidential custom message | `image-confidential` | AUTHENTIC with correct passphrase; AES-GCM encryption reported |
| Image payload preview/save | `image-file`, depth 4 | AUTHENTIC; PNG payload recognised; saved bytes match sender input |
| Audio payload preview/save | `audio-file`, depth 4 | AUTHENTIC; WAV payload recognised; saved bytes match sender input |
| BMP and depth 8 | `bmp-manual`, start 37 | AUTHENTIC; fixed-width canonical BMP size preserved |
| Required image negative | `image-payload-corruption` | SIGNATURE_INVALID because the message is signed; no trusted payload preview/save |
| Required audio negative | `audio-signature-corruption` | SIGNATURE_INVALID; no trusted payload preview/save |
| Required third mandatory-media negative | `audio-repetition3-damage2` | SIGNATURE_INVALID; repetition cannot repair two damaged copies |
| Matched robustness comparison | `audio-repetition1-damage1` then `audio-repetition3-damage1` | Uncoded fails; coded is AUTHENTIC with corrections reported |
| Wrong public key | `audio-wrong-key` | SIGNATURE_INVALID; use unrelated-public.pem |
| Wrong advanced start | `audio-wrong-start` | Rejected at a different derived location; use wrong_start from demo-only-secrets.json |
| Wrong passphrase | `image-wrong-passphrase` | CANNOT_VERIFY; signature may verify but plaintext is withheld |
| Outside-payload attack | `image-outside-payload` | AUTHENTIC despite changed cover samples; signature covers the payload |
| Video challenge | `video-positive`, then Video tab | AUTHENTIC; preview cover/stego and locate the manifest-claimed affected frames |
| Steganalysis | `analysis-noise-0`, `analysis-even-0`, `analysis-gradient-0` and their cover references | Inspect bit plane 0, amplified difference and metrics; export the analysis |

Robustness flips the last signature bit in one stored copy, then in two copies of
the repetition-3 envelope. Coded and uncoded cases use the same cover, message,
depth and manual start. This is matched logical damage, not an equal bit-error rate
or resistance to lossy compression. Repetition consumes about three times the space.

The receiver reruns a fixed steganalysis rule (channel-0 bit-0 uniformity p >= 0.05)
on 18 labelled fixtures: noise/even/gradient families, three seed entries, each
with a cover/stego pair. It reports false positives and misses. Gradient seeds
produce the same cover; these are not independent population samples or measured
natural-media detection accuracy. A p-value is not the probability of hidden data.

Video output is **video-only FFV1/MKV**: source audio is omitted. This bundle's
synthetic source has no audio track. Timing uses constant-rate frames; native
playback and source-audio omission were checked in [T08](../evidence/t08/README.md).
The Video tab's frame span is untrusted until verification succeeds.

## Sender actions and retained extras

For a live Protect operation, generate a new demo key pair in the application and
select the new private key locally. Use `party-a/original/` and the message files as
inputs, and write to a new output directory. Verification of those new files needs
the new matching public key; existing bundle files continue to use sender-public.pem.
Keep locally generated private keys out of the shared bundle.

Use an image drop and an audio picker selection to demonstrate both input routes.
Select manual start 37 for the image and HMAC start for audio. Show the depth slider
offers 1-8 and the capacity display responds to depth/start/message changes. T08 subsequently confirmed native picker/drop behaviour; these are live demo
preparation instructions, not evidence of a team rehearsal.

For capacity rejection, load the indexed original image or audio, depth 1, manual
start 37, and enter the indexed `message_bytes` count of `X` characters. The builder
actually attempts protection and requires CapacityError with no published
files. The receiver independently confirms the raw message already exceeds capacity;
the signed envelope's overhead only makes the overflow larger. This is input
validation, separate from the three required verification negatives.

Enable optional **Match the cover's file size where possible** for `image-short`.
Report the observed result, never promise exact PNG matching. Compare media sizes,
signed byte/percentage changes and separate manifest storage; the sender report
records actual values. WAV/BMP metadata can change file size despite fixed-width
samples. The unchanged source cover is not recoverable from stego alone.

In Attack Lab, use an authentic indexed input and run message corruption, signature
corruption, wrong-key, wrong-start and outside-payload edits individually. Wrong-start
requires an HMAC case such as audio-long. Export actual before/after results.
Wrong-key/start actions change verifier inputs and do not create a tampered file.

Use recovered text/hex views and save only AUTHENTIC payloads. For file cases the
verifier's optional recovered directory supplies exact-hash evidence; native GUI
preview/playback passed T08. T09 supplies the [timed script](demo_plan.md) and
[human completion records](submission_handoff.md).

AUTHENTIC concerns the signed payload and settings, not every cover byte. Timestamp
and nonce alone do not reject replay. No email, submission or real transfer is made
by these commands.
