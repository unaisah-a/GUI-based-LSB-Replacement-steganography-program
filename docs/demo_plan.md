# T09 live demo script

Plan: **22 minutes of content plus 3 minutes of contingency/questions**. These
are target timings, not a completed rehearsal. Every member must speak. Member
numbers allocate presentation time; they do not establish authorship. Replace each
contribution cue with an accurate account of that person's work and checking.

Use the [case index](../samples/t07/CASE_INDEX.md), [evidence index](evidence_index.md)
and [delivery checklist](submission_handoff.md).

## Prepare before starting the timer

1. Install Python 3.11 and pinned dependencies on the actual demo machines using
   the README. Run the receiver check in the handoff guide. Test image preview,
   received/recovered WAV playback and video playback on that hardware.
2. Open the app, input folders and empty output folders `tmp/demo-a/`,
   `tmp/demo-b/` and `tmp/demo-evidence/`. Use fresh filenames for every run.
   Do not overwrite supplied fixtures or source covers.
3. Below, A means `samples/t07/party-a/`; B means `samples/t07/party-b/`.
   Have A's `messages/short.txt`, `long.txt` and `custom.txt` ready. They contain
   Learning Outcome 1, the Project Overview paragraphs and fictional custom text.
   Attribution is in `messages/sources.json`.
4. Existing B fixtures require B's `sender-public.pem` and the applicable public
   demonstration inputs from `demo-only-secrets.json`. Manual cases need no start
   secret. The encrypted case also needs its demo passphrase. See the case index.
5. New live outputs require a new matching key pair. Keep the private key on A;
   verify with the new public key, not the fixture key. Confirm its fingerprint
   independently. A key arriving beside a file does not establish its owner's identity.
6. Arrange a real A-to-B transfer and receiver download. Transfer stego media,
   companion manifest and public key only. Real secrets need a separate secure
   channel. A local automated folder copy is not a second person's download.
7. Pre-open the indexed fixtures and T06/T07 reports as labelled backups. Do not
   claim a prepared fixture is the output of a failed live action.

## 00:00–02:00 — Member 1: security and keys

- Briefly open **Help → About** and **What verification establishes**. Explain
  GUI → verification → crypto/stego layers. The stego layer carries opaque bytes.
- Use **Keys → Generate demo key pair**; show paths and public-key fingerprint.
  The unencrypted demo private key stays local.
- Explain SHA-256, RSA-PSS and the record's media ID, timestamp, payload hash,
  nonce, metadata and embedding settings. Use the architecture guide/record example
  to point out the fields. Signature verification precedes trusted recovery.
- Say: “AUTHENTIC covers the payload and signed settings, not every cover byte.
  Public-key trust is external. Timestamp and nonce alone do not reject replay.”
- Give one truthful sentence about Member 1's contribution and how it was checked.

## 02:00–07:00 — Member 2: image, manual start and transfer

| Target time | Live action and expected evidence |
| --- | --- |
| 02:00–03:00 | Drag A's `original/image.png` into Protect. Paste `short.txt`, set a distinct media ID, manual start 37 and depth 2. Move the slider through 1–8 and show capacity updates; return to 2. Explain depth/distortion and signed-envelope overhead. |
| 03:00–03:30 | Temporarily move the manual start near the end of the available domain so the message cannot fit. Show the capacity warning/disabled protection; restore 37. Indexed oversized image/audio checks provide reproducible overflow evidence. Capacity rejection is not a verification negative. |
| 03:30–04:30 | Enable **Match the cover's file size where possible**. Choose a fresh output and **Protect & Sign** with the new private key. Show cover/stego previews, quality, byte/percentage changes and separate manifest storage. Read the actual size-matching outcome; success is not guaranteed. |
| 04:30–06:30 | Transfer new PNG, manifest and public key. B downloads into their folder, selects them in Verify, selects the original for comparison, and verifies AUTHENTIC. Show recovered short text, checks, text/hex views and comparison. **Save recovered payload...** to a fresh name. |
| 06:30–07:00 | Explain receiver use of the manual location and cross-checking signed settings. State the member's actual contribution/checks. Briefly select A's `original/image.bmp` to show the other supported image format, then Clear. |

## 07:00–12:00 — Member 3: audio and derived starts

| Target time | Live action and expected evidence |
| --- | --- |
| 07:00–08:30 | Use **Select File** for A's `original/audio-mono.wav`. Select `long.txt` as a file payload with **Choose payload file...**. Set depth 2 and HMAC-derived start with a demo value. Show capacity and explain receiver derivation. |
| 08:30–10:00 | Protect to a new WAV. Play cover and stego; demonstrate pause, seek and stop. Compare sample rate, channels, sample count, size and quality. Do not promise audible or inaudible distortion. WAV metadata can change size even with preserved samples. |
| 10:00–11:30 | Transfer/download WAV, manifest and corresponding public key. B selects these, enters the same start value and verifies AUTHENTIC. Show recovered Project Overview and per-check results. |
| 11:30–12:00 | Explain finite start-location search space: hiding the start is not encryption. State the member's actual contribution and checking. |

## 12:00–15:00 — Member 4: encryption and file recovery

- 12:00–13:15: Protect A's fictional `custom.txt` in an image with **Encrypt the
  message (AES-256-GCM)** enabled, HMAC start and a demo passphrase. Verify with
  the new matching public key and inputs. Explain confidentiality versus signing.
  Demonstrate wrong-passphrase rejection and withheld preview/save, then restore
  the correct passphrase and verify successfully.
- 13:15–14:30: Show Protect's file selector with A's `messages/payload.png` and
  explain file metadata. Explicitly switch to the prepared B `image-file` and
  `audio-file` fixtures, B's key and demonstration inputs. Verify each, preview the
  recovered PNG, play the WAV and save both to fresh paths. The recovered tone is
  0.1 seconds; the received cover tone is 2 seconds. Both are 440 Hz.
- 14:30–15:00: Explain inert text/hex and internal previews: recovered bytes are
  never executed. State the member's actual contribution and checking.

## 15:00–19:00 — Members 1 and 3: attacks and robustness

Use B's key and indexed inputs. Damaged files reuse their original manifest:
select it explicitly. Read observed outcomes alongside expectations.

| Target time | Live action | Expected result |
| --- | --- | --- |
| 15:00–15:40 | Attack Lab, `image-short`: message corruption | AUTHENTIC baseline then SIGNATURE_INVALID; mandatory image negative |
| 15:40–16:20 | `audio-long`: signature corruption | AUTHENTIC baseline then SIGNATURE_INVALID; mandatory audio negative |
| 16:20–17:00 | Authentic `audio-long`: wrong-key and wrong-start actions individually | Wrong key: SIGNATURE_INVALID. Wrong start: rejection with ambiguity notice. These change verification inputs and create no tampered file |
| 17:00–17:30 | `image-short`: outside-payload edit | AUTHENTIC can remain; explain payload-only authentication |
| 17:30–18:40 | Show Protect's repetition-3 checkbox. Verify indexed `audio-repetition1-damage1`, `audio-repetition3-damage1`, `audio-repetition3-damage2` | Uncoded failure; coded AUTHENTIC with correction report; coded SIGNATURE_INVALID. Last is the third mandatory negative: unrecoverable audio damage |
| 18:40–19:00 | Attack Lab **Save as evidence...** | Save actual before/after outcomes. Explain approximately triple storage and controlled one-copy/two-copy damage, not arbitrary lossy-transform resistance |

## 19:00–22:00 — Member 5: video, steganalysis and evidence

- 19:00–20:15: Protect A's short `original/video.mkv` with `short.txt`. Point to
  the warning before protection: source audio is omitted. Verify the fresh output;
  open it in Video, play and **Locate the payload frames** using its manifest and
  start inputs. The span is a manifest claim until verified. Explain FFV1/MKV and
  codec-driven size changes. Prepared `video-positive` is the labelled fallback:
  30 frames, 15 fps, two seconds.
- 20:15–21:15: In Steganalysis select B's `protected/analysis-even-0.png` and
  reference `analysis/even-0.png`, then Analyse. Show channel selection, bit plane 0,
  reference difference, distortion and indicators. Scaling is fixed. T07's 18
  synthetic fixtures gave 2/9 false positives and 8/9 misses; these are not
  natural-media accuracy estimates. A p-value is not a hidden-data probability.
- 21:15–22:00: Open the evidence index and actual exported attack log. Point to
  receiver and preservation reports. Steganalysis has no GUI export button; its
  reproducible reports come from evaluation/receiver scripts. State the member's
  actual contribution and explain AI assistance and checking truthfully. Recap
  key trust, replay, payload scope, fragile LSBs, omitted audio and detection limits.

## 22:00–25:00 — contingency and questions

Do not silently drop retained features. If an operation stalls, identify the failure,
use its labelled prepared fixture and record the missed live action. Screenshots
are fallback evidence, not proof of live success. If rehearsal runs long, reduce
repeated narration, file hunting and setup; retain all challenges, required cases
and member airtime. Record actual segment timings in the handoff guide. The planned
22 minutes does not prove feasibility.
