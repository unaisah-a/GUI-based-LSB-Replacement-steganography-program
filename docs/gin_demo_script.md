# Gin demo script for attacks and video steganography

Use this for your part of the team demonstration. It includes what to prepare, the exact app actions, a spoken explanation for each demonstration and what the results mean. Read the action instructions during rehearsal; speak the quoted lines during the presentation, adapting them to the result actually shown.

**How to deliver it:** read straight down each numbered sequence. Perform the *italic action* and say the quote immediately underneath while doing it. Actions marked “wait” require completion before the result line. Italic instructions and **Rehearsal notes** are not spoken. Choose either the live or prepared-sample opening; do not read both. Give the closing line once, at handover or in the team wrap-up.

The main route uses your teammates' freshly protected image and audio. The prepared-sample route is provided for practice or a clearly announced fallback. All results below are expected outcomes, not a record of a completed rehearsal.

## External-hash explanation (H03-H04 implemented)

This supplement applies to freshly generated version 2 outputs. The
[version 2 plan](IMPLEMENTATION_PLAN.md#external-payload-hash-agreed-target-not-implemented)
now adds the original message/file SHA-256 to the manifest through H02. H03 shows
expected versus recomputed hashes, with a cross-check against the signed record.
The practice paths below use H04's verified version 2 bundle. The live route still
requires your teammates' freshly protected outputs and matching manifests/keys.
Old version 1 practice outputs remain preserved but are rejected by this build.

The proposed receiver explanation is:

> "The expected payload hash is in the manifest. The app hashes the recovered message and compares the values, then checks their agreement with the authenticated signed record. The signature is what prevents someone from passing verification by replacing both the message and its expected hash."

During the five attacks, do not promise a visible hash mismatch for every rejection.
Message/signature corruption and wrong-key checks can stop at signature verification;
wrong-secret extraction can fail earlier. Their plaintext-hash comparison will say
**Not performed** when it was not reached. Outside-payload edits can still preserve
both payload-hash agreement and `AUTHENTIC`. Explain the actual displayed result.

Use matching output/manifest/public-key pairs from the verified
`samples/hash-manifest-v2` bundle for practice. This supplement is excluded
from the existing narration counts and timing estimates; it has not been rehearsed.

## 1. Your role and timing

Your job is to demonstrate five attack cases, export their evidence, then protect, verify and play a video and locate its payload frames. Explain what each result establishes and its limits.

This script keeps your adopted overall slot of **15:00–21:00**, followed by the team's wrap-up. It proposes moving the video transition from 19:30 to **18:45**, giving video more time within your existing slot. This is a suggested internal timing adjustment, not an agreed change to the team's PDF or a measured rehearsal result.

| Presentation clock | Your elapsed time | Action |
| --- | --- | --- |
| 15:00–15:15 | 0:00–0:15 | Introduce the checks |
| 15:15–16:00 | 0:15–1:00 | Corrupt the image message |
| 16:00–16:40 | 1:00–1:40 | Corrupt the audio signature |
| 16:40–17:10 | 1:40–2:10 | Wrong public key |
| 17:10–17:45 | 2:10–2:45 | Wrong start secret |
| 17:45–18:25 | 2:45–3:25 | Outside-payload image edit |
| 18:25–18:45 | 3:25–3:45 | Save attack evidence and transition |
| 18:45–19:45 | 3:45–4:45 | Protect the video |
| 19:45–20:20 | 4:45–5:20 | Verify the new video |
| 20:20–21:00 | 5:20–6:00 | Play video, locate frames and state limitations |

These are rehearsal targets. Pre-stage folders and the signing key; shorten repeated explanations if needed. Include real processing time when measuring. Do not drop video verification to make the timing appear to work.

The live-route narration contains **448 words**, plus **38 words** for the closing line. At an assumed 120–140 words per minute, the main narration alone takes roughly **3.2–3.7 minutes**, leaving about two to three minutes of the six-minute slot for actions and pauses. This is a word-count estimate, not a measured delivery time. Some setup can happen while you speak; wait for actual results before giving the result lines. If your closing belongs in the team's 21:00–22:00 wrap-up, save it for that slot.

## 2. Prepare before your speaking slot

### Understand the four tabs

| Tab | Your use |
| --- | --- |
| Protect | Create the new signed video payload |
| Verify | Authenticate the new video and recover its payload; diagnose any invalid baseline |
| Attack Lab | Run the five attacks and inspect before/after verification results |
| Video | Play the video and calculate the payload-frame range |

A **cover** is the original image, audio or video. A **stego file** is the protected output containing the hidden package. A **manifest** is its companion JSON file containing the extraction settings. The manifest is initially untrusted; relevant settings are checked against the signed information during verification.

### Agree the live handover

Have the following available on the demonstration machine before your slot. `IMAGE`, `AUDIO` and the other capitalised names below are shorthand in this script, not filenames to type into the app.

| Script name | What you need | Source |
| --- | --- | --- |
| `IMAGE` | Fresh protected image with a non-empty payload | Tristan's Protect output |
| `IMAGE_MANIFEST` | That exact output's companion manifest | Generated alongside `IMAGE` |
| `IMAGE_PUBLIC_KEY` | Public key matching the image's signing private key | Confirm with Tristan/Chanel |
| `AUDIO` | Fresh protected WAV using an HMAC-derived start | Unaisah's Protect output |
| `AUDIO_MANIFEST` | That exact output's companion manifest | Generated alongside `AUDIO` |
| `AUDIO_PUBLIC_KEY` | Public key matching the audio's signing private key | Confirm with Unaisah/Chanel |
| Image/audio start secrets | The actual secrets used, if their starts are derived | Share separately with the relevant presenter |
| `VIDEO_PRIVATE_KEY` and `VIDEO_PUBLIC_KEY` | A matching local key pair for your new video | Use the pair already prepared by Chanel, if available |

Use the ordinary image/audio outputs for this sequence, with encryption and repetition off to match the planned demonstration. Unaisah's damaged robustness examples are separate inputs. If using an encrypted output instead, you also need its correct passphrase for an authentic baseline.

Do not assume everyone used the same key pair or secret. You need only the **public key** for attacks and verification. Your local **private key** is needed only when you protect your new video. Do not transfer private keys to the receiver or write real secrets into this script or evidence notes.

For a connected sender-to-receiver demo, use the received copies of your teammates' outputs. Angelline's preceding receiver segment should establish successful extraction of the actual short image and long audio payloads. A prepared fixture or same-machine selection alone does not establish that the required transfer took place.

### Prepared inputs for practice or fallback

Repository root: `A:/Code/GUI-based-LSB-Replacement-steganography-program`.

| Script name | Prepared value relative to the repository root |
| --- | --- |
| `IMAGE` | `samples/hash-manifest-v2/party-b/protected/image-short.png` |
| `IMAGE_MANIFEST` | `samples/hash-manifest-v2/party-b/protected/image-short.png.manifest.json` |
| `AUDIO` | `samples/hash-manifest-v2/party-b/protected/audio-long.wav` |
| `AUDIO_MANIFEST` | `samples/hash-manifest-v2/party-b/protected/audio-long.wav.manifest.json` |
| Both public keys | `samples/hash-manifest-v2/party-b/sender-public.pem` |
| Image start secret | None; this fixture uses a manual start |
| Audio start secret | `t07-public-demo-start` |
| Image/audio passphrase | None; both are unencrypted |
| Original video cover | `samples/hash-manifest-v2/party-a/original/video.mkv` |
| Prepared video fallback | `samples/hash-manifest-v2/party-b/protected/video-positive.mkv` |
| Prepared video manifest | `samples/hash-manifest-v2/party-b/protected/video-positive.mkv.manifest.json` |
| Prepared video public key | `samples/hash-manifest-v2/party-b/sender-public.pem` |
| Prepared video start secret | `t07-public-demo-start` |

The printed secret is public demonstration data. It is not necessarily the secret your teammates choose for fresh outputs. A locally generated key pair does not automatically match these prepared fixtures.

### Preflight actions

1. Open File Explorer at the live output folder, public-key folder and original-video folder. For practice, use the paths above.
2. Confirm the image and audio each verify as `AUTHENTIC` with the intended manifests, keys and secrets. Use Angelline's existing successful checks where applicable. If troubleshooting, load each in **Verify**, select its manifest/public key, enter required secrets and click **Verify**.
3. Confirm the audio uses a derived start. A manual-start file cannot demonstrate the wrong-start-secret action.
4. Confirm the image has space outside its embedded region for the outside-payload action. Practise that action on the intended output; a nearly full cover may not have enough usable outside samples.
5. In **Protect**, select the intended local signing private key. Note its matching public-key path. If no pair exists, use **Keys → Generate demo key pair** and note the displayed paths. The menu may reuse an existing pair.
6. Choose a fresh video output name ending in `.mkv`, for example `gin-video-live.mkv` in your demo output folder. Do not overwrite the cover or an earlier output you still need.
7. If reusing the app after practice, save any wanted Attack Lab log before clicking **Clear**. Start the presentation with a clear log so the exported evidence represents that run.

## 3. Opening line

*Open **Attack Lab**.*

> “I will show how verification responds to changed data and incorrect inputs, then demonstrate video steganography.”

*If using your teammates' fresh outputs, point to their output folder.*

> “I am using the protected files produced earlier, with their matching manifests and public keys.”

*If using prepared samples instead, replace the preceding sentence with this line.*

> “I am using our prepared image and audio examples for these attacks.”

Do not claim the samples contain the professor's replacement payload unless they were regenerated with it.

## 4. Demonstrate the five attacks

Follow each action immediately with its quoted line. The actions describe the planned unencrypted, repetition-off inputs; use the actual required secrets if your teammates selected different settings. For every result cue, wait for completion and check the actual verdict before speaking.

Attack Lab keeps both secret fields editable. The hint below them says whether each is required or unused for the selected manifest. Typing a secret does not turn a manual-start file into an HMAC file; use the derived-start audio for that attack.

### Attack 1 Corrupt the image message

1. *Drag `IMAGE` into Attack Lab, or select it using the file picker.*

   > “First, I select the protected image to test whether a changed message is detected.”

2. *Check **Manifest** is `IMAGE_MANIFEST`; browse to it if not. Select `IMAGE_PUBLIC_KEY` under **Public key**.*

   > “I use its matching manifest for extraction and the sender's public key for verification.”

3. *For a manual start, leave **Start secret** blank. For a derived start, enter the image's actual secret. Leave **Passphrase** blank for an unencrypted image; otherwise enter its actual passphrase. Select **Corrupt the message**.*

   > “This action changes message bytes while leaving the original signature in place.”

4. *Click **Run Attack**. Wait. When the expected results appear, point to **Verdict before**, **Verdict after** and **Matched expectation**.*

   > “The baseline is AUTHENTIC; the modified copy is SIGNATURE_INVALID. The changed message no longer matches what was signed.”

**Expected:** `AUTHENTIC → SIGNATURE_INVALID`; matched expectation `yes`.

**Rehearsal note:** the signature fails before the later plaintext-hash comparison. This action creates an attacked copy; keep the original `IMAGE` for later baselines. It is not a general editor for creating a valid replacement signed message.

### Attack 2 Corrupt the audio signature

1. *Load the original `AUDIO`, not an attacked copy. Check **Manifest** is `AUDIO_MANIFEST` and select `AUDIO_PUBLIC_KEY`.*

   > “Next, I select the protected audio with its own manifest and public key.”

2. *Enter the audio's correct **Start secret**. For the prepared fixture, use `t07-public-demo-start`. Leave **Passphrase** blank for the planned unencrypted audio.*

   > “I enter the shared start secret so the app can locate the hidden package.”

3. *Select **Corrupt the signature**, then click **Run Attack**.*

   > “This time, the attack damages the signature itself.”

4. *Wait. Point to the authentic baseline and failed after-verdict.*

   > “The original passes, but the damaged signature fails verification even though the message bytes remain unchanged.”

**Expected:** `AUTHENTIC → SIGNATURE_INVALID`.

**Rehearsal note:** leave this original audio and its correct inputs selected for attacks 3 and 4. A failed signature does not by itself establish whether damage was deliberate.

### Attack 3 Use the wrong public key

1. *Keep the original audio, its manifest and correct start secret selected. Point to the **correct** `AUDIO_PUBLIC_KEY` in the key field.*

   > “I keep the correct inputs here to establish a valid baseline.”

2. *Select **Verify with the wrong public key**, then click **Run Attack**.*

   > “The action substitutes an unrelated public key without changing the audio.”

3. *Wait. Point to the before/after verdicts and the description of the substituted key.*

   > “Verification fails. This demonstrates that a wrong key can cause signature failure even when the file is unchanged.”

**Expected:** `AUTHENTIC → SIGNATURE_INVALID`; the media is unchanged.

**Rehearsal note:** do not manually select `unrelated-public.pem` in Attack Lab. The action introduces the wrong key after an authentic baseline. Manual wrong-key selection is an alternative demonstration in **Verify**.

### Attack 4 Use the wrong start secret

1. *Keep the original audio, manifest and correct public key selected. Keep its **correct** secret in **Start secret**.*

   > “This audio uses a secret-derived start, so the receiver needs the same secret.”

2. *Select **Verify with the wrong start secret**, then click **Run Attack**.*

   > “The action substitutes a secret that produces a different embedding position.”

3. *Wait. Point to the actual after-verdict and its explanation. Only use this line if verification was rejected.*

   > “Recovery and authentication now fail. This tests location hiding; the start secret does not encrypt the message.”

**Expected:** an `AUTHENTIC` baseline followed by rejection: `PAYLOAD_MISSING`, `CANNOT_VERIFY` or `SIGNATURE_INVALID`. Read the actual label rather than promising one.

**Rehearsal note:** this action requires HMAC mode. Different secrets can map to the same finite position, so the action searches for a different position. If it cannot find one, it reports a limitation instead of completing the test.

### Attack 5 Modify image pixels outside the payload

1. *Reload the original `IMAGE`. Restore `IMAGE_MANIFEST`, `IMAGE_PUBLIC_KEY` and any required secrets. The prepared manual-start image needs no secret or passphrase.*

   > “I return to the original protected image and restore its matching inputs.”

2. *Select **Modify pixels outside the payload**, then click **Run Attack**.*

   > “Here, we change pixels outside the embedded package.”

3. *Wait. Point to both `AUTHENTIC` verdicts and **Matched expectation: yes**.*

   > “Verification still passes because the payload and signed settings remain intact. AUTHENTIC does not mean every cover pixel is unchanged.”

**Expected:** `AUTHENTIC → AUTHENTIC` despite changed image samples.

**Rehearsal note:** **Changed: no** means the verdict did not change. It does not mean the image bytes are unchanged. This action needs sufficient space outside the payload; a refusal is not a successful attack result.

## 5. Save evidence and transition

1. *Click **Save as evidence...**. Choose a fresh text filename such as `gin-demo-attacks.txt`, then click **Save**.*

   > “I save the attack log so these verdicts and explanations can be reviewed.”

2. *Check the saved-status message, then open **Protect**.*

   > “Next, I will demonstrate the full video workflow.”

**Rehearsal note:** do not clear the log before saving. It records app results, not independently signed proof. Your image message and audio signature failures are two planned mandatory-media negatives; Unaisah's unrecoverable audio damage supplies the third. Wrong inputs and capacity refusal do not replace that agreed coverage.

## 6. Demonstrate video from protection to playback

### A Protect the video

Your selected forest cover is [forest-cover.mkv](<C:/Users/ginli/OneDrive/SIT/Year 2 Tri 1/Cyber Security Fundamentals/Project/forest-cover.mkv>): five seconds, 640 × 360, 25 fps, FFV1, no audio. It was converted from your supplied MP4 and passed a backend protect/verify check with exact text recovery; native GUI playback still needs rehearsal. Copy this MKV to the presentation machine if needed. The original bundled `samples/hash-manifest-v2/party-a/original/video.mkv` remains a fallback cover.

1. *In **Protect**, load your `forest-cover.mkv`. Use this cover, not an already protected output. The MP4 download itself is not the app input.*

   > “I select the original video as the cover. We embed data in its image frames.”

2. *Set **Media ID** to `GIN-VIDEO-DEMO`, **LSB depth** to `1` initially and **Start mode** to **Derived from a secret (HMAC)**. Enter your chosen video secret; for the public rehearsal example, use `t07-public-demo-start`.*

   > “I choose the depth and enter a shared secret to determine the embedding position.”

3. *Select **Typed text** and enter `Gin video demonstration`, or the professor's replacement. For a supplied file, use **A file (text, image, audio or any other)** and **Choose payload file...** instead.*

   > “Here is the payload I want the receiver to recover.”

4. *Untick **Encrypt the message (AES-256-GCM)**, **Apply repetition coding (factor 3)** and **Match the cover's file size where possible**. Select `VIDEO_PRIVATE_KEY`. Choose a fresh full **Stego file** path ending in `gin-video-live.mkv`. Check capacity; adjust valid settings if needed before proceeding.*

   > “I select the signing private key and a new output path, then check capacity.”

5. *Point to the video-only output notice. Click **Protect & Sign** and allow processing to finish.*

   > “The output uses lossless FFV1 in MKV to preserve the embedded bits. Source audio is omitted.”

6. *Once protection succeeds, note the actual output and manifest paths. They are `NEW_VIDEO` and `NEW_VIDEO_MANIFEST` for the following steps.*

   > “The protected video and its matching manifest are ready.”

**Rehearsal note:** protection must succeed before continuing. The entire signed package must fit, not just the user's message. FFV1 is the codec; MKV is the container. Retaining source audio would require additional audio handling and muxing. The package need not occupy every frame.

### B Verify the new video

1. *Open **Verify**, load `NEW_VIDEO` and confirm **Manifest** is `NEW_VIDEO_MANIFEST`.*

   > “I load the new output with the manifest generated for it.”

2. *Select `VIDEO_PUBLIC_KEY`, matching the private key just used. Enter the same video **Start secret**. Leave **Passphrase** blank because encryption was off. Clear any unrelated **Original cover**, or select the actual original video for an optional comparison.*

   > “I select the matching public key and enter the same start secret.”

3. *Click **Verify** and wait.*

   > “The receiver can check this without the private signing key.”

4. *If verification succeeds, point to `AUTHENTIC` and compare the recovered payload with your input. For a file payload, show its applicable preview and use **Save recovered payload...**.*

   > “The result is AUTHENTIC, and the recovered payload matches the input.”

**Expected:** `AUTHENTIC` with the exact payload recovered.

**Rehearsal note:** selecting the fixture public key by mistake can cause failure. The original cover is optional for comparison, not needed for authentication. The signature, hash and consistency checks validate the payload against the selected key; trust in that key's owner is established separately.

### C Play the video and locate the payload frames

1. *Open **Video**, load the same `NEW_VIDEO` and click **Play**. Let the clip play; use **Pause** or **Stop** if useful. Speak after playback is visibly working.*

   > “The protected video still plays, but playback alone does not authenticate the hidden payload.”

2. *Confirm **Manifest** is `NEW_VIDEO_MANIFEST`, enter the same video **Start secret** and click **Locate the payload frames**.*

   > “Using the same manifest and secret, I locate the payload's frame range.”

3. *Once the location is displayed, point to **Claimed payload region**: **Frames**, **Frames touched**, **Start sample** and **Embedded bytes**. Use the actual values rather than memorising a range.*

   > “This range is calculated from the supplied settings. Verify establishes authenticity. Lossy conversion can destroy the hidden bits.”

**Rehearsal note:** this tab provides playback and location calculation; it does not embed or independently authenticate the payload. Its region display remains labelled as based on untrusted manifest settings. A displayed range is not proof of successful extraction.

## 7. Closing line and likely questions

*Finish the frame lookup and hand back to the team, or use this once during the all-member wrap-up.*

> “These demonstrations show both successful verification and its limits: modified signed data or incorrect inputs can fail, while changes outside the payload can still pass. Video uses the same verification approach, with lossless output and no source audio.”

| Question | Short answer |
| --- | --- |
| Why does message corruption report SIGNATURE_INVALID rather than TAMPERED? | The stored message is signed. Its changed bytes fail the signature check before the later hash check. |
| Does failure prove an attacker modified the file? | No. Damage or the wrong receiver inputs can also cause failure. |
| What is the manifest? | The companion file containing extraction settings. It is initially untrusted; relevant settings are cross-checked against the signed record. |
| Why can an edited image still be AUTHENTIC? | We authenticate the embedded payload and signed settings, not every cover byte. |
| Is a secret-derived start encryption? | No. It conceals the position; AES-GCM is the separate encryption feature. |
| Why does the wrong-key action keep the correct key in the field? | That establishes an authentic baseline. The action substitutes the wrong key for the second check. |
| Why FFV1? | It is lossless, preserving the sample values that carry the bits when encoding the output. |
| Why no soundtrack? | The chosen video-writing workflow handles frames. Keeping source audio requires additional audio muxing and compatibility/timing checks, which were outside the implemented scope. |
| Does frame lookup prove the message exists? | No. It calculates a region from supplied settings. Verify extracts and authenticates the package. |
| Did you personally build everything you presented? | Describe only your actual implementation, integration, testing or documentation work. Presenting a feature does not establish authorship. |

## 8. When the professor supplies a different payload

1. Your teammates protect that new text/file using the agreed original covers. For your video, use **Typed text** or **A file (text, image, audio or any other)** with **Choose payload file...**, as appropriate. A file payload is embedded as bytes; its format need not be a supported cover format.
2. Check capacity, including package overhead. Increase depth only within the supported range and explain the trade-off if necessary. A fixed cover cannot hold an arbitrarily large payload. Do not silently truncate or alter the supplied content.
3. Use each new protected output and its new manifest. Keep the matching public key and actual required secrets. Do not use a prepared fixture and claim it contains the replacement payload.
4. Run the same five attack actions on the new baseline files. The audio must use a derived start for the wrong-secret action. Message corruption needs a non-empty stored message; outside-payload editing needs sufficient unused samples.
5. Verify the new video and show the supplied payload recovered. For a file payload, use the applicable preview and **Save recovered payload...**; not every file type has an inline preview.
6. Locate the new video's frames again. A new nonce, package length or settings can change the derived start and occupied range.

The app generates the new hash, record, signature and manifest. You do not manually edit those. If the professor instead modifies an already protected file, verify it against its original matching manifest and trusted public key as a tampering test.

## 9. If something goes wrong during rehearsal or presentation

| Problem | Action and honest explanation |
| --- | --- |
| Before-verdict is not AUTHENTIC | Check original protected file, matching manifest, correct public key and any required secrets in Verify. Do not continue presenting that as a valid baseline. |
| Wrong-secret action refuses to run | Check that the audio uses HMAC mode. If no alternative location can be found, report the limitation; use the known HMAC fixture only with a clear fallback announcement. |
| Outside-payload action refuses | There may be insufficient outside space. Use a suitable newly protected output/settings if time permits, or disclose switching to the prepared image fixture. |
| Repetition or encryption settings differ | Read the actual settings and result. Targeted message/signature actions modify the logical envelope; these are different from Unaisah's controlled one-copy/two-copy storage-damage tests. Do not assume repetition makes every attack recoverable. |
| Video capacity fails | Use the displayed capacity to select valid depth/settings. If the supplied payload still cannot fit, state that limit. |
| Newly created video fails verification | Recheck its own manifest, public key and start secret. Do not pair it with the prepared video's manifest. |
| Video playback fails but verification succeeds | State separately that extraction/authentication succeeded and local playback failed. Do not claim visible playback. |
| Live video operation cannot complete | Announce a prepared fallback. Use `video-positive.mkv`, its own manifest, `sender-public.pem` and `t07-public-demo-start`. Verify it, play it and locate its frames. This demonstrates the prepared output; it does not prove the failed live protection or contain a new professor-supplied payload. |

**Fallback sentence:**

> “I am switching to our prepared sample to demonstrate the remaining workflow. This sample was generated in advance.”

## 10. Final rehearsal checklist

- [ ] I know whether I am using live teammate outputs or prepared fixtures.
- [ ] My image/audio baselines verify successfully with the intended inputs.
- [ ] I can run all five attacks and explain the actual before/after results.
- [ ] I keep correct inputs in Attack Lab for wrong-key and wrong-secret actions.
- [ ] I can export the current attack log.
- [ ] I can protect a video into a fresh `.mkv` output and find its manifest.
- [ ] I can select the matching public key and recover the exact video payload.
- [ ] I can play the output and locate the claimed payload-frame range.
- [ ] I can explain outside-payload edits, external public-key trust, omitted audio and lossy-conversion fragility.
- [ ] I have rehearsed with a replacement payload and know the capacity limits.
- [ ] I have measured my complete segment, including file selection and processing.

These boxes are intentionally unchecked. The full explanations are in the [beginner study guide](demo_study_guide.md), especially sections 6, 8–10 and 12–18. Prepared-file details are in the [sample bundle guide](sample_bundle.md). This script follows the adopted teammate PDF's topic allocation with corrected actions; it does not replace the other presenters' sections or claim that their transfer/rehearsal occurred.
