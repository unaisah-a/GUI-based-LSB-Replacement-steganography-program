# Demonstration Plan

Target duration: **25 minutes**. Every item the brief requires appears below with the
tab it is shown in and the time it should take.

Two things to prepare and one habit to keep.

**Prepare:** generate the demo key pair from the *Keys* menu before starting, and have
a PNG, a WAV and a short lossless MKV ready in a folder. Create two folders on the
desktop named `party_a` and `party_b` — the transfer is shown physically, not
described.

**Habit:** whenever a verdict appears, read the caveat next to it out loud. The whole
argument of this project is that the application says what it can establish and no
more, and the caveats are where that shows.

---

## Timeline

| Time | Segment | Tab |
|---|---|---|
| 0–3 | Architecture and security design | — |
| 3–7 | Image positive case, A to B | Protect, Verify |
| 7–10 | Image attack: the two kinds of failure | Attack Lab |
| 10–15 | Audio positive case, and depth distortion | Protect |
| 15–18 | Audio negative case | Attack Lab |
| 18–21 | Signature and start-location security | Verify, Attack Lab |
| 21–23 | The innovation: robustness, video, size preservation | Protect, Video |
| 23–25 | Limitations and conclusion | — |

---

## 0–3 min · Architecture and security design

One diagram, three sentences, no code.

Say:

1. **The layering.** Utilities, stego, crypto, verification, GUI. The stego layer
   carries opaque bytes — no keys, no hashing, no verdicts. Everything cryptographic
   sits above it, which is why the same crypto works unchanged for three media.
2. **What is signed.** A canonical-JSON verification record — media ID, timestamp,
   nonce, SHA-256 of the message, depth, start method — plus the message itself, signed
   together with RSA-3072 PSS. Encrypt-then-sign when confidentiality is on.
3. **What is published.** A companion manifest beside the file, carrying the non-secret
   parameters the receiver needs to *find* the payload. It is unsigned, and it does not
   need to be: every field it publishes is also inside the signed record, so any edit
   is detectable.

Then name the trust boundary explicitly: **nothing extracted from a medium is believed
until the signature verifies.** That single rule explains the order of operations, and
the rest of the demonstration is that order playing out.

Reference: [`architecture.md`](architecture.md).

---

## 3–7 min · Image positive case, party A to party B

This is the brief's core requirement, so do it slowly and in full.

**Protect tab.**

1. Drag the PNG onto the drop zone. The media type, container and size appear —
   detected from **content**, not extension. Mention that a `.png` file that is really
   a BMP is handled correctly.
2. Paste the **short message** — one Learning Objective. Point at the capacity read-out
   updating as you type: the exact signed payload length, the capacity at the current
   depth, the percentage used.
3. Move the **LSB depth slider** through 1 to 8 and let the read-out move with it. This
   is the capacity/distortion trade-off made visible.
4. Set the start mode to **derived from a secret** and type one. Say what it does:
   the position is computed by HMAC from the secret plus the published parameters, so
   an attacker who knows the depth still cannot read the payload by scanning from zero.
5. Protect. Note the output path chosen beside the cover, and the reminder listing
   **what still has to be shared out of band**.
6. Read the quality panel: MSE, PSNR, largest sample change, and "within the depth
   bound".

**The transfer.** Copy exactly three files from `party_a` to `party_b`: the stego PNG,
its `.manifest.json`, and the public key. Say the private key stays behind and the
secret is spoken, not sent.

**Verify tab, working out of `party_b`.**

7. Drag the received file. Supply the public key and the secret. Verify.
8. `AUTHENTIC`, with the recovered message shown as **inert text**. Say that recovered
   content is never executed and never handed to the operating system to open.
9. Read the scope notice aloud. This is the most important sentence in the
   demonstration.

Then repeat quickly with the **long message** (the Project Overview paragraph) and the
**custom message** with encryption on, to cover all three required sizes. Then switch
the payload to **A file** and protect a small PNG or WAV. On the Verify tab the
recovered image is shown, or the recovered audio played, inside the application, and
**Save recovered payload...** writes it out under its original name. For the
encrypted one, point out that the passphrase is a *second* out-of-band secret, separate
from the start secret.

---

## 7–10 min · Image attack: two kinds of failure

**Attack Lab.** Load the stego PNG and its manifest.

1. **Corrupt the message.** Observed: `SIGNATURE_INVALID`. Explain why this is *not*
   `TAMPERED`: the signature covers the message as well as the record, so an attacker
   who can only change bytes cannot reach `TAMPERED`.
2. **Substitute the message and re-sign.** Observed: `TAMPERED` against the attacker's
   key, `SIGNATURE_INVALID` against the real sender's. This is the point — reaching
   `TAMPERED` requires a signing key, and the attack fails against a receiver who holds
   the right one.
3. **Modify pixels inside the payload.** Observed: `SIGNATURE_INVALID`. The attack
   inverts the last 64 samples of the payload region, which carry the signature, so the
   payload is still found and the signature check is what fails.
4. **Corrupt the length header.** Observed: `PAYLOAD_MISSING`. One sample changes, in
   the 4-byte length field that frames the payload. That field is stego framing, not
   part of the signed envelope, so the verifier never reaches the signature. Read the
   reason aloud: a payload was expected at this location, its length field is
   unusable, and this is *consistent with* modification. It does not claim
   modification, because a wrong secret or depth produces the same evidence.
5. **Modify pixels outside the payload.** Observed: `AUTHENTIC`. Pause here. The image
   has visibly changed and the verdict is still `AUTHENTIC`, because what was
   authenticated is the signed message, not the whole file. Say it as a limitation, not
   an excuse.
6. **Re-encode as lossy JPEG.** Observed: `CANNOT_VERIFY` — the verifier refuses lossy
   input by design, which is why the supported formats are lossless.

Each run shows *expected* beside *observed*. Point at the pairing: the attacks declare
what they predict, so a surprise is visible rather than glossed over.

---

## 10–15 min · Audio positive case and depth distortion

**Protect tab** with the WAV. Same workflow, and say so — the workflow is identical
because the crypto layer never learned what medium it is working on.

1. Protect at **depth 1**. Play cover and stego. Indistinguishable.
2. Protect the same message at **depth 8**. Play it. The distortion is audible.
3. Show the quality figures side by side: PSNR falls, largest sample change rises to
   255. Note that at depth 8 the whole low byte is replaced, so "least significant bit"
   has stopped meaning much.
4. Say plainly that the application recommends no depth. The right answer depends on
   the cover, so the trade-off is presented rather than decided.

Then verify it in the Verify tab to close the positive case for audio.

---

## 15–18 min · Audio negative case

**Attack Lab** on the stego WAV.

1. **Corrupt the verification record.** Observed: `SIGNATURE_INVALID`. Mention the
   detail: the attack changes one hex digit of the signed nonce, keeping the record
   both well-formed and the same length. A blind byte flip would break JSON parsing and
   give `CANNOT_VERIFY`, and a length-changing edit would be rejected during extraction
   — neither would demonstrate the signature.
2. **Corrupt the signature.** Observed: `SIGNATURE_INVALID`.
3. **Scale the amplitude** — a volume adjustment, the most ordinary thing anyone does
   to audio. Payload destroyed. Every sample changed at once.
4. **Corrupt samples outside the payload.** `AUTHENTIC` again, on the second medium.

---

## 18–21 min · Signature and start-location security

Three demonstrations, all in aid of one point: the parameters an attacker can see do
not let them forge anything.

1. **Wrong public key.** Verify the good file with an unrelated key. `SIGNATURE_INVALID`.
2. **Wrong start secret.** Verify with a wrong secret. Not `AUTHENTIC` — and note what
   the application does *not* say. It does not claim `WRONG_START_LOCATION`, because a
   wrong secret, a wrong depth, an absent payload and corruption produce
   indistinguishable bit streams. The verdict carries a note saying exactly that.
   Reserve `WRONG_START_LOCATION` for the one provable case.
3. **Tamper with the manifest, twice.**
   - Edit `message_length`: extraction still works and the cross-check against the
     signed record catches it → `TAMPERED`.
   - Edit `media_id`: it feeds the derivation, so the receiver looks in the wrong place
     and finds nothing → `PAYLOAD_MISSING`.

   Both are detections, by two different mechanisms. That is why the manifest does not
   need to be signed.

**Say this before anyone asks: authenticity here is payload-scoped.** A pixel flipped
*before* the payload region, or bytes changed in a WAV *outside* the payload, still
verify as `AUTHENTIC`. That is by design. The signature covers the verification record
and the message, not every sample of the file, and an LSB scheme has no way to sign
the samples that carry the signature. The result says so itself. Its notes carry the
scope notice ("It does not mean every part of the cover media is unchanged"). When the
file's SHA-256 no longer matches the digest in the manifest, a second note says the file
is not byte-for-byte the one that was protected, without changing the verdict, because
the manifest is unsigned.

**If asked why `TAMPERED` is never produced by modifying the media:** `TAMPERED` means
the signature verified but the manifest disagrees with the signed record. Any change
to the media that reaches the signed bytes fails the signature first. So without the
signing key an attacker can only produce `SIGNATURE_INVALID`, or a payload that cannot
be found or read.

---

## 21–23 min · The innovation and the extensions

State the innovation clearly, with its benefit and its limits. The brief asks for
exactly that.

**Innovation: the keyed start location bound to the signed record.** The position is
derived by HMAC from the secret plus the media ID, media type, nonce, depth and payload
length — and every one of those inputs is inside the signed record. So an attacker
cannot move the payload without breaking the signature, and cannot find it without the
secret. *Benefit:* concealment that survives an attacker who knows the algorithm and
the depth. *Limitation:* it is concealment, not encryption. It provides no
confidentiality on its own, and the interface says so.

Then, briefly, the extensions:

**Robustness.** Protect the same file twice, once with repetition coding on. Run *flip
random payload bits* at 0.5 % against both. Uncoded: fails. Coded: `AUTHENTIC`, and the
verdict includes a note saying how many bits were **repaired**. Then push the rate to
40 % and show it failing — there is no threshold, only a probability, and the honest
version of this demonstration includes the point where it stops working. Note the exact
cost: factor 3 triples the payload.

**Video.** Open the **Video** tab with a protected clip and its manifest. Enter the
secret and press *Locate the payload frames*. It reports which frames carry the payload
— a handful out of the whole clip — because video is treated as one flat sample domain
and the same keyed derivation picks the frame. Step to a carrier frame and then to a
clean one, with the cover as reference, and show the amplified difference: change in
one, nothing in the other.

Then run **re-encode with a lossy codec** in the Attack Lab and note that this is not
an exotic attack. It is what uploading or editing a clip does by default. That is why
the output codec is fixed to lossless FFV1 rather than offered as a choice.

**File-size preservation.** Tick *Match the cover's file size where possible* on a PNG.
Show the outcome row: matched, or not matched with the reason. Open
[`size_preservation.md`](../evidence/results/size_preservation.md) and show all three
measured outcomes — free, matched by padding, impossible. Say that the failures are
part of the result, and that a padding chunk may make a file *more* conspicuous than a
size mismatch would.

---

## 23–25 min · Limitations and conclusion

Do not rush this and do not soften it. Read four:

1. **`AUTHENTIC` does not mean the file is unchanged.** Only the payload region is
   authenticated. Demonstrated twice, in segments 7–10 and 15–18.
2. **`AUTHENTIC` does not reject a replay.** A timestamp and a nonce record when a file
   was protected and make it unique. They do not detect resending. A freshness check
   would need receiver-side state, and there is none.
3. **Extraction failures cannot be told apart.** Hence `CANNOT_VERIFY` and the notice
   attached to it.
4. **LSB replacement is fragile.** Any lossy re-encode, resample or resize destroys the
   payload. For video that is the default outcome, not an attack.

Close on the actual claim: the application establishes that a specific signed message
came from the holder of a specific private key and has not changed, and it tells the
user precisely what that does and does not cover.

---

## Contingencies

| If | Then |
|---|---|
| Playback fails on the demo machine | The preview says "Playback is not available on this machine" instead of offering a Play button that does nothing. Everything else keeps working. Use the quality figures (PSNR, largest sample change) for audio, and the Steganalysis difference image and the Video tab's per-frame view for image and video. **Test playback on the actual lab machine beforehand**: play `samples/audio/stego/stego.wav` in the Protect tab, and a recovered WAV payload in the Verify tab. |
| A file picker is slow | Use drag and drop; both routes emit the same signal. |
| An output path is occupied | The application refuses rather than overwriting. Change the name — this is the safety behaviour, so say so instead of hiding it. |
| A video encode is slow | Use a shorter clip. Video embedding re-encodes and verifies its own output, which is deliberate and costs a pass. |
| Time runs short | Drop the size-preservation item first, then the steganalysis indicators. Never drop the limitations segment. |

---

## Checklist against the brief

| Requirement | Segment |
|---|---|
| Party A to party B, downloaded to their own folder, extracted and verified | 3–7 |
| Companion manifest shown as part of the transfer | 3–7, 18–21 |
| Short message from a Learning Objective | 3–7 |
| Longer message from the Project Overview | 3–7 |
| Custom payload addressing confidentiality and integrity | 3–7 |
| Capacity checks | 3–7 |
| GUI-selectable LSB depth 1 to 8 | 3–7, 10–15 |
| Start-location selection and derivation explained | 0–3, 3–7, 18–21 |
| Receiver recovery for image **and** audio | 3–7, 10–15 |
| Cover and stego displayed or played, before and after | 3–7, 10–15 |
| Recovered payload displayed, never executed | 3–7 |
| Payload types: typed text, text file, image, audio | 3–7 |
| Two positive cases minimum | 3–7, 10–15 |
| Three negative cases minimum | 7–10, 15–18, 18–21 |
| Insufficient capacity as input validation | 3–7 |
| Innovation identified, with benefit and limitations | 21–23 |
| Limitations stated honestly | 23–25 |
