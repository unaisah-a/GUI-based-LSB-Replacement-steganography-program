# Limitations

Every claim this application makes has a boundary. This document states them, and
where the code enforces or displays a boundary it says where.

The rule followed throughout is that a limitation demonstrated is better than a
limitation omitted. Several of the items below have tests that assert the limitation
holds, rather than tests that avoid it.

---

## 1. What `AUTHENTIC` does and does not mean

`AUTHENTIC` means: the payload signature verified against the supplied public key,
and the message recovered from the envelope matches the SHA-256 digest inside the
signed record.

It does **not** mean:

**The cover is unchanged.** Only the payload region is authenticated. Modifying
samples outside it leaves the verdict `AUTHENTIC`. This is demonstrated deliberately
by the `image.outside`, `audio.outside` and `video.outside` attacks, and the
resulting notes say so. It is not a bug: authenticating a signed message is a
different goal from authenticating a whole file, and the application is honest about
which one it does.

**The file is fresh.** A timestamp and a nonce record *when* a file was protected and
make each file unique. They do not reject a replay. An attacker who resends an
old, genuinely signed file gets `AUTHENTIC`, correctly — the file *is* authentic;
it is simply old. Rejecting a replay needs a freshness check this application does
not implement: a receiver-side record of nonces already seen, or a challenge from the
receiver. None is claimed.

**The message is true.** The signature establishes who wrote the message and that it
has not changed. It says nothing about whether the contents are accurate.

The interface states this verbatim through
`app.utils.constants.AUTHENTIC_SCOPE_NOTICE`, so the wording cannot drift between
the code, the tests and this document.

---

## 2. Extraction failures cannot be told apart

A wrong LSB depth, a wrong start location, a wrong start secret, an absent payload
and sample corruption all produce a bit stream with no distinguishing feature. There
is no way to recover the cause from the result.

The consequence is deliberate and visible in the verdict vocabulary:

- `WRONG_START_LOCATION` is used **only** when the failure is provable — when the
  declared location does not fit the medium at all.
- A missing start secret is reported as `CANNOT_VERIFY` with a message saying the
  secret is required, not as `WRONG_START_LOCATION`.
- A wrong secret is reported as `PAYLOAD_MISSING` or `CANNOT_VERIFY`, with
  `constants.AMBIGUOUS_FAILURE_NOTICE` attached.
- The 4-byte length header in front of the envelope is stego framing and is **not
  signed**. A single flipped bit in it stops extraction before the signature is
  reached, so the verdict is `PAYLOAD_MISSING`, not `SIGNATURE_INVALID`. The reason
  says that the manifest declared a payload of a given length at that location, that
  the length field read there is unusable, and by how many bits it differs. It says
  this is consistent with modification, and equally with a wrong secret or depth. It
  does not claim either. The Attack Lab's *Corrupt the length header* shows this case
  on purpose.

Labelling every extraction failure as a wrong start location would be a stronger
claim than the evidence supports.

A related consequence: a mismatched read can decode a plausible length and return
wrong bytes **with no error at all**. Nothing in the stego layer's return value should
ever be treated as verified. The envelope magic and the signature are what establish
that a payload is real.

---

## 3. Concealment is not confidentiality

A derived start location makes the payload's position unpredictable to anyone without
the secret. That is concealment, and it is genuinely useful: it means an attacker who
knows the depth still cannot read the payload by scanning from offset zero.

It is not encryption. It provides no confidentiality on its own, and this is stated in
the interface through `constants.START_LOCATION_NOTICE`. Confidentiality requires the
optional AES-256-GCM path with a separately shared passphrase.

Nor does concealment survive analysis with the secret. An attacker who obtains the
start secret obtains the position, because the derivation is deterministic — which is
the whole point, since the receiver needs it too.

---

## 4. Fragility of LSB replacement

The payload does not survive anything that changes sample values. Specifically:

| Operation | Payload | Notes |
|---|---|---|
| Lossy image recompression (JPEG) | destroyed | Demonstrated by `image.lossy` |
| Lossy video re-encode | destroyed | Demonstrated by `video.lossy` |
| Audio amplitude scaling | destroyed | Every sample changes at once |
| Audio resampling | destroyed | Sample positions no longer correspond |
| Audio truncation | destroyed if it reaches the region | |
| Dropping video frames | unfindable | Bytes survive; the domain and positions shift |
| Cropping or resizing an image | destroyed | Sample count changes |
| Any format conversion | usually destroyed | |

For video this is not an exotic risk but the **default**. Uploading a clip, sharing it
through a messaging app, or opening it in an editor re-encodes it. Nothing hostile has
to happen for the payload to be gone. That is why the output codec is fixed to FFV1
rather than offered as a choice.

Supported containers are therefore restricted to lossless ones: PNG and BMP for
images, 16-bit PCM WAV for audio, FFV1 in Matroska for video. Lossy input is refused
with a message naming the format rather than accepted and silently broken.

---

## 5. Limits of the error-correcting code

Repetition coding at factor *n* repairs damage that leaves a majority of copies of
each bit intact. What it does and does not do:

**It helps against** scattered bit damage — the kind transmission or storage
corruption produces. Measured: at a 0.5 % bit error rate, a payload that is destroyed
without coding is fully repaired at factor 3.

**It does not help against** anything that changes every sample at once, because every
copy is damaged simultaneously. Amplitude scaling, resampling and lossy
recompression are all in this category, and the test suite asserts that coding does
not save them.

**It has no threshold, only a probability.** There is no error rate below which
recovery is guaranteed; there is a residual-error probability per bit that falls as
the factor rises. At a 2 % error rate factor 3 fails and factor 5 succeeds on the same
damage — but "succeeds" here means "succeeded on this measured case", not "will
always succeed".

**It costs capacity exactly.** Factor 3 triples the embedded payload, so it triples
the capacity required. The capacity read-out and the `CapacityError` message both
name this so it is not discovered by surprise.

**It does not repair a forgery.** Coding fixes transmission damage. A deliberately
constructed, internally consistent modification is not damage, and majority voting
will faithfully reproduce it.

---

## 6. Distortion rises with depth

Replacing the low *n* bits can move a sample by up to `2ⁿ − 1`. At depth 8 the entire
low byte is replaced, so a sample can change by up to 255 — the "least significant
bit" framing stops being meaningful well before that.

For audio the effect is audible at higher depths, and the application does not hide
it: the Protect tab reports PSNR, SNR and the largest per-sample change, and checks
the observed maximum against the theoretical bound for the chosen depth.

Nothing in the application recommends a depth. The trade-off between capacity and
distortion is presented and left to the user, because the right answer depends on the
cover.

---

## 7. Media-specific limits

### Image

- PNG and BMP only. Grayscale BMP is refused on load, because BMP stores 8-bit
  grayscale as an indexed-colour palette image.
- Alpha-channel samples are excluded from the embeddable domain, so an RGBA image has
  the same capacity as its RGB equivalent. Writing into alpha would be visible in any
  compositing operation.
- PNG file size changes even though the pixels are lossless, because altering low bits
  changes how well the data deflates. Lossless does not mean fixed-size.

### Audio

- 16-bit PCM WAV only. Other subtypes either apply lossy compression or use a sample
  width this layer does not handle, and are refused with a message saying which.
- Every channel carries payload bits; unlike an image's alpha channel there is nothing
  to exclude.

### Video

- The container's declared frame count must match what actually decodes. Containers
  routinely disagree, so `embed_video` counts the frames it reads and refuses rather
  than producing a file whose payload the receiver cannot locate.
- Output is always re-encoded, so a stego clip is **not** a near-copy of its cover and
  comparing their file sizes is not meaningful.
- Extraction decodes the clip twice: once for the length header, once for the payload.
  Seeking to the second range would be faster but is not reliable across containers,
  and a wrong seek would be indistinguishable from a missing payload.
- H.264 is unavailable in the bundled OpenCV build on many installations, including
  this one, because the OpenH264 library is not shipped. The lossy attack therefore
  tries a list of codecs and reports the one it used; Motion JPEG is the usual choice
  and is lossy in the same way.

---

## 8. Steganalysis indicators are not detectors

None of the indicators establishes that a file does or does not contain embedded data.
The module returns no verdict and no confidence, and the tab shows none.

- The two chi-square indicators report a goodness-of-fit **p-value** (Westfeld and
  Pfitzmann's pair-of-values attack). Replacement pushes it toward 1, so a threshold
  flags values at or above it. The p-value is the probability of counts this uneven
  *if* the pairs were even; it is **not** the probability that the file holds data.
  The synthetic cover in `samples/` already scores about 0.997 in its green channel
  with nothing embedded.
- Each figure is computed over the whole image. A small payload at a secret offset
  changes too few samples to move it: the committed sample stego image carries an
  814-byte payload and its p-values barely differ from the cover's.
- Natural media routinely produces values that look suspicious. A photograph's low
  bits are close to random already.
- A short or low-entropy payload routinely produces values that look ordinary.
- Where there was not enough data for a number to mean anything, `insufficient_sample`
  is set and the tab prints "insufficient sample" rather than a precise-looking figure
  computed from nothing.
- A threshold comparison, when a caller asks for one, records the comparison the
  caller requested. It is not a detection.

Video is not analysed at all; see [`architecture.md`](architecture.md) §10 for why,
and use the Video tab's per-frame difference instead.

---

## 9. Limits of the manifest

The manifest is unsigned and must be, because it publishes the parameters needed to
*locate* the payload before anything can be verified.

- It can be edited freely. Every edit is detectable, because every field is also in the
  signed record — but detection happens by one of two different routes depending on
  the field, and one of them (`PAYLOAD_MISSING`) does not identify *what* was edited.
- Losing the manifest makes verification impossible in practice. The verdict is
  `CANNOT_VERIFY`.
- The recorded SHA-256 of the stego file is a convenience for spotting a truncated
  download. It is **not** an integrity guarantee: anyone who modifies the file can
  recompute it.
- Pairing is by full file name, extension included, so a manifest cannot be silently
  paired with a different file that happens to share a stem. It can still be paired
  with the wrong file deliberately, which produces `PAYLOAD_MISSING` or
  `CANNOT_VERIFY`.
- **The manifest gives the hidden payload away.** The `.manifest.json` travels next to
  the stego file, in plain JSON, and says outright that the file carries a payload.
  Anyone who intercepts the pair can read the LSB depth (`lsb_depth`), the payload's
  exact size (`envelope_length`) and how its position was chosen (`start_method`),
  along with the media ID and nonce. The only thing it keeps hidden is *where* the
  payload starts, and only for the derived method: that position comes from the
  start secret, which is never in the manifest. For a manually chosen position the
  manifest publishes the position itself. So the manifest makes this a tool for
  *verifying* media, not for hiding that a message exists: the steganography conceals
  where the payload sits, but not that there is one.

---

## 10. Key management

- The demo private key is stored **unencrypted** (PKCS#8, no passphrase) so the
  demonstration can run unattended. This is stated in the interface through
  `constants.DEMO_KEY_NOTICE` and must never be treated as an acceptable arrangement
  for anything real.
- There is no PKI, no certificate, and no revocation. A public key is trusted because
  the receiver obtained it out of band; nothing in the application establishes that it
  belongs to who it claims to.
- Keys generated by this application are RSA-3072. Verification accepts any size the
  underlying library accepts, including 2048-bit, so an older demo key still verifies.
- Both shared secrets — the start-location secret and the message passphrase — are
  transferred out of band by definition. The application never writes either to any
  file, and the end-to-end tests assert that.

---

## 11. File-size preservation is per file, not general

WAV/BMP sample storage has fixed width, but whole-file size can change when the
writer removes metadata/padding or normalises headers. Their optional matching
result is measured without adjustment. PNG matching depends on the individual
image; video matching is unsupported. The Protect tab reports media size changes
and separate manifest bytes. See the [T06 measurements](../evidence/t06/README.md).

Video output uses constant-rate FFV1 and omits source audio. Invalid/missing rates,
odd dimensions and decoded timestamps departing by more than 2 ms from the declared
constant rate are rejected. Output rate and decoded frame count are checked again
before successful protection. Timestamp accuracy depends on the OpenCV backend;
this is not a claim to preserve arbitrary variable-rate video or container metadata.

When it does work by padding, the resulting file contains an ancillary PNG chunk that
would not normally be there. That may make it *more* conspicuous to an analyst than a
size mismatch would. Matching the size is not automatically the better choice, and the
tooltip says so.

---

## 12. Reversibility is not implemented

LSB replacement overwrites the original low bits, so the cover cannot be restored from
the stego file alone. Restoring it would require storing the displaced bits somewhere,
which means either a second sidecar file or a reversible scheme such as
histogram-shifting — neither of which this application implements. Nothing here claims
the original media can be recovered.

The *cover* is always left byte-for-byte unchanged on disk, which is a different and
weaker guarantee: embedding writes a new file and refuses to write over its input.

Both routes were considered and rejected, for different reasons.

**The displaced-bits sidecar was rejected as a claim that would not survive scrutiny.**
Writing the overwritten low bits into a second sidecar does restore the cover exactly,
and it is not difficult to build. But a receiver who must be given a file containing the
exact bits that were overwritten could have been given the original cover instead: the
two carry almost the same information, and the sidecar is a backup wearing the
vocabulary of reversible data hiding. Shipping it under the heading *reversibility*
would be the single overstated claim in an application built to avoid exactly that, so
it is not shipped.

**Histogram-shifting was rejected on scope, not on merit.** It is genuinely reversible
in the sense the literature means, recovering the cover from the stego object alone. It
is also a different embedding scheme: it shares none of the bit and capacity primitives
this project is built on, carries far less payload at comparable distortion, and would
stand beside the required LSB implementation rather than extend it. The planning reference (docs/planning_reference.md §11) asks for
it as an optional innovation and explicitly not as a replacement for the LSB spine. The
three innovations that were built — repetition coding with majority voting, video
embedding, and the file-size preservation experiments — reuse the existing layers and
are covered by tests, which is a better use of the same effort.

The honest summary is that this application hides data in a way that destroys what it
overwrites, and says so.

---

## 13. Testing boundaries

- Property-based tests generate images up to 64×64, audio up to a few seconds, and
  clips of eight 32×24 frames. Behaviour on a 4K image or a feature-length video is
  extrapolated from the arithmetic, not measured.
- Video codec availability is a property of the installed FFmpeg build. The tests
  require a working FFV1 encoder and would fail without one, which is the correct
  outcome — the application cannot function without a lossless codec.
- The scrypt cost is reduced in the test suite so it does not dominate the runtime. The
  production cost (`N = 2¹⁵`) is asserted separately.
- GUI tests run under Qt's `offscreen` platform. Playback through QtMultimedia depends
  on platform codecs and is not exercised; the widget degrades to a message when a
  player cannot be created, and that path is what the tests cover.

## T03 publication and input limits

Bundle rollback covers caught errors, not power failure or a killed process, and
two files cannot be published atomically as a pair. Do not publish concurrently to
the same destinations. If rollback itself fails, the error identifies retained
backup files for manual recovery. Source/output/manifest aliases and symbolic-link
output destinations are rejected. On POSIX, no-overwrite publication requires a
filesystem supporting hard links; an unsupported destination fails safely.

This build accepts manifests up to 1 MiB and bounds scrypt to estimated memory
`128*N*r <= 128 MiB` and work `N*r*p <= 2**22`. These are local resource limits;
they may reject an otherwise well-signed payload using unusually expensive costs.
The application's normal parameters are unchanged. They are not guarantees about
exact process memory use or elapsed time.
