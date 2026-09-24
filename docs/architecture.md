# Architecture

How the application is put together, and why. This describes what the code does
now; where a design choice had a plausible alternative, the alternative and the
reason for rejecting it are recorded next to it.

---

## 1. The shape of the system

Six layers, each depending only on the ones below it.

```text
┌──────────────────────────────────────────────────────────────┐
│  app/gui/            Protect · Verify · Attack Lab ·         │
│                      Video                                  │
├──────────────────────────────────────────────────────────────┤
│  app/verification/   protect · verifier · verdicts ·         │
│                      media_compare                           │
├──────────────────────────────────────────────────────────────┤
│  app/attacks/  app/analysis/  app/robustness/                │
├──────────────────────────────────────────────────────────────┤
│  app/crypto/         envelope · signatures · encryption ·    │
│                      manifest · start_location · key_manager │
├──────────────────────────────────────────────────────────────┤
│  app/stego/          media (facade) · image_stego ·          │
│                      audio_stego · video_stego ·             │
│                      bit_utils · capacity · paths            │
├──────────────────────────────────────────────────────────────┤
│  app/utils/          constants · file_utils · media_utils ·  │
│                      logging_utils                           │
└──────────────────────────────────────────────────────────────┘
```

Two rules hold throughout, and most of the design follows from them.

**The stego layer carries opaque bytes.** It hashes nothing, signs nothing,
verifies nothing, and holds no key material. It takes a `bytes` payload, a depth
and a start location, and writes bits. Everything cryptographic is above it.

**The layers below the GUI hold no Qt import.** Every workflow is therefore
testable without a window, and the GUI contains no steganography and no
cryptography of its own — only argument collection and rendering.

---

## 2. The payload envelope

One format for all three media. The magic and version live **inside the payload**,
not in the stego framing.

```text
Envelope
┌────────────┬─────────┬───────┬──────────┬───────────┬─────────────┐
│ b"INF2005E"│ version │ flags │ 3 × u32  │  record   │   message   │ signature
│  8 bytes   │  1 byte │ 1 byte│ lengths  │   (JSON)  │             │
└────────────┴─────────┴───────┴──────────┴───────────┴─────────────┘
```

The stego layer beneath it writes only a bare 4-byte big-endian length header
followed by these bytes. Both media do exactly that, and neither knows what the
bytes mean.

The length header is outside the signature. It cannot be inside it: the receiver
needs the length to know how many bytes to read before it has anything to verify.
Damage to it is reported as `PAYLOAD_MISSING`, with a reason stating that a payload
was expected there and its length field is unusable. See
[`limitations.md`](limitations.md) §2.

### Why the magic is not in the stego framing

The audio layer originally wrote its own `b"INF2005"` marker into the medium and
the image layer wrote none. Two options were considered:

*Move the magic down into the stego framing for both media.* Rejected. It would
have made the stego layer responsible for recognising a payload, which is the
"opaque bytes" boundary the image layer's specification fixes (Requirement 4.5),
and it broke 55 existing image tests for no gain.

*Move the magic up into the envelope.* Chosen. Both media now get the same
"is there a payload here?" signal, the format is versioned in one place, and the
stego layer's contract is unchanged. The old audio marker was removed; anything
written by the earlier code is not readable by this build, which is acceptable for
a project with no deployed data.

### The verification record

Canonical JSON — sorted keys, no insignificant whitespace — so that the bytes
signed by the sender are reproducible byte-for-byte by the receiver. Fields:

| Field | Purpose |
|---|---|
| `media_id` | Binds the record to a named file, and feeds the start derivation |
| `media_type` | `image`, `audio` or `video`, detected from content |
| `timestamp` | UTC, when the file was protected |
| `nonce_hex` | 128 random bits, per file. Not secret; the receiver needs it |
| `message_hash` | SHA-256 of the plaintext message |
| `message_length` | Of the plaintext |
| `lsb_depth` | 1 to 8 |
| `start_method` | `manual` or `hmac_prf` |
| `start_location` | The chosen index for `manual`; **`null`** for `hmac_prf` |
| `encryption` | Cipher, KDF and its parameters, or `null` |
| `ecc` | Scheme and factor, or `null` |
| `metadata` | Team-defined extras |
| `version` | Envelope format version |

`start_location` is `null` for the derived method for a concrete reason and not out
of caution: the derivation consumes the envelope length, and the envelope cannot be
built until the record inside it is complete. A derived location does not exist yet
at signing time. A manual one is chosen by the user beforehand, so it is signed.

---

## 3. The stego layer

### One flat sample domain per medium

| Medium | Sample | Traversal order | Total samples |
|---|---|---|---|
| Image | one 8-bit channel value | row-major, then channel; alpha excluded | `h × w × embeddable_channels` |
| Audio | one 16-bit PCM sample | interleaved scalar order (`L0 R0 L1 R1 …`) | `frames × channels` |
| Video | one 8-bit BGR channel value | frame order, then row-major, then channel | `frames × h × w × 3` |

A start location indexes this domain. The encoded stream's bits are written
most-significant-bit first into the `lsb_depth` lowest bits of consecutive samples
from that index, never wrapping. There is **no realignment** after the 32-bit
length header, so at depths that do not divide 32 the first payload bit sits partway
through a sample — extraction reads the same continuous stream, so this is
consistent rather than merely tolerated.

### Signed audio samples

PCM samples are signed 16-bit integers and the shared bit helpers work on unsigned
values. The array is **reinterpreted** with `view(np.uint16)`, not converted: a view
preserves the two's-complement bit pattern, which is what LSB replacement must
operate on. `-1` is `0xFFFF`; clearing its three low bits gives `0xFFF8`, which is
`-8`. That is the correct result of replacing three low bits, and it is not what
signed arithmetic would naturally produce.

### Video: why one flat domain rather than selected frames

The obvious video design is to choose a set of carrier frames keyed by something the
receiver also knows. Rejected, for two reasons: it would have required the stego
layer to know about keys and nonces, breaking the boundary the other two media keep;
and it would have added manifest fields for something the existing machinery already
does.

Treating the clip as one continuous domain makes video fall out of the existing
design with no new concepts. The keyed derivation already scatters the payload to an
unpredictable position, which for video means an unpredictable *frame and offset
within it*. So "which frames carry the payload" is decided by the same secret that
decides where in an image the payload starts, and no separate mechanism was needed.

Frames are streamed one at a time in both directions, because a ten-second 1080p
clip is about 1.8 GB of raw samples.

### Video: losslessness is checked, not assumed

Output is always **FFV1 in Matroska**, whatever the cover was. FFV1 is
mathematically lossless and ships in the FFmpeg build bundled with
`opencv-python`, so no external binary is required. (An `ffmpeg`-based pipeline was
the alternative; it was rejected because it makes the application depend on a binary
that may not be installed.)

Two container properties are verified rather than trusted:

*Frame count.* The sample domain is measured in frames, so if a container reports a
count different from what actually decodes, the sender and receiver measure different
domains and derive different start locations — silently. `embed_video` counts the
frames it really reads and refuses to continue on a mismatch.

*The written file.* `embed_video` reads its own output back and confirms the payload
extracts identically before moving the file into place. A codec that quietly
requantised would otherwise produce a file that fails much later, at verification,
with nothing to point at. The extra decode pass is worth it.

---

## 4. Start-location derivation

```text
HMAC-SHA256(
    key   = secret,
    data  = "INF2005-START" ‖ version ‖ media_id ‖ media_type
            ‖ nonce ‖ lsb_depth ‖ envelope_length
)  →  reduced into [0, total_samples − required_samples]
```

Domain-separated with a fixed label and a scheme version, so a future scheme cannot
collide with locations derived by this one. The inputs are all published in the
manifest except the secret itself.

The derivation consumes the **embedded** length — the envelope after any
error-correcting code — because that is what actually sits on the medium. Both sides
compute it the same way: the manifest publishes the raw `envelope_length` and the
`ecc` parameters, and each side derives `encoded_length(envelope_length, ecc)`.

Keeping the raw length in the manifest rather than the encoded one is deliberate: the
raw length is what the cross-check against the signed record compares, and storing
the encoded length would have broken that comparison.

---

## 5. Cryptography

| Concern | Mechanism | Note |
|---|---|---|
| Integrity of the message | SHA-256 digest inside the signed record | |
| Authenticity | RSA-3072 PSS over `record ‖ message` | Verification accepts 2048-bit keys, so an older demo key still works |
| Confidentiality | AES-256-GCM, key from scrypt over a passphrase | Optional |
| Concealment | keyed start location | **Not** confidentiality |

**Encrypt then sign.** The signature covers the ciphertext, so a receiver with the
wrong passphrase still learns that the record is genuine — the verdict is
`CANNOT_VERIFY` with "the signature verified, so the record is genuine, but the
message could not be decrypted", not a bare decryption error. Sign-then-encrypt
would have hidden that distinction.

Decryption happens at step 8 of verification, *after* the signature check, which is
what makes a wrong signing key report `SIGNATURE_INVALID` rather than surfacing as a
decryption failure.

---

## 6. The companion manifest

A JSON sidecar at `<stego file>.manifest.json`, carrying the non-secret parameters a
receiver needs in order to locate the payload at all: media ID, media type, nonce,
depth, envelope length, start method and location, container format, ECC parameters,
and a SHA-256 of the stego file.

It is **not signed**, and it does not need to be. Every field it publishes is also
inside the signed record, so the verifier cross-checks the two after the signature
verifies. An attacker can edit the manifest freely; what they cannot do is make the
edit undetectable.

Which mechanism catches an edit depends on the field:

- fields that feed the derivation (`media_id`, `media_type`, `nonce`, `lsb_depth`,
  `envelope_length`, `start_location`) move where the receiver looks, so nothing is
  found → `PAYLOAD_MISSING`
- any other field leaves extraction working and the mismatch is caught by the
  cross-check → `TAMPERED`

Both are detections. The distinction matters only when choosing a field to
demonstrate one mechanism or the other.

The recorded digest lets a receiver notice a truncated download before spending time
on extraction. It is *not* an integrity guarantee — anyone who modifies the file can
recompute it. The signature is the guarantee.

---

## 7. Verification: order of operations

```text
 1. read and validate the manifest        (untrusted input)
 2. measure the medium                    (total sample count)
 3. resolve the start location
 4. extract the payload bytes             (opaque bytes out)
 4b. remove the error-correcting code     (before the signature: that is the point)
 5. parse the envelope                    (structure only)
 6. verify the signature                  ← nothing before this is trusted
 7. validate the record                   (now safe to interpret)
 8. decrypt, if the record says so
 9. recompute the message digest and compare
10. cross-check the manifest against the signed record
```

Step 6 is the trust boundary. Everything before it is attacker-controlled: the
manifest arrived alongside the file, and the extracted bytes came out of a medium
anyone could have modified. So steps 1 to 5 only ever *validate structure* and never
act on a claim.

Step 4b sits before the signature check because the code exists precisely to repair
damage that would otherwise make the signature fail.

### Failures are verdicts, not exceptions

`verify_media` returns a verdict for every outcome a receiver can encounter,
including a missing payload, a bad signature, a wrong passphrase and a tampered
manifest. It raises only for faults that are not about the file being verified — an
unreadable public key, or a programming error in the arguments. A verdict is
therefore always something to display, never something to catch.

| Verdict | Meaning |
|---|---|
| `AUTHENTIC` | Signature verified and the recovered message matches the signed digest |
| `TAMPERED` | Signature verified, but the message or the manifest disagrees with the record |
| `SIGNATURE_INVALID` | The signature did not verify against the supplied key |
| `PAYLOAD_MISSING` | Nothing readable was found at the resolved location |
| `WRONG_START_LOCATION` | Only when *provable*: the declared location does not fit this medium |
| `CANNOT_VERIFY` | The cause is genuinely uncertain |

`WRONG_START_LOCATION` is used sparingly on purpose. A wrong secret produces
indistinguishable bytes from an absent payload or from corruption, so it is reported
as `PAYLOAD_MISSING` or `CANNOT_VERIFY` with a note saying the cause cannot be
identified. Labelling every extraction failure as a wrong start location would be a
claim the evidence does not support.

---

## 8. Robustness: repetition coding

Optional. The whole signed envelope is repeated an odd number of times and recovered
by per-bit majority vote.

```text
encode(data, 3) = data ‖ data ‖ data       (whole interleaved copies)
```

Three decisions worth recording:

**Whole copies, not consecutive bit repeats.** `AAABBBCCC` loses every copy of `A`
to a short burst of damage; `ABCABCABC` loses one copy of each. Real damage is
bursty, so the copies are laid end to end.

**Odd factors only.** An even factor admits a tied vote, which would have to be
broken arbitrarily.

**Applied to the whole signed envelope**, not just the message, so the signature is
protected too. Coding only the message would leave the signature — the thing the
whole verdict rests on — undefended.

The cost is exact: factor 3 triples the embedded length, so it triples the capacity
required. The capacity read-out and the `CapacityError` message both name it.

Measured behaviour, on a ~700-byte envelope with a fixed seed:

| Bit error rate | Uncoded | Factor 3 | Factor 5 |
|---|---|---|---|
| 0.5 % | 27 bad bytes | fully repaired | fully repaired |
| 2 % | 110 bad bytes | 5 bad bytes | fully repaired |
| 40 % | 687 bad bytes | 677 bad bytes | 668 bad bytes |

There is no threshold, only a probability of residual error per bit, which is why the
test suite's rates were measured rather than guessed.

What coding does **not** help against is stated as clearly as what it does: anything
that changes every sample at once — amplitude scaling, resampling, lossy
recompression — damages every copy simultaneously, so majority voting has nothing to
work with.

---

## 9. Attack simulator

Each attack produces a modified *copy* and declares the verdicts it expects, so the
Attack Lab can show "expected: SIGNATURE_INVALID, observed: SIGNATURE_INVALID" side
by side and the tests can assert on the pairing rather than on a hardcoded list.

`expected_verdicts` is a **set**. For some attacks the outcome is genuinely
unpredictable — a random bit flip may land in the record, the message or the
signature — and claiming a single verdict for those would be inventing precision.

| Target | Attacks |
|---|---|
| payload (any medium) | corrupt record / message / signature / magic / length header, truncate, flip random bits, substitute-and-re-sign |
| manifest | edit any published field |
| image | modify pixels inside / outside the payload, blank a region, re-encode as JPEG |
| audio | corrupt samples inside / outside the payload, scale amplitude, resample, truncate |
| video | corrupt samples inside / outside the payload, drop frames, re-encode lossily |

The *inside* attacks invert the **last** samples of the payload region. Those carry
the signature, so the payload is still found and the signature check fails. Aiming
at the first samples would hit the unsigned length header instead and demonstrate
nothing about the signature. That case has its own attack, *corrupt the length
header*.

Three details are worth naming:

**Corrupting the message gives `SIGNATURE_INVALID`, not `TAMPERED`,** because the
signature covers the message. Reaching `TAMPERED` requires an attacker who can
*re-sign*, which `resign_with_substituted_message` models explicitly with a key the
attacker controls — and which fails against a receiver holding the real sender's key.

**Length-preserving edits are necessary for a meaningful demonstration.** An edit
that changes the envelope length is rejected during extraction by the manifest's
published length, before the signature is examined, so the receiver sees
`PAYLOAD_MISSING` and the signature is never tested. The record attack therefore
changes one hex digit of the signed nonce: well-formed, same length, and the failure
lands exactly where it is aimed.

**The random-bit attack works on the bytes as they sit on the medium**, without
decoding any error-correcting code first. That is the honest model of transmission
damage, and it is the only way the coding demonstration means anything: an attack
that decoded the code, damaged the envelope and re-encoded would put the damage
*inside* the protected data, where no code could ever repair it.

---

## 10. Quality comparison

Protect and Verify retain numerical MSE/PSNR, sample-difference and media-property
comparisons. Statistical detection and analysis visualisations were removed in S01.


## 11. The interface

Four tabs, all real.

| Tab | Does |
|---|---|
| Protect | Collects settings, runs `protect_media`, shows capacity live and quality after |
| Verify | Runs `verify_media`, renders the verdict, its reasons and its caveats |
| Attack Lab | Runs focused payload/signature corruption or outside-payload edits and shows before/after verdicts; further challenge actions are T05 |
| Video | Clip properties, playback and the manifest-claimed payload frame range; video-only output disclosure |

Every backend call runs on a `QThreadPool` worker. Qt repaints only from the main
thread, so a long call there produces a window that stops responding, which during a
live demonstration looks like a crash. An exception inside a worker cannot propagate
to a caller — there is none left on that stack — so workers catch everything and emit
a message, which becomes a visible label rather than a traceback nobody sees.

The Protect tab's capacity read-out is debounced and measured on a background worker as the user types. Manual offsets are included; generation checks discard superseded results. That needs the *exact*
payload length before anything is signed, which is possible because every
variable-width field in the record is either fixed-length (nonce, digest, timestamp)
or already known (media ID, depth, start method). The signature size is read from the
selected key rather than assumed, because a 2048-bit key produces a 256-byte
signature and a 3072-bit key a 384-byte one.

---

## 12. File-size preservation

Investigated rather than claimed. See
the current [T06 evidence](../evidence/t06/README.md) for measured sizes, media
properties and a no-payload re-encoding baseline. Older evidence/results tables
cover canonical fixtures only and do not establish universal size preservation.

| Container | Exact size? | Why |
|---|---|---|
| WAV | canonical files usually match | Fixed-width samples; metadata may be removed |
| BMP | canonical files usually match | Fixed-stride pixels; padding/header layout may change |
| PNG | depends on the image | DEFLATE-compressed, so it is a property of the image, not the format |
| MKV | not applicable | The output is a full re-encode |

The Protect result displays media byte counts, signed byte/percentage change and
manifest storage separately. WAV/BMP matching reports the measured result without
adding padding. Video sizes reflect both codec/container changes and embedding.
Video protection requires even dimensions and a finite positive frame rate, checks
decoded timestamps against constant-rate timing within 2 ms, and reads back frame
count, dimensions and rate (relative tolerance 1e-5, absolute 1e-6 fps). No fallback
frame rate is substituted. Native playback remains a separate release check.

The PNG strategy re-encodes at every DEFLATE level looking for an exact hit, then
closes any remaining shortfall with an ancillary `stPd` chunk. It **cannot** always
succeed: when every candidate is already larger than the cover, bytes cannot be
removed from a PNG without changing its pixels. Three outcomes were measured — free,
matched by padding, and impossible — and all three appear in the evidence.

A padding chunk also carries a cost worth naming: it is unusual in an otherwise plain
PNG, so a file padded to match its cover may be *more* conspicuous to an analyst than
one that is simply the wrong size.

---

## 13. What verification does not establish

Repeated here because it is the easiest thing to overstate. The application states it
verbatim in the interface through `constants.AUTHENTIC_SCOPE_NOTICE`.

`AUTHENTIC` means the signed record and the recovered message match, and the
signature verified against the supplied public key. It does **not** mean every part
of the cover is unchanged, and it does **not** by itself reject a replayed file.
Modifying samples outside the payload region leaves the verdict `AUTHENTIC` — that is
demonstrated by an attack rather than left unmentioned.

See [`limitations.md`](limitations.md) for the full list.

## T03: Sender publication and receiver resource policy

The sender validates the cover, output and manifest paths pairwise (including
hard-link and case-normalized aliases) and rejects symbolic-link destinations.
Media and manifest are staged beside their destinations. Existing files are copied
to temporary backups before publication. Caught publication failures restore prior
outputs; a failed restoration raises `PublicationError` and retains the relevant
backups in its `recovery_paths` attribute for manual recovery. Staging files and
unneeded backups are cleaned up; cleanup failures are logged.

Each file replacement is atomic, but the pair is not a filesystem transaction.
Concurrent readers can briefly observe a mixed pair. Power loss, forced process
termination and concurrent writers to the same pair are outside the guarantee.
No-overwrite publication uses exclusive Windows rename or POSIX hard-link creation
so a destination appearing after validation is not overwritten. POSIX destinations
must support hard links; unsupported filesystems fail safely rather than fall back
to a potentially destructive overwrite.

Capacity checks use the selected manual offset and the actual serialized envelope,
encryption and repetition lengths. The offset's own serialized digit count is part
of the signed metadata overhead. The GUI preview still needs the T04 update.

Manifest reads are bounded to 1 MiB before JSON parsing; excessive nesting produces
a domain error. The existing envelope-section bounds remain in place. Scrypt calls
are refused before library allocation when estimated memory `128*N*r` exceeds
128 MiB or work `N*r*p` exceeds `2**22`. These are local compatibility/resource
limits, not exact process memory/time limits or claims of cryptographic strength.
The default `N=32768, r=8, p=1` is unchanged. Unsupported signed costs return
Cannot Verify; signature verification still precedes decryption.

A manifest-cross-check failure no longer returns recovered plaintext in
`VerificationResult.message`. Failure diagnostics and signature/hash flags remain.
This enforces the existing backend contract that recovered bytes are returned only
on success. T04 must still gate GUI preview/save directly on the final verdict.

`key_manager.public_key_fingerprint` returns lowercase SHA-256 hex of canonical DER
SubjectPublicKeyInfo for an RSA public key (or the public half of a private key).
It supports later out-of-band key comparison; no fingerprint UI, trust store or
payload format change was introduced in T03.

### T04 interface boundaries

Picker and drag/drop selections use the same validation route. A drop must contain
exactly one local URL; mixed local/remote drops are rejected. Clear resets the tab's
input as well as the drop widget. Workers discard results after their relevant
inputs change. Recovered plaintext preview/save requires the final AUTHENTIC verdict.
Sender and receiver inputs show the canonical public-key SHA-256 fingerprint with
an independent-trust reminder. The separate key-location menu, bulk attack runner,
extra GUI attack variants, arbitrary video-frame explorer, separate video capacity
table have been removed. Steganalysis was subsequently removed completely in S01. Backend catalogues and
experiments remain available for tests and T05 evaluation.
