# Architecture and wire format

## System boundary

The application protects a message or file payload by embedding a signed, optionally encrypted envelope in media. Verification authenticates that envelope relative to a public key the receiver already trusts. Cover-media bytes outside the embedded region are outside this authentication boundary.

```text
PySide6 GUI
  Protect | Verify | Attack Lab | Analysis | Video
                         |
Application services and operation control
  protection | verification | recovery | size | experiments
                         |
Security and carrier modules
  payload | manifest | signatures | encryption | starts
  image LSB | audio LSB | video frame LSB | repetition
                         |
PNG / supported BMP / PCM-16 WAV / FFV1 Matroska
```

GUI event handlers collect input and display results. `app/services/` coordinates complete operations. `app/crypto/`, `app/stego/`, `app/robustness/`, `app/verification/`, `app/attacks/`, and `app/analysis/` own the reusable logic.

Protect's capacity preview uses a separate worker and a 250 ms debounce timer. The GUI snapshots inputs, and key loading, file-payload reading, carrier inspection, and signed-envelope estimation run in the worker. Each edit invalidates previous results; one pending request replaces intermediate edits. Closing the tab cancels pending work and waits for the active estimate to stop safely. Bounded external probes can delay shutdown until they return. Final protection independently checks capacity using its fresh nonce.

## Main contracts

- `ProtectionOptions` describes media ID, depth, start method, confidentiality, robustness, size, recovery, overwrite, and video-frame choices.
- `estimate_protection_capacity(...)` builds the real signed envelope and reports its exact carrier cost without writing output.
- `protect_media(...)` stages and transactionally publishes protected media, manifest, and requested side artifacts.
- `Manifest` is the bounded version-1 extraction descriptor.
- `verify_media(...)` validates the manifest and trusted key, derives the start, extracts and parses the envelope, compares signed settings, verifies the signature, decrypts if necessary, and checks the plaintext digest.
- `VerificationResult` contains a `Verdict`, ordered checks, recovered bytes, content type, signed record, and resolved start when available.

## Protection flow

1. Read text as UTF-8 or load exact file bytes.
2. Inspect the carrier and build a version-1 signed record containing the media ID, timezone-aware timestamp, random record nonce, SHA-256 plaintext digest, content type, signer fingerprint, extraction settings, encryption metadata, and bounded custom metadata.
3. If requested, encrypt the message with AES-256-GCM. Associated data binds the media ID and record nonce.
4. Sign the domain-separated canonical record bytes and stored message with RSA-PSS/SHA-256. Supported RSA private keys are at least 2048 bits.
5. Serialize the `SMIV` envelope. If repetition mode is selected, repeat every envelope byte three times.
6. Calculate the exact carrier positions required. Reject an over-capacity request before publishing output.
7. Select the start directly or derive it with HMAC-SHA256 from the separate start secret and signed carrier context.
8. Embed the carrier payload and stage every requested output.
9. Optionally run size preservation and create an encrypted recovery sidecar from the complete original file.
10. Publish the complete bundle atomically. Existing destinations are restored if publication fails.

## Verification flow

1. Parse the manifest as bounded UTF-8 JSON; reject duplicate, missing, unknown, wrongly typed, or unsupported fields.
2. Load a supported RSA public key and compare its SHA-256 fingerprint with the manifest.
3. Resolve the start location. Manual starts come from the manifest; derived starts require the separately supplied secret.
4. Extract exactly the bounded carrier payload length. Decode repetition-3 when selected.
5. Parse the version-1 envelope and require exact lengths with no trailing data.
6. Compare manifest extraction controls with the signed record, including media type, depth, start method, manual start, robustness, payload length, and video frame index.
7. Verify the RSA-PSS signature over the exact canonical record and stored message.
8. If encrypted, authenticate and decrypt with AES-256-GCM.
9. Recompute SHA-256 over the recovered plaintext and compare it with the signed digest.
10. Return `AUTHENTIC` only after all required checks pass. Ambiguous extraction failures remain `CANNOT_VERIFY`.

## Version-1 envelope

The binary envelope begins with the big-endian structure `>4sBBIII`:

| Field | Meaning |
| --- | --- |
| `magic` | Four bytes: `SMIV`. |
| `version` | Payload format version, currently `1`. |
| `flags` | Bit 0 indicates AES-GCM encryption; all unsupported bits are rejected. |
| `record_length` | Canonical JSON signed-record byte length. |
| `message_length` | Stored plaintext or ciphertext-plus-tag length. |
| `signature_length` | RSA signature byte length derived from the key. |

The header is followed by the canonical record bytes, stored message bytes, and signature. Bounds are enforced before allocation: the record is at most 1 MiB, plaintext is at most 64 MiB, and signatures are bounded. The encryption flag must agree with signed encryption metadata.

The signed record has exactly these top-level fields:

- `record_version`
- `media_id`
- `nonce`
- `timestamp`
- `message_hash`
- `content_type`
- `public_key_fingerprint`
- `metadata`
- `extraction`
- `encryption`

`extraction` binds the carrier type, LSB depth, start method, envelope length, robustness mode, manual location when applicable, and selected video frame when applicable. `encryption` is either `{"algorithm":"none"}` or AES-256-GCM metadata with a canonical nonce.

## Companion manifest

The manifest is version-1 JSON and contains the information required before the hidden signed record can be reached:

- manifest and payload-format versions
- media type and media ID
- record nonce
- LSB depth and start method
- manual start location, only in manual mode
- envelope and expanded carrier-payload lengths
- robustness mode
- selected video frame, only for video
- expected public-key fingerprint

The manifest contains no derived start location, private key, AES key, recovery key, or start secret. It is not itself signed as a standalone file; verification cross-checks its controlling values against the signed record. Mutating a controlling value either prevents bounded extraction or produces a mismatch before `AUTHENTIC` can be returned.

## Carrier framing

### Image

PNG and supported BMP carriers embed across eligible color-channel bytes in pixel order. Alpha is preserved and excluded. The low-level framing is a four-byte big-endian payload length followed by opaque payload bytes.

### Audio

PCM-16 WAV carriers traverse scalar samples in frame order: `L0, R0, L1, R1, ...` for stereo. The low-level framing is ASCII `INF2005`, a four-byte big-endian length, and opaque payload bytes. Container-preserving paths change only eligible sample bytes.

### Video

Video support requires FFmpeg and ffprobe. The application decodes a selected RGB frame, embeds using the image-style framed stream, writes lossless FFV1 Matroska, remuxes compatible audio, and validates decoded frames and stream properties before publication. The selected frame index is signed and present in the manifest.

For every carrier, depth is 1–8 bits per eligible scalar sample and bits form one continuous stream. The required sample count is `ceil(encoded_bits / depth)`. A start is valid only when the complete framed payload fits.

## Start-location design

Manual mode records a zero-based scalar-sample index in both the signed record and manifest. Derived mode calculates a valid index with HMAC-SHA256 over carrier and signed context, including media type, media ID, nonce, depth, total samples, and required samples. The receiver needs the same separately transferred start secret.

The derivation hides a predictable location from a party without the secret; it does not encrypt the payload. The signed record authenticates the chosen method and all settings needed to reproduce it.

## Optional mechanisms

### Confidentiality

AES-256-GCM encrypts the message before signing. The signature covers the ciphertext and signed metadata; successful decryption then permits the signed plaintext-digest check. Keys are entered or exported separately and never written to the manifest.

### Repetition-3 robustness

Each envelope byte is stored three times. Extraction performs bitwise majority voting. This triples carrier payload size, corrects one divergent copy per bit group, and cannot promise recovery when two copies disagree in the same bit.

### Exact-size experiments

Supported BMP and PCM-16 WAV paths preserve container bytes outside the sample region and therefore retain length. PNG output searches bounded lossless compression settings and may add a valid private ancillary padding chunk when an exact target is attainable. The result report records whether exact equality was achieved and why an attempt failed.

### Byte-exact recovery

Standard LSB replacement overwrites original bits. Optional recovery therefore stores the complete original file in a separate AES-GCM sidecar bound to the protected-file hash. Restoration validates the sidecar, protected-file binding, original length, and original SHA-256 before publication. The sidecar is bounded to a 256 MiB original.

## Trust and transfer model

Party A keeps the private signing key. Party B receives protected media and the companion manifest, and obtains the public key through a trusted channel. Derived-start, encryption, and recovery secrets use a separate secure channel. The UI displays public-key fingerprints so the parties can compare them out of band.

The repository's receiver bundle deliberately includes a public key and public demonstration secrets so results are reproducible. Those values are evidence, not secure deployment credentials.

## Compatibility

Unknown manifest and envelope versions are rejected rather than guessed. Low-level image/audio carrier framing remains callable for experiments, but a raw low-level payload is not a signed application bundle and cannot produce `AUTHENTIC`. See [compatibility.md](compatibility.md) for historical boundaries.
