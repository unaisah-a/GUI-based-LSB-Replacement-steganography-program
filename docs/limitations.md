# Limitations and security assumptions

## Authentication scope

- `AUTHENTIC` means the hidden message, signed record, signer fingerprint, extraction settings, and plaintext SHA-256 digest passed verification relative to the supplied trusted public key.
- The signature does not cover every cover-media byte. An edit outside the embedded region can leave message verification successful.
- The application does not establish the identity of a key owner. Users must compare the displayed public-key fingerprint through a trusted channel.
- A timestamp and random nonce are signed context, but the application has no shared replay database or freshness policy. A previously authentic bundle can be replayed.
- Media substitution is detected only where signed settings, payload extraction, protected-file binding, or a demonstrated comparison exposes it. Do not describe the baseline as whole-media authentication.

## Confidentiality and secrets

- Start-location secrecy is not encryption. Anyone who finds or scans the payload can read an unencrypted message.
- AES-256-GCM protects stored message bytes, but the signed record contains the SHA-256 hash of the recovered plaintext. That visible hash can confirm guesses of short or predictable messages. Add unpredictable context when offline guessing matters.
- The manifest is non-secret and omits derived locations and keys. Start secrets, AES keys, recovery keys, and trusted public keys must be transferred separately as appropriate.
- Checked-in receiver-bundle AES and start values are explicitly public demonstration values. They provide reproducibility, not confidentiality.
- The GUI can generate and export demo secrets. Users remain responsible for protected storage, secure transfer, rotation, and deletion.
- RSA private keys must remain with the signer and must never be included in receiver evidence. The application supports password-protected private-key files, but password strength and workstation security remain external responsibilities.

## Steganography limits

- LSB replacement is concealment, not a substitute for cryptography. Fixed framing bytes and statistical changes may be discoverable.
- Increasing LSB depth increases capacity and usually increases visible or audible distortion.
- Re-encoding, resampling, resizing, color conversion, normalization, metadata tools that rewrite sample data, and deliberate bit edits can damage the payload.
- Capacity depends on the complete signed envelope, carrier framing, start location, depth, encryption overhead, and robustness overhead. Repetition-3 triples the embedded envelope length.
- The robust mode is three-copy repetition with majority voting, not general error correction. It corrects one differing copy in a corresponding bit group and fails when the demonstrated error boundary is exceeded.
- `CANNOT_VERIFY` can result from missing payload, wrong secret, wrong settings, corruption, unsupported input, or malformed framing. The verifier does not claim a specific cause when the evidence cannot distinguish one.

## Format limits

- Baseline images are PNG and the BMP layouts explicitly supported by the custom reader/writer. Alpha bytes are excluded from embedding.
- Audio support is PCM-16 WAV. MP3, AAC, compressed WAV codecs, resampling, and lossy audio are unsupported.
- Video support requires external `ffmpeg` and `ffprobe` executables on `PATH`.
- Protected video output is lossless FFV1 in Matroska. LSB survival is not expected after lossy transcoding; the recorded H.264 experiment produces `CANNOT_VERIFY` only for its tested file and settings.
- Video embeds in one selected decoded RGB frame. It is bounded for coursework-scale inputs and is not a streaming or large-production-media pipeline.
- The version-1 envelope allows at most 64 MiB of plaintext and 1 MiB of signed-record JSON. Recovery sidecars accept originals up to 256 MiB. Carrier capacity will usually impose a lower limit.
- Unknown envelope or manifest versions, non-canonical encodings, duplicate JSON fields, unexpected fields, and inconsistent types are rejected. There is no automatic migration of historical unversioned artifacts.

## File size and reversibility

- A lossless codec preserves decoded content, not compressed file length. PNG byte size can change even when pixels differ only in selected LSBs.
- Exact PNG size is attempted through bounded compression search and a valid private ancillary padding chunk. Some target sizes are unattainable and the result reports that fact.
- Supported BMP and PCM-16 WAV workflows can preserve layout and length by changing eligible sample bytes in place. This does not mean every possible BMP or WAV variant is supported.
- Video exact-size preservation is unsupported.
- Standard LSB replacement is not inherently reversible because original low bits are overwritten.
- Byte-exact restoration requires the separately stored encrypted sidecar, its recovery key, and the exact protected file to which it is bound. The sidecar stores the whole original and can exceed the protected media's size; it is not reversible steganography.

## Manifest and metadata

- The manifest is needed to bootstrap bounded extraction but is not trusted in isolation. Its controlling values must match signed record values before success.
- Media IDs, timestamps, content type, signer fingerprint, extraction parameters, and custom metadata are visible in the signed record after extraction. Encryption covers the message bytes only.
- A manual start location is disclosed in the manifest. Derived mode omits the location but still reveals that HMAC-SHA256 derivation is used.

## GUI and operational limits

- Long operations use worker threads and cooperative cancellation. Cancellation occurs at safe checkpoints and may not be immediate while an external tool or bounded media operation is completing.
- Media preview and playback depend on codecs and multimedia support available to the local Qt installation.
- Recovered file payloads are saved only after authentic verification and are not automatically executed. Users must still handle untrusted file formats safely.
- Transactional publication protects a complete local output bundle from partial replacement, but it does not provide distributed transactions for later copying, cloud upload, or messaging.
- Release desktop evidence was collected on Windows 11 with Qt's `windows` platform at 2560×1440. Other supported desktops should run through PySide6 but were not part of that native screenshot audit.

## Analysis and experiment limits

- PSNR, MSE, SNR, histograms, bit planes, sample differences, and statistical indicators describe measured files; they do not prove secrecy or the absence of steganography.
- Human visual and listening judgments are subjective and must be recorded as observations, not universal results.
- Attack Lab creates controlled copies and reports verification outcomes. Its attacks are demonstrations, not an exhaustive adversarial security assessment.
- Seeded robustness, compression, and lossy-video results apply to the recorded fixtures and settings. They must not be generalized into guarantees for all media.
- The [extension evaluation](extension_evaluation.md) deliberately records steganalysis false alarms, misses, and insufficient-data cases. Its fixed rule is uncalibrated and its bundled covers are synthetic. Natural photographs remain a team-supplied evaluation input.
- Independent random-bit-noise trials improve on single-copy-only tests, but do not model compression, resampling, or correlated burst damage. Even repetition fails whole-message recovery at higher tested noise probabilities.

## Evidence limits

- The R12 evidence reports the tested dependency versions, machine, suite result, receiver matrix, and native GUI cases. It is release evidence for that environment, not a certification of every platform.
- The repository excludes real private signing keys and scans evidence for private-key markers and indexed secret values. This does not replace a team review of any new files added before submission.
- Team names, identifiers, contribution percentages, acknowledgements, actual A-to-B transfer, rehearsal observations, and signatures require truthful human completion.
