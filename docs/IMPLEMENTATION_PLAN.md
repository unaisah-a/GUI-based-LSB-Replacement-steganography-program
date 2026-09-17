# Implementation plan and interrupted-build handoff

## 1. Review baseline and instructions for resuming

This document reconciles the agreed whole-project plan in the conversation with the repository as inspected and resumed on 2026-09-17. It is a continuation plan, not a request to replace the existing implementation.

- Current HEAD: `0cda95e` — `feat: Add implementation plan documentation`. R01 and R02 are implemented in the current working tree and remain uncommitted at this handoff.
- R02 acceptance review on 2026-09-17: the focused transaction/recovery/GUI/verification run was **34 passed in 2.22 seconds**. The repository run was **451 passed, 1 failed in 14.44 seconds**. The remaining failure is the pre-existing RGB-versus-alpha metric inconsistency recorded under R09 below, exposed by Hypothesis with an alpha-only difference.
- The local audit environment uses Python 3.14-compatible package versions. Installing the exact requirements file attempted to build `numpy==2.1.3` from source because that pin has no Python 3.14 wheel; clean installation of the pinned set therefore remains an R12/R13 concern.
- The suite includes a subprocess-based, offscreen GUI construction test. Passing it does not establish successful interactive workflows, playback, responsiveness, visual layout, or completion of optional features.
- `ffmpeg` and `ffprobe` are currently discoverable on PATH. Their availability has not yet been exercised by this branch because R10 remains unimplemented.
- No applicable `AGENTS.md` was found in the repository search.
- R01 hardens the security boundaries. R02 adds staged bundle publication, overwrite rollback, optional artifact orchestration, path collision checks, and focused fault-injection coverage.

Preserve the existing image layer, audio layer, security primitives, services, widgets, tests, and passing behaviour. Resume with the focused integration and validation tasks below. Empty files are not evidence that equivalent functionality is absent elsewhere.

### Source precedence and agreed scope

1. User instructions in this conversation define authorised work. The latest request authorises R02 only; later tasks remain pending.
2. The assignment brief defines assessed requirements: `INF2005-ACW1-spec_v5-f2f.pdf`, previously read in full from `C:\Users\ginli\OneDrive\SIT\Year 2 Tri 1\Cyber Security Fundamentals\Project\`.
3. [The repository README](../README.md) supplies team context and proposed engineering choices. It explicitly remains a planning reference, not the submission README.
4. The user selected the **full README roadmap**, implemented by the assistant, rather than a team work schedule. Extensions remain in the agreed build scope even though they are individually optional for assessment.

The accepted verification boundary remains hidden-message and signed-record authenticity relative to a separately trusted public key. Whole-cover authentication and automatic replay rejection are not part of this implementation. Demonstrate these limits honestly. Document instructions, including the brief's email request, are not authorisation to send messages or submit work.

## 2. Project requirements and marking considerations

### Mandatory capabilities and evidence

| Requirement | Required outcome |
| --- | --- |
| FR1–FR2: cover objects | Accept a standard image format and audio format. Baseline: PNG/BMP and PCM-16 WAV. |
| FR3: payload | Media ID, timestamp, cryptographic hash, nonce, and team-defined metadata in a compact verification payload. |
| FR4: signature | Sign with a private key and verify with the corresponding trusted public key. |
| FR5–FR6: embedding | LSB replacement in both mandatory media types; GUI-selectable depths 1–8. |
| FR7: start location | Select or derive a start, recover the same location, and explain how the information is protected. Include non-zero positions in demonstrations. |
| FR8–FR10: verification | Extract message/signature, recompute the relevant hash, and return a clear, justified verdict. |
| FR11: cases | At least two positive and three actual verification-negative cases overall; at least one positive and one negative for each mandatory medium. Capacity rejection is additional input validation, not a substitute for a negative verification case. |
| FR12: reproducibility | Source, setup README, sample files, test evidence, and safe key-generation/verification instructions. |
| FR13: innovation | At least one implemented, useful improvement beyond the simplest fixed-location LSB example, with evidence and limitations. |
| Capacity and usability | Check the complete encoded payload against eligible capacity; show/play original and stego media before/after workflows and recovered payloads where applicable. |
| Required messages | A short Learning Outcome message, the longer Project Overview paragraph, and a relevant custom message demonstrating confidentiality and integrity. |
| Transfer | Party A sends protected media; party B downloads to their own folder and independently extracts/verifies. Include this design's manifest and separately supplied secrets/trusted public key. |
| Demo and accountability | At most 25 minutes, every member speaks/demonstrates, truthful contribution distribution, originality signatures, acknowledged sources and AI use. |

### Rubric: 40 marks

| Criterion | Marks | Implementation/evidence priority |
| --- | ---: | --- |
| Security design and framing | 5 team | Explain envelope, start derivation, trust bootstrap, and verification scope for both media. |
| Image workflow and cases | 9 team | Working GUI round trip, start recovery, positive case, meaningful negative case. |
| Audio workflow and cases | 10 team | Working GUI round trip and playback, start recovery, positive/negative cases. |
| Hash/signature and failure handling | 5 team | Show each check and explain why verification succeeds or fails. |
| Innovation | 4 team | Demonstrate and evaluate implemented improvements, not merely planned features. |
| Individual explanation | 5 individual | Each member understands their actual contribution and the end-to-end workflow. |
| Limitations, ethics, AI reflection | 2 team | Accurate claims, responsible use, original work, disclosure and checking of AI assistance. |

Core image/audio demonstrations account for 19 marks and security for another 10. Finish and harden those before video. Do not allow feature count to displace reliable demonstrations.

Deadlines from the brief: demo plan, signed originality declaration, and agreed contribution statement one day before the demo; source, README, samples, evidence, and key instructions by Week 5 Friday. Exact demo date and team/member identifiers remain external inputs; do not invent them.

### Agreed extensions

- Attack Lab and statistical steganalysis with measured quality changes.
- Three-copy repetition coding and majority voting, with capacity cost and corruption limits demonstrated.
- FFmpeg/FFV1 lossless Matroska video, selected-frame embedding, verified colour-byte preservation, compatible audio remuxing, and a lossy-transcoding experiment.
- Explicit WAV/BMP layout-preserving output and PNG compression/padding experiments. Exact size is conditional, not universally guaranteed.
- Encrypted sidecar-assisted byte-exact original restoration. The sidecar stores original file bytes; this is not inherently reversible LSB embedding.

## 3. Agreed architecture and interfaces

```text
PySide6 GUI
    -> application services and verification orchestration
        -> crypto / robustness / media adapters / analysis / attacks
            -> image, PCM audio, and optional lossless video files
```

### Preserve the current contracts

- `main.py` creates the application and `MainWindow`. Five tabs currently exist: Protect, Verify, Attack Lab, Analysis, Video.
- `app/services/protection.py`: `ProtectionOptions`, `ProtectionResult`, `protect_media(...)`.
- `app/services/media.py`: `CarrierInfo`, `inspect_carrier(...)`, and carrier-specific framing overhead.
- `app/verification/verifier.py`: `verify_media(...)`, `resolve_start_location(...)`; results use `Verdict`, `CheckStatus`, `VerificationCheck`, and `VerificationResult`.
- Image API: `embed_image(...)`, `extract_image(...)`; audio now also exposes `embed_audio(...)`, `extract_audio(...)` wrappers around the established `_lsb` functions.
- Existing image transport is a four-byte big-endian payload length plus payload. Audio transport is `INF2005` magic, four-byte length, and payload. Keep these compatible; future robust reading must preserve continuous bit ordering at depths that do not divide header bit counts.
- Start positions are zero-based eligible scalar-sample indices. Image alpha is excluded from embedding. Audio traversal interleaves channels in frame order.

### Security data flow

1. Encode text as UTF-8 or accept file bytes; calculate plaintext SHA-256.
2. Build the canonical JSON signed record with identifiers, nonce, timestamp, digest, content type, signer fingerprint, extraction settings, and metadata.
3. Optionally encrypt the message with AES-256-GCM using a fresh nonce and a separately shared 32-byte key.
4. Sign the exact record and stored message/ciphertext using RSA-PSS/SHA-256 (RSA-2048 baseline). Signature lengths come from the key.
5. Put the record, stored message, and signature in the versioned `SMIV` envelope with explicit lengths. Optionally repeat each envelope byte three times.
6. Account for envelope, redundancy, and carrier framing before selecting the start. For N eligible samples, B encoded bytes, and depth k, require `ceil(8B/k)` samples and choose within `0..N-required_samples`, inclusive.
7. Derive starts with HMAC-SHA256 using the separate start secret, media ID, nonce, media type, sample counts, and depth, or use a validated manual start.
8. Send stego media and a non-secret manifest. Derived locations/secrets are not exported in the manifest. The manifest exposes lengths and settings needed to bootstrap extraction; it is untrusted until compared to the signed record.
9. Receiver bounds-checks inputs, resolves the start, extracts/decodes, verifies the signature and signed settings, decrypts if needed, and verifies the message hash.

Preserve distinct envelope length (`payload_length`) and redundancy-expanded carrier payload length (`embedded_payload_length` / manifest `carrier_payload_length`). Signed settings plus validated expansion rules must authenticate the latter relationship.

### Remaining architecture work

Introduce worker execution with cancellation/progress and expose reusable compare/attack orchestration. Optional size/recovery processing now belongs to the protection service's staged transaction. Keep existing analysis functions; do not duplicate them merely to fill scaffold files. UI success must continue to say **“Message and signed record verified.”** Treat uncertain extraction failures as `CANNOT_VERIFY`, not a proven wrong-start cause.

## 4. Completed work to preserve

“Completed” below means the stated slice exists and has relevant passing coverage; it does not mean the entire subsystem is release-ready.

| Completed slice | Implementation and evidence |
| --- | --- |
| Baseline environment | Local `.venv` and working pytest invocation. Original baselines were 357 and then 380 passing tests; the post-R01 suite is 430 passing tests. Exact pinned installation on Python 3.14 remains unresolved under R12/R13. |
| Image carrier | Substantial PNG/BMP I/O, capacity, bit utilities, LSB embedding/extraction, alpha handling, atomic image writes, and extensive property/example tests. |
| Image analysis backend | Quality metrics, bit planes, difference images, histograms, and multiple statistical indicators already implemented and tested. |
| Audio carrier baseline | PCM-16 WAV read/write, depths 1–8, embedding/extraction, non-zero starts, common API wrappers, and atomic single-file output. |
| Audio analysis backend | Existing information and distortion/quality computations. More assertions are still needed; see partial work. |
| Security primitives | SHA-256, RSA-PSS helpers, key-derived signature lengths, PEM import/export, password-protected private-key support, fingerprints, AES-GCM helpers. |
| Core application workflow | Image/audio protect -> saved media + manifest -> reload -> verify, with manual/derived starts and optional encryption. Tests cover both media with and without encryption. |
| Verification baseline | Structured checks and conservative failure verdicts; wrong public key and wrong secret covered. |
| GUI foundation | Entry point, five-tab shell, file pickers/drop zones, image preview/WAV playback widgets, key generation, encryption controls, basic results and comparisons. Offscreen construction test passes. |
| Attack primitives | Separate-copy embedded corruption and outside-region edits; tests show failures and the message-only verification boundary. |
| Repetition primitive | Byte triplication, bitwise majority decoder, signed robustness choice and expanded capacity accounting. Unit and image integration recovery tests pass. |
| Recovery primitive | AES-GCM sidecar, binding to protected-file hash, original length/hash checks, byte-exact restoration and wrong-protected-file rejection tests. |
| PNG padding primitive | Legal private ancillary chunk with CRC, exact target sizing when possible, and unchanged decoded pixels test. |
| R01 security boundaries | Manifest and envelope parsing now enforce exact types, required/supported versions, duplicate-free canonical JSON, signed-record schema, encryption flag/metadata agreement, bounded lengths, RSA key types/sizes, and signed/manifest/carrier length relationships. WAV extraction now performs the same manifest-length cross-check as image extraction. Malformed verification inputs remain structured failures. Focused tests: 73 passed; full suite: 430 passed. |
| R02 transactional publication | Protection stages media, manifest, optional size processing, and recovery sidecar before publishing the complete bundle. Existing destinations are backed up and restored on publication failure; aliases and collisions are rejected before embedding; recovery and PNG helpers require explicit overwrite permission. Recovery binds to final post-processed bytes and expected PNG size inability is reported in the successful result. Fault-injection coverage exercises every stage and GUI propagation. Focused tests: 34 passed. |

## 5. Partially completed work and specific inconsistencies

These are the remaining observed gaps after completing R01 and R02. Not every issue can be attributed solely to the interruption; some predate it.

| Files / area | Observed incomplete or inconsistent behaviour | Follow-up |
| --- | --- | --- |
| `app/gui/protect_tab.py` | Capacity display excludes signed/encryption/redundancy overhead and does not account for manual start. Success reports envelope bytes as embedded bytes even under repetition. | R03, R04 |
| GUI workflow tabs | Protection, verification, comparison, and attacks execute synchronously; no worker/progress/cancel mechanism. File/message handling is text-only on Protect. Verify cannot save recovered files or display/play recovered non-text payloads. | R04 |
| `app/gui/verify_tab.py`, `widgets/result_panel.py` | Key fingerprints exist in backend checks but there is no convenient fingerprint review flow. Previously displayed results are not systematically cleared when input or a new operation fails. | R04 |
| `app/verification/verifier.py` | Robust mode still invokes ordinary carrier header parsing. A damaged image length header or audio magic/length can stop extraction before majority decoding, contrary to the agreed manifest-bounded robust read. | R05 |
| `app/attacks/payload_attacks.py` | Attack positions use unexpanded `manifest.payload_length`. For robust mode, “near boundary” is inaccurate; outside-region calculation at start zero can target inside the redundant region. | R05, R06 |
| `app/crypto/start_location.py`, `signatures.py` | “Compatibility” wrappers retain callable shapes but changed legacy HMAC input strings and signature domain/PSS settings. Old saved artifacts are not necessarily wire-compatible. Establish fixtures and document migration rather than claiming backward compatibility. | R03 |
| `app/services/size_preservation.py` | PNG padding and size comparison exist; compression-setting search does not. WAV/BMP handling compares byte counts rather than preserving original container layout. Padding has no explicit large-target allocation bound. | R08 |
| `app/robustness/recovery.py` | Backend create/restore now has collision checks and explicit overwrite control, but no GUI restore route or storage-overhead presentation exists. | R07 |
| `app/gui/steganalysis_tab.py` | Only textual image quality/LSB proportions and audio metrics are exposed. Existing bit-plane, difference, histogram, and richer indicators are not presented; waveform views/export and full media comparison remain absent. | R09 |
| `app/analysis/image_analysis.py`, `tests/test_image_analysis.py` | Quality comparison excludes alpha from MSE but uses full-array equality for `pixel_identical`; an alpha-only difference therefore reports non-identical pixels with zero MSE. Hypothesis now retains this failing example. | R09 |
| `app/gui/attack_tab.py` | Two attacks only; no seed/severity controls, remaining negative scenarios, paired automatic verification, or report export. | R06 |
| `app/gui/video_tab.py`, `app/stego/video_stego.py` | Tab is explanatory text; stego module is empty. Carrier inspection supports only image/audio and verifier explicitly rejects video despite schema accepting a video type. | R10 |
| GUI tests | Construction and R02 service-error propagation are covered offscreen. Tests still do not drive key creation, successful protect/verify workflows, restoration, or cancellation. | R04, R12 |
| `tests/test_audio_quality.py` | Import-time report/printing script, not an assertion-based test. | R03, R09 |
| `README.md`, `docs/architecture.md`, `docs/limitations.md` | README remains planning context; architecture remains audio-only, while limitations now adds the R01 plaintext-hash/confidentiality boundary but is not yet a complete system document. | R13 |
| `requirements.txt` | Direct dependencies are pinned, but comments still instruct members to pin already-pinned packages. On Python 3.14, `numpy==2.1.3` has no compatible wheel and falls back to a source build. Fresh pinned installation and video setup have not been validated for release. | R12, R13 |
| Samples/evidence/keys | Only earlier audio originals/stego and audio reports exist. No completed signed sample matrix, transfer bundle, committed public demo key, screenshots, or extension evidence. | R11, R12 |

### Empty scaffold inventory

- Video backend: `app/stego/video_stego.py`.
- Media-specific attack placeholders: `app/attacks/image_attacks.py`, `audio_attacks.py`, `video_attacks.py`. Working attacks already live in `payload_attacks.py`.
- Analysis placeholders: `app/analysis/quality_metrics.py`, `steganalysis.py`. Working image/audio analysis already exists in the media-specific modules.
- Comparison placeholder: `app/verification/media_compare.py`.
- Utility placeholders: `app/utils/constants.py`, `file_utils.py`, `logging_utils.py`, `media_utils.py`.
- Submission document placeholders: `docs/demo_plan.md`, `docs/test_cases.md`, `docs/contribution_statement.md`.
- Empty package `__init__.py` files and `.gitkeep` files are normal scaffolding, not broken implementations.
- `app/robustness/error_correction.py` is a re-export of the implemented repetition helpers, not a separate error-correction algorithm. Do not infer Hamming/Reed-Solomon support from its filename.

Do not fill placeholders just to make every file non-empty. Extend existing owners or remove unused scaffolding only when the relevant feature is completed and references are checked.

## 6. Remaining tasks, dependencies, and acceptance criteria

R01 and R02 are complete. R03–R13 remain pending, including completion of partial features. IDs provide a stable order for future turns. Add regression tests alongside each correction; do not defer correctness testing to the final milestone.

### R01 — Harden envelope, manifest, and verification boundaries — COMPLETE

**Depends on:** preserved core services; no other pending task.

Validate exact field types and supported versions, signed-record schema, encryption/header consistency, length relationships, key type, and resource bounds. Keep malformed inputs within structured failure results. Authenticate or strictly cross-check all fields that control interpretation; version any incompatible format correction explicitly. For encrypted messages, document that a visible plaintext hash permits guessing low-entropy messages; do not silently claim all metadata is confidential.

**Acceptance:** mutation tests for every controlling field, truncated/oversized lengths, floats/bools/lists in scalar fields, missing versions, duplicate JSON keys, invalid encodings, inconsistent encryption settings, and unsuitable keys produce justified failures without crashes or unsafe allocations. Header-flag changes cannot silently change interpretation. Build-time output is always accepted by the corresponding bounded parser. Audio/image lengths agree with manifest and signed record. No malformed case returns `AUTHENTIC`.

**Completion evidence:** `tests/test_security_boundaries.py` covers record/manifest field mutations, missing and unsupported versions, duplicate keys, invalid UTF-8, framing limits, encryption flag/nonce inconsistencies, unsuitable keys, builder/parser agreement, and structured malformed-payload failure. `tests/test_audio_stego.py` covers the new WAV manifest-length check; the existing image tests retain the equivalent image check. `docs/limitations.md` records the visible plaintext-hash guessing boundary. Review runs completed with 73 focused tests and 430 total tests passing. No wire-format version bump was needed because version-1 builders already emit the canonical schema and the formerly unauthenticated encryption flag is now strictly cross-checked against signed metadata.

### R02 — Make output publication and path handling failure-safe — COMPLETE

**Objective:** make protection and optional-artifact publication transactional so a reported success always represents one complete, mutually consistent bundle and any failure preserves inputs and prior destinations.

**Likely files:** `app/services/protection.py`, `app/gui/protect_tab.py`, `app/robustness/recovery.py`, `app/services/size_preservation.py`, and focused service/GUI/failure-injection tests. A small service-level staging/publication helper may be added if it keeps transaction handling out of GUI callbacks.

**Depends on:** completed R01 validation and the existing atomic single-file image, manifest, recovery, and PNG writers. Coordinate path/output contracts needed later by R07 and R08 without implementing those feature expansions during R02.

Preflight output paths and optional settings before embedding; stage artifacts and publish under a clear overwrite policy. Preserve existing output files on failures, including overwrite rollback. Extend distinct-path checks to manifests, recovery files, original/protected files, and source aliases where applicable. Keep single-file atomic writers.

**Acceptance:** injected media, manifest, sidecar, post-processing, and final-publication failures leave original inputs and pre-existing destinations unchanged; new incomplete outputs are removed and never presented as a complete successful bundle. A documented overwrite policy applies consistently to every artifact. Same-path and filesystem-alias collisions among source, protected output, manifest, recovery sidecar, and other optional outputs are rejected before embedding. Invalid recovery/size settings fail before protection writes. Temporary and backup files are cleaned after success and failure. Optional size-preservation failure is reported separately without pretending that signing or embedding failed. Regression tests exercise new destinations, existing destinations with overwrite both disabled and enabled, injected failures at each publication step, and GUI error propagation.

**Completion evidence:** `app/services/protection.py` now validates every destination and optional setting before embedding, generates all artifacts under same-directory staging names, creates recovery from the final post-processed protected bytes, and publishes with backup/rollback semantics. `overwrite=False` rejects any existing artifact; `overwrite=True` applies to the whole bundle and restores prior files if publication fails. Direct recovery and PNG-padding writers now reject path aliases and require explicit overwrite permission. `tests/test_protection_transaction.py`, `tests/test_robustness.py`, and `tests/test_protect_tab.py` cover new/existing destinations, collision and invalid-setting preflight, media/manifest/postprocess/sidecar/publish failures, cleanup, final-byte recovery binding, conditional size reporting, and GUI error handling. The focused R02-adjacent run passes 34 tests.

**Acceptance review:** complete for the defined runtime-failure scope. Media, manifest, post-processing, sidecar, and final-publication faults are injected in focused tests. Staged generation leaves new and existing destinations untouched; final-publication faults remove newly published artifacts and restore backups. Existing destinations are rejected before embedding when overwrite is disabled and replaced as one bundle when enabled. Same-path and hard-link aliases, invalid recovery keys/paths, and invalid size flags reject before embedding. Successful and failed transactions clean their normal staging/backup files; if operating-system rollback itself fails, the service reports an incomplete rollback and deliberately retains any unrecovered backup rather than deleting the last copy. Conditional PNG size failure remains a successful protection result with a separate `unavailable:` method, and recovery hashes the final post-processed output. The GUI passes optional settings to the service, catches transaction errors, and does not preview failed output. No R02 application-code change was required by this review.

### R03 — Finish carrier integration, capacity, and compatibility checks

**Objective:** provide one exact carrier-capacity contract used by the protection service and GUI, complete image/audio boundary coverage, harden PCM-16 WAV validation and property preservation, and establish the supported compatibility boundary for retained APIs and saved artifacts.

**Likely files:** `app/services/media.py`, `app/services/protection.py`, `app/gui/protect_tab.py`, `app/stego/capacity.py`, `app/stego/image_stego.py`, `app/stego/audio_stego.py`, `app/crypto/start_location.py`, `app/crypto/signatures.py`, `tests/test_verification.py`, `tests/test_audio_stego.py`, `tests/test_audio_quality.py`, and focused capacity/compatibility tests or fixtures.

**Depends on:** completed R01 validation and R02 transactional publication. Preserve the current carrier framing and use R02 staging so all new capacity or validation failures occur before final output publication.

Provide one exact capacity calculation for services/UI, including manual offset, carrier framing, signature, encryption and triplication. Harden audio validation and preserve PCM properties; reuse shared bit helpers where it does not alter existing framing. Record legacy API versus saved-format compatibility separately.

**Acceptance:** image and mono/stereo PCM-16 WAV service round trips pass at depths 1–8, manual/derived starts, zero and exact-fit boundaries, Unicode/binary messages, and encrypted modes. Over-capacity cases reject before output creation. Image alpha and WAV rate/channel/frame counts remain unchanged. Capacity matches actual encoded length. Retained legacy fixtures either read successfully or receive an explicit unsupported/migration explanation. Replace audio quality print-only coverage with actual assertions.

### R04 — Complete usable, responsive GUI workflows

**Depends on:** R01–R03; expose R05/R07–R10 features as those land.

Add workers, progress and cancellation for long operations; move optional protection orchestration into services. Add text/file payload input, accurate capacity, recovered-file save, recognised image/audio payload preview/playback, and useful public-key fingerprint/secret export controls. Clear stale results and provide actionable errors. Keep arbitrary recovered content inert.

**Acceptance:** an automated GUI workflow signs/embeds/verifies image and audio and an encrypted file payload; saved recovered bytes match input. Invalid key paths/passwords/secrets and output collisions show errors without unhandled callbacks. A running job leaves navigation responsive and supports safe cancellation. Results distinguish trusted verification from merely parsed metadata. Manual visual QA confirms usable layout, previews, playback and file dialogs on the demo machine. Secret export is deliberate and separate from the public manifest.

### R05 — Complete robust extraction and corruption experiments

**Depends on:** R01–R03.

Retain triplication/majority voting; add bounded robust extraction using validated manifest length even when the ordinary carrier header is damaged. Keep signed verification as the final authority. Correct attack-region arithmetic to use expanded length.

**Acceptance:** both mandatory media recover from controlled single-copy bit faults, including a damaged transport header where manifest-bounded recovery is feasible. Misleading/out-of-bounds manifests are rejected. Tests cover non-dividing LSB depths, redundancy lengths and unrecoverable multi-copy faults. The outside-payload attack never writes within the expanded region, including manual start zero. Export seeded corruption results comparing recovery and capacity with/without redundancy. Do not claim resilience to arbitrary compression/resampling.

### R06 — Finish Attack Lab and failed-verification evidence

**Depends on:** R01–R03, R05 for redundancy-aware positions; R04 for GUI execution.

Retain existing copy attacks and add targeted message/record/signature changes, wrong-key and wrong-secret scenarios, truncation, seeded image/audio noise, and replay/substitution demonstrations. Run verification before/after and export settings/outcomes. Wrong-key/secret cases should change verification inputs, not unnecessarily mutate media.

**Acceptance:** image and audio positives plus at least three distinct negative verification cases are reproducible. Required negatives include an image corruption, audio corruption, and wrong public key. All attacks preserve originals; seeds/severity replay identical mutations. Replay/outside-region cases explicitly show the baseline limitation rather than false detection claims. Robust attacks distinguish corrected versus rejected corruption.

### R07 — Finish sidecar-assisted recovery workflow

**Depends on:** R01–R02, R04; coordinate final protected-file binding with R08.

Keep current encrypted sidecar format/primitives, add safe creation and GUI restoration, separate recovery key handling, and display storage overhead. Create the sidecar only after the final protected bytes are established.

**Acceptance:** GUI restores byte-for-byte original PNG/BMP/WAV files verified by SHA-256; wrong key, corrupted/truncated sidecar, wrong protected file, unsafe destination and unintended overwrite all fail safely. Existing outputs survive failure. UI/docs identify this as an encrypted original-file backup bound to the stego output, not reversible LSB or a free-capacity feature.

### R08 — Finish file-size preservation experiments

**Depends on:** R02–R03; before final recovery binding in R07.

Retain PNG chunk-padding helper, add bounded lossless compression search, and implement explicit supported-layout preservation for WAV/BMP. Keep experimental PNG padding separate from the default metadata-stripping image writer. Reject unsupported preservation layouts rather than silently claiming them.

**Acceptance:** supported WAV/BMP fixtures preserve file length and non-sample container regions; saved payloads still verify. PNG trials report exact-size success only when achieved, handle larger outputs and padding gaps below 12 bytes, and preserve decoded pixels/payload through re-encoding. Large target sizes are bounded. Export original/final sizes, method and failure reason. No general PNG exact-size guarantee is stated.

### R09 — Expose existing analysis and complete comparison/export

**Depends on:** R03–R04; reuse current image/audio analysis.

Add bit-plane and difference views, histogram comparison, existing statistical indicators, audio waveforms/differences, media properties/file hashes, and report export. Implement controlled 1–8 LSB quality experiments with documented message size, encoded size, and embedding density.

**Acceptance:** GUI renders existing backend outputs correctly; mismatched shapes/rates produce clear errors; exported metrics agree with backend results. Zero-error infinity cases display clearly. Both media provide usable before/after comparisons. Evidence records PSNR/MSE or SNR with parameters and listening observations. Statistics remain indicators, and higher depth is not claimed to be invariably more audible for every sample.

### R10 — Implement lossless video extension

**Depends on:** R01–R04; core image/audio acceptance first. FFmpeg/ffprobe availability is an additional dependency.

Replace the explanatory-only Video tab with the agreed FFV1/Matroska selected-frame workflow. Extend carrier inspection, signed extraction metadata/manifest, protection/verification, frame choice and preview. Preserve compatible audio via remuxing. Bound decoding work and fail clearly on unsupported inputs or missing tooling.

**Acceptance:** generated short sample round-trips through the saved video using verified colour-byte preservation. Tests/evidence check selected-frame pixels, frame count/timing/resolution and preserved audio properties. An invalid frame and missing tools fail clearly without disabling image/audio. A lossy-transcode experiment reports actual extraction/verification results. Include video preview and an end-to-end verification demonstration, not just a tab label.

### R11 — Generate reproducible samples and A/B bundles

**Depends on:** R01–R03 and R06; add extension fixtures after R05/R07–R10.

Generate deterministic image, mono/stereo PCM audio and short video covers with source scripts. Extract exact short/long message text from the supplied brief and create a fictional confidential custom message. Produce original/protected/tampered artifacts, manifests, public demo keys and safe regeneration instructions. Keep random security nonces/keys fresh; reproducible workflows do not mean reusing AES-GCM nonces.

**Acceptance:** one documented process reproduces outcomes and expected message bytes. A separate receiver folder needs no sender memory or private signing key. Confidentiality, capacity rejection, required positives/negatives, robustness and extensions have named fixtures. No real secrets/private keys enter committed evidence. Existing audio samples are retained or clearly identified as legacy low-level samples rather than misrepresented as signed bundles.

### R12 — Complete integration, release and evidence checks

**Depends on:** R01–R11.

Run the expanded suite and clean-environment installation, exercise real desktop workflows, and export screenshots/logs/results with settings, versions, input hashes and expected/actual outcomes. Add failure-path and GUI integration coverage missing from the current suite.

**Acceptance:** all preserved and new tests pass; fresh setup launches `main.py`; receiver image/audio verification works solely from the documented bundle and separately supplied keys. Optional tool absence is handled. Evidence supports every claim, including limits, and contains no secrets. Record actual test counts/results rather than treating today's 380 passes as release sign-off.

### R13 — Finish documentation and submission preparation

**Depends on:** R01–R12 for final claims; draft progressively as features settle.

Preserve the current planning README under project documentation and replace the root README with tested setup/use/reproduction instructions. Complete architecture/wire-format, test cases, limitations, demo plan, contribution and originality/AI-use materials. Explain trust, secret sharing, replay, media-binding limits, known-message hash leakage, and legacy compatibility. Remove stale dependency comments and clearly label optional tools/features.

**Acceptance:** every FR and rubric criterion maps to an implemented feature and evidence or an explicit limitation. Demo script fits 25 minutes and allocates all five members speaking time. Required package contents and deadlines are listed. Team ID/names, contribution percentages, acknowledgements, actual transfer/rehearsal and signatures remain truthful human-completed fields. No messages, uploads, signatures or submissions are fabricated or sent automatically.

## 7. Recommended resumption order and final handoff

1. **Protect existing work:** retain the reviewed baseline and completed R01/R02 slices. Do not restart scaffolding or rewrite tested media/analysis modules.
2. **Repair integration boundaries:** R01 and R02 are complete; implement R03 next. Add targeted regression tests for the concrete issues in section 5.
3. **Finish core user workflows:** R04, then complete R05/R06; produce initial image/audio demo bundles through R11.
4. **Complete remaining roadmap:** R08 and R07 with final-byte binding coordinated; R09; then R10 once the core is stable.
5. **Release evidence and handoff:** complete R11 -> R12 -> R13. Documentation can be drafted earlier but final claims must follow verification.

The next single implementation action should be **R03: finish carrier integration, capacity, and compatibility checks**. Its objective, dependencies, and acceptance criteria are recorded above. Likely files are `app/services/media.py`, `app/services/protection.py`, `app/gui/protect_tab.py`, `app/stego/audio_stego.py`, `tests/test_verification.py`, `tests/test_audio_stego.py`, and focused capacity/compatibility tests. Do not begin R04 or extension work while R03 remains incomplete.

No user-supplied cover media or payload is needed to resume: synthetic covers and required messages can be prepared by the implementer. The team must eventually supply identifiers, actual contributions/signatures, the demo date, and participants/devices for the real A-to-B demonstration. These external inputs do not block code completion.

Definition of done: all agreed core and extension workflows are implemented and verified within documented limits; the application is usable from a fresh documented setup; evidence and submission documents are ready for the team's review and genuine acknowledgements. The present repository is a working foundation with incomplete integration and extensions, not a completed submission.
