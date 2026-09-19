# Implementation plan and interrupted-build handoff

## Review follow-up R14: completed 2026-09-19

The latest user request authorises resuming the interrupted implementation of the review recommendations and associated documentation. This section supersedes the earlier R13-only resumption scope below; earlier acceptance counts and evidence remain historical.

**Completed:** capacity previews debounce edits for 250 ms and perform key loading, file reads, and estimation in a background worker. Revision checks discard stale successes/errors; shutdown waits safely. The GUI and README explain numeric sample locations, lowest-1-to-8-bit replacement, unchanged original files versus changed output bytes, conditional exact file size, and optional private-key password protection. Signature failures now acknowledge alteration or a mismatched public key. Existing drag-and-drop and output-location selection remain available.

The demo reserves 22 minutes for content and three for contingencies, includes all five speakers, and uses image/audio for all three mandatory negative cases. Video remains additional. The reproducible extension evaluation records false alarms, misses, inconclusive cases, and independent-bit-noise recovery at five rates. Its synthetic covers and low-level payload experiments do not establish natural-image detection accuracy or end-to-end noisy signed-carrier recovery. See [evaluation and measured limits](extension_evaluation.md).

The local release packager includes untracked deliverables and a per-file SHA-256 inventory, excludes environments/Git metadata, and rejects unexpected sample PEMs and private-key markers in non-source artifacts. It refuses overwrite and performs no commit or upload. The checkpoint does not replace a reviewed Git commit or the team's submission review.

**Validation:** the complete suite passed **584 tests in 98.34 seconds**. After a final missing-input fingerprint-label correction, all **eight focused GUI/evaluation/packaging tests passed in 4.02 seconds**. Tests cover responsiveness, stale results, coalescing, errors, closure, evaluation determinism/accounting, unchanged cover inputs, recovery limits, and archive reproducibility/inventory/overwrite/private-key checks. Compilation and whitespace checks pass. The updated controls were visually checked on native Windows; see `evidence/screenshots/review-protect-controls.png`. Measured results are in `evidence/results/review-extension-evaluation.json`. R12 clean-install evidence is historical, not a fresh-install claim for R14.

**Next:** H01 below remains the next human operational task, now depending on R01 through R14. Conduct the real A-to-B transfer and timed rehearsal, then record actual observations and complete team declarations. No transfer, listening observation, signature, or submission has been fabricated.

## 1. Review baseline and instructions for resuming

This document reconciles the agreed whole-project plan in the conversation with the repository as inspected and resumed through 2026-09-19. It is a continuation plan, not a request to replace the existing implementation.

- Current HEAD: `5f2041e` — `Add comprehensive tests for media protection, recovery, and size preservation`. The completed R03–R13 work remains in the current working tree.
- R13 acceptance review on 2026-09-19: the focused release-check run was **5 passed in 11.14 seconds** and the repository run was **578 passed in 98.25 seconds** with no failures. All 10 receiver cases and capacity rejection reproduce, the R12 finalizer passes, all 11 Markdown files have valid local links, the original planning README is preserved byte-for-byte, all five members have timed demo roles, required mappings/deadlines are present, personal paths are removed, and human declarations remain explicitly incomplete. Compilation and `git diff --check` also pass.
- R12 acceptance review on 2026-09-19: the focused release-check run was **5 passed in 10.97 seconds**. The repository run was **578 passed in 98.85 seconds** with no failures. A clean Python 3.14 installation, dependency check, startup smoke test, 10-case receiver audit, optional-tool-absence path, native Windows Qt workflows, screenshot review, artifact hashes, and secret exclusions all pass. Compilation and `git diff --check` also pass.
- R11 acceptance review on 2026-09-18: the focused reproducible-bundle run was **6 passed in 20.99 seconds**. The repository run was **573 passed in 85.59 seconds** with no failures. All 10 receiver cases and the separate capacity-rejection case reproduce their expected outcomes; compilation and `git diff --check` also pass.
- R10 acceptance review on 2026-09-18: the focused video, GUI, verification, transaction, and security-boundary run was **84 passed in 47.67 seconds**. The repository run was **567 passed in 63.51 seconds** with no failures. Compilation and `git diff --check` also pass.
- R09 acceptance review on 2026-09-18: the focused image/audio analysis, GUI and operation-control run was **105 passed in 1.96 seconds**. The repository run was **561 passed in 16.78 seconds** with no failures. Compilation and `git diff --check` also pass.
- R04 acceptance review, reconfirmed on 2026-09-18: the focused GUI/workflow/service run was **78 passed in 6.09 seconds** and the threading-heavy GUI subset passed three consecutive runs. The repository run was **501 passed, 1 failed in 16.36 seconds**; the sole failure remains the unchanged R09 RGB-versus-alpha metric inconsistency. A native Windows desktop run completed real encrypted image/audio file-payload workflows, advanced WAV playback without a media error, opened and cancelled the platform file picker, switched tabs during a running operation, cancelled cleanly, and produced visually reviewed Protect/Verify screens.
- R03 acceptance review on 2026-09-18: the focused carrier/capacity/audio/verification/transaction/GUI run was **122 passed in 5.04 seconds**. The repository run was **496 passed, 1 failed in 12.72 seconds**. The sole failure remains the unchanged R09 RGB-versus-alpha metric inconsistency recorded below.
- R02 acceptance review on 2026-09-17: the focused transaction/recovery/GUI/verification run was **34 passed in 2.22 seconds**. The repository run was **451 passed, 1 failed in 14.44 seconds**. The remaining failure is the pre-existing RGB-versus-alpha metric inconsistency recorded under R09 below, exposed by Hypothesis with an alpha-only difference.
- The release requirements are pinned to Python 3.14-compatible versions and were installed from binary wheels in a fresh environment. `pip check`, application startup, focused release checks, and the complete suite pass in that environment.
- The suite includes subprocess-based offscreen GUI workflow tests. R04 also received a native Windows desktop acceptance run; later optional-feature and release-machine checks remain scoped to their own tasks.
- `ffmpeg` and `ffprobe` are discoverable on PATH, their versions are recorded in release evidence, and generated-video tests exercise them. The release audit separately confirms that mandatory image/audio inspection remains usable when those optional executables are absent.
- No applicable `AGENTS.md` was found in the repository search.
- R01 hardens the security boundaries. R02 adds staged bundle publication and rollback. R03 supplies exact carrier integration and compatibility boundaries. R04 completes responsive image/audio GUI protection and verification workflows, trusted recovered-payload handling, and deliberate secret export.

Preserve the existing image layer, audio layer, security primitives, services, widgets, tests, and passing behaviour. Resume with the focused integration and validation tasks below. Empty files are not evidence that equivalent functionality is absent elsewhere.

### Source precedence and agreed scope

1. User instructions in this conversation define authorised work. The latest request authorises R13 acceptance testing and this plan update only; the human handoff task identified below has not started.
2. The assignment brief defines assessed requirements: `INF2005-ACW1-spec_v5-f2f.pdf`, previously read in full from the team-provided course-material location outside this repository.
3. [The preserved planning README](planning_reference.md) supplies team context and proposed engineering choices. [The repository README](../README.md) is now the tested setup, use, reproduction, and evidence guide.
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
- `app/services/protection.py`: `ProtectionCapacity` and `estimate_protection_capacity(...)` expose the actual signed-envelope and robustness cost without writing files.
- `app/services/media.py`: `CarrierInfo`, `CarrierCapacity`, `inspect_carrier(...)`, and carrier-specific framing overhead.
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

The implemented architecture is feature-complete for the agreed build scope and is documented in `docs/architecture.md`, with compatibility and claim boundaries in the adjacent documentation. UI success must continue to say **“Message and signed record verified.”** Treat uncertain extraction failures as `CANNOT_VERIFY`, not a proven wrong-start cause.

## 4. Completed work to preserve

“Completed” below means the stated slice exists and has relevant passing coverage; it does not mean the entire subsystem is release-ready.

| Completed slice | Implementation and evidence |
| --- | --- |
| Baseline environment | Local `.venv` and working pytest invocation. Original baselines were 357 and then 380 passing tests; the post-R12 suite is 578 passing tests. Exact pinned installation, dependency consistency and startup are validated on Python 3.14. |
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
| R03 carrier integration and capacity | Protection and the GUI use one `CarrierCapacity` contract calculated from the actual signed envelope, encryption expansion, robustness expansion, carrier framing, depth, and start. Image plus mono/stereo PCM-16 WAV service round trips cover depths 1–8, manual/derived starts, encrypted and binary/Unicode payloads, exact-fit and over-capacity boundaries, alpha preservation, and WAV rate/channel/frame preservation. Direct WAV output now has explicit alias/overwrite and decoded-property checks. Audio quality tests use generated fixtures and assertions. [Compatibility boundaries](compatibility.md) distinguish callable APIs from saved-byte compatibility. Focused tests: 122 passed. |
| R04 responsive GUI workflows | Protect and Verify support text or file payloads, worker execution, progress, cooperative cancellation, exact file-byte recovery, authenticated image/WAV preview or playback, signer fingerprints, stale-result clearing, and private secret export separate from the manifest. Attack and Analysis operations also run outside the GUI thread. Automated and native Windows desktop acceptance runs cover image/audio encryption, errors, collisions, navigation, cancellation, dialogs, layout and playback. Focused tests: 78 passed. |
| R05 robust extraction and experiments | Repetition-3 verification uses strictly bounded manifest lengths to recover image and audio payloads when carrier header values are damaged, while signed-envelope verification remains authoritative. Attack positions use the expanded stored length. Deterministic experiments report seeded faults, exact recovery, capacity cost and stated limitations. Focused and adjacent tests: 216 passed. |
| R06 Attack Lab evidence | Attack Lab runs paired baseline/outcome verification for targeted record/message/signature corruption, valid-container truncation simulation, deterministic image/audio noise, wrong keys/secrets, substitution, replay and outside-region edits. JSON reports record settings, checks, fingerprints, message digests and explicit trust-boundary limitations without secret values. Focused tests: 50 passed. |
| R07 sidecar-assisted recovery | Verify now provides safe desktop restoration from the encrypted complete-original sidecar using a separate recovery key, strict bounded framing inspection, protected-file binding, explicit overwrite confirmation, SHA-256 confirmation, and storage-overhead presentation. PNG/BMP/WAV workflow and failure-path tests pass. Focused and adjacent tests: 94 passed. |
| R08 size/layout preservation | PNG preservation searches all ten bounded lossless compression levels and adds legal private ancillary padding only when an exact target is attainable. Supported BMP and PCM-16 WAV paths retain original container bytes outside sample regions and preserve exact length. Transactional JSON reports record sizes, method, attempts and failure reason. Focused and adjacent tests: 277 passed. |
| R09 analysis and comparison evidence | Analysis presents image bit-plane, amplified-difference and per-channel histogram views, every existing statistical indicator, audio waveform/difference views, media properties and SHA-256 hashes. Atomic JSON reports and deterministic depth-1–8 experiments record message/encoded sizes, density and quality metrics with explicit interpretation limits and human listening observations. Focused tests: 105 passed; full suite: 561 passed. |
| R10 lossless video extension | Bounded FFmpeg/ffprobe integration embeds the framed signed payload into one authenticated frame of a short video, writes FFV1 Matroska, remuxes compatible audio, and verifies the complete decoded RGB frame set plus timing, resolution, frame rate/count and audio-stream properties before publication. Protection, verification, preview and an actual H.264 verification-failure experiment are integrated through the GUI and services. Focused tests: 84 passed; full suite: 567 passed. |
| R11 reproducible sample and receiver bundles | One atomic generator creates deterministic image, mono/stereo PCM and FFV1 covers plus brief-derived short/long and fictional confidential messages while using fresh RSA/AES keys, start secrets and payload nonces. The standalone receiver bundle contains 10 indexed positive/negative/robustness/video cases, capacity-rejection evidence, portable paths, expected bytes, a public key and explicitly labelled demonstration secrets, but no signing private key. Focused tests: 6 passed; full suite: 573 passed. |
| R12 release integration and evidence | Python 3.14-compatible direct dependencies install from binary wheels in a clean environment, `pip check` passes, and `main.py --smoke-test` proves application startup. Automated release audits reproduce all 10 receiver cases, exercise optional FFmpeg absence, run three native Windows Qt image/audio verification workflows, capture visually reviewed screenshots, validate hashes, and reject private-key or secret leakage. Focused tests: 5 passed; full suite: 578 passed. |
| R13 documentation and submission preparation | The original planning README is preserved byte-for-byte and the root README now supplies tested setup, operation, reproduction, evidence, and key-handling instructions. Architecture, wire format, limitations, compatibility, requirement/rubric mapping, ten receiver cases, a 25-minute five-member demo, contribution/originality templates, AI-use disclosure, deadlines, evidence index, and packaging checks are documented. Personal paths were removed and all human-specific claims remain placeholders. Focused tests: 5 passed; full suite: 578 passed. |

## 5. Remaining human completion items

No implementation or documentation slice remains after R01 through R13. The following external facts and actions cannot be completed truthfully from the repository alone.

| Files / area | Observed incomplete or inconsistent behaviour | Follow-up |
| --- | --- | --- |
| Human handoff | Team identifiers, actual contributions, acknowledgements, transfer/rehearsal observations, official declaration wording, and signatures require truthful completion by the team. | H01 |

### Empty scaffold inventory

- Media-specific attack placeholders: `app/attacks/image_attacks.py`, `audio_attacks.py`, `video_attacks.py`. Working attacks already live in `payload_attacks.py`.
- Analysis placeholders: `app/analysis/quality_metrics.py`, `steganalysis.py`. Working image/audio analysis already exists in the media-specific modules.
- Comparison placeholder: `app/verification/media_compare.py`.
- Utility placeholders: `app/utils/constants.py`, `file_utils.py`, `logging_utils.py`, `media_utils.py`.
- Empty package `__init__.py` files and `.gitkeep` files are normal scaffolding, not broken implementations.
- `app/robustness/error_correction.py` is a re-export of the implemented repetition helpers, not a separate error-correction algorithm. Do not infer Hamming/Reed-Solomon support from its filename.

Do not fill placeholders just to make every file non-empty. Extend existing owners or remove unused scaffolding only when the relevant feature is completed and references are checked.

## 6. Remaining tasks, dependencies, and acceptance criteria

R01 through R13 are complete. No further implementation task is planned. H01 is the next operational task and requires the real team, devices, course details, observations, and signatures.

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

### R03 — Finish carrier integration, capacity, and compatibility checks — COMPLETE

**Objective:** provide one exact carrier-capacity contract used by the protection service and GUI, complete image/audio boundary coverage, harden PCM-16 WAV validation and property preservation, and establish the supported compatibility boundary for retained APIs and saved artifacts.

**Likely files:** `app/services/media.py`, `app/services/protection.py`, `app/gui/protect_tab.py`, `app/stego/capacity.py`, `app/stego/image_stego.py`, `app/stego/audio_stego.py`, `app/crypto/start_location.py`, `app/crypto/signatures.py`, `tests/test_verification.py`, `tests/test_audio_stego.py`, `tests/test_audio_quality.py`, and focused capacity/compatibility tests or fixtures.

**Depends on:** completed R01 validation and R02 transactional publication. Preserve the current carrier framing and use R02 staging so all new capacity or validation failures occur before final output publication.

Provide one exact capacity calculation for services/UI, including manual offset, carrier framing, signature, encryption and triplication. Harden audio validation and preserve PCM properties; reuse shared bit helpers where it does not alter existing framing. Record legacy API versus saved-format compatibility separately.

**Acceptance:** image and mono/stereo PCM-16 WAV service round trips pass at depths 1–8, manual/derived starts, zero and exact-fit boundaries, Unicode/binary messages, and encrypted modes. Over-capacity cases reject before output creation. Image alpha and WAV rate/channel/frame counts remain unchanged. Capacity matches actual encoded length. Retained legacy fixtures either read successfully or receive an explicit unsupported/migration explanation. Replace audio quality print-only coverage with actual assertions.

**Completion evidence:** `CarrierInfo.capacity(...)` is the common carrier-cost calculation, and `estimate_protection_capacity(...)` builds the actual versioned signed envelope without writing so both the service and Protect tab report envelope bytes, repetition expansion, media framing, required samples, available samples, start, and fit consistently. Protection reuses the same preparation path before R02 staging. `tests/test_carrier_integration.py` exercises all depths for image/mono/stereo WAV, manual and derived starts, AES-GCM, binary/Unicode payloads, start zero, exact fit, over-capacity rejection, alpha, PCM properties, and triplication. `tests/test_audio_stego.py` locks the retained low-level packet adapters, PCM-16 validation, aliases, and overwrite policy. `tests/test_audio_quality.py` now generates mono/stereo fixtures and asserts distortion bounds and mismatched-rate handling. The offscreen Protect-tab test checks exact capacity presentation. `docs/compatibility.md` records why pre-versioned start/signature artifacts require their original revision while current low-level carrier packets remain extractable with known settings.

**Acceptance review:** complete. The focused R03 suite passes all 122 tests and covers image plus mono/stereo PCM-16 WAV at depths 1–8, manual and derived starts, start zero, exact-fit and over-capacity boundaries, Unicode and binary payloads, encryption, repetition expansion, alpha preservation, WAV rate/channel/frame preservation, adapter compatibility, and asserted audio distortion bounds. Capacity estimates use the exact prepared signed and optionally encrypted/repeated payload, agree with the bytes passed to the carrier, and reject insufficient capacity before output creation. The compatibility note explicitly distinguishes retained callable/packet compatibility from unsupported pre-versioned signed artifacts. The full suite passes 496 tests; its sole failure is the separately tracked R09 alpha-only quality-metric inconsistency and does not exercise the R03 carrier path. No R03 application-code change was required by this review.

### R04 — Complete usable, responsive GUI workflows — COMPLETE

**Objective:** make the existing image/audio protection and verification journeys usable end to end in the desktop UI, including file payloads, responsive execution, cancellation, recovered-content handling, and clear trust/error state.

**Likely files:** `app/gui/main_window.py`, `app/gui/protect_tab.py`, `app/gui/verify_tab.py`, `app/gui/widgets/result_panel.py`, `app/gui/widgets/media_preview.py`, a focused worker/controller module under `app/gui/`, supporting service orchestration under `app/services/`, and GUI workflow tests under `tests/`.

**Depends on:** completed R01 validation, R02 transactional publication, and R03 carrier/capacity integration. Later R05/R07–R10 features should be exposed only as those tasks land.

Add workers, progress and cancellation for long operations; move optional protection orchestration into services. Add text/file payload input, accurate capacity, recovered-file save, recognised image/audio payload preview/playback, and useful public-key fingerprint/secret export controls. Clear stale results and provide actionable errors. Keep arbitrary recovered content inert.

**Acceptance:** an automated GUI workflow signs/embeds/verifies image and audio and an encrypted file payload; saved recovered bytes match input. Invalid key paths/passwords/secrets and output collisions show errors without unhandled callbacks. A running job leaves navigation responsive and supports safe cancellation. Results distinguish trusted verification from merely parsed metadata. Manual visual QA confirms usable layout, previews, playback and file dialogs on the demo machine. Secret export is deliberate and separate from the public manifest.

**Completion evidence:** `TaskRunner` provides one owned background thread per operation, with progress and cooperative cancellation. Protection checks cancellation at transaction-safe stages before bundle publication. Protect accepts UTF-8 text or bounded file bytes, signs the MIME type and safe source filename, reports exact capacity, displays the signer fingerprint, and exports selected secrets only through a separately confirmed private bundle. Verify clears stale state, displays the trusted-key fingerprint, exposes recovered bytes only after an `AUTHENTIC` result, previews authenticated PNG/BMP payloads, loads authenticated WAV payloads for playback, and writes recovered bytes atomically with explicit overwrite handling. Protect, Verify, Attack and Analysis freeze their input snapshot while work runs but leave main-tab navigation active. `tests/test_gui_workflows.py`, `tests/test_operation_controls.py`, and the updated Protect tests cover complete encrypted image/audio file workflows, byte-exact recovery, trusted/untrusted state, invalid paths/passwords/secrets, collisions, responsiveness, cancellation cleanup, and explicit output writers.

**Acceptance review:** complete and reconfirmed. The focused R04 and adjacent suite passes 78 tests; the threading-heavy GUI subset passed three consecutive independent runs. The latest full-suite run passes 501 tests, with only the separately tracked R09 alpha-only quality-metric failure. On the native Windows desktop backend, real encrypted image and stereo PCM-16 WAV workflows both produced and verified complete bundles with exact recovered file bytes. WAV playback advanced to 64 ms with no media error. The platform file picker remained visible for approximately one second and cancelled cleanly, tab navigation changed during a running operation, and cooperative cancellation reported `Operation cancelled.` Visual review confirmed readable Protect and Verify layouts, working scroll regions, side-by-side media views, an explicit trusted result, detailed checks, and recovered-payload controls. Secret export requires a separate path and confirmation and is never written to the public manifest.

### R05 — Complete robust extraction and corruption experiments — COMPLETE

**Objective:** make repetition-3 recovery use bounded manifest information when carrier framing is damaged, and make corruption experiments calculate the complete expanded embedded region correctly.

**Likely files:** `app/verification/verifier.py`, `app/stego/image_stego.py`, `app/stego/audio_stego.py`, `app/robustness/redundancy.py`, `app/attacks/payload_attacks.py`, and focused tests in `tests/test_robustness.py`, `tests/test_verification.py`, and `tests/test_attacks.py`.

**Depends on:** completed R01–R04 validation, transactional publication, carrier-capacity integration, and responsive GUI execution.

Retain triplication/majority voting; add bounded robust extraction using validated manifest length even when the ordinary carrier header is damaged. Keep signed verification as the final authority. Correct attack-region arithmetic to use expanded length.

**Acceptance:** both mandatory media recover from controlled single-copy bit faults, including a damaged transport header where manifest-bounded recovery is feasible. Misleading/out-of-bounds manifests are rejected. Tests cover non-dividing LSB depths, redundancy lengths and unrecoverable multi-copy faults. The outside-payload attack never writes within the expanded region, including manual start zero. Export seeded corruption results comparing recovery and capacity with/without redundancy. Do not claim resilience to arbitrary compression/resampling.

**Completion evidence:** image and audio now expose bounded extraction paths that skip fixed carrier framing and read exactly the validated expanded manifest length. The verifier uses these paths only for repetition-3, then requires successful majority decoding, envelope parsing, RSA-PSS verification, signer matching, signed-record/manifest agreement, optional authenticated decryption and plaintext hashing before returning `AUTHENTIC`. Attack arithmetic targets the actual expanded boundary and keeps outside-payload edits beyond the full occupied region. A seeded experiment API compares unprotected and repetition-3 recovery, stored bytes and required samples, and atomically exports JSON with an explicit compression/resampling limitation. Tests cover image and stereo PCM-16 WAV, depths 3/5/6/7, damaged headers, one-copy recovery, two-copy rejection, misleading and oversized manifests, manual start zero, deterministic export and overwrite refusal.

**Acceptance review:** complete. The focused R05 and adjacent suite passes 216 tests, compilation succeeds and `git diff --check` reports no whitespace errors. The complete suite passes 522 tests with only the separately tracked R09 alpha-only image-quality inconsistency. Review found no path that treats manifest-bounded bytes as authentic before the existing cryptographic checks, and no R05 acceptance item remains incomplete.

### R06 — Finish Attack Lab and failed-verification evidence — COMPLETE

**Objective:** turn the existing attack primitives into reproducible image/audio verification demonstrations with controlled negative inputs, before/after outcomes and exportable evidence.

**Likely files:** `app/attacks/payload_attacks.py`, `app/attacks/`, `app/gui/attack_tab.py`, `app/verification/verifier.py` only if a result contract needs extension, and focused attack/service/GUI tests under `tests/`.

**Depends on:** R01–R03, R05 for redundancy-aware positions; R04 for GUI execution.

Retain existing copy attacks and add targeted message/record/signature changes, wrong-key and wrong-secret scenarios, truncation, seeded image/audio noise, and replay/substitution demonstrations. Run verification before/after and export settings/outcomes. Wrong-key/secret cases should change verification inputs, not unnecessarily mutate media.

**Acceptance:** image and audio positives plus at least three distinct negative verification cases are reproducible. Required negatives include an image corruption, audio corruption, and wrong public key. All attacks preserve originals; seeds/severity replay identical mutations. Replay/outside-region cases explicitly show the baseline limitation rather than false detection claims. Robust attacks distinguish corrected versus rejected corruption.

**Completion evidence:** `app/attacks/experiments.py` now runs an `AUTHENTIC` baseline before every controlled outcome and exports atomic `SMIV-ATTACK-EVIDENCE` JSON with scenario settings, key fingerprints, verification checks, verdicts and authenticated message digests rather than recovered content or secret values. Targeted signed-record, stored-message and signature bit changes, valid-container tail erasure, seeded stored-payload noise, wrong-key/secret inputs, substituted manifests, byte-identical replay copies and outside-region edits are supported for image/audio workflows as applicable. Mutation functions write separate outputs and reject aliases/collisions. Attack Lab exposes scenario, seed, severity, repetition-copy, verification-input and report controls, runs on the existing worker, and presents baseline/outcome verdicts plus the relevant limitation.

**Acceptance review:** complete. The focused attack, robustness, verification, GUI workflow and operation-control suite passes 50 tests. Tests cover authenticated image/audio baselines, three targeted negative regions for each medium, wrong public key and wrong derived-start secret without media mutation, valid-container truncation, deterministic seeded noise, source preservation, substitution, replay and outside-region boundaries, atomic report collision handling, robust one-copy correction versus two-copy rejection, and an offscreen end-to-end Attack Lab export. The complete suite passes 537 tests with only the separately tracked R09 alpha-only image-quality inconsistency. Compilation and `git diff --check` pass, and no R06 acceptance item remains incomplete.

### R07 — Finish sidecar-assisted recovery workflow — COMPLETE

**Objective:** complete the encrypted sidecar workflow from final protected-byte binding through safe desktop restoration, with separate key handling and clear storage-cost and trust-boundary presentation.

**Likely files:** `app/robustness/recovery.py`, `app/services/protection.py`, a recovery orchestration service under `app/services/`, `app/gui/protect_tab.py`, `app/gui/verify_tab.py` or a focused recovery panel, and recovery/service/GUI tests under `tests/`.

**Depends on:** R01–R02, R04; coordinate final protected-file binding with R08.

Keep current encrypted sidecar format/primitives, add safe creation and GUI restoration, separate recovery key handling, and display storage overhead. Create the sidecar only after the final protected bytes are established.

**Acceptance:** GUI restores byte-for-byte original PNG/BMP/WAV files verified by SHA-256; wrong key, corrupted/truncated sidecar, wrong protected file, unsafe destination and unintended overwrite all fail safely. Existing outputs survive failure. UI/docs identify this as an encrypted original-file backup bound to the stego output, not reversible LSB or a free-capacity feature.

**Completion evidence:** `app/robustness/recovery.py` strictly inspects the versioned sidecar framing, exact declared length and configured size bound before decryption, then authenticates the complete-original backup and its protected-file SHA-256 binding before any atomic output write. `app/services/recovery.py` adds cancellable restoration orchestration and re-hashes the written output. The Verify tab embeds a focused recovery panel with a separate masked key, protected-media synchronisation, sidecar size/overhead inspection and explicit overwrite confirmation. Protect reports the sidecar's total bytes and format/authentication overhead and describes it as a complete encrypted original-file backup created from the final post-processed stego bytes. `tests/test_recovery_workflow.py` and the offscreen GUI workflow cover byte-exact PNG/BMP/WAV restoration and SHA-256 confirmation.

**Acceptance review:** complete. The focused R07 and adjacent recovery, transaction, carrier, verification and GUI suite passes all 94 tests. Wrong keys, corrupted or truncated sidecars, unsupported versions, trailing data, different protected files, path aliases, existing destinations and overwrite failures are rejected without creating or damaging output. Existing output survives even when overwrite was requested but authentication fails. The complete suite passes 554 tests; its sole failure is the separately tracked R09 alpha-only image-quality inconsistency. `git diff --check` reports no whitespace errors, and no R07 acceptance item remains incomplete.

### R08 — Finish file-size preservation experiments — COMPLETE

**Objective:** make size/layout preservation measurable and honest for the supported PNG, BMP and PCM-16 WAV cases, while ensuring every post-processed protected file still verifies and remains compatible with recovery binding.

**Likely files:** `app/services/size_preservation.py`, `app/services/protection.py`, `app/stego/image_io.py`, `app/stego/audio_stego.py`, `app/gui/protect_tab.py`, and focused size/layout, protection-transaction and GUI tests under `tests/`.

**Depends on:** R02–R03; before final recovery binding in R07.

Retain PNG chunk-padding helper, add bounded lossless compression search, and implement explicit supported-layout preservation for WAV/BMP. Keep experimental PNG padding separate from the default metadata-stripping image writer. Reject unsupported preservation layouts rather than silently claiming them.

**Acceptance:** supported WAV/BMP fixtures preserve file length and non-sample container regions; saved payloads still verify. PNG trials report exact-size success only when achieved, handle larger outputs and padding gaps below 12 bytes, and preserve decoded pixels/payload through re-encoding. Large target sizes are bounded. Export original/final sizes, method and failure reason. No general PNG exact-size guarantee is stated.

**Completion evidence:** `app/services/size_preservation.py` now dispatches by file signature to bounded PNG, BMP and WAV strategies. PNG tries compression levels 0–9, accepts only exact output or a legal ancillary-chunk gap, caps target and padding allocations, and returns an explicit failure reason while retaining a valid verifying output when exact size is unavailable. BMP replacement retains original headers, row padding, orientation, metadata and trailing bytes while replacing only BGR(A) sample bytes. WAV replacement retains the original RIFF structure and every non-data chunk while replacing only frame-aligned integer PCM-16 sample bytes. Unsupported or internally inconsistent layouts are rejected. Optional JSON reports are staged and published with the protected bundle; recovery sidecars continue to bind after preservation to the final staged bytes. Protect displays measured original/final sizes, method and failure reason.

**Acceptance review:** complete. The focused R08 and adjacent carrier, verification, image/audio I/O, transaction and GUI suite passes 277 tests. Tests verify exact BMP/WAV file length, byte equality outside sample regions, preservation of custom BMP header/trailer bytes and a WAV `JUNK` chunk, successful signed-payload verification, PNG exact-size search/padding, valid larger-output failure reporting, sub-12-byte padding rejection, target bounds, atomic JSON export, report-path validation and report-failure cleanup. The complete suite passes 547 tests with only the separately tracked R09 alpha-only image-quality inconsistency. Compilation and `git diff --check` pass, and no R08 acceptance item remains incomplete.

### R09 — Expose existing analysis and complete comparison/export — COMPLETE

**Objective:** complete the image/audio comparison workflow and exported evidence, including consistent image equality metrics for alpha-channel changes and controlled depth experiments whose claims match the measured data.

**Likely files:** `app/analysis/image_analysis.py`, `app/analysis/audio_analysis.py`, `app/gui/steganalysis_tab.py`, existing comparison/result widgets where reuse is appropriate, and focused analysis/GUI/report tests in `tests/test_image_analysis.py`, `tests/test_audio_quality.py`, and `tests/test_gui_workflows.py`.

**Depends on:** R03–R04; reuse current image/audio analysis.

Add bit-plane and difference views, histogram comparison, existing statistical indicators, audio waveforms/differences, media properties/file hashes, and report export. Implement controlled 1–8 LSB quality experiments with documented message size, encoded size, and embedding density.

**Acceptance:** GUI renders existing backend outputs correctly; mismatched shapes/rates produce clear errors; exported metrics agree with backend results. Zero-error infinity cases display clearly. Both media provide usable before/after comparisons. Evidence records PSNR/MSE or SNR with parameters and listening observations. Statistics remain indicators, and higher depth is not claimed to be invariably more audible for every sample.

**Completion evidence:** `app/analysis/experiments.py` builds one comparison bundle for display and export, including media properties, streaming SHA-256 file hashes, image quality/per-channel metrics, bit-plane and amplified-difference arrays, complete histograms, all four existing indicator families, and downsampled audio waveform/difference data. It runs the same deterministic payload from sample zero at depths 1–8 and records message bytes, carrier-encoded bytes, written/total samples, embedding density, MSE, PSNR or SNR, maximum difference and changed-sample percentage. JSON export is atomic, refuses unintended overwrite and encodes unbounded metrics as `null` plus an explicit flag instead of non-standard numeric literals. The Analysis tab renders these results from its worker, accepts a human listening observation, and labels the statistical and perceptibility limits.

**Acceptance review:** complete. The focused analysis, GUI and operation-control suite passes all 105 tests; the complete repository suite passes all 561 tests. Tests cover image and stereo PCM-16 audio displays, exported/backend metric agreement, all eight depth rows, message/encoded sizes and density, file hashes/properties, indicator families, overwrite refusal, mismatched media, shapes and sample rates, human listening notes, offscreen pixmap rendering and JSON export. Alpha-only image changes now explicitly report colour equality and zero colour-channel MSE/∞ PSNR while still reporting whole-image inequality and the alpha-channel error. The GUI and report state that indicators are not detection and that depth observations apply only to the tested cover/message. Compilation and `git diff --check` pass, and no R09 acceptance item remains incomplete.

### R10 — Implement lossless video extension — COMPLETE

**Objective:** add the optional FFV1/Matroska video carrier as a complete protected-media workflow, including selected-frame embedding, signed extraction settings, verification, preview, compatible audio remuxing and measured lossless/lossy evidence, without weakening image/audio behavior.

**Likely files:** `app/stego/video_stego.py`, `app/gui/video_tab.py`, `app/services/media.py`, `app/services/protection.py`, `app/verification/verifier.py`, payload/manifest schema handling where video settings must be authenticated, and focused video service/GUI tests plus generated short fixtures under `tests/`.

**Depends on:** R01–R04; core image/audio acceptance first. FFmpeg/ffprobe availability is an additional dependency.

Replace the explanatory-only Video tab with the agreed FFV1/Matroska selected-frame workflow. Extend carrier inspection, signed extraction metadata/manifest, protection/verification, frame choice and preview. Preserve compatible audio via remuxing. Bound decoding work and fail clearly on unsupported inputs or missing tooling.

**Acceptance:** generated short sample round-trips through the saved video using verified colour-byte preservation. Tests/evidence check selected-frame pixels, frame count/timing/resolution and preserved audio properties. An invalid frame and missing tools fail clearly without disabling image/audio. A lossy-transcode experiment reports actual extraction/verification results. Include video preview and an end-to-end verification demonstration, not just a tab label.

**Completion evidence:** `app/stego/video_stego.py` provides bounded probe/decode operations, four-byte carrier framing, standard and manifest-bounded extraction, selected-frame LSB embedding, staged FFV1/Matroska output, compatible audio remuxing, and H.264 experiment transcoding. Before publication it decodes the saved file and requires byte-exact agreement with every intended RGB frame plus stable dimensions, frame count/rate, timing and audio-stream properties. The signed record and canonical manifest require the selected frame index for video and reject it for other media. Carrier inspection, capacity calculation, protection, robust extraction, verification and GUI controls all use that authenticated setting. The Video tab previews a selected frame and exports atomic lossy-experiment evidence based on an actual verification attempt.

**Acceptance review:** complete. Generated 96×64 six-frame FFV1/PCM fixtures round-trip through direct and encrypted signed service workflows. Tests assert exact unchanged frames outside the selection, intended selected-frame bytes after save/redecode, frame count/rate/duration/resolution, decoded audio bytes and audio properties. They also cover invalid frame selection, absent tools with image/audio inspection still usable, repetition-3 bounded extraction, signed frame-index mismatch, offscreen Protect-to-Verify operation, selected-frame preview, and an H.264 experiment whose report records the actual non-authentic verdict and checks. The focused R10 and adjacent run passes all 84 tests; the complete repository suite passes all 567 tests. Compilation and `git diff --check` pass, and no R10 acceptance item remains incomplete.

### R11 — Generate reproducible samples and A/B bundles — COMPLETE

**Objective:** create deterministic, documented sender and receiver evidence bundles for the required image/audio cases and completed extensions, while generating fresh cryptographic keys and nonces and excluding private signing keys from receiver or committed evidence.

**Likely files:** a focused generator under `scripts/` or `tools/`; generated and documented artifacts under `samples/image/`, `samples/audio/`, `samples/video/`, and `samples/receiver/`; public demo-key material; and focused generator/reproduction tests plus sample-specific instructions under `samples/` or `docs/test_cases.md`.

**Depends on:** R01–R03 and R06; add extension fixtures after R05/R07–R10.

Generate deterministic image, mono/stereo PCM audio and short video covers with source scripts. Extract exact short/long message text from the supplied brief and create a fictional confidential custom message. Produce original/protected/tampered artifacts, manifests, public demo keys and safe regeneration instructions. Keep random security nonces/keys fresh; reproducible workflows do not mean reusing AES-GCM nonces.

**Acceptance:** one documented process reproduces outcomes and expected message bytes. A separate receiver folder needs no sender memory or private signing key. Confidentiality, capacity rejection, required positives/negatives, robustness and extensions have named fixtures. No real secrets/private keys enter committed evidence. Existing audio samples are retained or clearly identified as legacy low-level samples rather than misrepresented as signed bundles.

**Completion evidence:** `scripts/generate_samples.py` atomically creates deterministic RGB image, mono/stereo PCM and six-frame FFV1/PCM covers, the whitespace-normalised brief Learning Outcome and Project Overview messages, and a clearly fictional confidential message. Each run creates fresh RSA/AES keys, derived-start secrets and envelope nonces, then discards the signing private key. `samples/r11/receiver/case-index.json` names six authentic and four non-authentic image/audio/video outcomes, including AES-GCM confidentiality, repetition-3 correction/failure and measured H.264 loss, while `capacity-rejection.json` records rejection before output creation. The receiver folder includes only its public key, expected message bytes, manifests, media and labelled evidence-only AES/start values. `scripts/verify_sample_bundle.py` reproduces every indexed result without sender state. Legacy WAV examples remain untouched and are explicitly labelled unsigned low-level samples.

**Acceptance review:** complete. The checked-in bundle has 63 files, with all 62 non-index files matching the size and SHA-256 inventory in `bundle-index.json`. All 10 receiver cases match their recorded verdicts and recovered bytes, and the independent capacity case confirms no output was created. The matrix supplies positive and negative cases for both mandatory media, four actual verification-negative cases overall, deterministic original/protected/tampered artifacts, mono/stereo audio, confidentiality, robustness and video extensions. Regeneration tests prove cover/message bytes remain deterministic while RSA fingerprints, AES keys, start secrets and payload nonces change. JSON contains no absolute workspace path, no PEM private-key marker exists, and the public-key ignore exception is limited to the named receiver key. The focused R11 suite passes all 6 tests; the complete repository suite passes all 573 tests. Compilation and `git diff --check` pass, and no R11 acceptance item remains incomplete.

### R12 — Complete integration, release and evidence checks — COMPLETE

**Objective:** validate a release candidate from a clean supported environment and native desktop, close only integration defects exposed by that audit, and capture reproducible evidence for every implemented claim without including secrets.

**Likely files:** `requirements.txt`, `pytest.ini` or narrowly related startup/configuration files if the clean install exposes defects; focused release-check scripts under `scripts/`; integration tests under `tests/`; and generated version, hash, result, log and screenshot artifacts under `evidence/results/`, `evidence/logs/`, and `evidence/screenshots/`.

**Depends on:** R01–R11.

Run the expanded suite and clean-environment installation, exercise real desktop workflows, and export screenshots/logs/results with settings, versions, input hashes and expected/actual outcomes. Add failure-path and GUI integration coverage missing from the current suite.

**Acceptance:** all preserved and new tests pass; fresh setup launches `main.py`; receiver image/audio verification works solely from the documented bundle and separately supplied keys. Optional tool absence is handled. Evidence supports every claim, including limits, and contains no secrets. Record actual test counts/results rather than treating today's 380 passes as release sign-off.

**Completion evidence:** direct dependencies are pinned to Python 3.14-compatible releases. A fresh virtual environment installed `requirements.txt` from binary wheels, passed `pip check`, launched `main.py --smoke-test`, and completed the full suite. `scripts/collect_release_evidence.py` records dependency/tool versions, verifies the 10-case receiver matrix using only its bundle inputs, and confirms mandatory media inspection with FFmpeg unavailable. `scripts/run_desktop_release_check.py` completes authentic image/audio and rejected-image workflows on the native Windows Qt platform and captures three screenshots. `scripts/finalize_release_evidence.py` parses the real logs, verifies report and screenshot hashes, and rejects private key material or indexed secret values.

**Acceptance review:** complete. The focused release checks pass all 5 tests and the complete repository suite passes all 578 tests. The independently rerun finalizer reports 578 tests, 10 passing receiver cases, three passing native desktop cases on Qt `windows`, visually reviewed screenshots, and successful optional-tool absence handling. Clean-environment startup and dependency checks pass; compilation and `git diff --check` pass. The evidence summary contains hashes for eight release artifacts and reports no private key material or secret values. No R12 acceptance item remains incomplete.

### R13 — Finish documentation and submission preparation — COMPLETE

**Objective:** turn the verified release candidate into a submission-ready, reproducible documentation set that accurately maps every requirement and claim to the implemented system, checked samples, and R12 evidence while reserving team-specific declarations and real transfer/rehearsal results for truthful human completion.

**Likely files:** `README.md`; a preserved planning reference under `docs/`; `docs/architecture.md`, `docs/limitations.md`, `docs/test_cases.md`, `docs/demo_plan.md`, and `docs/contribution_statement.md`; any originality/AI-use or evidence-index document required by the brief.

**Depends on:** R01–R12 for final claims; draft progressively as features settle.

Preserve the current planning README under project documentation and replace the root README with tested setup/use/reproduction instructions. Complete architecture/wire-format, test cases, limitations, demo plan, contribution and originality/AI-use materials. Explain trust, secret sharing, replay, media-binding limits, known-message hash leakage, and legacy compatibility. Remove stale dependency comments and clearly label optional tools/features.

**Acceptance:** every FR and rubric criterion maps to an implemented feature and evidence or an explicit limitation. Demo script fits 25 minutes and allocates all five members speaking time. Required package contents and deadlines are listed. Team ID/names, contribution percentages, acknowledgements, actual transfer/rehearsal and signatures remain truthful human-completed fields. No messages, uploads, signatures or submissions are fabricated or sent automatically.

**Completion evidence:** the original planning README is preserved at `docs/planning_reference.md`, while the root README provides tested setup, GUI use, receiver reproduction, evidence, and security/key instructions. `docs/architecture.md` specifies the actual layers, flows, version-1 envelope/manifest, carrier framing, start derivation, optional mechanisms, and trust model. `docs/limitations.md` records authentication, replay, confidentiality, steganography, format, size, recovery, metadata, GUI, analysis, and evidence limits. `docs/test_cases.md` maps every functional requirement and rubric criterion to implementation and evidence. `docs/demo_plan.md` schedules all five members within exactly 25 minutes. Contribution, originality/AI-use, submission, deadline, evidence-index, packaging, and human-completion materials are present. Legacy personal absolute paths were removed.

**Acceptance review:** complete. The full suite passes all 578 tests and focused release checks pass all 5 tests. The standalone receiver reproduces all 10 indexed outcomes and capacity rejection, and the release finalizer validates the recorded environment, native desktop cases, hashes, and secret exclusions. All 11 Markdown documents have resolving local links; the preserved planning README has the same Git blob hash as the original; five distinct member roles, nine functional-requirement rows, and four deadline entries are present. Privacy, compilation, and whitespace checks pass. Fifty-nine explicit placeholders or instructions keep identifiers, contributions, acknowledgements, actual transfer/rehearsal, official declarations, and signatures for truthful human completion. No R13 acceptance item remains incomplete.

### H01 — Conduct and record the real A-to-B transfer and timed rehearsal

**Objective:** have the five-person team perform the documented transfer and complete 25-minute rehearsal on the intended equipment, then record only actual observations needed for the final human submission review.

**Likely files:** `docs/demo_plan.md`, `docs/test_cases.md`, and `docs/submission_checklist.md`; the team may also retain separate course-approved rehearsal notes or transfer evidence.

**Depends on:** completed R01–R13; confirmed team members and roles; the real Party A/Party B devices or separate folders/accounts; current course dates and submission instructions; the team's chosen transfer and separate key/secret channels.

**Acceptance:** Party B independently verifies the transferred image and audio cases without Party A's private key or process state; the trusted public-key fingerprint and any required secret channel are checked; actual image/audio observations and problems are recorded; all five members perform their allocated segments; the complete rehearsal lasts no more than 25 minutes; no private signing key enters receiver or submission evidence. This task does not authorize fabricated observations, signatures, uploads, or messages.

## 7. Recommended resumption order and final handoff

1. **Protect existing work:** retain the reviewed baseline and completed R01–R13 slices. Do not alter verified behavior for submission-only edits.
2. **Perform the real handoff:** complete H01 with the team and record the actual transfer and rehearsal results.

The next single logical task is **H01: conduct and record the real A-to-B transfer and timed rehearsal**. Its objective, dependencies, likely files, and acceptance criteria are recorded above. It is a human operational task, not another implementation slice.

No user-supplied cover media or payload is needed to resume: synthetic covers and required messages can be prepared by the implementer. The team must eventually supply identifiers, actual contributions/signatures, the demo date, and participants/devices for the real A-to-B demonstration. These external inputs do not block code completion.

Definition of done for repository work is met: all agreed core and extension workflows are implemented and verified within documented limits; the application is usable from a fresh documented setup; evidence and submission documents are ready for team completion. Remaining work is H01 and the team's truthful identifiers, contributions, acknowledgements, declarations, signatures, packaging approval, and submission.
