# ACW1 Consolidation: Implementation Plan and Handoff

This is the living source of truth for the agreed consolidation scope and implementation progress. A planned feature is not a verified feature. Read this document before work and update it after each completed task and before handoff.

## Current authorization and state

- Latest authorised execution scope: **commit and push the completed H02-H05 changes**, requested on 1 October 2026 after H05 completion. Publish on `integration/acw1-consolidated`, preserving untracked practice outputs and original branches. S01 remains complete and S02 remains unauthorised.
- Publication preparation: fetched `origin`; local and remote integration heads both remained `32b4125`. All 117 files in H05's source/runtime snapshot still match. Extend sample byte-preservation attributes to the version 2 bundle so Git line-ending conversion cannot invalidate its checksums. H05 evidence and the validated ZIP describe the pre-publication working tree; publication metadata and attributes are later changes. The resulting commit and push are recorded by Git, not retroactively added to historical validation reports.
- Integration branch: `integration/acw1-consolidated`.
- Current integration workspace: `A:/Code/GUI-based-LSB-Replacement-steganography-program`; laptop work used `C:/Code/INF2005-ACW1-consolidated`.
- Original worktree: `C:/Code/GUI-based-LSB-Replacement-steganography-program`, on `gin`.
- Base: `Tristan`, commit `6167e72203e3a3045cdc4fa8ae36f4080689df34`.
- Selective source: `gin`, commit `f3c267e10a47fa8bba7ace1078a7dce0e6d68f8e`.
- T01 status: DONE. Documentation, branch/base and worktree-preservation checks passed.
- T01-T09: DONE. Native checks and final full suite pass with the documented pytest-qt logging-capture mitigation.
- T01/T02 established the workspace and clean baseline. T03 added backend safeguards; T04 updated the GUI and regressions. Dependency pins and existing demo samples remain unchanged; T07 adds a separate samples/t07 bundle.

## S01 scope reduction (current)

DONE: removed steganalysis code, feature-only tests, current feature claims and nine analysis-only sample cases. Quality/size comparisons and video remain. Full suite: 1713 passed in 47.30s; retained fixture hashes unchanged. See [S01 evidence](../evidence/s01/README.md) for native observations and final package report. Historical records below describe their original scope.

Follow-up audit (DONE): removed unused region-selection helpers and the unused image-input alias, plus stale worker/test/dependency comments. Re-ran the full suite (1713 passed), lint and fixture checks on the uncommitted S01 working tree. Historical references and absence/legacy-index regressions remain intentionally.

Optional stage S02 (TODO, not authorised): remove video from GUI, media dispatch, preview, attacks, samples, tests and dependencies; retain image/audio formats and playback. Expected bundle then has 17 cases/two capacity checks/10 exports. Reassign Member 5 airtime to receiver evidence and limitations. Apply only after a separate user decision.

## 1. Objective and decisions

Build one polished INF2005 ACW1 desktop app from Tristan, selectively adapting Gin's safeguards and evaluation methods. Demonstrate all functional requirements, the four retained optional challenges and every retained user-facing extra. Plan 22 minutes of content plus 3 minutes of contingency within the 25-minute maximum.

Tristan is the base for its consistent media architecture, integrated GUI workflows and attack framework. Gin supplies ideas and regression cases for transactional publication, receiver bundles and measured challenge evaluation. Do not blindly merge either branch into the other.

### Requirements and references

Use the full assignment brief as the source of requirements. The group comparison is contextual analysis, not an instruction source or guaranteed marking outcome.

- Assignment brief: `C:/Users/ginli/OneDrive/SIT/Year 2 Tri 1/Cyber Security Fundamentals/Project/INF2005-ACW1-spec_v5-f2f.pdf`.
- Group comparison: `C:/Users/ginli/Downloads/Telegram Desktop/INF2005_Branch_Comparison_and_Rubric_Assessment.pdf`.
- User clarification: the professor requires all retained features to be presented and has said each optional challenge can earn additional marks. Do not drop a challenge based on the written rubric's combined innovation allocation.
- These local reference paths may be unavailable on another machine. The requirements below capture the agreed implementation scope; consult the original brief when resolving an assessment ambiguity.

### Confirmed defaults

- Keep drag-and-drop, normal file pickers and file-size preservation.
- Keep the four retained optional challenges. Integrate overlapping demonstrations to save time.
- Focused GUI polish, not a full redesign.
- Fresh samples using Tristan's envelope/manifest format; no Gin-format compatibility reader.
- Python 3.11 remains the documented baseline; T02 verified clean installation on Python 3.11.16 with every existing direct dependency pin unchanged.
- Keep OpenCV/FFV1 video processing with **video-only output**. Source audio is omitted. Disclose this before protection and in the result. Do not add external FFmpeg as a required dependency.
- Preserve original branches and uncommitted work. Do not merge or delete them.
- Do not import Gin's complete service architecture or encrypted original-file recovery sidecars.
- Prepare transfer/submission instructions and artifacts, but send no emails/messages and make no submissions.
- Use member placeholders. Never invent contributions, percentages, signatures, rehearsal results or test outcomes.

## 2. Product scope

### Mandatory workflows and retained extras

Keep GUI image/audio LSB replacement and extraction, depths 1-8, manual and HMAC-derived starts, capacity checking, signed records containing media ID/timestamp/hash/nonce/team metadata, corresponding private/public-key operations, hash recomputation, clear verdicts, cover/stego display or playback, applicable payload previews, and reproducible Party A-to-B verification.

Retain AES-GCM encryption for confidentiality; typed text/file payloads; trusted recovered-payload preview/save; key generation and fingerprint presentation; drag-and-drop and picker equivalence; optional file-size matching with measured outcomes; and evidence export needed for the demo.

Hashing/signing alone does not provide confidentiality. The message hash checks the original payload bytes; the signature authenticates that hash, the verification record, stored message and signed framing rather than every cover byte. Public-key trust is external. Timestamp/nonce alone do not reject replay. The unsigned manifest's whole-file digest is informational.

<a id="external-payload-hash-agreed-target-not-implemented"></a>

### External payload hash: H02-H05 complete

The working tree writes and requires manifest version 2. Its external `message_hash` copies the original plaintext/file SHA-256 from the signed record; `stego_sha256` remains a separate whole-media-file digest. Version 1 samples are preserved but rejected by this build. H03 compares manifest, authenticated record and recovered payload hashes, displays complete selectable values and exports their evidence. H04's replacement bundle passed independent receiver acceptance: 20 cases, two capacity checks and 11 exact exports. H05 passed the final 1,832-test suite, Ruff, native hash-display inspection and extracted-package receiver/startup checks; see [release evidence](../evidence/h05/README.md).

- **Manifest contract (H02 implemented):** version 2 requires `message_hash`, a 64-character hexadecimal SHA-256 digest normalised to lowercase. Protection copies it from the existing signed record. It hashes the exact original text/file bytes before encryption, not ciphertext, the complete envelope or the cover. The embedded envelope/signature format and `stego_sha256` are unchanged.
- **Strict compatibility (H02 implemented):** reject version 1 and missing, null or malformed `message_hash` values with `CANNOT_VERIFY` and an instruction to regenerate the protected output and matching manifest. No expected hash is inferred from received content.
- **Verification:** retain signature verification before decryption. Recompute the recovered plaintext hash and compare it with both the external manifest and authenticated record. Add `message_hash` to manifest cross-checking. An otherwise valid signed payload with a different manifest hash yields `TAMPERED`, identifies the manifest discrepancy and withholds plaintext preview/save. Preserve extraction, signature and decryption failure verdicts; unavailable comparisons are `Not performed`.
- **Interfaces and evidence:** retain the computed digest in the recovered-message result and carry structured hash evidence in verification summaries and Attack Lab exports: algorithm, manifest hash, authenticated record hash, computed hash and separate comparison statuses. Never log plaintext, passphrases or keys. Before verification the manifest hash is an unverified claim. Clear hash evidence when inputs change.
- **Implemented display:** `Expected payload SHA-256 - manifest`, `Authenticated record SHA-256`, `Recomputed payload SHA-256`, `Payload matches manifest`, `Manifest hash matches signed record`, and `Payload hash matches signed record`. Comparison statuses are `Yes`, `No` or `Not performed`; unavailable digest values say `Unavailable`. Existing signature and signed-message checks remain. Hashes are complete and selectable in the shared Verify/Attack Lab panel. Input changes clear current results; labelled completed attacks remain in the history log.
- **Security boundary:** the manifest remains unsigned in this design; its expected hash gains authentication through agreement with the signed record. Do not add a detached signature or independently signed manifest. Publishing the plaintext digest permits equality comparisons and testing guesses of predictable messages, even when the message is encrypted. It does not expose an AES key or establish integrity of every cover sample.
- **Samples and rollout (H04 implemented):** generated and independently verified `samples/hash-manifest-v2`, with matching public keys, 20 positive/negative cases and no saved private keys. All 232 pre-existing sample/evidence files, including user outputs, retain their original hashes. Live demo paths now use the verified bundle. The five attacks and retained features are unchanged. See [H04 evidence](../evidence/h04/README.md).

Detailed acceptance scenarios are in [test_cases.md](test_cases.md#planned-external-payload-hash-acceptance-not-executed). The [sample guide](sample_bundle.md) and [handoff](submission_handoff.md) record the validated version 2 fixtures and release commands.

### Optional challenges

| Challenge | Retained capability and demonstration | Limit to explain |
| --- | --- | --- |
| Advanced starts | HMAC-derived location, receiver recovery, wrong-secret failure | Finite search space; start hiding is not encryption |
| Attack simulation | Payload corruption, signature corruption, wrong-key verification, wrong-start extraction, outside-payload edits | Report actual verdicts; failure causes may be ambiguous |
| Robust embedding | Repetition-3, correction reporting, matched coded/uncoded damage, unrecoverable damage | Independent bit recovery does not establish resistance to arbitrary lossy transforms |
| Video | One short FFV1 clip protected/verified, preview and affected-frame indication | Video-only output; codec size/property limits |

### Deliberate cuts

- No original-file recovery sidecar or full Gin service architecture.
- Do not add password-protected private-key generation.
- Remove the GUI's bulk attack runner and attack variants outside the focused set above.
- Remove arbitrary video-frame exploration and the separate video capacity-by-depth table.
- Remove the separate key-location menu; display paths in generation results and existing inputs.
- Keep bulk robustness experiments in development scripts, not extra app workflows.
- Keep useful backend regression tests/helpers. Update obsolete GUI tests/docs when controls are removed.
- Hiding a retained feature under Advanced does not exempt it from the demo.

## 3. Implementation approach

### Backend and security

Preserve Tristan's layered architecture, media facade, protect/verify interfaces and envelope format. Adapt Gin's transactional publication: validate path aliases, stage media/manifest, back up existing destinations, restore them on failure and clean temporary artifacts. Never replace source media unintentionally.

Keep signatures verified before trusting records/decrypting; bounded input parsing; validated cryptographic parameters before expensive operations; and capacity accounting for framing, signatures, metadata, encryption, repetition, depth and start location. Keep diagnostic explanations conservative when damaged framing, incorrect secrets and absent embedding cannot be distinguished.

Avoid a second crypto/media implementation. Keep public API changes additive and minimal: structured publication failures, measurement results and explicit video limitations, reusing existing result types where sufficient.

### GUI and input handling

Retain Protect, Verify, Attack Lab and Video tabs. Use one validation route for picker/drop selections. Reject nonexistent paths, directories, unsupported inputs, remote URLs and inappropriate multiple-file drops, including mixed local/remote drops.

Preserve responsive workers, playback controls and rejection of stale results. Preview/save recovered payloads only after successful verification. Clearly label video-only output before protection and in results.

### Size and media properties

Default to normal lossless output; retain explicit optional size matching. Preserve supported dimensions, sample count, sample rate and channels. Never truncate content or weaken security to match size. Show original/output bytes, absolute/percentage change, matching success/failure and companion-file storage separately.

For video, test frame dimensions/count, supported frame rate, duration and extraction after saving. Reject unsupported inputs rather than silently claiming preservation. Source audio omission is the explicitly accepted exception.

### Samples and release

Create fresh short Learning Outcome, long Project Overview and encrypted custom payloads, plus applicable image/audio file payload examples. Prepare original/protected/tampered samples and separate Party A/Party B folders. Receiver verification must work in a fresh process without private keys. Include a case index, verification command and instructions; clearly label demonstration secrets.

Required cases include image/audio positives and image payload corruption, audio signature corruption and unrecoverable audio damage as three mandatory-media negatives. Show capacity rejection separately. Provide reproducible demonstrations for every retained challenge and extra.

Package source, samples, public keys, docs and current evidence; exclude private keys. Extract and verify the archive's receiver workflow. Do not reuse historical screenshots/logs as proof of this build.

## 4. Task ledger

Allowed statuses: TODO, IN_PROGRESS, BLOCKED, DONE. DONE requires acceptance evidence. BLOCKED requires the specific blocker and resolution. Update Changes, Evidence and Remaining fields as work proceeds. Do not overwrite history with optimistic summaries.

| ID | Task | Dependencies | Status | Acceptance criteria |
| --- | --- | --- | --- | --- |
| T01 | Integration workspace and living guide | None | DONE | Branch/worktree from exact Tristan base; original work preserved; guide, root agent pointer and README link present; documentation diff checked |
| T02 | Reproducible baseline and feature/demo inventory | T01 | DONE | Clean Python 3.11 setup results, dependency checks and FR1-FR13/challenge/extra gap inventory recorded |
| T03 | Publication/security safeguards | T02 | DONE | Path alias, rollback, trust-boundary and capacity regressions pass |
| T04 | GUI simplification and input handling | T03 | DONE | Agreed cuts completed; retained inputs/previews/workers validated; no orphan controls or stale docs |
| T05 | Five challenge workflows | T03, T04 | DONE | Each retained capability has reproducible demo, tests/evaluation and stated limitations |
| T06 | Size/property preservation | T03, T05 | DONE | Representative size/property measurements recorded; unexpected growth investigated |
| T07 | Sender/receiver sample bundle | T04, T05, T06 | DONE | Required messages, positives, negatives and challenges reproduce independently without private keys |
| T08 | Integrated release validation | T07 | DONE | Full suite, lint, clean setup, native desktop checks and extracted-package verification complete |
| T09 | Demo/submission handoff | T08 | DONE | Feature-complete timed script, evidence index and human-task checklist delivered; actual rehearsal tracked honestly |
| D01 | Standalone beginner demo study guide | S01 and current demo script | DONE | Self-contained theory, accurate current workflows/limits, lecture-versus-extra mapping, practice cases and answers, member preparation and quick revision; local links and factual examples checked |
| D02 | Review adopted teammate PDF and align study guide | D01 and teammate PDF | DONE | All PDF pages reviewed; named speaking allocation/timings reflected; gaps and corrections grounded in current app/brief; documentation checks recorded |
| D03 | Detailed script for Gin's attack and video segment | D02 and current app workflows | DONE | Complete actions and speaking lines, correct live/fixture input handling, all five attacks and video protect/verify/playback/frame lookup, honest timing/fallbacks and documentation checks |
| D04 | Expand Gin's spoken demo narration | D03 | DONE | Expanded narration for all attacks and video stages, cues tied to actual results, preserved operational steps, checked word count and honest timing estimate |
| D05 | Interleave actions and speech in Gin's script | D04 | DONE | Each live action immediately followed by its speech; all attacks and video stages preserved; result waits explicit; references and updated word count checked |
| V01 | Prepare forest video cover | User-supplied MP4 and retained video workflow | DONE | New short lossless MKV without modifying source; valid dimensions/timing, successful signed text round trip, exact recovery and frame-location check; actual evidence and GUI limits recorded |
| D06 | Diagnose disabled Attack Lab secret fields | User's open app and current manifest | DONE | Inspect current native state and manifest; explain expected disabling or identify a reproducible defect |
| F01 | Keep Attack Lab secret fields editable | User correction after D06 | DONE | No manifest-based locking; hints follow typed/picked manifests and clear; keyboard editing survives all manifest types and wrong-input actions; focused tests and lint pass |
| H01 | Document external payload hash design | User's documentation-only instruction | DONE | Current/planned behaviour separated throughout affected docs; links, terminology and documentation-only diff checked |
| H02 | Required version 2 manifest hash | H01 and user implementation authorisation | DONE | Required validated plaintext `message_hash`; protection publishes it; old/malformed manifests clearly rejected; focused schema tests pass |
| H03 | Verification, GUI and hash evidence | H02 | DONE | External/computed/signed comparisons and accurate statuses; signature-first failure handling and preview gate preserved; GUI/evidence tests pass |
| H04 | Fresh version 2 demo bundle | H02, H03 | DONE | New `samples/hash-manifest-v2` bundle with matching keys and expected cases; originals/old fixtures preserved; no saved private keys |
| H05 | Validate and document implemented release | H02-H04 | DONE | Focused tests, Ruff, full suite, GUI inspection and independent receiver verification pass; actual revision/evidence recorded; live docs updated |

### H05 work record

- Status: DONE. User authorised the next task after H04. Validation, native hash inspection, extracted receiver acceptance and current documentation are complete. No commit/push or human submission is claimed.
- Changes: release sample inventory includes only the preserved regression fixtures and the new verified bundle, excluding untracked practice outputs. Add reusable archive audit/extraction and current dependency/legacy-rejection/startup probes. Historical release scripts remain untouched. Native inspection found horizontal overflow and clipped unbroken hashes; read-only plain-text digest fields now wrap between characters without altering selected/copied bytes. Add three window-layout regressions.
- Evidence context: Windows 11, PowerShell, `.venv-t08` Python 3.11.16, unchanged pins, base HEAD `32b4125b29a70c3f31827acac6d5a1efb9cc0c9f` plus uncommitted H02-H05 changes. [H05 evidence](../evidence/h05/README.md) records source hashes, executed commands, screenshots and limitations.
- Executed tests: initial focused schema/hash/bundle/package tests **134 passed in 7.48s**; final GUI/hash/consolidation tests **56 passed in 2.82s**; final full suite `.venv-t08/Scripts/python.exe -m pytest --no-qt-log -q --junitxml=evidence/h05/full-final.xml`: **1,832 passed in 50.84s**, no failures/skips. Ruff, dependency consistency and `git -c core.safecrlf=false diff --check` pass. Earlier full run: 1,829 passed in 50.64s, before the three layout regressions.
- Native acceptance: final app launched on the interactive desktop (PID 16308). Version 2 image fixture: AUTHENTIC with three matching complete hashes; double-click selects the exact 64-character hash. Changing manifest clears evidence/recovery; manifest-only mismatch gives TAMPERED, No/No/Yes comparisons and disabled recovery. Wrong key gives SIGNATURE_INVALID, unavailable authenticated/computed hashes and Not performed comparisons. Attack Lab reproduces AUTHENTIC to SIGNATURE_INVALID with before/after history; changing its key clears current panels while retaining completed history. Vertical scrolling exposes the full panel at the default window size. This did not repeat native playback, drag/drop, encryption or all-media testing; those have automated current coverage and separately labelled historical native evidence.
- Package acceptance: `dist/H05-candidate.zip` passed independent member/source-byte audit, private-key/exclusion checks, extraction, dependency-pin/startup probe and receiver process isolation: **20 cases, two capacity checks, 11 exact authenticated exports**, zero private keys. Final delivery build/check commands and the external archive report location are in [the handoff](submission_handoff.md); reports stay outside their own archive to avoid circular hashes.
- Preservation: historical samples/evidence and user practice files were retained; the native app appended only its excluded runtime log. The 78-file version 2 bundle remains byte-identical to H04. Original branches remain unchanged.
- Remaining: none for H05. Human declarations, actual transfer, rehearsal and submission remain open. S02 video removal is not authorised.

### H04 work record

- Status: DONE. User authorised the next task after H03; bundle, isolation, preservation and no-private-key acceptance criteria are met.
- Scope: extend the existing generator with plaintext/encrypted manifest-hash discrepancies and explicit hash-comparison expectations; create `samples/hash-manifest-v2`, matching public keys and standalone receiver instructions. Signing keys remain in memory. Add a reusable receiver-isolation command without changing historical evidence scripts. Only the two new public-key paths are unignored.
- Preservation: captured SHA-256 for all 232 existing files under samples/evidence, including untracked user practice outputs, in `tmp/h04/preserved-before.json` before generation. Existing H02-H03 working-tree changes are preserved; base HEAD remains `32b4125`, Windows PowerShell and `.venv-t08` Python 3.11.16 with unchanged pins.
- Executed generation: `.venv-t08/Scripts/python.exe -m scripts.build_sample_bundle --output samples/hash-manifest-v2`: **20/20 cases passed**. The new 78-file bundle is 6,101,340 bytes; nine baseline protected outputs, retained negative/robustness cases and two added manifest-only hash discrepancies. The generated index records expected comparison statuses as well as verdicts. Both new public keys are visible to Git; private-key exclusions remain.
- Executed receiver acceptance: `.venv-t08/Scripts/python.exe -m scripts.check_receiver_isolation --bundle samples/hash-manifest-v2/party-b --output tmp/h04/isolated-final`: **20 cases, two capacity checks, 11 exact exports, zero private keys**, all passed using copied runtime/Party B files in a fresh `python -I` process without Party A. An earlier run at `tmp/h04/isolated-receiver` also passed; the final run includes the helper's tested nested-output guard. This is local process/file isolation, not a human transfer or OS access sandbox.
- Executed tests: `.venv-t08/Scripts/python.exe -m pytest tests/test_sample_bundle.py tests/test_manifest_v2.py tests/test_hash_evidence.py --no-qt-log -q`: final **104 passed in 7.58s**, no failures/skips. Earlier iterations passed 7 in 3.01s and 103 in 6.29s. `.venv-t08/Scripts/python.exe -m ruff check .` and `git -c core.safecrlf=false diff --check`: PASS. No new full-suite/native run claimed; H03's full-suite result remains historical for its state.
- Final audit: Python via PowerShell here-string verified all **232 pre-existing file hashes unchanged**, all **78 new bundle hashes stable**, all **11 final recovered files byte-for-byte equal to original sender inputs**, **176 local documentation links/anchors**, balanced fences and current demo paths. Full bundle scan found no private PEM material. Live sample paths were switched only after isolated verification passed. [H04 evidence](../evidence/h04/README.md) records commands, environment, source/bundle hashes and receiver/audit reports.
- Remaining: none for H04. H05 must validate native GUI behaviour and the completed release package, adapting historical package checks that still target version 1 fixtures. No release archive, human transfer, rehearsal, commit or push claimed.

### H03 work record

- Status: DONE. User authorised the next task after H02; comparison, failure-handling, GUI and export acceptance criteria are met.
- Changes: retain the recomputed SHA-256 in `RecoveredMessage`; add structured `HashEvidence` to verification summaries; compare external, authenticated and recovered digests, including `message_hash` in manifest cross-checking. Preserve earlier failure verdicts and signature-before-decryption; manifest-only discrepancy is `TAMPERED` with no recovered content. Add a shared selectable/wrapping hash panel to Verify and Attack Lab, refresh manually edited unverified manifests, clear current evidence on input changes/retries/errors, reject stale worker results, and include before/after hashes in JSON/text attack exports without plaintext or secrets. Completed attack logs remain historical evidence.
- Evidence context: Windows PowerShell, `.venv-t08` Python 3.11.16, HEAD `32b4125` plus the existing uncommitted H02 patch and this H03 patch, unchanged dependencies. Existing practice outputs, historical evidence and samples are preserved.
- Executed tests (all with `.venv-t08/Scripts/python.exe -m pytest`, offscreen Qt and `--no-qt-log -q`): `tests/test_manifest.py tests/test_manifest_v2.py tests/test_verification.py tests/test_attacks.py tests/test_gui_tabs.py tests/test_gui_lab_tabs.py tests/test_gui_consolidation.py`: **447 passed in 12.85s**. `tests/test_hash_evidence.py tests/test_manifest_v2.py`: **90 passed in 2.27s**. Expanded `tests/test_hash_evidence.py`: **33 passed in 1.28s**. Final full suite with no file filter: **1810 passed in 46.64s**, no failures/skips, including the final Attack Lab retry invalidation change.
- Executed static/documentation checks: `.venv-t08/Scripts/python.exe -m ruff check .` and `git -c core.safecrlf=false diff --check`: PASS. A PowerShell here-string through `.venv-t08/Scripts/python.exe -` checked all **166 local links/anchors**, balanced fences, no tracked changes in samples/historical evidence/envelope code and absence of the H04 bundle: PASS. The earlier Ruff import-order finding was fixed before the final suite.
- Visual evidence: a PowerShell here-string through `.venv-t08/Scripts/python.exe -` created a `QApplication` with `QT_QPA_PLATFORM=offscreen`, explicitly loaded `C:/Windows/Fonts/segoeui.ttf` and rendered a manifest-mismatch `ResultPanel` at 680 × 1050. Inspected `tmp/h03/hash-panel.png`: all three complete hashes, comparison statuses and disabled recovery controls are readable. This is widget rendering, not a native desktop acceptance run.
- Remaining: none for H03 acceptance. H04 must generate the replacement version 2 bundle; H05 must complete release/native/independent-receiver acceptance. No sample generation, release packaging, commit or push performed.

### H02 work record

- Status: DONE. User authorised H02 after reviewing the laptop's H01 plan; schema, publication and rejection acceptance criteria are met.
- Preparation: `git fetch origin` and `git merge --ff-only origin/integration/acw1-consolidated` advanced this checkout from `567cced` to `32b4125`, including F02 and H01. Existing untracked practice outputs and original branches remain untouched.
- Changes: mandatory validated lowercase `message_hash`, manifest version 2, copy from the existing signed record through `Manifest.from_record`, actionable legacy/invalid-hash rejection using the existing `CANNOT_VERIFY` path. Envelope/signature and whole-file digest unchanged. Documentation distinguishes the implemented contract from pending H03 comparisons and H04 samples.
- Evidence context: Windows PowerShell, `.venv-t08` Python 3.11.16, base HEAD `32b4125` plus this uncommitted H02 working tree; unchanged dependencies, offscreen Qt with the established `--no-qt-log` mitigation. Historical evidence and sample files were not rewritten.
- Executed tests: `.venv-t08/Scripts/python.exe -m pytest tests/test_manifest_v2.py tests/test_manifest.py tests/test_verification.py --no-qt-log -q`: **234 passed in 3.65s**. `.venv-t08/Scripts/python.exe -m pytest --no-qt-log -q`: **1777 passed in 48.05s**, no failures/skips. New coverage includes exact plaintext hashes for text/file bytes in image/audio/video, encryption and repetition combinations, JSON round trips, uppercase normalisation, missing/null/wrong-type/length/non-hex/whitespace rejection, early `CANNOT_VERIFY`, and rejection of an untouched historical version 1 fixture.
- Executed static checks: `.venv-t08/Scripts/python.exe -m ruff check .` and `git diff --check`: PASS. Initial Ruff identified four test regex literals needing raw-string markers; corrected with no assertion or application behaviour change. The full-suite result predates only those syntax-equivalent markers and documentation/comment edits.
- Final checks: `.venv-t08/Scripts/python.exe -m pytest tests/test_manifest_v2.py --no-qt-log -q`: **60 passed in 1.12s** after the regex edits. Repeated Ruff and `git -c core.safecrlf=false diff --check`: PASS. A PowerShell here-string through `.venv-t08/Scripts/python.exe -` checked all **166 local links/anchors** in changed Markdown files, balanced fences and empty tracked diffs for samples, historical evidence and `app/crypto/envelope.py`: PASS. Existing untracked practice outputs remain outside this patch.
- Remaining: none for H02 acceptance. H03 must implement external/computed/signed hash comparisons, preview gating and GUI/export evidence; until then a syntactically valid external hash is not authenticated. H04 must generate the replacement bundle, because preserved version 1 samples cannot verify on this build. H05 must validate the completed release. No native GUI inspection, new demo bundle, release package, commit or push claimed.

### H01 work record

- Status: DONE. Documentation-only implementation of the agreed plan; no application or test changes authorised.
- Changes: document the version 2 contract, hash comparisons, planned display/evidence, strict future compatibility and fresh-bundle rollout. Correct overstatements about unsigned manifests and distinguish current instructions from future demo notes.
- Evidence context: Windows PowerShell, base HEAD `24e35592f08352f1bdae82addf40a5cac0eb7703`; tracked working tree initially clean. The two untracked `samples/t07/party-a/original/image_stego.png` output files (media and manifest) are pre-existing and excluded. External Project-folder voice notes are excluded.
- Executed validation: `git diff --check` passed. A PowerShell here-string through `.venv/Scripts/python.exe -` checked the 12-file documentation-only diff, all 15 added local links/anchors, balanced code fences, explicit future-status wording, H02-H05 TODO status, empty staging area and absence of the proposed bundle: PASS. No digest examples were added; the contract explicitly specifies 64 hexadecimal characters and lowercase normalisation. A targeted `rg` audit found no remaining current-document claims that a manifest must be unsigned or every manifest field/edit is authenticated. Reviewed the diff and the unaffected original requirements, historical planning reference, ethics and contribution documents; those do not need edits for this design.
- Boundaries: no application tests run, test files changed, samples regenerated or historical evidence rewritten. The external voice notes and pre-existing untracked outputs were not edited. All 12 changed files are README/repository documentation; the documentation-preparation phase performed no staging, commit or push.
- Publication follow-up: user subsequently authorised committing and pushing these 12 documentation files to the existing `origin/integration/acw1-consolidated` destination. Generated demo outputs remain excluded. Pre-commit `git diff --check` passed; the code and tests are unchanged from the documented baseline.
- Remaining: H02-H05 remain TODO and require later implementation authorisation. Current application behaviour and version 1 compatibility are unchanged.

### F02 work record

- Status: DONE. The already-disabled start-location control is visibly faded in derived mode and restored in manual mode.
- Changes: added explicit opacity for the number box, disabled its label alongside it, and added a mode-specific tooltip.
- Publication scope: user authorised commit and push on 1 October 2026; include only `app/gui/protect_tab.py` and this ledger. The untracked `samples/t07/party-a/original/image_stego.png` and its manifest are generated user outputs and remain local.
- Evidence: Windows PowerShell, `.venv` Python 3.11.16, base HEAD `567cced2ddfa9aeb50b6690a92d5bc4ae48a3cf6` plus this application/documentation patch in `C:/Code/INF2005-ACW1-consolidated` (initial working tree clean). `.venv/Scripts/python.exe -m pytest tests/test_gui_tabs.py -q -p no:cacheprovider`: 75 passed in 8.66s. Initial run reached the end but failed writing the existing pytest cache with WinError 5; disabling cache resolved it. `.venv/Scripts/python.exe -m ruff check app/gui/protect_tab.py` and `git diff --check`: PASS.
- Visual check: rendered both modes using offscreen Qt and inspected `tmp/f02-derived.png` and `tmp/f02-manual.png`; field/label fading and restoration are visible. Offscreen fonts rendered as boxes, so this does not establish native text appearance.
- Remaining: no implementation work. Restart an already-running app to load the change. No native app restart or full-suite run performed.

### P01 publication record

- Status: DONE. User authorised commit and push on 1 October 2026; implementation and documentation commit `7fbc15d` was successfully pushed to `origin/integration/acw1-consolidated`.
- Scope: README, Attack Lab fix, regression tests, implementation ledger, beginner study guide and Gin's demo script. Generated practice media/manifests are excluded and left untouched.
- Preparation: `git fetch origin` succeeded; `git merge --ff-only origin/integration/acw1-consolidated` advanced the branch from `8922a74` to `025a3ca`, preserving three remote commits whose net change adds `samples/t07/party-a/messages/huge.txt`. No original branches changed.
- Validation: F01's recorded 47-test run and Ruff result apply to the unchanged application/test patch. These are prior working-tree results, not a new test run after the fast-forward. `git diff --cached --check` passed for the six staged files. `git push origin integration/acw1-consolidated` succeeded, advancing the remote from `025a3ca` to `7fbc15d`.
- Remaining: no implementation publication work. This ledger completion is a separate documentation follow-up; generated practice outputs remain untracked and the existing app process still requires a restart to load F01.

### F01 work record

- Diagnosis: D06 explained the current manual/unencrypted selection but did not address the reported workflow problem. User explicitly requested removing the disabling behaviour itself. The old `_apply_manifest_hints` called `setEnabled` based on manifest flags, skipped state refresh for missing/invalid manifests, and was not connected to manual manifest-path edits; clearing the file also retained the old manifest.
- Changes: removed manifest-based enable/disable calls from Attack Lab. Both fields stay editable, with visible required/unused hints and corresponding placeholders. Hints update when the manifest path changes; clearing the selected file resets its manifest/hints. Existing secret contents remain user-editable. Wrong-start backend still requires HMAC and an authentic baseline. Updated Gin's script to match.
- Evidence so far: regression `test_secret_fields_remain_editable` failed on the old implementation as expected (passphrase disabled). After changes, focused GUI suites passed 47 tests in 2.42 seconds; Ruff passed. Final run adds keyboard-entry assertions after both wrong-input actions. Windows PowerShell, `.venv-t08` Python 3.11.16, offscreen Qt with `--no-qt-log`; base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` plus existing uncommitted documentation/demo outputs and this fix.
- Final executed checks: `.venv-t08/Scripts/python.exe -m pytest tests/test_gui_lab_tabs.py tests/test_gui_consolidation.py --no-qt-log -q`: 47 passed in 2.32 seconds, including keyboard editing after wrong-key and wrong-start actions and transitions through manual/HMAC, encrypted/unencrypted and invalid/cleared manifests. `.venv-t08/Scripts/python.exe -m ruff check app/gui/attack_tab.py tests/test_gui_lab_tabs.py` and `git diff --check`: PASS.
- Remaining: none for F01 code/test acceptance. The user's existing process still contains old imported code; its inputs/logs were left intact and a restart is required to load the fix. No claim of native validation of the new build or a fresh full-suite run.

### D06 work record

- Evidence: Windows Computer Use `@oai/sky` through `mcp__node_repl__js` inspected the running Media Integrity & Steganography Tool. Native accessibility and foreground screenshot showed `image-short.png` with its matching Party B manifest; both secret fields disabled. Read manifest confirms manual start 37 and `encrypted: false`. Status bar still showed the earlier wrong-start result `AUTHENTIC -> PAYLOAD_MISSING`; this is observed existing UI state, not a newly executed attack.
- Diagnosis: expected state for the selected image. `_apply_manifest_hints` enables start-secret input only for HMAC and passphrase input only for encrypted payloads. The prepared `audio-long.wav` manifest is HMAC and unencrypted, so selecting that file should enable start secret while leaving passphrase disabled. No defect established for the reported state.
- Changes/limits: activated and inspected the existing app window; no field values changed, attacks run, logs cleared or app restarted. No source code change/test run. Base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` plus existing working-tree changes. Remaining: none for diagnosis; user can proceed with the image outside-payload action without clearing disabled fields.

### V01 work record

- Changes: created `C:/Users/ginli/OneDrive/SIT/Year 2 Tri 1/Cyber Security Fundamentals/Project/forest-cover.mkv` from the first five seconds of `2187-155747497_tiny.mp4` in the same folder; linked it as the selected cover in Gin's script. Original MP4 and bundled samples were not changed. New cover: FFV1/bgr0, 640 × 360, constant 25 fps, 125 frames, no audio, 10,545,753 bytes. Source was 30.08 seconds, H.264/AAC, 640 × 360, 25 fps.
- Environment: Windows PowerShell, Python 3.11.16 `.venv-t08`, OpenCV 4.10.0; existing FFmpeg executable at `A:/Tools and Utilities/ffmpeg-2026-02-26-git-6695528af6-full_build/bin/ffmpeg.exe`. This is a cover-preparation tool, not a new app dependency. Base app revision remains `8922a743c86cb7bf6d86cd68d09fe60dba34e349` with the existing documentation/demo working-tree outputs.
- Executed conversion: `ffmpeg -hide_banner -loglevel error -n -i <source> -map 0:v:0 -t 5 -vf fps=25 -c:v ffv1 -level 3 -pix_fmt bgr0 -an <cover>` using the absolute source/output paths above. `ffprobe` checked codec, stream count, dimensions, rate, duration and size. PowerShell here-string via `.venv-t08/Scripts/python.exe -` decoded all 125 cover/output frames and ran `protect_media` then `verify_media` at depth 1/HMAC with public demo inputs and an ephemeral in-memory key pair: AUTHENTIC, exact recovery of `Gin video demonstration`, valid frame span. Backend protect/verify/span/output-decode sequence took 1.62 seconds on this run; not a GUI rehearsal time. Temporary verification outputs were cleaned up and no test private key was saved.
- Provenance: source SHA-256 `d1f10878c9cd8792e76a84522018d16865918e664332757698e86ab757f9a311`; new cover SHA-256 `f03684e3c5a8a45387cb2419f697c26e993b5ae9727f596937a1b3061a330928`. User supplied the download selected from `https://pixabay.com/videos/forest-trees-wind-weather-2187/`; the conversion is cover preparation before embedding.
- Remaining: none for cover preparation/backend acceptance. Native GUI playback and the actual timed team handover still need human rehearsal; neither is claimed here. Live protection will create a new stego output/manifest and requires the team's chosen signing key pair and start secret.

### D05 work record

- Changes: rewrote script sections 3–6 into chronological italic actions followed immediately by quoted speech. Preserved all five attacks, evidence export and full video protect/verify/playback/location workflow. Moved supporting explanations to rehearsal notes; updated opening/closing cues and the narration estimate.
- Evidence context: documentation-only edit in Windows PowerShell. Main live-route speech is 448 words plus 38 closing words, excluding alternate prepared-sample opening and fallback speech. Numbered actions keep exact input names and separate each result explanation from the preceding wait.
- Executed checks: base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` with prior documentation/demo outputs still in the working tree. PowerShell here-string via `.venv-t08/Scripts/python.exe -` checked 10 sections, all 32 numbered actions immediately paired with speech, five attack waits/verdicts, video success cues, 448+38 spoken words, fixture paths, links, table widths, whitespace and unchecked checklist: PASS. Initial audit incorrectly expected 34 pairs; corrected the audit to check every numbered action and the actual 32-pair count. `git diff --check`: PASS.
- Remaining: none for D05. Timing remains an estimate, with actual rehearsal for the user. No application tests or native demonstration were run, and existing demo outputs were left untouched.

### D04 work record

- Changes: expanded the five attack explanations, evidence transition and video narration in [Gin's script](gin_demo_script.md); added before-action/after-result cues and delivery instructions. Kept operational steps, sample choices and scope intact. The timing paragraph separates estimated speech duration from an actual rehearsal.
- Evidence context: Windows PowerShell; current documentation builds on D03. Quoted speech was counted using a PowerShell here-string piped to `.venv-t08/Scripts/python.exe -`: live route 475 words plus 38 closing words; prepared-sample alternative and fallback sentence excluded from that route count.
- Executed checks: base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` plus existing working-tree documentation/demo outputs. PowerShell here-string via `.venv-t08/Scripts/python.exe -` checked 10 sections, local links/fixture paths, tables/whitespace, all five attack action/verdict blocks and before/after speech, all three video stages/result cues, 475+38 spoken words and unchecked checklist: PASS. `git diff --check`: PASS.
- Remaining: none for D04. Actual delivery speed and end-to-end timing require the user's rehearsal; no application tests or human rehearsal claimed. Existing demo outputs were not changed.

### D03 work record

- Changes: created [Gin's detailed script](gin_demo_script.md) and linked it from study-guide section 17. Includes handover inputs, fixture paths, preflight, five attacks, evidence export, complete video workflow, speaking lines, questions, changed payloads, troubleshooting and unchecked rehearsal checklist. Suggested timing shifts the video transition within Gin's existing six-minute slot; it is not recorded as team agreement or a successful rehearsal.
- Evidence context: Windows PowerShell; base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` plus existing D01/D02 documentation changes. Existing untracked user demo video/manifest and attacked PNG/WAV outputs were observed and left untouched; no claim about who ran them or whether they passed. Current GUI labels and attack behaviour checked against source, including wrong-input baselines and logical-envelope corruption.
- Executed checks: PowerShell here-string piped to `.venv-t08/Scripts/python.exe -` checked all 10 script sections; script/study-guide links, anchors, table widths, fences and whitespace; eight existing fixture paths; five exact attack labels and six workflow labels against source; continuous proposed 360-second schedule and unchecked rehearsal checklist: PASS. `git diff --check`: PASS. No application suite or native rehearsal was run for this documentation task.
- Remaining: none for D03. Actual live handover, timed rehearsal and any team agreement on the internal timing adjustment remain human actions. No source-PDF edits or application changes were made.

### D02 work record

- Changes: aligned study-guide section 17 with the user-selected teammate PDF's named presenters and schedule; added operational corrections and Gin's sequence. Section 15 clarifies fixture/fresh key switching and Verify versus Attack Lab wrong-input demonstrations. Source references distinguish the adopted PDF from the earlier repository script. Names describe speaking roles only, not authorship.
- Evidence: reviewed all eight PDF pages as extracted text and four rendered page pairs; checked assignment brief pages 2–4 and implementation behaviour, including authentic-baseline enforcement and demo-key reuse. Windows PowerShell; base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` plus prior D01 and current D02 documentation edits. Source PDF SHA-256: `5242b230885d4db7b7c49d86ef0e0eaa6ed7c2995827b9dfdbe0a0f791b145f9`.
- Executed checks: PowerShell here-string piped to `.venv-t08/Scripts/python.exe -` audited 20 numbered sections, 37 local links/anchors, balanced fences/table widths, all five presenter names and nine PDF schedule rows, trailing whitespace and unchanged source-PDF SHA-256: PASS. `git diff --check`: PASS. No application tests or native rehearsal were run for this documentation-only review.
- Remaining: none for D02. The source PDF is not edited; applying the corrections to the team's speaking script, actual transfer and timed rehearsal remain team actions.

### D01 work record

- Changes: added [the beginner guide](demo_study_guide.md) and a README discovery link. Twenty numbered sections explain foundations, current workflows, design choices and limits, all retained extras, fixture-based practice, presenter preparation, 18 model answers and a final revision sheet. Terminology is introduced for a reader with no lecture background.
- Evidence: checked current implementation, GUI labels and sample index against the guide, using the lecture/brief review from this task as teaching context. Base HEAD `8922a743c86cb7bf6d86cd68d09fe60dba34e349` plus these uncommitted documentation changes; initial working tree clean; Windows PowerShell, `.venv-t08/Scripts/python.exe --version` returned Python 3.11.16.
- Executed checks: PowerShell here-string piped to `.venv-t08/Scripts/python.exe -` audited all 20 sections, 37 local links/anchors, balanced code fences/table columns, binary/capacity calculations, current bundle counts and 14 practice rows against actual media/manifest paths and indexed expected verdict sets: PASS. `git diff --check`: PASS. No fresh application test suite or native playback run was needed or claimed for this documentation task.
- Remaining: none for D01. Reader practice and the team's actual transfer/rehearsal remain human actions. Application behaviour, dependency pins and fixture bytes were not changed.

### T01 work record

- Changes: created branch/worktree from the agreed Tristan SHA; added this guide, root AGENTS.md instructions and README discovery link.
- Evidence: PowerShell assertions verified exact base/branch, original refs/status, the three-file change scope, README/AGENTS guide links and T02-T09 TODO statuses. git diff --check passed; see the verification log below.
- Remaining: none for T01. T01 was subsequently committed as a8ac5dc. T02 was authorized by the next user request; T03-T09 remain unauthorized.

### T02-T09 work records

For each task below, replace the placeholder when work is authorized. Record changes, exact evidence and remaining acceptance items; do not mark a task complete only because code was written.

| Task | Changes | Evidence | Remaining |
| --- | --- | --- | --- |
| T02 | Clean Python 3.11.16 environment; unchanged pins; baseline and complete feature/demo gap inventory | [T02 report](../evidence/t02/README.md): 1729 tests passed, pip check/lint/startup passed, three committed samples AUTHENTIC | None for T02; identified gaps assigned to T03-T09, not fixed |
| T03 | Staged publication/rollback, aliases, bounded JSON/KDF, manual-offset sender capacity, failed-verification plaintext withholding, fingerprint helper | [T03 report](../evidence/t03/README.md): 226 focused and 1785 full tests passed; lint and compatibility/startup probe passed | None for backend T03; GUI gating, preview and fingerprint presentation remain T04 |
| T04 | Agreed control cuts, shared picker/drop validation and clear handling, background offset-aware capacity, stale-result rejection, AUTHENTIC-only preview/save, fingerprints and video-only notices | [T04 report](../evidence/t04/README.md): 1799 full tests passed; lint, sample compatibility and startup passed | None for T04; native desktop validation remains T08; new challenge actions/evaluation remain T05 |
| T05 | Wrong-key/wrong-start actions; reproducible five-challenge evaluation and demo guide | [T05 evidence](../evidence/t05/README.md): 1809 tests passed; pinned Python 3.11.16; lint, compatibility/startup and challenge evaluation passed | None for T05; native checks T08, sample bundle T07 |
| T06 | 66 saved-file measurements; codec baselines; metadata-aware size reporting; video timing/count safeguards | [T06 evidence](../evidence/t06/README.md): all 66 authentic, properties preserved; 1820 tests pass across five processes; lint and startup/compatibility pass | None for T06; combined-process Qt access violation requires T08 investigation |
| T07 | Fresh samples/t07, builder, receiver verifier, case index and guide; required PDF message wording checked | [T07 evidence](../evidence/t07/README.md): 27 cases and two capacity checks pass in isolated receiver process; 20 authenticated exports; 82 focused tests and lint pass | None for T07; native/release validation T08, real transfer/rehearsal T09 |
| T08 | Clean .venv-t08; explicit media-player disposal; scrollable tab pages; corrected alpha metric property; archive exclusions; audio-bearing video and extraction checks | [T08 evidence](../evidence/t08/README.md): current full suite 1830 pass, lint/dependencies/startup pass, audio omission verified, extracted receiver 27 cases/2 capacity checks/20 exports pass | Native checks passed; 932 repeated GUI tests and final 1830-test suite pass with supported --no-qt-log mitigation. Underlying native defect not proven; see evidence limits |
| T09 | Current timed script; evidence index; unsigned contribution/AI records; delivery and rehearsal checklist; refreshed archive | [T09 evidence](../evidence/t09/README.md): document links/cases, lint and extracted receiver/startup verification | Real transfer, timed team rehearsal, declarations/signatures, notification and submission remain human tasks |

## 5. Requirement and feature-to-demo matrix

T09 maps these retained features to the executable [timed script](demo_plan.md). The [evidence index](evidence_index.md) identifies technical validation and its limits. T02 inventory remains historical. Every live segment still requires the real team demonstration/rehearsal; passing tests are not proof of presentation timing. One action can satisfy several requirements.

| Requirement / feature | Planned implementation or check | Live segment / presenter | Current evidence status |
| --- | --- | --- | --- |
| FR1 Image input | PNG/BMP input, validation and preview | 2-7 / Member 2 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR2 Audio input | PCM-16 WAV, validation and playback | 7-12 / Member 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR3 Payload generation | Media ID, timestamp, hash, nonce, metadata | 0-2 and image result / Members 1, 2 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR4 Digital signature | Generate/select keys, sign, verify, fingerprint | 0-2 and receiver steps / Members 1-3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR5 Image embedding | Saved-file LSB round trip | 2-7 / Member 2 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR6 Audio embedding | Saved-file LSB round trip | 7-12 / Member 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR7 Variable start | Manual and HMAC-derived starts, recovery/security | 2-12 / Members 2, 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR8 Extraction | Fresh receiver extracts payload/signature | 2-12 / Members 2, 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR9 Hash verification | Recompute signed payload hash, explain scope | 0-2 and receiver steps / Members 1-3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR10 Verdicts | Per-check results, truthful failure explanations | Receiver steps and 15-19 / Members 1-3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR11 Positive/negative cases | Image/audio positives, three mandatory negatives | 2-12 and 15-19 / Members 1-3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR12 Reproducibility | A-to-B folder transfer, receiver index, evidence export | 2-7 and 19-22 / Members 2, 5 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| FR13 Innovation | Four retained challenges with limits | Throughout | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| LSB depths 1-8 | Show selector and bit/capacity tradeoff; all depths tested | 2-7 / Member 2 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Capacity check | Full overhead and start accounted for, overflow rejected | 2-7 / Member 2 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Cover/stego comparison | Image display and audio playback before/after | 2-12 / Members 2, 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Required message lengths | Brief short/long text and custom confidential payload | 2-15 / Members 2-4 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| File payload preview/save | Applicable image/audio payloads, authenticated recovery | 12-15 / Member 4 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| AES confidentiality | Encrypt/decrypt custom payload, explain signature distinction | 12-15 / Member 4 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Drag/drop and picker | Valid input through both routes; automated invalid cases | 2-12 / Members 2, 3 | T08 native picker/drop passed; live rehearsal pending |
| File-size preservation | Optional matching, measured sizes and format limitations | 2-12 / Members 2, 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Advanced start challenge | Derivation and wrong-secret failure | 7-12 and 15-19 / Members 3, 1 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Attack challenge | Focused five controls, including outside-region limitation | 15-19 / Members 1, 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Robustness challenge | Matched damage, recovery, unrecoverable third negative | 15-19 / Members 1, 3 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Video challenge | Protect/verify short clip, preview, affected frames, audio omission | 19-22 / Member 5 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Evidence export | Export the demonstrated results | 19-22 / Member 5 | Technical evidence: [index](evidence_index.md); live rehearsal pending |
| Limitations/AI/contributions | Brief explanations integrated into each member's segment | Throughout / All | Human completion required |

## 6. Verification plan and logs

### Required validation

- Full integrated suite, lint, clean-install startup and dependency check. Explain every failure/skip; release capabilities must be exercised.
- Saved-file image/audio tests at depths 1-8, manual/derived starts, exact-fit/overflow capacity, encryption/wrong-key failures, malformed records and manifest changes.
- Failure injection for publication; restore existing outputs and preserve source files, including path aliases.
- Qt event tests plus native Windows drag/drop, picker, playback and preview checks. Leave acceptance open when native checks cannot run.
- Size/property measurements on flat/photographic PNG, BMP, mono/stereo WAV and short video. No invented universal growth threshold.
- Repetition recovery and failure under controlled damage, with matched uncoded comparison.
- Retired detection experiments remain historical evidence only; S01 validates numerical quality comparisons.
- Fresh receiver process and extracted submission archive verification without private keys.

### Historical branch inspection (not integration certification)

These results were reported in the planning conversation using the available Python 3.13 environment, not either branch's exact clean documented setup. They are not new T01 tests and are not directly comparable suite totals.

| Branch | Result | Limitation |
| --- | --- | --- |
| gin at f3c267e | 574 passed, 5 failed, 5 skipped | Dependency mismatch, missing receiver samples and unavailable FFmpeg affected results |
| Tristan at 6167e72 | 833 focused tests passed | Full-suite collection encountered blocked SciPy modules; exact documented environment not certified |

Measured existing Tristan sample byte sizes: PNG 122431 -> 122497 (+66, +0.054%); WAV 882044 -> 882044 (0, 0%); MKV 145222 -> 146193 (+971, +0.669%). These are historical measurements of specific files, not universal guarantees or integrated-build evidence. Native drag-and-drop has not been verified by this work.

### T01 verification log

| Check | Environment / revision | Result |
| --- | --- | --- |
| Original status and branch refs before setup | Windows PowerShell; original worktree on gin at f3c267e | Clean status; Tristan at exact selected SHA |
| git worktree add -b integration/acw1-consolidated C:/Code/INF2005-ACW1-consolidated 6167e72203e3a3045cdc4fa8ae36f4080689df34 | Original worktree | Succeeded; integration HEAD at 6167e72 |
| New worktree status and instruction discovery | Integration worktree at 6167e72 | Initially clean; no tracked AGENTS.md or implementation guide to overwrite |
| PowerShell assertions for README/AGENTS links, existing guide target, exact changed/untracked file lists and T02-T09 TODO rows; git diff --check | Integration working tree based on 6167e72; Windows PowerShell | PASS; only README.md, AGENTS.md and docs/IMPLEMENTATION_PLAN.md changed |
| git status --porcelain, git branch --show-current, git rev-parse HEAD/gin/Tristan, git worktree list | Both worktrees; Windows PowerShell | PASS; original gin worktree clean, gin/Tristan refs unchanged, integration at selected Tristan SHA |

For future tasks, append command, environment, tested revision/working-tree state, actual result and evidence paths. Record skipped/blocked checks explicitly. Never log private keys or real secrets.

### T02 verification log

- Authorized scope: next task only, T02; T03-T09 were not executed.
- Tested HEAD: `a8ac5dcd0cd5256c9280e95db77b3747607e463d`; application/tests identical to Tristan `6167e72`.
- Windows, local CPython 3.11.16, fresh .venv; all 14 existing direct pins installed unchanged and verified. `pip check`: no broken requirements.
- `python -m pytest -q --basetemp=tmp/t02-pytest --junitxml=evidence/t02/pytest.xml`: **1729 passed in 66.24s**, zero failures/errors/skips, QT_QPA_PLATFORM=offscreen.
- `python -m ruff check .`: PASS before and after the T02 evidence probe was added.
- `python evidence/t02/probe_baseline.py`: exact pins PASS, existing PNG/WAV/MKV samples AUTHENTIC, real main.main offscreen startup/normal timed exit PASS.
- Full commands, environment, logs and per-feature gaps: [T02 evidence report](../evidence/t02/README.md).
- Native drag/drop, audible playback, remote CI, fresh sample generation, real transfer and timed rehearsal were not performed. They remain later-task acceptance items.
- No code fixes were made. Findings include publication/path safety, final-verdict preview/save gating, unbounded upper KDF costs, manual-start capacity preview, mixed-URL drops, absent fingerprint presentation, sample wording/negative-bundle gaps and optional-feature simplification/evaluation.
### T03 verification log

- Authorized scope: T03 only; T04-T09 were not executed.
- Base HEAD: `27572c98cc734e0daa24dcc1377df0234a970618`, plus uncommitted T03 changes; Python 3.11.16 and unchanged pins.
- Focused publication/security + verification/encryption/size tests: **226 passed in 6.52s**.
- Final full suite: **1785 passed in 57.23s**, no failures/errors/skips; `QT_QPA_PLATFORM=offscreen`.
- Ruff and existing-format PNG/WAV/MKV verification/real offscreen startup probe: PASS.
- Failure injection verifies originals survive embedding, manifest, backup, first/second publication and interrupt failures. Incomplete restoration retains recovery backups.
- [T03 evidence](../evidence/t03/README.md) includes commands, logs, API/limit notes and a source-hash summary.
- No GUI edits, native playback/drag-drop tests, regenerated samples, dependency changes or commits. Original branches/worktree preserved.

### T04 verification log

- Authorized scope: T04 only; resumed after usage interruption. T05-T09 not executed.
- Tested HEAD: `27572c98cc734e0daa24dcc1377df0234a970618` plus uncommitted T03/T04 changes; Python 3.11.16, unchanged pins.
- Full suite: **1799 passed in 44.60s**, zero failures/errors/skips, offscreen Qt. This includes 21 new T04 regressions; seven obsolete GUI-only tests were removed with the corresponding controls. Backend attack tests remain.
- Ruff, committed PNG/WAV/MKV compatibility and real offscreen startup: PASS.
- All nine T03 source/test hashes match the T03 evidence summary.
- Offscreen screenshots have unavailable font glyphs; they do not establish visual readability. Native appearance/playback/drop validation remains T08.
- See [T04 evidence](../evidence/t04/README.md) for commands, scope and remaining work.

### T05 verification log

- Authorised scope: T05 only, following the user instruction to execute the next task.
- Python 3.11.16 isolated .venv-t05, unchanged direct pins; HEAD 35b498a plus T05 working tree.
- Full suite: **1809 passed in 38.17s**, no failures/errors/skips; offscreen Qt.
- Ruff, dependency check, existing PNG/WAV/MKV compatibility and offscreen startup: PASS.
- Five challenge workflows reproduced; synthetic steganalysis measured 2/9 false positives and 7/9 misses. Controlled repetition-3 recovery and failure demonstrated for image/audio.
- Commands, provenance, source hashes and remaining limits: [T05 evidence](../evidence/t05/README.md).
- T06-T09 not started. No private keys persisted; no native playback or rehearsal claimed.

### T06 verification log

- Authorised scope: T06 only. Base HEAD `9b1d6d2824137dc0bfae422c677fae7e0d839f0d` plus T06 working-tree changes; Windows, Python 3.11.16 in `.venv-t05`, unchanged pins.
- `python -m scripts.evaluate_preservation --output tmp/t06-final`: 66 cases, all AUTHENTIC with exact message recovery; supported properties and samples outside the payload preserved. Flat/photographic PNG, BMP, mono/stereo WAV and short FFV1/MJPEG sources measured at depths 1/4/8 with matching off/on.
- No-payload baselines attribute MJPEG growth primarily to FFV1 re-encoding and confirm BMP/WAV header/metadata size exceptions. PNG matching succeeds in 6/9 attempts; failures are retained and explained. Manifest bytes are separate.
- Final test state: **1820 passed across five processes** (1590 excluding four GUI modules; GUI modules 21/43/91/75). Zero test failures/skips in those runs. Ruff and unchanged sample compatibility/real offscreen startup pass.
- Combined-process caveat: initial 1819-test run passed; after one additional cleanup regression, two full runs stopped with native Qt access violations around GUI teardown/construction. Logs retained; root cause unresolved, assigned to T08. Do not call the final combined-process suite clean.
- [T06 evidence](../evidence/t06/README.md) records exact commands, measurements, source hashes and limits. No native playback, source-audio-track test, release bundle or rehearsal was performed. T07-T09 not started.

### T07 verification log

- Authorised scope: T07 only. Base HEAD `b59c4a11fb42b7f0154e8ad507431407c03f174c` plus T07 working-tree changes; Windows, Python 3.11.16, unchanged dependencies. Application code unchanged.
- `python -m scripts.build_sample_bundle --output samples/t07`: 27 cases, including required messages, encrypted custom payload, PNG/WAV file payloads, mandatory image/audio negatives, repetition recovery/failure, wrong inputs, outside-payload limitation, video and steganalysis fixtures. Separate actual image/audio capacity rejections publish no output.
- `python evidence/t07/check_isolated_receiver.py --output tmp/t07-isolated`: copies only receiver data and runtime code, runs fresh Python with `-I`; all 27 cases and two capacity checks pass, 20 exact authenticated payloads exported, no private keys or sender folder.
- Focused `test_sample_bundle.py`, `test_e2e.py`, `test_payload_files.py`, `test_challenge_evaluation.py`: **82 passed in 7.41s**, no failures/errors/skips. Ruff and diff checks pass. Full-suite/native validation is T08; no clean combined-process claim.
- Fresh analysis: 2/9 false positives, 8/9 misses on 18 labelled synthetic fixtures. Video: 30 frames at 15 fps, 2 seconds, changed frame 9 inside claimed span. These are current bundle results, not reused T05 measurements.
- Exact commands, source/bundle hashes, development corrections and limits: [T07 evidence](../evidence/t07/README.md). T08-T09 not started; real human transfer/rehearsal and submissions remain undone. Existing untracked samples/r11 untouched.

### T08 in-progress verification log

- Authorised scope: T08 only; base `3b79700c44196f64bc8a9f1f937392e34c056e43`. Windows, fresh Python 3.11.16 `.venv-t08`, 24 packages installed with existing direct pins unchanged; `uv pip check` passes. Initial restricted-network install failed; approved retry succeeded. Startup/committed-sample probe passes.
- Initial full baseline in `.venv-t05`: 1826 passed in 71.81s (`evidence/t08/baseline.txt/xml`). Clean `.venv-t08` combined GUI run reproduced a Windows native access violation (`gui-clean.txt`).
- Draft MediaPreview.closeEvent unloads the player before standalone widget destruction, with regression. Combined GUI run then passed 231 tests in 10.41s (`gui-close.txt/xml`), but the subsequent full `.venv-t08` run still hit an access violation (`pytest.txt`). This change does NOT establish a crash fix. Root cause remains unresolved.
- Draft packager excludes unrelated samples/r11 and includes .gitattributes/AGENTS.md; regression updated. No release archive/extracted receiver validation yet.
- Native app launched from `.venv-t08` (launch PID 23668). Initial Protect screen was captured and readable. Input attempts were rejected with "window bounds changed" despite refreshed state. During recovery, Computer Use reported the user pressed physical Escape. Native automation stopped immediately; no picker/drop/playback acceptance claimed. App may remain open.
- All changes uncommitted. T08 remains IN_PROGRESS, not DONE. Resume crash investigation, validate draft changes, finish native checks when user permits Computer Use, then package and verify extraction. T09 not started.

### T08 earlier retry (historical blocked state)

- User authorised a retry, then explicitly chose: "Continue code and test checks; leave desktop checks pending". Desktop automation stopped after that instruction. Native file picker loaded image-file.png and displayed the received image; verification, payload save, playback and drag/drop were not completed.
- Native capture exposed clipped manifest rows. Tab pages now scroll rather than forcing all content into the available height; the small-display regression passes, but final native visual confirmation remains pending.
- A generated alpha-only image difference exposed an incorrect test assertion: overall MSE/PSNR exclude alpha by design. Corrected the property without changing metric behaviour. A new preview reload assertion also needed Windows path normalisation; both failures are retained in earlier logs.
- Strengthened player disposal (including failed backend creation), audio-output ownership and DLL-search-directory lifetime. These changes do NOT establish a fix for the native crash. Combined GUI retries still produced access violations; a diagnostic captured python311.dll + 0x3abdf on a native thread, which is not a root-cause diagnosis.
- Current working-tree full suite: **1830 passed in 74.27s**, no failures/skips, Python 3.11.16 in .venv-t08, unchanged pins, QT_QPA_PLATFORM=offscreen. Lint, dependency consistency and original PNG/WAV/MKV/startup checks pass. A single passing retry does not supersede the intermittent failures.
- Source video with audio: protected output has FFV1 video only, 30 frames, 15 fps, 128x96, two seconds; AUTHENTIC with exact payload recovery. FFmpeg/ffprobe were development-check tools, not new application dependencies.
- Preliminary source archive extracted into a fresh folder: all member bytes match, no private keys/unrelated samples/r11, 27 receiver cases and two capacity checks pass, 20 exact authenticated exports; original-format compatibility and offscreen startup also pass from extraction. Final candidate archive/report live under dist; see T08 evidence for commands and provenance.
- T08 is **BLOCKED**, not DONE: completing it requires an idle desktop for the deferred native checks and a demonstrated resolution of the intermittent native crash. Latest source changes are uncommitted. T09 remains untouched.

### T08 completion verification log

- User subsequently authorised native checks and confirmed manual drag/drop and both audible audio players. Native image/audio/video verification was AUTHENTIC; image/audio saves exactly match original payload hashes. Video visibly plays to two seconds. Final native reload confirms manifest text is readable after label-height and scrolling fixes.
- Capture-enabled full run still crashed. Supported pytest-qt `--no-qt-log` mitigation retains native stderr messages and all tests/exception checks: 932 repeated GUI tests pass in 32.75s; final combined-process suite **1830 passed in 52.50s**, no failures/skips. The underlying native defect remains unproven; this is a demonstrated test-runner configuration mitigation, not a claimed player-only fix.
- Ruff and diff checks pass. Existing clean-install, dependency, original-format/startup and audio-bearing video checks remain applicable; dependency pins unchanged. Base HEAD remains `3b79700c44196f64bc8a9f1f937392e34c056e43` plus uncommitted T08 changes.
- Final archive/extraction commands and report: [T08 evidence](../evidence/t08/README.md), `dist/T08-validated-report.json`. The report records exact archive/member hashes and receiver/startup results outside the archive. Check successful report before handoff.
- T08 DONE with documented mitigation and limits. T09 not started. No commit/push or human transfer/rehearsal/submission claimed.

### T09 verification and handoff log

- Authorised T09 after commit/push of T08 at `2aa68adf83f0e57cefa8cff10b4a78f3ac4c4f41`. Documentation/package changes only; no application or dependency changes. T08 full-suite/native results remain baseline evidence, not a new T09 full run.
- Replaced historical demo draft with current 22+3 minute script covering all retained features, mandatory cases and all five challenges. Added evidence index and delivery checklist; corrected unsupported ownership and stale GUI export instructions.
- Read local brief pages 2–4 for package/relative deadlines/all-member airtime/AI notification. Real calendar dates, contributions and signatures remain for the team.
- Validation commands and exact package report: [T09 evidence](../evidence/t09/README.md). Local links/indexed case references and lint checked; final archive is independently extracted and receiver/startup checked before handoff.
- T09 DONE means deliverables prepared and rehearsal tracked honestly. No actual human transfer, measured full rehearsal, message or submission is claimed. No automatic commit/push authorised for T09.

## 7. Demo and delivery

Every retained user-facing feature must map to a live action. Prepare files/keys/folders ahead of time; reuse mandatory workflows to demonstrate advanced starts and attacks. Screenshots are fallback evidence, not a substitute for required working demonstrations.

**D02 update:** the user has adopted `INF2005_ACW1_Demo_Script_and_Presentation_Split_.pdf`. Its named allocation and timings, plus necessary action corrections, are in [study-guide section 17](demo_study_guide.md#17-what-each-presenter-should-prepare). The numbered-member schedule below records the earlier T09 plan; it is no longer the team's selected speaking allocation. Required feature coverage still applies.

| Time | Presenter | Content |
| --- | --- | --- |
| 0-2 | Member 1 | Security boundary, record fields, key generation/fingerprint |
| 2-7 | Member 2 | Image drop, short payload, depth/manual start/capacity, size matching, A-to-B verify and comparison |
| 7-12 | Member 3 | Audio picker, long payload, derived start, playback, sizes and receiver verification |
| 12-15 | Member 4 | Encrypted custom/file payload, trusted recovery/save, applicable image/audio payload previews |
| 15-19 | Members 1 and 3 | Focused attacks and negatives, outside-region limit, repetition recovery/failure |
| 19-22 | Member 5 | Video protect/verify, evidence export and remaining limitations |
| 22-25 | All | Contingency and questions |

Integrate contribution explanations and AI-use reflection into members' segments. Include the third negative in robustness. A real rehearsal must establish feasibility; reduce setup/narration/duplicate actions if needed without dropping agreed capabilities. Never invent rehearsal timing.

Deliver README, architecture/limitations, this living guide, requirement/demo matrix, fresh samples, current test evidence, submission archive and timed script. Human-only items remain names, agreed contribution percentages, signatures, actual transfer/rehearsal records, required AI-use notifications and submission by the brief's deadlines.

## 8. Decision log (earlier scope decisions are historical)

| Decision | Reason |
| --- | --- |
| Tristan replaces the initial Gin-base recommendation | Assignment-facing architecture and existing GUI reduce integration work; Gin safeguards can be adapted narrowly |
| Keep all five optional challenges | User reports professor awards additional marks per challenge |
| Demonstrate every retained extra; plan 22+3 minutes | Professor's presentation scope overrides earlier shorter target |
| Video-only output | User explicitly chose simpler OpenCV flow over audio preservation with FFmpeg |
| Retain size matching and drag/drop | Explicit protected user preferences |
| Fresh samples, focused GUI polish, no Gin-format reader | Confirmed user choices |
| Execute T01 only | Original setup authorization, completed and committed as a8ac5dc |
| Execute T02 only | Subsequent user authorization; baseline/inventory completed |
| Execute T03 only | Subsequent user authorization; backend safeguards completed |
| Execute T04 only | GUI simplification/input handling completed under prior authorization |
| Execute T05 only | Latest user instruction authorises the next task; five challenge workflows completed; T06-T09 remain TODO |
| Execute T06 only | Subsequent user instruction authorises size/property evaluation; completed with evidence; T07-T09 remain TODO |
| Execute T07 only | Subsequent user instruction authorises fresh sender/receiver bundle; completed with independent receiver evidence; T08-T09 remain TODO |
| Execute T08 only | Subsequently authorised integrated validation, including resumed native checks; completed with documented mitigation |
| Execute T09 only | Subsequently authorised the next task after T08 push; prepare handoff without performing human declarations, messages or submission |

## 9. Historical T09 handoff (superseded by S01 above)

- Current branch/workspace: `integration/acw1-consolidated` at `A:/Code/GUI-based-LSB-Replacement-steganography-program`.
- Current state: T01-T09 DONE. Latest authorised scope: T09 handoff only. Human delivery actions remain open in [submission_handoff.md](submission_handoff.md).
- HEAD `2aa68adf83f0e57cefa8cff10b4a78f3ac4c4f41` contains committed/pushed T08. T09 documentation and evidence are uncommitted. See the T09 evidence report.
- T07 bundle: [guide](sample_bundle.md), [case index](../samples/t07/CASE_INDEX.md), [evidence](../evidence/t07/README.md). 27 receiver cases, two capacity checks, 20 authenticated exports and 82 focused tests pass without private keys.
- T08 validation is complete with the documented pytest-qt logging-capture mitigation: 1830 full tests and 932 repeated GUI tests pass; native picker/drop/preview/save/playback/layout pass. See final archive report for extraction provenance and evidence report for limits.
- T09 delivered the [script](demo_plan.md), [evidence index](evidence_index.md) and honest unperformed transfer/rehearsal/submission records. Prepared archive/report are under dist; rebuild after human personalisation.
- Existing untracked samples/r11 remains untouched. Original branches remain untouched.
- Human tasks: names/contributions/signatures, real transfer/rehearsal, notifications and submission remain open.
