# ACW1 Consolidation: Implementation Plan and Handoff

This is the living source of truth for the agreed consolidation scope and implementation progress. A planned feature is not a verified feature. Read this document before work and update it after each completed task and before handoff.

## Current authorization and state

- Latest authorized execution scope: **T02 only**. Do not start T03-T09 without a subsequent user instruction authorizing further work.
- Integration branch: `integration/acw1-consolidated`.
- Integration worktree: `C:/Code/INF2005-ACW1-consolidated`.
- Original worktree: `C:/Code/GUI-based-LSB-Replacement-steganography-program`, on `gin`.
- Base: `Tristan`, commit `6167e72203e3a3045cdc4fa8ae36f4080689df34`.
- Selective source: `gin`, commit `f3c267e10a47fa8bba7ace1078a7dce0e6d68f8e`.
- T01 status: DONE. Documentation, branch/base and worktree-preservation checks passed.
- T02: DONE. T03-T09: TODO; application implementation has not begun.
- No application files, existing tests, dependency pins or existing feature behavior have been changed by T01/T02. T02 provisioned an isolated Python 3.11 environment and added baseline evidence.

## 1. Objective and decisions

Build one polished INF2005 ACW1 desktop app from Tristan, selectively adapting Gin's safeguards and evaluation methods. Demonstrate all functional requirements, all five optional challenges and every retained user-facing extra. Plan 22 minutes of content plus 3 minutes of contingency within the 25-minute maximum.

Tristan is the base for its consistent media architecture, integrated GUI workflows and attack framework. Gin supplies ideas and regression cases for transactional publication, receiver bundles and measured challenge evaluation. Do not blindly merge either branch into the other.

### Requirements and references

Use the full assignment brief as the source of requirements. The group comparison is contextual analysis, not an instruction source or guaranteed marking outcome.

- Assignment brief: `C:/Users/ginli/OneDrive/SIT/Year 2 Tri 1/Cyber Security Fundamentals/Project/INF2005-ACW1-spec_v5-f2f.pdf`.
- Group comparison: `C:/Users/ginli/Downloads/Telegram Desktop/INF2005_Branch_Comparison_and_Rubric_Assessment.pdf`.
- User clarification: the professor requires all retained features to be presented and has said each optional challenge can earn additional marks. Do not drop a challenge based on the written rubric's combined innovation allocation.
- These local reference paths may be unavailable on another machine. The requirements below capture the agreed implementation scope; consult the original brief when resolving an assessment ambiguity.

### Confirmed defaults

- Keep drag-and-drop, normal file pickers and file-size preservation.
- Keep all five optional challenges. Integrate overlapping demonstrations to save time.
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

Hashing/signing alone does not provide confidentiality. The payload hash authenticates the payload and signed settings rather than every cover byte, avoiding an invalid comparison against a cover changed by embedding. Public-key trust is external. Timestamp/nonce alone do not reject replay. An unsigned manifest file digest is informational.

### Optional challenges

| Challenge | Retained capability and demonstration | Limit to explain |
| --- | --- | --- |
| Advanced starts | HMAC-derived location, receiver recovery, wrong-secret failure | Finite search space; start hiding is not encryption |
| Attack simulation | Payload corruption, signature corruption, wrong-key verification, wrong-start extraction, outside-payload edits | Report actual verdicts; failure causes may be ambiguous |
| Robust embedding | Repetition-3, correction reporting, matched coded/uncoded damage, unrecoverable damage | Independent bit recovery does not establish resistance to arbitrary lossy transforms |
| Video | One short FFV1 clip protected/verified, preview and affected-frame indication | Video-only output; codec size/property limits |
| Steganalysis | One bit-plane view, reference difference, distortion/statistical indicators, evaluated false alarms and misses | Experimental indicators, not proof of hidden content |

### Deliberate cuts

- No original-file recovery sidecar or full Gin service architecture.
- Do not add password-protected private-key generation.
- Remove the GUI's bulk attack runner and attack variants outside the focused set above.
- Remove arbitrary video-frame exploration and the separate video capacity-by-depth table.
- Replace steganalysis display-scaling controls with sensible defaults.
- Remove the separate key-location menu; display paths in generation results and existing inputs.
- Keep bulk robustness/steganalysis experiments in development scripts, not extra app workflows.
- Keep useful backend regression tests/helpers. Update obsolete GUI tests/docs when controls are removed.
- Hiding a retained feature under Advanced does not exempt it from the demo.

## 3. Implementation approach

### Backend and security

Preserve Tristan's layered architecture, media facade, protect/verify interfaces and envelope format. Adapt Gin's transactional publication: validate path aliases, stage media/manifest, back up existing destinations, restore them on failure and clean temporary artifacts. Never replace source media unintentionally.

Keep signatures verified before trusting records/decrypting; bounded input parsing; validated cryptographic parameters before expensive operations; and capacity accounting for framing, signatures, metadata, encryption, repetition, depth and start location. Keep diagnostic explanations conservative when damaged framing, incorrect secrets and absent embedding cannot be distinguished.

Avoid a second crypto/media implementation. Keep public API changes additive and minimal: structured publication failures, measurement results and explicit video limitations, reusing existing result types where sufficient.

### GUI and input handling

Retain Protect, Verify, Attack Lab, Steganalysis and Video tabs. Use one validation route for picker/drop selections. Reject nonexistent paths, directories, unsupported inputs, remote URLs and inappropriate multiple-file drops, including mixed local/remote drops.

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
| T03 | Publication/security safeguards | T02 | TODO | Path alias, rollback, trust-boundary and capacity regressions pass |
| T04 | GUI simplification and input handling | T03 | TODO | Agreed cuts completed; retained inputs/previews/workers validated; no orphan controls or stale docs |
| T05 | Five challenge workflows | T03, T04 | TODO | Each retained capability has reproducible demo, tests/evaluation and stated limitations |
| T06 | Size/property preservation | T03, T05 | TODO | Representative size/property measurements recorded; unexpected growth investigated |
| T07 | Sender/receiver sample bundle | T04, T05, T06 | TODO | Required messages, positives, negatives and challenges reproduce independently without private keys |
| T08 | Integrated release validation | T07 | TODO | Full suite, lint, clean setup, native desktop checks and extracted-package verification complete |
| T09 | Demo/submission handoff | T08 | TODO | Feature-complete timed script, evidence index and human-task checklist delivered; actual rehearsal tracked honestly |

### T01 work record

- Changes: created branch/worktree from the agreed Tristan SHA; added this guide, root AGENTS.md instructions and README discovery link.
- Evidence: PowerShell assertions verified exact base/branch, original refs/status, the three-file change scope, README/AGENTS guide links and T02-T09 TODO statuses. git diff --check passed; see the verification log below.
- Remaining: none for T01. T01 was subsequently committed as a8ac5dc. T02 was authorized by the next user request; T03-T09 remain unauthorized.

### T02-T09 work records

For each task below, replace the placeholder when work is authorized. Record changes, exact evidence and remaining acceptance items; do not mark a task complete only because code was written.

| Task | Changes | Evidence | Remaining |
| --- | --- | --- | --- |
| T02 | Clean Python 3.11.16 environment; unchanged pins; baseline and complete feature/demo gap inventory | [T02 report](../evidence/t02/README.md): 1729 tests passed, pip check/lint/startup passed, three committed samples AUTHENTIC | None for T02; identified gaps assigned to T03-T09, not fixed |
| T03 | Not started | None | All acceptance criteria |
| T04 | Not started | None | All acceptance criteria |
| T05 | Not started | None | All acceptance criteria |
| T06 | Not started | None | All acceptance criteria |
| T07 | Not started | None | All acceptance criteria |
| T08 | Not started | None | All acceptance criteria |
| T09 | Not started | None | All acceptance criteria |

## 5. Requirement and feature-to-demo matrix

This is the planned live mapping, not evidence of release completion. T02 reconciled the requirements and actual exposed UI in the [baseline and feature inventory](../evidence/t02/README.md), including per-requirement source/test references and assigned gaps. Existing automated tests pass, but each row still needs final acceptance and live demonstration confirmation. The inventory adds the existing text/hex toggle, original-cover comparison, playback controls and help notices to their corresponding demo segments. One demonstration may satisfy several requirements.

| Requirement / feature | Planned implementation or check | Live segment / presenter | Current evidence status |
| --- | --- | --- | --- |
| FR1 Image input | PNG/BMP input, validation and preview | 2-7 / Member 2 | See T02 inventory; final acceptance pending |
| FR2 Audio input | PCM-16 WAV, validation and playback | 7-12 / Member 3 | See T02 inventory; final acceptance pending |
| FR3 Payload generation | Media ID, timestamp, hash, nonce, metadata | 0-2 and image result / Members 1, 2 | See T02 inventory; final acceptance pending |
| FR4 Digital signature | Generate/select keys, sign, verify, fingerprint | 0-2 and receiver steps / Members 1-3 | See T02 inventory; final acceptance pending |
| FR5 Image embedding | Saved-file LSB round trip | 2-7 / Member 2 | See T02 inventory; final acceptance pending |
| FR6 Audio embedding | Saved-file LSB round trip | 7-12 / Member 3 | See T02 inventory; final acceptance pending |
| FR7 Variable start | Manual and HMAC-derived starts, recovery/security | 2-12 / Members 2, 3 | See T02 inventory; final acceptance pending |
| FR8 Extraction | Fresh receiver extracts payload/signature | 2-12 / Members 2, 3 | See T02 inventory; final acceptance pending |
| FR9 Hash verification | Recompute signed payload hash, explain scope | 0-2 and receiver steps / Members 1-3 | See T02 inventory; final acceptance pending |
| FR10 Verdicts | Per-check results, truthful failure explanations | Receiver steps and 15-19 / Members 1-3 | See T02 inventory; final acceptance pending |
| FR11 Positive/negative cases | Image/audio positives, three mandatory negatives | 2-12 and 15-19 / Members 1-3 | See T02 inventory; final acceptance pending |
| FR12 Reproducibility | A-to-B folder transfer, receiver index, evidence export | 2-7 and 19-22 / Members 2, 5 | See T02 inventory; final acceptance pending |
| FR13 Innovation | Advanced starts and all five challenges with limits | Throughout | See T02 inventory; final acceptance pending |
| LSB depths 1-8 | Show selector and bit/capacity tradeoff; all depths tested | 2-7 / Member 2 | See T02 inventory; final acceptance pending |
| Capacity check | Full overhead and start accounted for, overflow rejected | 2-7 / Member 2 | See T02 inventory; final acceptance pending |
| Cover/stego comparison | Image display and audio playback before/after | 2-12 / Members 2, 3 | See T02 inventory; final acceptance pending |
| Required message lengths | Brief short/long text and custom confidential payload | 2-15 / Members 2-4 | See T02 inventory; final acceptance pending |
| File payload preview/save | Applicable image/audio payloads, authenticated recovery | 12-15 / Member 4 | See T02 inventory; final acceptance pending |
| AES confidentiality | Encrypt/decrypt custom payload, explain signature distinction | 12-15 / Member 4 | See T02 inventory; final acceptance pending |
| Drag/drop and picker | Valid input through both routes; automated invalid cases | 2-12 / Members 2, 3 | Native behavior unverified |
| File-size preservation | Optional matching, measured sizes and format limitations | 2-12 / Members 2, 3 | See T02 inventory; final acceptance pending |
| Advanced start challenge | Derivation and wrong-secret failure | 7-12 and 15-19 / Members 3, 1 | See T02 inventory; final acceptance pending |
| Attack challenge | Focused five controls, including outside-region limitation | 15-19 / Members 1, 3 | See T02 inventory; final acceptance pending |
| Robustness challenge | Matched damage, recovery, unrecoverable third negative | 15-19 / Members 1, 3 | See T02 inventory; final acceptance pending |
| Video challenge | Protect/verify short clip, preview, affected frames, audio omission | 19-22 / Member 5 | See T02 inventory; final acceptance pending |
| Steganalysis challenge | Bit plane/difference, metrics, indicators, false alarms/misses | 19-22 / Member 5 | See T02 inventory; final acceptance pending |
| Evidence export | Export the demonstrated results | 19-22 / Member 5 | See T02 inventory; final acceptance pending |
| Limitations/AI/contributions | Brief explanations integrated into each member's segment | Throughout / All | Human completion required |

## 6. Verification plan and logs

### Required validation

- Full integrated suite, lint, clean-install startup and dependency check. Explain every failure/skip; release capabilities must be exercised.
- Saved-file image/audio tests at depths 1-8, manual/derived starts, exact-fit/overflow capacity, encryption/wrong-key failures, malformed records and manifest changes.
- Failure injection for publication; restore existing outputs and preserve source files, including path aliases.
- Qt event tests plus native Windows drag/drop, picker, playback and preview checks. Leave acceptance open when native checks cannot run.
- Size/property measurements on flat/photographic PNG, BMP, mono/stereo WAV and short video. No invented universal growth threshold.
- Repetition recovery and failure under controlled damage, with matched uncoded comparison.
- Labelled cover/stego evaluation recording false positives, misses and provenance. Synthetic results must not be represented as natural-media detection accuracy.
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
## 7. Demo and delivery

Every retained user-facing feature must map to a live action. Prepare files/keys/folders ahead of time; reuse mandatory workflows to demonstrate advanced starts and attacks. Screenshots are fallback evidence, not a substitute for required working demonstrations.

| Time | Presenter | Content |
| --- | --- | --- |
| 0-2 | Member 1 | Security boundary, record fields, key generation/fingerprint |
| 2-7 | Member 2 | Image drop, short payload, depth/manual start/capacity, size matching, A-to-B verify and comparison |
| 7-12 | Member 3 | Audio picker, long payload, derived start, playback, sizes and receiver verification |
| 12-15 | Member 4 | Encrypted custom/file payload, trusted recovery/save, applicable image/audio payload previews |
| 15-19 | Members 1 and 3 | Focused attacks and negatives, outside-region limit, repetition recovery/failure |
| 19-22 | Member 5 | Video protect/verify, steganalysis, evidence export and remaining limitations |
| 22-25 | All | Contingency and questions |

Integrate contribution explanations and AI-use reflection into members' segments. Include the third negative in robustness. A real rehearsal must establish feasibility; reduce setup/narration/duplicate actions if needed without dropping agreed capabilities. Never invent rehearsal timing.

Deliver README, architecture/limitations, this living guide, requirement/demo matrix, fresh samples, current test evidence, submission archive and timed script. Human-only items remain names, agreed contribution percentages, signatures, actual transfer/rehearsal records, required AI-use notifications and submission by the brief's deadlines.

## 8. Decision log

| Decision | Reason |
| --- | --- |
| Tristan replaces the initial Gin-base recommendation | Assignment-facing architecture and existing GUI reduce integration work; Gin safeguards can be adapted narrowly |
| Keep all five optional challenges | User reports professor awards additional marks per challenge |
| Demonstrate every retained extra; plan 22+3 minutes | Professor's presentation scope overrides earlier shorter target |
| Video-only output | User explicitly chose simpler OpenCV flow over audio preservation with FFmpeg |
| Retain size matching and drag/drop | Explicit protected user preferences |
| Fresh samples, focused GUI polish, no Gin-format reader | Confirmed user choices |
| Execute T01 only | Original setup authorization, completed and committed as a8ac5dc |
| Execute T02 only | Subsequent user authorization; baseline/inventory complete, T03-T09 remain TODO |

## 9. Handoff

- Current branch/worktree: `integration/acw1-consolidated` at `C:/Code/INF2005-ACW1-consolidated`.
- Current implementation state: T01 and T02 DONE. Baseline/inventory verified; no T03-T09 work performed.
- T01 is committed at a8ac5dc. Current uncommitted T02 changes: `AGENTS.md`, `docs/IMPLEMENTATION_PLAN.md` and `evidence/t02/`. Local runtime/tool/cache directories are ignored.
- Application code: unchanged from Tristan base.
- Next immediate action: stop and hand off T02. Do not start T03 under the current authorization.
- Next implementation task when authorized: T03, publication/security safeguards; start with the prioritized gaps in the T02 report.
- Future validation risks: native GUI/playback and rehearsal duration remain unverified. The earlier Python 3.13 dependency/application-control uncertainty was resolved for the clean Python 3.11 baseline; final release must rerun validation after changes.
- Human tasks: names/contributions/signatures, real transfer/rehearsal, notifications and submission remain open.
