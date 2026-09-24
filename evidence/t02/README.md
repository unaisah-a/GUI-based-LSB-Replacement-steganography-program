# T02: Clean baseline and feature/demo inventory

## Outcome and boundary

**T02 complete.** The unchanged Tristan application installs and runs in a clean Python 3.11 environment. All **1,729 existing tests passed**, with zero failures, errors or skips. This establishes a baseline, not completion of T03-T09 or release readiness. No application, test, sample, dependency-pin or CI configuration was modified.

- Date: 2026-09-24 (Asia/Singapore).
- Branch: `integration/acw1-consolidated`.
- Tested HEAD: `a8ac5dcd0cd5256c9280e95db77b3747607e463d` (T01 documentation commit).
- Application/test source is identical to Tristan `6167e72203e3a3045cdc4fa8ae36f4080689df34`.
- Platform: Windows 11, build 26200 (Python platform string reports Windows-10-10.0.26200-SP0).
- Runtime: isolated uv-managed CPython **3.11.16**, x86-64, with a new `.venv`; no reuse of the earlier Python 3.13 environment.
- Every direct pin in requirements.txt installed unchanged and matched installed metadata. Full resolved environment is recorded for transitive dependencies.
- Python provisioning used a local `uv==0.12.18` installation and local managed-runtime/cache directories under ignored `tmp/`; it did not change the system's default Python.

## Checks and evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Clean install of requirements.txt | PASS, exit 0, all declared pins unchanged | [install.txt](install.txt) |
| Exact direct-pin assertions and runtime identity | PASS, all 14 direct pins matched | [probe.txt](probe.txt), [environment.txt](environment.txt), [python-version.txt](python-version.txt) |
| pip check | PASS: No broken requirements found | [pip-check.txt](pip-check.txt) |
| Full existing suite, offscreen Qt | PASS: 1729 tests, 0 failures/errors/skips; pytest reports 66.24 seconds | [pytest.txt](pytest.txt), [pytest.xml](pytest.xml) |
| Baseline Ruff | PASS | [ruff.txt](ruff.txt) |
| Ruff including the final T02 evidence probe | PASS | [ruff-final.txt](ruff-final.txt) |
| Existing committed PNG/WAV/MKV samples | All three AUTHENTIC using committed public key and documented demo start secret | [probe.txt](probe.txt) |
| Real main.main entry point | PASS: offscreen Qt event loop started, exited normally by timed quit | [probe_baseline.py](probe_baseline.py), [probe.txt](probe.txt) |
| Native Explorer drag/drop, audible playback, lab hardware | Not run in T02; remains T04/T08 acceptance | No claim of native verification |
| Remote GitHub Actions | Not triggered or observed; local commands passed | CI presence is not proof of a remote successful run |

The probe patches only the entry-point event loop to quit after one second and disables application file logging. It does not modify application source, regenerate samples, create keys or certify native media playback. The full suite uses its existing fixtures and does not regenerate committed evidence (`--write-evidence` was not used).

### Reproduction commands

From the integration root, with Python 3.11 installed:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip freeze --all
$env:QT_QPA_PLATFORM = 'offscreen'
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe -m pytest -q --basetemp=tmp/t02-pytest --junitxml=evidence/t02/pytest.xml
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe evidence/t02/probe_baseline.py
```

Actual provisioning on this machine (Python 3.11 was initially absent):

```powershell
# Run with the existing Python 3.13 interpreter; installs only a local tool.
python -m pip install --target tmp/t02-tools uv==0.12.18
$env:UV_PYTHON_INSTALL_DIR = Join-Path (Get-Location) 'tmp/t02-python'
$env:UV_CACHE_DIR = Join-Path (Get-Location) 'tmp/t02-uv-cache'
.\tmp\t02-tools\bin\uv.exe python install 3.11 --no-bin
.\tmp\t02-tools\bin\uv.exe venv --python 3.11 --seed .venv
```

The actual bootstrap executable was the existing Python313/python.exe under the user's local Programs directory. The selected runtime resolved to 3.11.16. Use that exact patch version for this baseline if `3.11` later resolves differently. Full test/lint results concern the current pinned stack, not a guarantee about future transitive package resolution.

## Functional requirement inventory

All test modules below participated in the passing full suite. This table identifies implemented behavior and remaining work; it does not treat presence of tests as proof of every new acceptance criterion.

| Requirement | Actual source and test evidence | Gap / next task | Demo segment |
| --- | --- | --- | --- |
| FR1 Image input | app/stego/image_io.py and image_stego.py; test_image_io.py, test_image_stego.py, test_gui_tabs.py; PNG sample verified | Final picker/drop native checks T04/T08 | Member 2, 2-7 |
| FR2 Audio input | app/stego/audio_stego.py; test_audio_stego.py, test_audio_quality.py; WAV sample verified | Audible native playback and lab setup T08 | Member 3, 7-12 |
| FR3 Verification payload | app/crypto/envelope.py VerificationRecord includes media_id, timestamp, nonce, message_hash, metadata; test_envelope.py, test_e2e.py | Confirm signed-field presentation in focused demo T04/T09; brief-exact samples T07 | Members 1-3, 0-12 |
| FR4 Signature | app/crypto/signatures.py, key_manager.py and verification/verifier.py; test_signatures.py, test_crypto.py | Fingerprint presentation absent in current GUI; add planned trust UX T03/T04 | Members 1-3, 0-12 |
| FR5 Image LSB embedding | image_stego.py and lsb_core.py; test_image_stego.py, test_media_facade.py, test_e2e.py | Preserve during consolidation; fresh evidence T07/T08 | Member 2, 2-7 |
| FR6 Audio LSB embedding | audio_stego.py and lsb_core.py; test_audio_stego.py, test_e2e.py | Preserve during consolidation; fresh evidence T07/T08 | Member 3, 7-12 |
| FR7 Start selection/recovery/security | app/crypto/start_location.py and signed/manifest extraction parameters; test_start_location.py, test_manifest.py | Capacity preview omits selected manual offset; actual protection checks location later. Fix preview T03/T04 | Members 2-3, 2-12 |
| FR8 Extraction/decoding | media facade plus verification/verifier.py; test_verification.py, test_e2e.py; all committed media samples verified | Gate trusted GUI preview/save on final verdict T03/T04 | Members 2-4, 2-15 |
| FR9 Hash verification | SHA-256 message digest and verification after signature/decryption; test_verification.py, test_encryption.py, test_e2e.py | Clearly explain payload-only scope and informational manifest digest T09 | Members 1-3, 0-12 |
| FR10 Verdicts | verdicts.py and verifier.py; test_verification.py, test_gui_shell.py | Retain ambiguity notices; presentation/trust gating T03/T04 | Receiver steps and 15-19 |
| FR11 Cases | test_e2e.py includes image/audio positives and corruption, wrong-key/start, capacity and encryption negatives | No committed tampered media bundle; controlled robustness third negative and all selected cases must be packaged T07 | Members 1-3, 2-12 and 15-19 |
| FR12 Reproducibility | scripts/generate_samples.py and package_submission.py; test_package_submission.py; current positives verify | Generator uses one generic message; no receiver case index, required message files or tampered set. Complete T07/T08 | Members 2/5, 2-7 and 19-22 |
| FR13 Innovation | All five extension areas exist with backend/GUI tests | Repetition trials and labelled steganalysis false-alarm/miss evaluation still needed T05; explanation/rehearsal T09 | Throughout |

### Brief-specific checks beyond the FR table

- Depths 1-8 are exposed in Protect; existing image/audio/video tests cover depths. Show selector and tradeoff without repeating eight complete live encodes.
- Capacity includes envelope/signature/encryption/repetition overhead. GUI `_update_readout` calls `media.measure` without the selected manual start; backend `resolve_start_location` validates later. This can make the preview misleading even though the final operation refuses overflow.
- Protect has cover/stego previews; Verify has received-file and recovered-file previews and an optional original-cover comparison. Keep and allocate both comparison routes to the image/audio demo.
- Existing test_e2e.py short/long texts are paraphrases, not the exact Learning Outcome/Project Overview required by the brief. scripts/generate_samples.py uses a single generic 62-byte message for all three covers. T07 must use the required source wording.
- Current committed media include original/protected PNG/WAV/MKV and a public sample key. Tampered files and native screenshots are absent (screenshots contains a README only).
- No real A-to-B transfer or rehearsal was performed in T02. Human declarations, contributions and notifications remain open.

## Optional challenge inventory

| Challenge | Actual baseline | Gap / owner |
| --- | --- | --- |
| Advanced starts | HMAC-derived start using secret and context; manual alternative; test_start_location.py and test_verification.py pass | Explain search-space/confidentiality limits and prepare wrong-secret step T05/T07/T09 |
| Attack simulation | 22 registered attack entries plus per-file selection, bulk runner and evidence export; test_attacks.py and test_gui_lab_tabs.py pass | Reduce UI to agreed focused set T04/T05. Wrong-key/start exist in verification tests/workflows but are not dedicated registry entries; add focused actions without importing the whole Gin framework |
| Robustness | Protect exposes repetition at the default factor 3; error-correction/reporting and controlled recovery tests pass in test_robustness.py | Prepare matched coded/uncoded demo, one-copy recovery and unrecoverable damage; add measured trial evidence T05/T07 |
| Video | Streamed cross-frame OpenCV FFV1 embedding; video/facade/E2E tests pass; committed MKV verifies | No explicit source-audio omission notice in Protect/Video UI; add T04/T05. Remove exploration controls; verify supported property boundaries T05/T06 |
| Steganalysis | Image/audio indicators, reference comparison, channel/plane controls and disclaimers; test_steganalysis.py and GUI tests pass | Simplify views T04; add labelled false-alarm/missed-detection evaluation with provenance T05. Existing statistical tests are not calibrated real-world accuracy evidence |

## Actual extra-feature/control inventory

This reconciles the plan with the exposed GUI so retained controls are not accidentally omitted from the demonstration. None of the following cuts/additions was implemented in T02.

| Exposed feature | Decision / mapped action |
| --- | --- |
| Keys: Generate demo key pair | KEEP; Member 1 opening step. Existing dialog already shows paths |
| Keys: Show key locations | CUT in T04; duplicate information |
| Help: About / What verification establishes | KEEP as help, reference briefly in Member 1 security explanation; do not add a separate feature presentation |
| Drop-zone Select File / Clear, invalid-selection feedback | KEEP; image drag/drop and audio picker, clear/reselect during transition; native checks T08 |
| Protect: text/file source, AES passphrase, depth, manual/derived start, repetition, size matching | KEEP; all covered by the existing 22-minute matrix |
| Protect/Verify: original/stego/received/recovered media preview, Play/Stop/seek | KEEP; exercise playback controls during audio step and file payload preview |
| Verify: optional original-cover comparison | KEEP; fold comparison table into image/audio receiver steps |
| Result panel: Show as text / Show as hex | KEEP under recovered-payload inspection; one quick toggle in Member 4's existing step, not an additional workflow |
| Result panel: Save recovered payload | KEEP, but explicitly gate on AUTHENTIC in T04 |
| Attack Lab: Run Attack / Clear log / Save as evidence | KEEP; run negatives, clear between prepared cases, export final log |
| Attack Lab: Run every applicable attack and variant parameters | CUT in T04 except parameters needed by focused retained cases |
| Steganalysis: reference selector, Analyse, bit-plane/channel selector | KEEP reference/Analyse; choose a sensible default channel/plane presentation in T04, mapped to Member 5 |
| Steganalysis: scale planes to black and white | CUT control in T04; use sensible default |
| Video: locate payload frames and affected-frame indication | KEEP, Member 5 |
| Video: arbitrary frame slider/Show frame, reference exploration, separate capacity-by-depth table | Simplify to required preview/affected-frame view; remove exploration and duplicate capacity UI T04 |
| Original-file recovery sidecar, additional private-key password workflow | NOT PRESENT in this baseline; do not import/add |
| CI, packaging, bulk evaluation scripts | Development/evidence tools, not extra GUI workflows; retain useful tooling |

## Prioritized gaps for subsequent tasks

1. **T03 publication safety:** sender checks input vs output but does not provide full manifest/path-alias validation or backup restoration of replaced media/manifest as a bundle. Adapt the agreed transaction safeguards and failure-injection tests.
2. **T03/T04 trusted-result gating:** verifier returns a `TAMPERED` manifest-cross-check result with recovered bytes. VerifyTab `_on_verified` passes `result.message` directly to preview; ResultPanel enables payload buttons whenever bytes exist. Add final-verdict gating even though message hash/signature passed in that particular failure path.
3. **T03 bounded KDF costs:** encryption `_validate_cost` validates positive values, power-of-two N and a lower bound, but has no upper work/memory limits. Add defensible bounds and tests before expensive processing; signature-first ordering remains important.
4. **T03/T04 manual-start capacity and responsiveness:** preview measures from the full carrier and runs synchronous media measurement in `_update_readout`; video edits can trigger expensive scans. Include chosen start and prevent stale/blocking previews as planned.
5. **T04 mixed-URL drops:** DropZone `_single_local_file` filters remote URLs before counting, so one local plus one remote URL is accepted. Require exactly one original URL and local-file validation. Existing green tests do not cover this gap.
6. **T03/T04 fingerprint UX:** no fingerprint implementation/presentation was found in Tristan's crypto/GUI search. Add the planned independently trusted public-key fingerprint display; do not imply fingerprints themselves establish trust.
7. **T04/T05 focused optional UX:** remove agreed peripheral controls, expose focused wrong-key/start actions, show video-only warning and keep all five challenges.
8. **T05/T06 evaluation:** add measured repetition trials and labelled steganalysis error rates; regenerate representative size/property evidence without universal guarantees.
9. **T07 samples:** exact brief text, custom confidentiality case, required image/audio negatives, Party A/B layout and receiver index are missing from the committed sample set.
10. **T08/T09 release/human evidence:** native interactions, real transfer, complete retained-feature demonstration and timed rehearsal remain unverified. A passing offscreen suite does not replace them.

T02 is an inventory/baseline task: these findings are assigned to later tasks and deliberately left unfixed. The next authorized implementation task would be T03; do not start it without user authorization.
