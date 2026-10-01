# H05 version 2 release validation — DONE

Validated on 1 October 2026, Windows 11, PowerShell, `.venv-t08` Python 3.11.16.
Base HEAD: `32b4125b29a70c3f31827acac6d5a1efb9cc0c9f`, branch
`integration/acw1-consolidated`, plus uncommitted H02-H05 changes.
`source-hashes.json` identifies the final source/test/runtime files. No commit,
push, human transfer, rehearsal, declaration or submission is claimed.

## Results and changes

- Final full suite: **1,832 passed in 50.84s**, no failures/skips;
  [stdout](full-final.txt) and [JUnit](full-final.xml).
- Initial focused schema/hash/bundle/package run: **134 passed in 7.48s**
  ([focused.txt](focused.txt)); final hash/GUI/consolidation run: **56 passed in
  2.82s** ([gui-layout.txt](gui-layout.txt)). Earlier full run before the three
  layout regressions: 1,829 passed in 50.64s (`full.txt/xml`).
- [Ruff](ruff.txt) and [24-package dependency consistency](dependencies.txt): PASS.
  Extracted startup probe also checked every direct dependency pin unchanged.
- Native inspection found default-window horizontal overflow and clipped hashes.
  Digest values now use read-only plain-text fields that wrap between characters,
  preserving the exact 64-character selection. Form rows can wrap on narrow views.
- `scripts/release_samples.txt` explicitly lists released samples. Unlisted local
  practice outputs remain on disk and stay outside the archive. Missing or unsafe
  inventory entries fail packaging. Private-key scanning remains mandatory.
- New `scripts/check_release_package.py` audits archive members against source
  bytes, rejects unsafe/duplicate paths and private PEMs, extracts into a new
  directory, then runs the extracted receiver-isolation and startup probes.
  `scripts/probe_release.py` confirms pins, actionable version 1 rejection and
  the actual entry point's offscreen startup. Historical evidence scripts are intact.

## Native evidence

Used the computer-use plugin's `@oai/sky` Windows API. The final app launch was
PID 16308, with a 1180 × 820 client area (1182 × 852 captured outer window).
Sandbox launches exposed no desktop window; the approved interactive launch
worked. Only task-created app instances were closed. No signing key was saved.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Native picker, matching v2 image and public key | AUTHENTIC; three full hashes; all comparisons Yes | [Image](native-authentic.png), [tree](native-authentic.txt) |
| Double-click digest selection | Exact `165cc628962b784801a52d1fa396a7cd6272a7cb22a08438ed63a4e4047b2f5d` selected | [Image](native-selected-hash.png), [tree](native-selected-hash.txt) |
| Manual manifest change | Current evidence/message cleared; save disabled | [Tree](native-input-cleared.txt) |
| External hash changed to zero | TAMPERED; signature valid; No/No/Yes comparisons; recovery disabled | [Image](native-mismatch.png), [tree](native-mismatch.txt) |
| Unrelated public key | SIGNATURE_INVALID; signed/computed digests Unavailable; comparisons Not performed | [Image](native-signature-failure.png), [tree](native-signature-failure.txt) |
| Attack Lab wrong-key action | AUTHENTIC → SIGNATURE_INVALID; full expected hash and before/after history | [Image](native-attack.png), [tree](native-attack.txt) |
| Attack Lab key change | Current panels clear; completed run remains labelled in history | [Tree](native-attack-cleared.txt) |

Vertical scrolling exposes lower results. Native selection was visually checked
and returned the exact digest through accessibility. Current GUI regressions check
Verify at 900/1180 pixels and Attack Lab at 1180 pixels. Attack Lab still needs
horizontal scrolling at 900 pixels because of its wider controls; no narrow-screen
redesign is claimed. Native playback, drag/drop, all media and encryption were not
repeated in H05. Their current automated coverage and historical native evidence
remain separate. The app's status bar retains the last completed operation when
inputs change; the current result/hash panels and recovery controls clear.

## Commands actually executed

From the workspace root; `python` below means `.venv-t08/Scripts/python.exe`.
Automated Qt tests use offscreen mode and the established `--no-qt-log` mitigation.

```powershell
python -m pytest tests/test_package_submission.py tests/test_release_package.py tests/test_manifest_v2.py tests/test_hash_evidence.py tests/test_sample_bundle.py --no-qt-log -q
python -m pytest tests/test_hash_evidence.py tests/test_gui_consolidation.py --no-qt-log -q
python -m pytest --no-qt-log -q --junitxml=evidence/h05/full-final.xml
python -m ruff check .
$env:UV_CACHE_DIR='tmp/uv-cache'
uv pip check --python .venv-t08/Scripts/python.exe
git -c core.safecrlf=false diff --check
python -m scripts.package_submission --output dist/H05-candidate.zip
python -m scripts.check_release_package --archive dist/H05-candidate.zip --output tmp/h05/package-candidate
python -m scripts.package_submission --output dist/H05-validated.zip
python -m scripts.check_release_package --archive dist/H05-validated.zip --output tmp/h05/package-final
```

The candidate's [package report](package-candidate.json) records its exact SHA-256,
453 member hashes and subprocess commands. All **20 receiver cases, two capacity
checks and 11 exact authenticated exports** passed without private keys or Party A
in the copied receiver workspace; see [receiver report](receiver-report.json).
The extracted startup probe passed. This reuses installed dependencies and is local
process/file isolation, not an OS denial-of-access sandbox or a human transfer.

The final delivery archive is rebuilt after documentation/audit completion using
the same checker: `dist/H05-validated.zip`, with output `tmp/h05/package-final`.
Its `package-report.json` is also copied to `dist/H05-validated-report.json`.
That external report identifies the final archive without a circular self-hash.
See [handoff commands](../../docs/submission_handoff.md).

## Investigation and preservation

The first package audit falsely matched a dummy PEM header inside test source;
anchoring PEM headers to the beginning of a line fixed it. Nine package-check
tests passed after that change (`package-tests.txt`). A first layout attempt
removed horizontal overflow but clipped the manifest digest; the final native
run above uses the corrected text-wrapping control. An exploratory Attack Lab
900-pixel assertion failed; the retained regression covers its default width.
A test command named a nonexistent `test_gui_widgets.py`; the corrected command
above passed. UV's default cache was inaccessible; using the existing workspace
cache passed without an installation or pin change. Failed attempts are not counted as passing checks.

The final audit compared H04's pre-existing-file and bundle snapshots. Historical
samples/evidence and user practice outputs are unchanged. The native app appended
to its ignored runtime log, which remains excluded from packaging. All 78 current
bundle files retain H04 hashes. `audit.json` records the actual comparison counts
and exact receiver-export checks. Original branches remain untouched.
