# S01 — full steganalysis removal

Base: `93aa40ac58d929e18572c9c43bd0bc7c5ae0c181`, integration/acw1-consolidated,
plus uncommitted S01 changes. Windows, Python 3.11.16 in `.venv-t08`, unchanged
dependency pins. Only stage 1 is authorised; optional video removal is unapplied.

## Changes and results

- Removed the GUI tab, analysis facade, indicator/visualisation APIs and their
  feature-only tests. Preserved numerical quality comparisons and associated
  metric, alpha, input-validation and immutability regressions.
- Removed analysis experiments from generation/receiver/evaluation scripts.
  Index/report schema v2 has no analysis fields. A regression checks v1 payload
  verification ignores retired analysis fields, even when their files are absent.
- Current bundle: 18 verification cases, two capacity checks, 11 authenticated
  exports. Removed nine exclusive analysis cases and reference images. The 44
  retained fixture/media/manifest/key hashes in `retained-fixture-hashes.json`
  match their pre-removal bytes. Retained payloads were not re-signed.
- Updated current documents and demo to four tabs/four challenges. Historical
  reports and design references are retained and explicitly superseded.
- SciPy remains for the preservation experiment's photographic fixture. No
  remaining application code uses statistical detection. Video is unchanged.
- **Full suite: 1713 passed in 47.30s**, no failures/skips (`pytest.txt/xml`).
  Earlier focused run: 158 passed in 6.72s before the additional legacy-index and
  retained input-validation coverage. The final full suite includes both.
- Follow-up removal audit: deleted unused `Region`, `_coerce_region`,
  `_apply_region`, `ImageInput` and their unused import; corrected three stale
  comments in workers, GUI tests and dependencies. Searched app, scripts, current
  samples and requirements for retired detection/visualisation names. Remaining
  mentions are historical records, removal notes and absence/legacy regressions.
  The full-suite result above is the fresh post-audit run; native observations
  below predate this helper/comment cleanup.
- Ruff passes. `scope-check.json` records fixture/index/document checks.

## Native checks

Launched `.venv-t08/Scripts/pythonw.exe main.py` on the normal Windows desktop
(launch PID 26636). Observed Protect, Verify, Attack Lab and Video; navigated all
four. The image fixture selected through the Windows picker displayed correctly.
The retained `video-positive.mkv` played visible frames. The mono WAV player
changed Play to Pause, advanced and returned to Play at 0:02 without an error.
This is an observed player-state check, not a new human confirmation of audibility;
the earlier T08 user audibility confirmation remains historical evidence.
Scrolling exposed the audio controls correctly. A native resize drag did not alter
the window dimensions; small-display layout coverage comes from the passing GUI
tests, not a claimed successful native resize. Normal window close was checked.
No new real transfer, timed rehearsal, signature or submission is claimed.

## Commands and package provenance

From repository root, python below means `.venv-t08/Scripts/python.exe`:

```powershell
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest -q --junitxml=evidence/s01/pytest.xml
python -m ruff check .
python evidence/s01/check_scope.py
python -m scripts.package_submission --output dist/INF2005_ACW1_S01.zip
python evidence/t08/check_package.py --archive dist/INF2005_ACW1_S01.zip --extract tmp/s01-package-audit --report dist/S01-audit-package-report.json
```

The archive report is outside the ZIP to avoid a circular hash. It records the
archive/member hashes, source-byte matching and fresh isolated receiver/startup
commands. Require receiver_passed=true, 18 cases, two capacity checks and 11 exports
before handoff. Prior T08/T09 totals describe their historical builds.

No commit or push is included in S01 implementation. Video removal requires a
separate user instruction; no configuration switch was added.
