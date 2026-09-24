# T04 GUI simplification and input handling

Status: DONE. Scope: T04 only, on `integration/acw1-consolidated` in
`C:/Code/INF2005-ACW1-consolidated`. Tested HEAD `27572c98cc734e0daa24dcc1377df0234a970618`
plus uncommitted T03/T04 changes, Python 3.11.16 and unchanged dependency pins.

## Changes

- Removed bulk attacks and extra GUI attack variants, video frame/reference exploration and capacity-by-depth table, steganalysis scaling checkbox and separate key-location menu. Backend experiments/tests remain.
- Retained five tabs, normal pickers, drag/drop and size matching. Picker/drop share validation; mixed URL drops are refused. Clear resets tab input.
- Capacity measurement runs on a debounced worker, includes manual offset and discards superseded results. Other tab workers reject results for superseded inputs.
- Final AUTHENTIC verdict gates recovered preview/save. Public-key fingerprints appear in Protect/Verify with an external-trust reminder.
- Video-only FFV1/MKV output is disclosed before protection and in results; Video shows playback and manifest-claimed frame span.

## Executed validation

PowerShell, repository root, `QT_QPA_PLATFORM=offscreen`:

```powershell
.venv\Scripts\python.exe -m pytest -q --basetemp=tmp/t04-full --junitxml=evidence/t04/pytest.xml
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe evidence/t02/probe_baseline.py
git diff --check
```

- Full suite: **1799 passed in 44.60s**, no failures/errors/skips. See `pytest.txt` and `pytest.xml`.
- 21 new input/trust/worker/fingerprint regressions. Seven obsolete GUI-only tests removed; retained tests adapted to focused controls and asynchronous capacity. Backend coverage remains.
- Existing GUI/video suite after adaptation: 281 passed (`second.txt`). Initial failure logs are retained as development history, not final results.
- Existing PNG/WAV/MKV samples: AUTHENTIC; real `main.main` offscreen startup exits successfully (`probe.txt`).
- All nine T03 source/test SHA-256 hashes match `evidence/t03/summary.json`.
- Original `gin` and `Tristan` refs preserved. No commit, sample regeneration or dependency change.

## Limits and handoff

The two offscreen screenshots have missing font glyphs in this environment; they are
not evidence of readable native rendering. Native appearance, playback and physical
drag/drop remain T08. Automated input/drop, preview/save and worker checks pass.

T05 remains TODO: dedicated wrong-key/wrong-start challenge actions, reproducible
robustness and steganalysis evaluation. Current Attack Lab exposes message/signature
corruption and media-specific outside-payload edits. No optional challenge is dropped.
The inherited demo script is explicitly historical; the living implementation guide
contains the current feature/time matrix. T09 prepares the final script and rehearsal.
