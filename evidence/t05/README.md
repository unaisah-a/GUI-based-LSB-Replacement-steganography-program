# T05 five challenge workflows

Status: DONE. T05 only; T06-T09 not executed.

Tested on Windows, Python 3.11.16, all 14 direct dependency pins unchanged.
Branch integration/acw1-consolidated; HEAD 35b498a6a5becfdc9e0d6a0aa33591d1913cb34c
plus the T05 working-tree changes identified in source_hashes.json. Current workspace:
A:/Code/GUI-based-LSB-Replacement-steganography-program. The old C:/Code worktree
paths in historical T01-T04 records are not this execution environment.
The pre-existing untracked samples/r11 directory was left untouched.

## Changes

- Added wrong-key/wrong-HMAC-start actions to the focused Attack Lab. Both require
  successful baseline verification, preserve input files and label the original
  input rather than claiming to write output. Derived-location collisions use a
  bounded search; manual starts receive an explicit unsupported-action error.
- Added a development evaluation script and end-to-end regression for all five
  challenges, plus backend/GUI regressions for substitution, failure guards and
  collision search exhaustion. No bulk GUI controls were restored.
- Added [demonstration steps and limitations](../../docs/challenge_workflows.md).
- Added .venv-*/ to ignored local environments. Existing .venv was not modified.

## Executed commands and results

PowerShell, repository root; QT_QPA_PLATFORM=offscreen for pytest and startup:

```powershell
# UV_CACHE_DIR=tmp/uv-cache; UV_PYTHON_INSTALL_DIR=tmp/uv-python
uv venv --python 3.11 .venv-t05
uv pip install --python .venv-t05/Scripts/python.exe -r requirements.txt
.venv-t05/Scripts/python.exe -m scripts.evaluate_challenges --output tmp/t05-demo-2
.venv-t05/Scripts/python.exe -m pytest -q --basetemp=tmp/t05-pytest --junitxml=evidence/t05/pytest.xml
.venv-t05/Scripts/python.exe -m ruff check . --exclude .venv-t05
uv pip check --python .venv-t05/Scripts/python.exe
.venv-t05/Scripts/python.exe evidence/t02/probe_baseline.py
git diff --check
```

- Full suite: **1809 passed in 38.17s**, no failures/errors/skips; pytest.txt/xml.
- Ruff: PASS. uv pip check: all 24 installed packages compatible.
- probe.txt: all direct pins match, committed PNG/WAV/MKV samples AUTHENTIC,
  real application offscreen startup/normal exit PASS.
- challenge_results.json: all 15 focused attack demonstrations matched expectations
  across PNG/WAV/MKV; all three original protected files verified AUTHENTIC.
- Controlled image/audio robustness: one-bit damage fails uncoded, repetition-3
  recovers with a reported correction, damage to two copies fails. Six outcomes.
- Video: saved-file extraction authenticates; ten decoded frames; actual changed
  frames checked against the payload span. Synthetic input contains no audio.
- Fixed steganalysis rule: **2/9 false positives, 7/9 misses**, on 18 labelled
  synthetic cases. Per-case indicators, quality and provenance are retained.
  These are fixture results, not natural-media detection accuracy.

## Development failures and limits

The pre-existing .venv runs Python 3.14.3, has different pins and lacks OpenCV; the
first experiment could not import cv2. A separate Python 3.11.16 environment was
created. Initial cache/network restrictions were resolved with workspace-local UV
paths and approved dependency downloads. The first pinned experiment selected an
incorrect overall indicator scope; it was corrected to the existing channel-0
indicator. Initial focused tests exposed the new HMAC-only action in manual-start
parameterised tests; those tests now exclude it and dedicated derived/manual/error
regressions cover it. Final full-suite and experiment results above supersede these
failed development attempts.

Generated media remain in tmp/t05-demo-2, reproducible using the script; this is
not the T07 sample bundle. Keys are generated in memory and only public keys saved.
No native rendering/playback, source-audio omission test, real transfer or rehearsal
was performed. Native desktop validation remains T08, size/property evaluation T06,
release samples T07 and final demo/submission handoff T09.
