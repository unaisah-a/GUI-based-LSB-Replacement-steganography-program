# T08 integrated validation — DONE

Base: `3b79700c44196f64bc8a9f1f937392e34c056e43`, branch
`integration/acw1-consolidated`, plus the uncommitted T08 working tree.
Windows 11 (build 26200), Python 3.11.16, fresh `.venv-t08`, unchanged direct
dependency pins. `source-hashes.json` identifies the final changed source files.
No commit, push, T09 work, actual human transfer or rehearsal is claimed.

## Current result

- **1830 tests passed in 52.50s**, no failures or skips: `stable-full.txt/xml`.
- Repeated GUI diagnostic: **932 passed in 32.75s**, `no-log-diagnostic.txt`.
- Ruff, 24-package dependency consistency, pinned versions, original PNG/WAV/MKV
  authenticity and real offscreen application startup pass.
- Audio-bearing source video becomes authenticated FFV1 video-only output:
  30 frames, 15 fps, 128x96, two seconds. Exact payload recovered.
- Fresh package extraction passes all 27 T07 receiver cases and two capacity
  checks, with 20 authenticated files exported. Original samples and offscreen
  startup also pass using the extracted code.
- Native picker, manual drag/drop, image/audio payload preview and exact save,
  audible audio and visible video playback passed on the authorised final retry.
- The test-runner crash is mitigated by the supported `--no-qt-log` option.
  The underlying native defect is not proven; earlier crashes remain recorded.

## Changes

- Main-window tab pages scroll when loaded manifests/results need more height.
  Native observation found clipped manifest rows; a styled small-display test
  checks scrolling and row readability. Values now grow and reserve wrapped-text
  height. The final native reload shows the complete derived-start value.
- Preview clear/close destroys the player before its surface, owns audio output
  under the player and permits subsequent loading. Failed backend construction
  also disposes the player immediately. The Windows DLL-search handle is retained.
  These are lifecycle improvements, **not a demonstrated crash fix**.
- Corrected the generated image-quality property: overall MSE/PSNR compare colour
  channels; alpha-only differences still make `pixel_identical` false. Production
  metric behaviour and the existing explicit alpha regression are unchanged.
- Packager includes `.gitattributes` and `AGENTS.md`, excludes unrelated
  `samples/r11`, and retains its private-key scan. Original branches and unrelated
  sample work were not changed.

## Executed commands

Commands ran from `A:/Code/GUI-based-LSB-Replacement-steganography-program`.
`python` below means `.venv-t08/Scripts/python.exe`, unless stated otherwise.
All automated Qt tests used `QT_QPA_PLATFORM=offscreen`.

```powershell
$env:UV_CACHE_DIR='tmp/uv-cache'
uv venv --python .venv-t05/Scripts/python.exe .venv-t08
uv pip install --python .venv-t08/Scripts/python.exe -r requirements.txt
uv pip check --python .venv-t08/Scripts/python.exe
$env:QT_QPA_PLATFORM='offscreen'
python -m pytest -q --junitxml=evidence/t08/current-full.xml
python -m ruff check .
python evidence/t02/probe_baseline.py
python evidence/t08/check_video_audio.py --output tmp/t08-video-audio
python -m scripts.package_submission --output dist/T08-preliminary.zip
python evidence/t08/check_package.py --archive dist/T08-preliminary.zip --extract tmp/t08-package-preliminary --report dist/T08-preliminary-report.json
```

Installation initially failed with restricted network access; the approved retry
succeeded (`install.txt`). Current environment checks are `pip-check.txt`,
`ruff.txt`, and `probe-final.txt`. The baseline probe executes the real entry point
with a timed offscreen exit; it does not establish playback or drag/drop.

The video check uses the existing development installation of FFmpeg/ffprobe
(`video-audio.txt` records its version). It muxes T07's video and tone, checks
source audio presence, then protects/verifies through the application and probes
the result. Its signing key is never saved. This introduces no application
dependency or audio-preserving video feature.

## Crash investigation and historical runs

| Evidence | Actual outcome |
| --- | --- |
| `baseline.txt/xml` | Previous `.venv-t05` full baseline: 1826 passed in 71.81s |
| `gui-clean.txt` | Fresh `.venv-t08` combined GUI run: native access violation |
| `gui-close.txt/xml` | Initial close cleanup: 231 GUI tests passed |
| `pytest.txt` | Subsequent full run: native access violation |
| `retry-gui.txt` | Shell/tabs modules: 167 passed |
| `retry-full.txt/xml` | 1827 passed; incorrect alpha property failed |
| `retry-focused.txt` | Corrected property, GUI and packager: 272 passed |
| `preview-stress-before.txt` | 135 isolated preview tests passed; not an integrated crash fix |
| `gui-stress.txt`, `gui-stress-dispose.txt` | Repeated combined GUI collections: native access violation before completion |
| `preview-idle.txt`, `preview-construction.txt` | Isolated preview/idle: 10 passed; preview/construction/idle: 19 passed |
| `video-lifetime.txt` | 30 isolated video preview lifecycle cases passed |
| `video-preview-stress.txt` | 20 identical node selectors collected but only **one** test executed; not 20 repetitions |
| `gui-without-preview.txt` | Diagnostic selection: 223 passed, nine deselected; not full acceptance |
| `gui-dispose-failure.txt` | Immediate failed-backend disposal: 232 passed |
| `final-tests.txt/xml` | 1829 passed; new reload assertion failed on Windows slash normalisation, subsequently corrected |
| `gui-final.txt` | Combined GUI stress still crashed, exit -1073741819; no completed XML |
| `native-module.txt` | Diagnostic access violation in python311.dll + 0x3abdf, native thread; root cause unknown |
| `current-full.txt/xml` | Final source/test state: **1830 passed in 74.27s**, exit 0 |

The repeated GUI diagnostic used these four modules, repeated four times with
`--keep-duplicates -v`: `test_gui_consolidation.py`, `test_gui_lab_tabs.py`,
`test_gui_shell.py`, `test_gui_tabs.py`. It failed before completing the first
group. `native_fault_probe.py` preserves the Windows-only diagnostic harness
(originally run from `tmp/t08_native_fault.py`); it reports the faulting module
without suppressing exceptions. Invoke it with the four test paths and `-v`.
Temporary idle diagnostics waited 15 seconds after preview teardown; the video
lifecycle diagnostic loaded T07 video in 30 independent previews with 20 ms waits.

The failing instruction's module alone cannot identify the responsible Python,
PySide, Qt, codec or application lifecycle defect. No dependency was upgraded,
backend disabled, failure ignored or test split presented as a clean integrated
result. A passing retry does not establish stability.

## Final native desktop checks (25 September 2026)

After earlier interruptions and deferral, the user authorised an idle-desktop retry.
Native Windows app: `.venv-t08/Scripts/pythonw.exe main.py`, normal desktop Qt
platform, launch PID 28744. Image/audio/video fixtures were selected using the
Windows file picker. Bundled public key and public demonstration start value were
used; no private key was persisted.

- `image-file.png`: AUTHENTIC, recovered image displayed; native Save dialog wrote
  `tmp/t08-native-image.png`, 1,644 bytes, exactly matching sender `payload.png`.
  SHA256: `0f02cfabf22a629bb41c2973231db07cf5b68b1f537301827bd95166de8d73c0`.
- `audio-file.wav`: AUTHENTIC; native Save wrote `tmp/t08-native-audio.wav`,
  4,454 bytes, exactly matching sender `payload.wav`. SHA256:
  `44e05eb1cad5637ac44a0f0eeb8fbf8a170d3f10718d487589585a8296d32506`.
  Received and recovered players advanced and returned to Play. The user replayed
  both and confirmed hearing both. The fixture is a 2-second 440 Hz cover and a
  0.1-second excerpt payload; their durations intentionally differ.
- `video-positive.mkv`: AUTHENTIC with 105 recovered bytes; playback visibly showed
  the moving yellow square and gradient, progressing to the 2-second endpoint.
- The user manually dragged `analysis-even-0.png` from Explorer into Verify and
  confirmed it loaded; the subsequent screenshot also showed AUTHENTIC. The
  automation API rejected cross-window dragging, so this is human evidence.
- After the final label-height change, a fresh native launch (PID 28236) loaded
  `audio-file.wav` through the picker. The full “derived from the secret” value,
  manifest rows and warning were readable at 1182x852. The focused styled layout
  tests passed (9 tests, `native-layout-final.txt`).

## Test-runner mitigation and limits

A full capture-enabled run still crashed (`native-current-full.txt`). The same
four GUI modules repeated four times with `--no-qt-log --keep-duplicates -q`
passed all 932 tests. `pytest.ini` now applies `--no-qt-log`, and the complete
single-process suite passed all 1830 tests (`stable-full.txt/xml`). Commands:

```powershell
$guiTests=@('tests/test_gui_consolidation.py','tests/test_gui_lab_tabs.py','tests/test_gui_shell.py','tests/test_gui_tabs.py') * 4
python -m pytest --no-qt-log --keep-duplicates @guiTests -q
python -m pytest -q --junitxml=evidence/t08/stable-full.xml
python -m ruff check .
git diff --check
```

[pytest-qt documents](https://pytest-qt.readthedocs.io/en/stable/logging.html) that
this option restores Qt's native stderr logging. No test, multimedia backend,
exception capture or dependency pin was removed. No project test uses `qtlog` or
Qt-log failure rules. Installed pytest-qt replaces the Qt message handler around
each test; an interaction with that capture is the supported inference, not a
proven upstream root cause. Earlier player lifecycle changes alone did not fix
it. The passing stress/full runs and native workflow establish the tested
configuration, not a guarantee against every future native crash.

## Package provenance and remaining work

`package-preliminary.json` records the successful preliminary extraction, exact
archive/member hashes, fresh-process commands and outputs. `check_package.py`
compares every ZIP member byte with its source, scans for private-key headers,
checks exclusions, extracts to a new directory and invokes the extracted receiver
and startup probe with Python `-I`. Recovered payload hashes are checked by the
receiver, not merely counted.

The final candidate is built after this report and the ledger are saved:

```powershell
python -m scripts.package_submission --output dist/T08-validated.zip
python evidence/t08/check_package.py --archive dist/T08-validated.zip --extract tmp/t08-package-native --report dist/T08-validated-report.json
```

Its exact hash, member inventory and executed extraction results belong in
`dist/T08-validated-report.json`, outside the archive to avoid a circular hash.
These final commands are a recipe until that report exists with successful
results. The archive is a validation candidate, not a completed submission.

T08 acceptance is complete with the documented test-runner mitigation. The final
archive check must report success before handoff; its report is outside the ZIP
to avoid a circular hash. T09, human transfer/rehearsal and submission remain open.
