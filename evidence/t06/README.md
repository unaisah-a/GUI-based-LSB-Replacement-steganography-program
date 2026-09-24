# T06: Size and media-property preservation

Windows, CPython 3.11.16 in the existing `.venv-t05`, unchanged dependency pins.
Status: DONE. Base HEAD: `9b1d6d2824137dc0bfae422c677fae7e0d839f0d`, plus the T06 working-tree
changes identified by `source_hashes.json`. Only T06 was authorised.

## Measured results

The [66-row table](measurements.md) and [complete measurements](measurements.json)
cover 11 input files at depths 1, 4 and 8, with optional matching off and on.
All outputs verified AUTHENTIC and recovered the exact message. Every source file
remained byte-for-byte unchanged. All decoded shapes/properties were preserved,
sample changes stayed within the chosen depth's bound and samples outside the
payload region were unchanged.

Inputs: flat PNG, photographic PNG, uncompressed flat PNG, canonical RGB BMP, BMP
with a 128-byte pre-pixel gap, two-second mono 22050 Hz and stereo 44100 Hz PCM-16
WAV, stereo WAV with a JUNK chunk, and 12-frame 256x192 video at 10, 29.97 and 25 fps.
The photograph is the raccoon image in the pinned SciPy's `misc/face.dat`, attributed
there to public-domain-image.com; its source hash and resize are recorded in JSON.
Video consists of shifted photographic frames; audio consists of generated tones.
No random-noise fixture is presented as a photograph.

Selected depth-1 results (bytes, matching disabled):

| Input | Cover | Protected | Change | Explanation |
| --- | ---: | ---: | ---: | --- |
| Flat PNG | 590 | 2402 | +1812 | Changed low bits reduce compression on a tiny, uniform cover |
| Photographic PNG | 107976 | 107990 | +14 | Content-dependent DEFLATE change |
| Uncompressed flat PNG | 147760 | 2409 | -145351 | Default compressed output; no-payload baseline is only 590 bytes |
| Canonical BMP | 147510 | 147510 | 0 | Fixed-width pixel storage and matching header layout |
| BMP with gap | 147638 | 147510 | -128 | Writer removes the pre-pixel gap; no-payload baseline confirms it |
| Mono WAV | 88244 | 88244 | 0 | Sample count/rate/width/channels retained |
| Stereo WAV | 352844 | 352844 | 0 | Sample count/rate/width/channels retained |
| WAV with JUNK chunk | 352980 | 352844 | -136 | 128 data bytes plus eight chunk-header bytes removed |
| FFV1, 10 fps | 901754 | 901990 | +236 | Same codec baseline is 901754; small embedding-related change |
| FFV1, 29.97 fps | 901754 | 902004 | +250 | Same codec baseline is 901754; fractional rate retained |
| MJPEG, 25 fps | 210950 | 593017 | +382067 | FFV1 no-payload baseline is 591312; codec conversion dominates |

The MJPEG case grows by 181.117%, but only 1705 output bytes are above its
no-payload FFV1 baseline. It is not evidence that embedding alone triples a file.
Flat PNG's large percentage is likewise relative to a very small compressed input.
No universal growth threshold is asserted.

PNG matching succeeded in 6/9 attempts (photographic and uncompressed-flat cases)
and failed honestly for all three compressed-flat cases. Successful padding changes
container bytes, not pixels; failed attempts retain valid protected output. WAV/BMP
matching makes no adjustment, so metadata/header exceptions remain mismatches.
Video matching is reported as unsupported even if lengths happen to coincide.

Companion manifests occupy 653-679 bytes per case, excluded from media sizes. The
shared public key is another 451 bytes. Private keys were never saved. Fresh RSA-PSS
signatures, nonces and timestamps mean compressed sizes can differ on rerun; the
recorded numbers describe this run, not deterministic byte lengths.

## Changes

- Added `scripts/evaluate_preservation.py` with saved-file decoding, independent
  property comparisons, source/output hashes and no-payload re-encoding baselines.
- Corrected blanket WAV/BMP size guarantees: fixed-width samples do not guarantee
  fixed container size. The GUI reports signed byte/percentage change and separate
  manifest storage; docs and matching outcomes explain metadata/header changes.
- Removed the video fallback frame rate. Invalid rates and odd dimensions are
  rejected. Decoded timestamps must follow the declared constant rate within 2 ms.
  Saved output is checked for actual decoded frame count and frame rate as well as
  dimensions/payload recovery. Rate tolerance is 1e-5 relative / 1e-6 fps absolute.
- Added regressions for the measurement matrix, metadata exceptions, GUI storage
  reporting, invalid rates, odd dimensions, changed encoder timing, truncated
  decoding and irregular input/output timestamps. Rejected output is removed.

## Commands and evidence

Run from `A:/Code/GUI-based-LSB-Replacement-steganography-program` in PowerShell:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
.venv-t05/Scripts/python.exe -m scripts.evaluate_preservation --output tmp/t06-final
.venv-t05/Scripts/python.exe -m pytest -v --basetemp=tmp/t06-recheck --junitxml=evidence/t06/pytest.xml
.venv-t05/Scripts/python.exe -m ruff check . --exclude .venv-t05
.venv-t05/Scripts/python.exe evidence/t02/probe_baseline.py
git diff --check
```

The evaluator requires a new output directory; use a different name when repeating.
Generated media stay under ignored `tmp/`; this is not the T07 release bundle.
Measurements were copied from `tmp/t06-final/results.json`; the Markdown table is
a rendering of those same records. No dependency installation was needed.

Final validation: **1820 passed**, zero failures/skips, split across five processes:
1590 in `pytest-core.txt`/XML, then 21/43/91/75 in the respective
`test_gui_consolidation`, `test_gui_lab_tabs`, `test_gui_shell`, `test_gui_tabs`
logs/XML. Ruff passes (`ruff.txt`). The probe (`probe.txt`) checks
every direct dependency pin, verifies the existing PNG/WAV/MKV samples and runs the
real application entry point to a normal timed offscreen exit.

Development history: the first focused run passed 126 tests and failed one obsolete
assertion looking for the former blanket byte-count wording. That assertion was
updated to require the fixed-width/metadata qualification. A subsequent full run
passed 1819 tests in 45.80s. After adding saved-output timestamp cleanup and its
regression, a full run stopped with a Windows access violation in Qt event teardown
(`pytest-interrupted.txt`). A detailed combined-process rerun also stopped around
GUI construction (`pytest-interrupted-verbose.txt`). Root cause is unresolved;
individual GUI modules and the remaining suite all pass in separate processes.
This is a T08 integration-stability investigation, not a clean final monolithic
suite claim. `pytest-initial.xml` records the earlier 1819-test run only.

The final process-isolated commands were:

```powershell
.venv-t05/Scripts/python.exe -m pytest -q --ignore=tests/test_gui_consolidation.py --ignore=tests/test_gui_lab_tabs.py --ignore=tests/test_gui_shell.py --ignore=tests/test_gui_tabs.py --basetemp=tmp/t06-core --junitxml=evidence/t06/pytest-core.xml
foreach ($testName in @('test_gui_consolidation','test_gui_lab_tabs','test_gui_shell','test_gui_tabs')) {
    & .venv-t05/Scripts/python.exe -m pytest -q "tests/$testName.py" "--basetemp=tmp/t06-$testName" "--junitxml=evidence/t06/$testName.xml"
}
```

## Boundaries

No metadata-preservation promise is added. Video duration here is decoded frame
count divided by frame rate, not arbitrary container timing. Timestamp checks rely
on OpenCV's backend and cannot establish preservation of unsupported timing data.
The video fixtures contain no audio: source-audio omission with a real audio track
was not retested. Native playback, drag/drop and visual acceptance remain T08.
T07-T09 were not started; no release sample bundle, package or rehearsal was made.
Existing untracked `samples/r11` and branch refs were not modified. The local `gin`
ref remains `f3c267e`; no local `Tristan` ref existed at the start of this task.
