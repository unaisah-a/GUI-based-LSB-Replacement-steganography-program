# T07: Sender/receiver sample bundle

Status: DONE. Authorised scope: T07 only. Base HEAD
`b59c4a11fb42b7f0154e8ad507431407c03f174c` plus the T07 working-tree changes.
Windows, CPython 3.11.16 in `.venv-t05`, existing pins unchanged. No application
code changed. Source and bundle hashes are in [source_hashes.json](source_hashes.json).

## Deliverables and acceptance

- [samples/t07](../../samples/t07/README.md): 128 files, approximately 7.5 MB, with
  separate Party A and Party B folders, original/protected/tampered media, messages,
  public keys, explicitly public demo secrets, relative case index and checksums.
- [Guide](../../docs/sample_bundle.md): receiver commands, expected verdicts,
  all five challenge demonstrations, retained extras, limits and fresh-key sender
  instructions. Neither side contains a private signing key.
- [Receiver report](receiver-report.json): **27/27 case expectations passed**;
  **20 AUTHENTIC**, seven expected failures. Exact hashes, lengths, payload types,
  signed filenames, signature/hash flags and correction counts are checked.
- Required negatives: image message corruption, audio signature corruption and
  unrecoverable repetition-3 audio damage all return SIGNATURE_INVALID. Corrected
  one-copy damage returns AUTHENTIC; matched uncoded damage fails. Wrong key/start/
  passphrase and outside-payload modification are separate cases.
- Short Learning Outcome: 105 UTF-8 bytes. Long Project Overview: 673 bytes,
  including both paragraphs. Fictional encrypted custom payload: 325 bytes.
  Source files use fixed UTF-8 bytes, avoiding platform newline differences.
  PNG and WAV file payloads are recognised and exported with exact source bytes.
- Image/audio capacity attempts request 28792/5504 raw message bytes at depth 1,
  start 37, where raw maxima are 28791/5503. The sender raises CapacityError before
  publishing either media or manifest. Party B independently recomputes overflow.
- Video: 30 frames, 15 fps, 2 seconds; actual changed frame 9 lies in claimed span
  [9, 9]. Output verifies AUTHENTIC. Synthetic input contains no audio track.
- Steganalysis: newly measured **2/9 false positives and 8/9 misses**, from 18
  noise/even/gradient fixtures. Rule fixed at channel-0 bit-0 uniformity p >= 0.05.
  Gradient seeds repeat the same cover. These are not natural-media accuracy rates;
  different message/signature bytes explain why this is not the T05 result.

## Independent receiver evidence

[check_isolated_receiver.py](check_isolated_receiver.py) copies only `app/`, the
receiver verifier script and `party-b/` into a new directory. It starts Python with
`-I`, with that copied directory as its working directory. No sender folder,
original source message folder, signing script or private key directory is copied.
The child exits 0, checks all 27 cases and exports exactly 20 authenticated payloads.
See [isolation.json](isolation.json) for the actual command, location and results.

This proves the workflow does not depend on sender files or in-memory signing state.
It is local file/process isolation, not an operating-system access sandbox or an
actual transfer by another person. Public-key trust remains external. Checksums
only detect transfer damage relative to the supplied inventory.

## Executed validation

```powershell
.venv-t05/Scripts/python.exe -m scripts.build_sample_bundle --output samples/t07
$env:QT_QPA_PLATFORM = 'offscreen'
.venv-t05/Scripts/python.exe -m pytest -q tests/test_sample_bundle.py tests/test_e2e.py tests/test_payload_files.py tests/test_challenge_evaluation.py --basetemp=tmp/t07-complete-tests --junitxml=evidence/t07/pytest.xml
.venv-t05/Scripts/python.exe evidence/t07/check_isolated_receiver.py --output tmp/t07-isolated
.venv-t05/Scripts/python.exe -m ruff check . --exclude .venv-t05
git diff --check
```

- **82 passed in 7.41s**, zero failures/errors/skips: [pytest.txt](pytest.txt), XML.
- Ruff: PASS. Diff whitespace check: PASS.
- Receiver subprocess: PASS, no stderr, no private-key files, 20 exports.
- Tests cover fresh receiver isolation, required positive/negative verdicts,
  exact source message/file recovery, output refusal, leaked-key rejection,
  checksum damage, unexpected-verdict failure without export and path confinement.
- Existing end-to-end, file-payload and five-challenge evaluation tests also pass.
- Direct byte comparisons confirm all three stored source texts match their
  embedded strings. A scan of the whole sample tree finds no private-key PEM block.
  The two public PEMs are explicitly allowed by narrow `.gitignore` exceptions.

The assignment wording was checked using pypdf from the bundled document runtime;
system `pdftotext` was unavailable. Source PDF SHA-256:
`cd7291804645c7da9f36542bf5213ea15c7c66f7222aecde3e32248239464069`.
Only the required page-1 message text is included; the source PDF is not redistributed.

Development corrections: the first focused run passed 81 tests and failed one
incorrect test expectation of TAMPERED for image message corruption. The actual
signature covers the message, so SIGNATURE_INVALID is correct. The guide and test
were corrected. Initial lint caught an unused import and exception chaining; both
were fixed. A final source-byte check also removed Windows text newline translation
from the generator and normalised the generated sender text file. The final 82-test
run checks exact recovered text and file bytes. The generated guide copies and their
receiver checksum were refreshed; protected samples and keys were not regenerated.

## Remaining scope

T08 and T09 were not started. No submission archive, clean-install certification,
native preview/playback/drop check, real transfer, rehearsal or submission is claimed.
The T06 combined-process Qt access violation remains unresolved for T08; this task
ran the relevant 82-test subset, not the complete integrated suite. Source-audio
omission with an audio-bearing input still needs native/release validation.

Original branches, existing tracked demo samples and untracked `samples/r11` were
left untouched. No dependencies changed. The user subsequently authorised committing
and pushing T07. Next task when authorised: T08, integrated release validation.

Commit preparation found that Git's `core.autocrlf=true` would change checksummed
text files on checkout. `.gitattributes` disables text conversion for `samples/t07/**`
so source payloads, public keys, manifests and transfer checksums retain exact bytes.
After restaging with `git add --renormalize -- samples/t07`, all 128 indexed blobs
matched the working-tree bytes. Exporting those blobs to `tmp/t07-staged-final`
and running the receiver verifier returned exit 0 with all 27 cases passing.
