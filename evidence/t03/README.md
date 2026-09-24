# T03: Publication and security safeguards

Scope: T03 only, based on integration HEAD `27572c98cc734e0daa24dcc1377df0234a970618`
with the uncommitted changes described here. Python 3.11.16, unchanged dependency
pins, Windows, offscreen Qt tests. Original gin/Tristan refs and checkout preserved.

## Changes

- Added a small publication module in Tristan's verification layer, adapting Gin's
  backup/rollback approach without importing its service architecture.
- Rejects input/output/manifest aliases, hard links, case aliases and symbolic-link
  destinations. Validates destinations before signing and again before publication.
- Stages both artifacts, backs up existing outputs, publishes only after successful
  staging and restores prior outputs on caught failures. No-overwrite publication
  refuses late-arriving destinations. Incomplete rollback retains recovery backups
  and reports their paths via `PublicationError.recovery_paths`.
- Sender capacity checks now include manual start, actual signed-record size,
  signature, encryption and repetition overhead.
- Bounds manifest reads to 1 MiB and handles excessively nested JSON as a domain
  error rather than an uncaught recursion failure.
- Bounds scrypt estimated memory/work before constructing the library KDF; defaults
  and signature-before-decryption ordering remain unchanged.
- Withholds recovered plaintext when signed settings and the companion manifest
  disagree; returns the failure verdict/diagnostics without previewable bytes.
- Adds canonical public-key fingerprint helper for later GUI use. No envelope or
  manifest wire-format change; existing samples remain compatible.

## Validation

- Focused suite: **226 passed**. See [focused.txt](focused.txt).
- Final full suite: **1785 passed in 57.23s**, zero failures/errors/skips; recorded in [pytest.txt](pytest.txt) and [pytest.xml](pytest.xml).
- Ruff: [ruff.txt](ruff.txt).
- Existing PNG/WAV/MKV samples and real offscreen app startup:
  [probe.txt](probe.txt), using the unchanged [T02 probe](../t02/probe_baseline.py).
- New regressions are in `tests/test_publication_security.py`: alias rejection;
  embedding/manifest/backup/first- and second-install failure injection; interrupt
  rollback; existing/absent/mixed destination recovery; retained backups when
  restoration fails; late no-overwrite collisions; successful replacement;
  exact-fit/one-sample-overflow boundaries for encrypted and repeated image/audio
  payloads; plaintext withholding; excessive signed KDF costs; signature-before-
  decryption; canonical fingerprint equivalence; bounded/deeply nested JSON.

Commands from the integration root:

```powershell
$env:QT_QPA_PLATFORM = 'offscreen'
.\.venv\Scripts\python.exe -m pytest -q tests/test_publication_security.py tests/test_verification.py tests/test_encryption.py tests/test_size_preservation.py --basetemp=tmp/t03-focused-complete
.\.venv\Scripts\python.exe -m pytest -q --basetemp=tmp/t03-final --junitxml=evidence/t03/pytest.xml
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe evidence/t02/probe_baseline.py
```

An initial focused run had four failures in the new boundary fixture: it calculated
capacity from a two-digit start while testing a five-digit start. Corrected the
fixture to account for signed metadata width and asserted equal envelope lengths;
no capacity check was weakened. An intermediate full run passed 1783 tests before
the final two JSON-boundary regressions were added; the final evidence supersedes it.

## Limits and next task

Two replacements are not a crash-atomic transaction. Concurrent readers can see a
mixed pair briefly; power loss, forced termination and concurrent writers are not
covered. Recovery files may require manual restoration if the filesystem stays
locked. POSIX exclusive publication requires hard-link support. Resource bounds
are local policy, not exact memory/runtime guarantees.

No GUI controls changed, no new demo samples generated, no dependency changes,
no native desktop/playback claim and no commits made in this task. T04 still owns
explicit GUI verdict gating, manual-offset capacity preview/responsiveness,
fingerprint presentation, mixed-URL drop rejection and the agreed UI simplification.
T04-T09 remain TODO until separately authorized.

Source and result hashes are recorded in [summary.json](summary.json).
