# H04: version 2 sender/receiver bundle

H04 is complete: `samples/hash-manifest-v2` contains **20 verification cases,
two capacity checks and 11 exact authenticated payload exports**. No private key
was saved. This is bundle acceptance, not a packaged release, native GUI check,
human transfer or rehearsal.

## Provenance

- Windows PowerShell, Windows build 26200, Python 3.11.16 in `.venv-t08`.
- Base HEAD: `32b4125b29a70c3f31827acac6d5a1efb9cc0c9f`, plus uncommitted H02-H04 work.
- Dependency pins unchanged. [Source hashes](source-hashes.json) identify the actual
  application, scripts and bundle tests used; HEAD alone does not identify this build.
- [Bundle hashes](bundle-hashes.json) cover all 78 generated files (6,101,340 bytes).
  Keys, nonces, timestamps and signatures are fresh; rebuilding produces different bytes.
- [Audit](audit.json) records the sender public-key fingerprint, absence of private
  PEM keys, Git visibility of both public keys, and exact recovery checks.

## Executed commands and results

Run from `A:/Code/GUI-based-LSB-Replacement-steganography-program`:

```powershell
.venv-t08/Scripts/python.exe -m pytest tests/test_sample_bundle.py tests/test_manifest_v2.py tests/test_hash_evidence.py --no-qt-log -q
.venv-t08/Scripts/python.exe -m ruff check scripts tests/test_sample_bundle.py
.venv-t08/Scripts/python.exe -m scripts.build_sample_bundle --output samples/hash-manifest-v2
.venv-t08/Scripts/python.exe -m scripts.check_receiver_isolation --bundle samples/hash-manifest-v2/party-b --output tmp/h04/isolated-final
```

- Final focused regression run: **104 passed in 7.58s**, no failures/skips; repository-wide
  `.venv-t08/Scripts/python.exe -m ruff check .` and `git -c core.safecrlf=false diff --check` passed.
  Earlier iterations passed 7 in 3.01s and 103 in 6.29s. The final test adds rejection
  of an isolation output nested inside the receiver bundle, preventing recursive copies.
- Generator's verification: **20/20 cases passed**.
- [Independent receiver report](receiver-report.json): **20/20 cases and 2/2 capacity
  checks passed**, 11 exports, no private keys. Hash-comparison statuses are checked
  against explicit case expectations, as well as verdicts and recovered byte hashes.
- [Isolation record](isolation.json): copied only `app`, the receiver script and
  Party B; ran the copied script with `python -I` in a fresh process and directory.
  No Party A folder was present. This does not impose an OS access sandbox.
  The earlier `tmp/h04/isolated-receiver` run also passed; reports here are from
  `tmp/h04/isolated-final` with the final helper code.

The two added cases change only `message_hash` in the manifest, for plaintext and
encrypted image payloads. Both return TAMPERED, retain valid signature/signed-message
checks, report No for manifest comparisons and export no plaintext. All previous
image/audio/video, wrong-input, outside-payload and repetition cases are retained.
The bundle-index schema `t07-v2` is separate from manifest `format_version: 2`.

## Preservation and independent byte checks

Before generation, a Python audit through a PowerShell here-string recorded SHA-256
for all **232 existing files** under samples/evidence, including untracked practice
outputs, to `tmp/h04/preserved-before.json`. After generation it recomputed every
hash: all unchanged. Original covers, old fixtures and historical evidence remain intact.

The same audit scanned every new bundle file for private PEM material, confirmed
the receiver's fingerprint against its public key, checked both public-key paths
with `git check-ignore --quiet`, and compared all 11 recovered files byte-for-byte
with the original sender inputs. All checks passed. Only the two specific public
key paths were added to `.gitignore` exceptions; private-key exclusions remain.

Final documentation/byte audit: **176 local links/anchors**, balanced fences and live
demo paths passed; all 78 bundle hashes still matched, and all 11 exports from the
final isolated run matched original sender bytes. No application files changed in H04.

Standalone README files travel with the bundle and Party B. Live repository demo
paths were updated only after independent acceptance. Public demo values retain
their existing `t07-` names for continuity; they protect no real information.

## Remaining work

H05 must validate the completed release, including native GUI checks and a rebuilt,
extracted package using this bundle. Historical T08/S01 package checks target older
fixtures and cannot certify version 2. No archive, commit, push, message or submission
was performed for H04. Human contributions, transfer and rehearsal remain unclaimed.
