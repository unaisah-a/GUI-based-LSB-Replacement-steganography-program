# Version 2 sender/receiver demonstration bundle

This bundle has 20 verification cases and 2 capacity checks.
Use the app built with H02-H03 manifest version 2 support and Python 3.11 with the
repository's pinned requirements. This is local demo material, not a submitted release.

## Verify independently

Copy only party-b, the app directory and scripts/verify_sample_bundle.py to the
receiver's machine. No party-a folder or private key is needed. From the copied
runtime's parent directory, replacing RECEIVED with the copied party-b path:

```powershell
python -I scripts/verify_sample_bundle.py RECEIVED --report receiver-report.json --recovered recovered
```

The report and recovered directory must not already exist. Exit code 0 means all
indexed verdicts, hash-comparison expectations, exact recovered hashes/lengths and
capacity checks passed. Only authenticated successful cases are exported (11 files).
This command does not establish a real human transfer or rehearsal.

## GUI inputs

Paths in case-index.json are relative to the receiver folder. Select each case's
media, listed manifest and public key in Verify. Damaged media may reuse a baseline
manifest, so select the listed manifest explicitly. sender-public.pem matches this
bundle; unrelated-public.pem is intentionally wrong. A newly generated local key
does not match these fixtures. Confirm the sender fingerprint independently.

demo-only-secrets.json contains PUBLIC DEMONSTRATION VALUES ONLY, including wrong
inputs for negative cases. Case fields start_secret/passphrase name entries in that
file; null means unused. These values protect no real information. No private key
is saved in either Party A or Party B.

The two manifest-hash-mismatch cases use unchanged signed media with a modified
manifest. Expect TAMPERED, valid signature and signed-message check, No for the two
manifest comparisons, and no payload preview/save. Earlier extraction/signature
failures show Not performed for unavailable comparisons. Wrong passphrase permits
the signed-record comparison but prevents recomputing the plaintext hash.

AUTHENTIC concerns the payload and signed settings, not every cover sample.
Outside-payload edits can remain AUTHENTIC; stego_sha256 is only an unsigned
whole-file transport check. The checksum inventory detects transfer damage, not
malicious replacement. Publishing plaintext hashes allows predictable-message
guessing even when encryption is used. Repetition recovery does not establish
resistance to arbitrary lossy transforms. Video output is FFV1/MKV without audio.

## Sender material

The complete bundle also has party-a/original covers, party-a/messages inputs,
protected/tampered outputs, a generation report and CASE_INDEX.md. Use fresh local
keys only for newly protected outputs; keep private keys outside shared folders.
The existing historical samples remain separate and are not upgraded in place.
