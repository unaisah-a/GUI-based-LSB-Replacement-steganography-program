# Submission checklist and evidence index

The assignment brief remains authoritative. This checklist records the requirements reconciled during implementation; the team must confirm the current learning-platform instructions and exact dates before submission.

## Deadlines recorded from the brief

- Demo plan: due **one day before the demo**.
- Signed originality declaration: due **one day before the demo**.
- Agreed contribution statement: due **one day before the demo**.
- Source, setup README, samples, evidence, and key instructions: due **Week 5 Friday**.
- Exact calendar dates, submission location, team identifier, and member details: **[human completion required from the current course site/brief]**.

## Required package contents

- [x] Application source under `app/` and `main.py`.
- [x] Pinned Python dependencies in `requirements.txt`.
- [x] Setup, launch, usage, test, sample, and key-handling instructions in the root README.
- [x] Image and audio workflows with selectable LSB depth and capacity checks.
- [x] Signed payload, companion manifest, trusted-public-key verification, and clear verdicts.
- [x] Required short, long, and custom messages under `samples/r11/messages/`.
- [x] Positive and actual negative image/audio cases in the receiver bundle.
- [x] Reproducible sample generator and standalone receiver verifier.
- [x] Release logs, structured results, hashes, and screenshots under `evidence/`.
- [x] Architecture, limitations, compatibility, test matrix, and demo plan.
- [ ] Team ID and all member names entered consistently.
- [ ] Contribution percentages agreed and totaling 100%.
- [ ] All external sources and AI assistance acknowledged under course rules.
- [ ] Official originality declaration reviewed and signed by every member.
- [ ] Real Party A-to-B transfer performed and recorded.
- [ ] Full demonstration rehearsed on the actual equipment.
- [ ] Final archive opened and tested after packaging.

## Release evidence index

| Artifact | Claim supported |
| --- | --- |
| `evidence/results/r12-validation-summary.json` | Final pass/fail summary, clean environment, suite count, receiver count, desktop platform, visual-review flag, secret checks, and hashes for eight artifacts. |
| `evidence/results/r12-release-audit.json` | Python/OS/dependency/tool versions, ten receiver outcomes, capacity case, optional FFmpeg-absence behavior, and explicit scope limits. |
| `evidence/results/r12-desktop-audit.json` | Three native Windows Qt verdicts, platform/display facts, and screenshot hashes. |
| `evidence/logs/r12-clean-install.txt` | Successful requirements installation context, Python 3.14.3, requirements hash, package versions, and `pip check`. |
| `evidence/logs/r12-full-suite.txt` | Recorded **578 passed in 100.02 seconds** complete-suite result. |
| `evidence/logs/r12-main-smoke.txt` | Successful application startup smoke check. |
| `evidence/screenshots/r12-image-authentic.png` | Native GUI image-positive verification. |
| `evidence/screenshots/r12-audio-authentic.png` | Native GUI audio-positive verification. |
| `evidence/screenshots/r12-image-rejected.png` | Native GUI corrupted-image rejection. |
| `samples/r11/receiver/case-index.json` | Authoritative ten-case receiver matrix and references to public demo material. |
| `samples/r11/receiver/verification-report.json` | Reproduced expected/actual receiver outcomes. |
| `samples/r11/receiver/capacity-rejection.json` | Oversized payload rejected without output publication. |
| `samples/r11/sender/evidence/*.json` | Measured corruption, robustness, and lossy-video experiments. |

Artifact sizes and SHA-256 values are stored in the validation summary. Re-run the finalizer after deliberately replacing any R12 evidence; otherwise preserve the reviewed files.

## Final technical verification

Run from a clean checkout or extracted submission archive:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe main.py --smoke-test
.\.venv\Scripts\python.exe scripts\verify_sample_bundle.py samples\r11\receiver
.\.venv\Scripts\python.exe -m pytest -q
```

If video will be demonstrated:

```text
ffmpeg -version
ffprobe -version
```

Manual checks:

- [ ] Launch the real GUI and verify image positive, audio positive, and one actual negative.
- [ ] Confirm image preview and audio playback on the demo equipment.
- [ ] Confirm every public-key fingerprint shown during the demo matches the trusted value.
- [ ] Confirm no real private keys or unlabelled secrets are in the archive.
- [ ] Confirm recovered files are saved as data and never auto-executed.
- [ ] Confirm documentation links work within the extracted package.

## Real transfer and rehearsal record

Complete after the events occur:

| Check | Actual result |
| --- | --- |
| Party A and device | [human completion required] |
| Party B and separate device/folder | [human completion required] |
| Protected media and manifest transfer channel | [human completion required] |
| Trusted public key channel and fingerprint comparison | [human completion required] |
| Start/AES secret channel, if used | [human completion required] |
| Receiver outcome without sender state/private key | [human completion required] |
| Rehearsal date and duration | [human completion required] |
| Issues found and resolved | [human completion required] |

## Packaging review

Create a local snapshot from the current workspace, including untracked deliverables:

```powershell
.\.venv\Scripts\python.exe scripts\package_release.py --output output\smiv-reviewed-release.zip
```

The ZIP contains source, tests, documentation, samples, evidence, and `RELEASE_INVENTORY.json` with sizes and SHA-256 hashes. It excludes virtual environments, Git metadata, caches, and editor settings. It refuses existing output paths and unexpected sample PEM files. The named public demo key and explicitly public demonstration secrets are included. Review the contents for any newly added confidential material; marker checks are not a general secret detector. This creates a local checkpoint without committing, uploading, or signing anything. Regenerate to a new filename after further edits; Git still needs a reviewed commit before a clone can reproduce untracked work.

After extraction, install dependencies and run the technical verification commands above. The archive is a technical snapshot; the team-specific human declarations remain incomplete until supplied by the team.

- [ ] Exclude `.venv/`, caches, temporary output, local editor settings, and unrelated files.
- [ ] Include the receiver bundle and all referenced expected-message bytes/manifests/media.
- [ ] Include required evidence without modifying its recorded hashes.
- [ ] Include the public demo key; exclude signing private keys.
- [ ] Keep demo-only secrets clearly labelled and never describe them as secure.
- [ ] Confirm paths are relative and no personal absolute path appears in submitted JSON or prose.
- [ ] Confirm the root README is the submission guide and `docs/planning_reference.md` is labelled as historical planning context.
- [ ] Verify the archive on a second folder/device before upload.
- [ ] Have every member review the final uploaded file list and submission receipt.

No upload, email, signature, or declaration is performed automatically by this repository.
