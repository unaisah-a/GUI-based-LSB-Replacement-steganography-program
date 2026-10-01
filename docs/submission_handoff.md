# T09 delivery checklist and human records

The technical handoff is prepared. **No submission, full timed team rehearsal or
real A-to-B transfer is claimed.** T09 DONE means the script, evidence index and
handoff are delivered; human obligations below remain open.

## Version 2 release validated: H02-H05 complete

The current build requires version 2 manifests and compares external, authenticated
and recomputed payload hashes. The new bundle and release pass the checks recorded
in [H05 evidence](../evidence/h05/README.md): 1,832 tests, Ruff, native hash display,
independent receiver verification and extracted application startup. Original
version 1 fixtures remain for regression tests and are rejected by this build.

All technical rollout items are complete. The native check covers the changed
hash interface; it does not claim a repeat of historical playback or drag/drop.
Human obligations below remain open. The user subsequently authorised committing
and pushing H02-H05 on 1 October 2026; see the integration branch's Git history.
The validated ZIP and H05 evidence retain their pre-publication snapshot; later
publication notes and sample byte-preservation attributes do not change the tested
application. No submission was performed.

## Requirements checked against the brief

The local `INF2005-ACW1-spec_v5-f2f.pdf`, pages 2–4, specifies **one day before
demo day** for the demo plan, originality declaration and contribution statement;
**week 5, Friday** for source, README, samples, test evidence and key instructions.
Confirm calendar dates, portal and team number against course announcements.
Repository timestamps do not establish submission dates.

The brief requests AI-use notification to `khengleong.tan@singaporetech.edu.sg`,
subject **ACW1 used in genAI query**, including device/source details. The team
must confirm previous notifications and send any required notification itself.
No email has been sent by this task.

| Human obligation | Owner | Status |
| --- | --- | --- |
| Confirm team number, names and student numbers | Team | OPEN |
| Agree responsibilities and percentages totalling 100% | All | OPEN; [contribution statement](contribution_statement.md) |
| Complete originality form and signatures/acknowledgements | All | OPEN; use official form if supplied |
| Complete accurate AI/source/device disclosures and reflection | All | OPEN; [AI-use record](ethics_and_ai_use.md) |
| Send/confirm required AI-use notification | Designated member | OPEN; retain receipt/reference |
| Assign named presenters, test demo hardware and rehearse | Team | OPEN; [script](demo_plan.md) and record below |
| Actual image/audio transfer, download and verification | Sender/receiver | OPEN; record below |
| Confirm dates/portal, fill placeholders and rebuild personalised archive | Designated member | OPEN |
| Submit documents/project files and retain receipts | Designated member | OPEN |

## Current receiver and release-package commands

From the repository root with Python 3.11 and pinned requirements installed:

```powershell
.venv/Scripts/python.exe -m scripts.verify_sample_bundle samples/hash-manifest-v2/party-b --report tmp/receiver-final.json --recovered tmp/receiver-final-files
.venv/Scripts/python.exe -m scripts.check_receiver_isolation --bundle samples/hash-manifest-v2/party-b --output tmp/hash-v2-isolated-final
.venv/Scripts/python.exe -m scripts.package_submission --output dist/H05-validated.zip
.venv/Scripts/python.exe -m scripts.check_release_package --archive dist/H05-validated.zip --output tmp/h05/package-final
```

Use fresh report/recovered/extraction paths on repeat. The validation machine uses
`.venv-t08` instead of `.venv`. Expected receiver result: 20 cases and two capacity
checks pass, with 11 exact authenticated exports. See [H04 evidence](../evidence/h04/README.md).
The final archive is `dist/H05-validated.zip`; its exact SHA-256 and member hashes
are recorded in `tmp/h05/package-final/package-report.json` (also copied beside
the archive as `dist/H05-validated-report.json`). Keep this report outside the ZIP.
The check runs only extracted/copied application files in fresh `python -I`
processes, verifies current fixtures and probes startup and legacy rejection.
It reuses the installed pinned dependencies; it is not a fresh dependency install
or an OS access sandbox. Historical [S01 evidence](../evidence/s01/README.md)
does not certify the current source tree or a later archive.

Included: source, pinned requirements, tests, docs, evidence, public keys and
original/protected/tampered samples. Excluded: private demo keys, environments,
caches, local app logs, unrelated `samples/r11` and all samples absent from
`scripts/release_samples.txt` (including local practice outputs). After filling declarations or
changing files, rebuild/recheck and use the real team number for the required name.
Earlier hashes do not certify later changes. Do not submit private keys.

## Actual transfer record — NOT PERFORMED

Send each new stego file, companion manifest and matching public key. B must
download to their own folder and verify. Confirm key fingerprint separately.
Do not record real start secrets or passphrases here.

| Medium | Sender/receiver | Date/method | Download folder/file hash | Fingerprint confirmation | Verdict/recovered hash/evidence |
| --- | --- | --- | --- | --- | --- |
| Image | TO COMPLETE | NOT PERFORMED | TO COMPLETE | TO COMPLETE | TO COMPLETE |
| Audio | TO COMPLETE | NOT PERFORMED | TO COMPLETE | TO COMPLETE | TO COMPLETE |

## Rehearsal record — NOT PERFORMED

| Run/date/hardware | Participants | Actual segment/end times | Missed features/failures | Fix/repeat result |
| --- | --- | --- | --- | --- |
| TO COMPLETE | TO COMPLETE | NOT MEASURED | TO COMPLETE | TO COMPLETE |

Record each member's actual airtime. All must attend and explain their own work.
Check every feature-matrix row against the script. Pass only when the full demo
fits 25 minutes and required live workflows work; the plan is not timing evidence.

## Submission record — NOT SUBMITTED

| Deliverable | Confirmed deadline | Submitted by/timestamp | Receipt/final SHA-256 |
| --- | --- | --- | --- |
| Demo plan, originality and contributions | TO CONFIRM | NOT SUBMITTED | TO COMPLETE |
| Source, README, samples, evidence and key instructions | TO CONFIRM | NOT SUBMITTED | TO COMPLETE |
