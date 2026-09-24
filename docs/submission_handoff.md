# T09 delivery checklist and human records

The technical handoff is prepared. **No submission, full timed team rehearsal or
real A-to-B transfer is claimed.** T09 DONE means the script, evidence index and
handoff are delivered; human obligations below remain open.

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

## Package and receiver commands

From the repository root with Python 3.11 and pinned requirements installed:

```powershell
.venv/Scripts/python.exe -m scripts.verify_sample_bundle samples/t07/party-b --report tmp/receiver-final.json --recovered tmp/receiver-final-files
.venv/Scripts/python.exe -m scripts.package_submission --output dist/INF2005_ACW1_T09.zip
.venv/Scripts/python.exe evidence/t08/check_package.py --archive dist/INF2005_ACW1_T09.zip --extract tmp/t09-final --report dist/T09-final-package-report.json
```

Use fresh report/recovered/extraction paths on repeat. The validation machine uses
`.venv-t08` instead of `.venv`. Expected receiver result: 27 cases and two capacity
checks pass, with 20 exact authenticated exports. The archive check compares every
member to source, rejects private keys, extracts to a fresh folder and runs isolated
receiver plus original-format/startup checks. Its report records archive/member
hashes outside the ZIP. See [executed T09 evidence](../evidence/t09/README.md).

Included: source, pinned requirements, tests, docs, evidence, public keys and
original/protected/tampered samples. Excluded: private demo keys, environments,
caches, local app logs and unrelated `samples/r11`. After filling declarations or
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
