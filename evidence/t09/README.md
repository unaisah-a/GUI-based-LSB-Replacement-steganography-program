# T09 demo and submission handoff

Authorised by the user's next-task instruction after T08 was committed/pushed.
Base: `2aa68adf83f0e57cefa8cff10b4a78f3ac4c4f41`, integration/acw1-consolidated.
Environment: Windows PowerShell, Python 3.11.16 in `.venv-t08`, unchanged pins.
Scope: documentation, evidence index, human records and package preparation.
Application code and tests are unchanged; the T08 1830-test result is inherited
baseline evidence, not a newly executed T09 full suite.

## Delivered

- [22+3 minute script](../../docs/demo_plan.md): all five tabs/challenges, retained
  controls, required short/long/custom messages, image/audio positives and three
  mandatory negatives, per-member airtime, limitations and contingencies.
- [Evidence index](../../docs/evidence_index.md): requirement links, current versus
  historical results, native versus automated evidence and known limits.
- [Handoff/checklist](../../docs/submission_handoff.md): packaging, receiver commands,
  brief deadlines, notification and explicitly unperformed human records.
- Replaced unsupported inherited ownership/shared-work claims with an unsigned
  contribution template. Added observed AI assistance without claiming a complete
  team history, reviewed authorship or signatures. Corrected stale export controls
  and separated legacy/T07/new-live key instructions.
- Updated task ledger and feature matrix; original branches and samples/r11 remain
  untouched. No commit/push, message, actual transfer, rehearsal or submission.

## Validation and provenance

The local assignment PDF was read with bundled-runtime pypdf: pages 2–4 establish
required contents, 25-minute/all-member presentation, relative deadlines and AI-use
notification. T07 already checked required message wording against page 1. Calendar
dates and the team's actual contributions are not inferred.

Commands run from repository root (python means `.venv-t08/Scripts/python.exe`):

```powershell
python evidence/t09/check_handoff.py
python -m ruff check .
git diff --check
python -m scripts.package_submission --output dist/INF2005_ACW1_T09.zip
python evidence/t08/check_package.py --archive dist/INF2005_ACW1_T09.zip --extract tmp/t09-final --report dist/T09-final-package-report.json
```

`handoff-check.json` records validated links/case references and document hashes;
`ruff.txt` records lint. The archive report is outside the ZIP to avoid a circular
hash. It must show receiver_passed=true, 27 cases, two capacity checks and 20 exact
authenticated exports, along with passing isolated original-sample/startup checks.
The packager excludes private keys and unrelated work. This package still contains
explicit human placeholders: it is a technical handoff, not a submitted assignment.

T09 acceptance is document/package delivery and honest tracking of rehearsal;
actual human actions remain OPEN in the handoff. No elapsed rehearsal time or
transmission/submission evidence is fabricated. After personalising documents,
rebuild and rerun the archive check before submission.


Executed results: 104 local links and 27 indexed case mappings passed; all 12
selected demo case IDs exist. Ruff passed. The initial archive extraction passed
27 cases, two capacity checks, 20 exports and both subprocesses. A final formatting
check found Windows line-ending duplication in edited Markdown; it was corrected,
document hashes refreshed and the archive rebuilt/rechecked at the final paths
above. No application code changed. The first link check also caught a mixed
Markdown encoding introduced during editing; all delivered documents are UTF-8.
