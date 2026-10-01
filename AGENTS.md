# Repository work instructions

- Use UK English. Respect the latest authorised scope and preserve unrelated work.
- Keep image/audio/video, quality comparisons and current app behaviour. Steganalysis removal is complete; video removal is not authorised.
- Keep the README a standalone app guide. Preserve historical evidence unchanged; distinguish it from current validation.
- Samples belong only in `samples/original`, `samples/protected` and `samples/tampered`. Test fixtures belong in temporary directories. Public keys belong in `keys/public`; never record private keys or secrets in documentation.
- Preserve the original gin and Tristan branches. Do not send messages, submit work or invent declarations, contributions or test results.
- Maintain the concise ledger below using TODO, IN_PROGRESS, BLOCKED and DONE. Record actual commands, environment and tested working-tree state before handoff.

## Task ledger

- CLEANUP — DONE (1 October 2026): removed docs and all previous samples (including local outputs), rewrote README, retained only three sample folders with Git placeholders, updated packaging/generator paths and replaced the on-disk legacy regression with a temporary fixture. User explicitly authorised these deletions. App behaviour is unchanged.
- Validation: Windows/PowerShell, `.venv-t08` Python 3.11.16; base `267948ceb1ad4ad0950f36f2d2f83b73f6005a00` plus uncommitted cleanup changes on `integration/acw1-consolidated`. `python -m pytest --no-qt-log -q --junitxml=tmp/cleanup/full-suite.xml`: 1,833 passed in 53.30s. `python -m ruff check .` and `git -c core.safecrlf=false diff --check`: PASS. Structure/README checks passed; all 163 pre-existing evidence/key files retain their hashes.
- Archive validation: `python -m scripts.package_submission --output dist/INF2005_ACW1_cleanup-check.zip` and `python -m scripts.check_release_package --archive dist/INF2005_ACW1_cleanup-check.zip --output tmp/cleanup/archive-initial`: PASS, 285 members, matching source bytes, no private keys, pinned dependencies and offscreen startup verified. The archive is rebuilt after this ledger update; use the latest external report under `tmp/cleanup/archive-final/` for its hash. This uses installed dependencies and does not claim a clean installation or native playback check.
- Packaging: add future sample files to `scripts/release_samples.txt`. Sample verification is pending and `submission_ready` remains false; previous archives/reports describe historical states. No commit, push or submission performed.
- SAMPLES — TODO: user will supply new originals later; prepare protected/tampered files, matching manifests/public keys and verification evidence then. No submission-ready package is claimed while samples are pending.
- README-SAMPLES — DONE: user requested final-use wording for the sample locations, removing temporary empty-folder wording. Documentation only; samples remain pending. Reviewed the changed section and ran `git -c core.safecrlf=false diff --check` on the uncommitted working tree based on `267948c`, Windows/PowerShell. Existing archives predate this edit; no tests, archive rebuild, commit or push performed.

- Publication: user authorised committing and pushing the cleanup and README edits to `origin/integration/acw1-consolidated`. Remote fetch confirmed no divergence from base `267948c`; whitespace checks pass. Existing evidence remains unchanged; the proposed evidence reorganisation has not been implemented. Git history and remote refs record the publication outcome.
