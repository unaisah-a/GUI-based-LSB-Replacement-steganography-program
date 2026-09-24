# Responsible Use, Originality and AI Use

[`limitations.md`](limitations.md) covers what the application can and cannot
establish technically. This document covers the rest: what the tool should and should
not be used for, what in this repository is the project's own work, and how AI tools
were used.

---

## 1. Responsible use

**Legitimate uses.** The tool is built to demonstrate integrity and authenticity. Its
intended uses are teaching how LSB steganography works and fails, proving that a
specific message came from the holder of a specific key and has not changed,
watermarking media you own, and testing whether a file survives a given handling
chain (the Attack Lab and the robustness experiments exist for this).

**Illegitimate uses.** Hiding material in files you do not own or have no right to
alter. Moving data past monitoring you are bound by, such as exfiltrating data from an
employer or institution. Concealing illegal content. Planting payloads in files that
others will open without knowing. The tool does nothing to stop these uses. The
signature identifies the key that signed a payload, but it does not make a use
legitimate.

**Concealment is not confidentiality.** Hiding a message makes it harder to notice,
not harder to read. Anyone who knows or guesses the depth and the start location can
read an unencrypted payload bit for bit. The keyed start location raises the cost of
finding the payload, but it is not encryption. Only the optional AES-256-GCM layer
provides confidentiality. The interface says this, and a user who needs secrecy must
turn encryption on and share the passphrase separately.

**The manifest reveals that a payload exists.** The companion manifest names the LSB
depth, the payload length and the start method. A file that arrives with a
`.manifest.json` beside it announces that something is hidden in it. That is the right
trade-off for an integrity tool, where the receiver is meant to find the payload. It
makes the tool unsuitable for covert communication, and it should not be presented as
covert. See [`limitations.md`](limitations.md) §9.

**The Attack Lab is dual-use.** The same attacks that show where verification stops
also show an adversary how to damage or strip a payload: which edits go unnoticed,
which destroy it, and that re-signing requires a key. These experiments are included because
an integrity claim that has not been attacked is not worth much, and every attack here
is standard, published technique. Use them on media you own or are authorised to test.

**Handling recovered content.** Recovered bytes come from whoever made the file. The
application shows them as inert text or a hex dump. It renders a recognised image or
plays a recognised audio file inside the application. It never executes recovered
bytes and never hands them to the operating system to open. Saving a recovered file
is a deliberate user action, and the proposed name has any directory parts removed.
Opening a saved file afterwards carries the same risk as opening any file from an
untrusted sender.

---

## 2. Originality

**Project implementation areas (team authorship review required).** The code and
documents under these paths require source/AI attribution review: everything under `app/`, `tests/` and `scripts/`, the
stylesheet under `assets/`, and the documents under `docs/`. That covers:

- the LSB embedding and extraction core shared by image, audio and video
- the capacity arithmetic
- the envelope format and verification record
- the keyed start-location derivation
- the manifest and its cross-check against the signed record
- the verdict rules
- the attack catalogue
- the file-size experiment
- the GUI

**Published techniques, implemented here.**

- LSB replacement.
- Repetition coding with majority-vote decoding.
- HMAC-based derivation.

The algorithms are standard. The team must confirm the provenance of their
implementation before signing the originality declaration.

**Provided by libraries.** Every cryptographic primitive comes from the `cryptography`
package; none is implemented here. That covers RSA-PSS, AES-256-GCM, scrypt, HMAC and
SHA-256. The other libraries used:

- `numpy`: array arithmetic.
- `Pillow`: PNG and BMP encode and decode.
- `soundfile`: WAV input and output.
- `opencv-python`: video decode and encode, including its bundled FFV1 codec.
- `scipy`: photographic fixture for preservation evaluation.
- `PySide6`: the interface and media playback.
- `pytest`, `hypothesis`, `pytest-qt`, `coverage` and `ruff`: testing and linting.

All are listed with pinned versions in `requirements.txt` and in
[`contribution_statement.md`](contribution_statement.md) §7.

---

## 3. Use of AI tools

> **TODO — to be written by the team.** This section must say, accurately:
>
> - which AI tools were used;
> - what each was used for (for example code generation, refactoring, test writing,
>   documentation, review);
> - which parts of the repository they affected;
> - how the team checked what they produced.
>
> Do not submit with this section empty or guessed.


### Observed consolidation assistance; not a complete team declaration

Codex assisted this consolidation with repository inspection, implementation and
regression-test edits, generated fixtures/evaluation scripts, documentation,
validation and packaging. T08 included native desktop automation; the user manually
confirmed drag/drop and hearing both audio players. T09 prepares the demo and
handoff documents. Task reports and commits identify affected paths and observed
checks. The final T08 suite passed 1830 tests with a documented pytest-qt logging
capture mitigation; native checks and exact recovered-file comparisons are recorded.
Automated checks do not replace each member understanding and reviewing the code.

The team must add any other tools, earlier branch assistance, copied material,
actual device/source details, individual review and errors corrected. Do not treat
this observed record as a complete history or claim all members performed a review.
The notification required by the brief is listed in the submission handoff; it has
not been sent by this task.

| Member/tool and actual device/source | Purpose and affected files | Human review/checks and corrections | Notification reference |
| --- | --- | --- | --- |
| TO COMPLETE | TO COMPLETE | TO COMPLETE | TO COMPLETE |
