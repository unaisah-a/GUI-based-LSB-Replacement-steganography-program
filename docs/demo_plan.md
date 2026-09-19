# Demonstration plan — maximum 25 minutes

This plan allocates a speaking and demonstration segment to all five members. Replace bracketed fields with real names and record actual rehearsal results. Do not claim that a transfer, observation, or rehearsal occurred until it has.

## Before the demo

- Use a clean receiver folder or a second device/account for Party B.
- Confirm `python --version`, dependency installation, `pip check`, application startup, and FFmpeg availability if video will be shown.
- Copy the protected media and companion manifest through the transfer channel chosen by the team.
- Supply the public key and any start/AES secret through the team's independently trusted channel.
- Keep the private signing key only with Party A.
- Open the three required message files and confirm their wording.
- Verify every selected sample once and keep the R12 evidence available as fallback.
- Disable notifications and unrelated applications; confirm audio volume and screen scaling.

## Timed script

| Time | Owner | Content and action |
| --- | --- | --- |
| 0:00–2:00 | **Member 1: [name]** | Explain the authentication boundary, signed record, RSA-PSS trust, public-key fingerprint, and why start hiding is not encryption. |
| 2:00–6:00 | **Member 2: [name]** | Drag in PNG, choose a non-zero start, explain depths 1 and 8, show capacity and protect the short Learning Outcome message. Party B downloads the transferred media/manifest and verifies; then show `image-message-corruption-negative`. |
| 6:00–11:00 | **Member 3: [name]** | Use PCM-16 WAV and the long Project Overview message with a derived start. Show receiver verification, before/after playback, original/output byte counts, then `audio-signature-corruption-negative`. Explain that equal size does not mean identical samples. |
| 11:00–15:00 | **Member 4: [name]** | Show the confidential custom image case and separate AES/start-secret transfer. Demonstrate file-payload recovery and responsive capacity updates. Explain exact-size preservation limits and the optional encrypted original backup. |
| 15:00–19:00 | **Member 5: [name]** | Show repetition-3 one-copy recovery and `audio-robust-two-copy-negative`, the third required image/audio failure. Explain the storage cost and independent-noise evaluation. Briefly show steganalysis false alarms; keep video as backup material. |
| 19:00–22:00 | **All; Member 1 leads** | Explain replay, outside-region edits, plaintext-hash guessing, and key handling. Each member identifies actual work; summarize AI assistance and how it was checked. |
| 22:00–25:00 | **All** | Reserve for transfer delays, transitions, or questions. Do not schedule extra features into this buffer. |

Planned content: **22:00**. Contingency: **3:00**. Maximum total: **25:00**. Record the actual duration after a real rehearsal.

## Required cases and messages

- Short message: `samples/r11/messages/short.txt` in `image-short-positive`.
- Long message: `samples/r11/messages/long.txt` in `audio-long-positive`.
- Custom confidentiality/integrity message: `samples/r11/messages/confidential.txt` in `image-confidential-positive`.
- Required image negative: `image-message-corruption-negative`.
- Required audio negative: `audio-signature-corruption-negative`.
- Third mandatory negative: `audio-robust-two-copy-negative`. All three required failures must come from image/audio workflows. `video-h264-lossy-negative` is an optional extra and cannot substitute for one of them.
- Capacity rejection: show separately as input validation, not as a verification-negative substitute.

## Questions every member should be ready to answer

1. What is signed, what is encrypted, and what is only hidden?
2. Why does the receiver need a manifest and why is it not trusted by itself?
3. How is the start location recovered without storing a derived location?
4. What does `AUTHENTIC` prove, and what does it leave outside scope?
5. Why can replay or an outside-region cover edit still pass?
6. How do depth and repetition change capacity and distortion?
7. Why are PNG compressed length, decoded equality, and byte equality different?
8. Why does lossy transcoding usually destroy a video LSB payload?
9. Why is the recovery sidecar not reversible LSB embedding?
10. Which private or secret values must never travel with the public bundle?

## Fallback order

If time or equipment fails, preserve the assessed core in this order:

1. Image positive and negative.
2. Audio positive and negative with playback.
3. Security design, start recovery, and signature/hash checks.
4. Confidential custom message.
5. Repetition innovation and its limit.
6. Analysis, recovery, size, and video extras.

Use recorded evidence only to explain a result already produced by the current build. Do not present a screenshot as a live run.

## Human completion record

| Item | Team entry |
| --- | --- |
| Demo date/time | [complete before submission] |
| Party A member/device | [complete after actual assignment] |
| Party B member/device/folder | [complete after actual assignment] |
| Transfer channel used | [complete after actual transfer] |
| Separate key/secret channel | [complete after actual transfer] |
| Rehearsal date | [complete after rehearsal] |
| Actual rehearsal duration | [complete after rehearsal] |
| Image observation | [record actual observation] |
| Audio listening observation | [record actual observation] |
| Issues and mitigations | [record actual findings] |
