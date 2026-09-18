# Screenshots

Captured by hand from the running application, one file per shot below. Name each
file with its number and slug, for example `03_authentic.png`, so the list and the
folder stay in step. Each shot is tied to the segment of
[`docs/demo_plan.md`](../../docs/demo_plan.md) where it appears.

Unless a shot says otherwise, use the committed samples: the sample public key is
`keys/public/samples_public.pem` and the start secret is `demo-start-secret`. For shots
that protect a new file, use your own demo key pair (*Keys → Generate demo key pair*).

Capture the whole window, so the tab name, the verdict banner and the reason are all
readable in the same image.

| # | File | Segment | Tab | How to produce it | What must be visible |
|---|---|---|---|---|---|
| 1 | `01_protect_capacity_readout.png` | 3–7 | Protect | Drop `samples/images/original/cover.png`, type the short message, depth 1. | Detected media type and container, the exact signed payload length, capacity and percentage used |
| 2 | `02_capacity_refusal.png` | 3–7 | Protect | Same cover at depth 1, paste a message far larger than the capacity (or choose a large payload file), press **Protect && Sign**. | The "does not fit at depth 1" read-out and the refusal dialog, with no stego file written |
| 3 | `03_protect_quality.png` | 3–7 | Protect | Protect the short message at depth 3 with a derived start location. | Cover and stego previews side by side, the quality panel (MSE, PSNR, samples changed), and the list of secrets to share |
| 4 | `04_authentic.png` | 3–7 | Verify | Verify the file from shot 3 from the `party_b` folder with the right key and secret. | `AUTHENTIC` banner, all flags, the recovered message as inert text, and the scope notice |
| 5 | `05_authentic_file_payload.png` | 3–7 | Protect, then Verify | Protect with the payload set to *A file*, choosing a small PNG. Then verify it. | The recovered image shown in *Recovered file preview*, its detected type, and the **Save recovered payload...** button |
| 6 | `06_signature_invalid.png` | 7–10 | Attack Lab | Load the stego PNG and run *Modify pixels inside the payload*. | Expected beside observed, observed `SIGNATURE_INVALID` |
| 7 | `07_authentic_outside_payload.png` | 7–10 | Attack Lab | Run *Modify pixels outside the payload* on the same file. | Observed `AUTHENTIC` on a visibly modified file, with the scope note |
| 8 | `08_cannot_verify_lossy.png` | 7–10 | Attack Lab | Run *Re-encode as lossy JPEG*. | Observed `CANNOT_VERIFY` and the reason naming the lossy format |
| 9 | `09_audio_depth_quality.png` | 10–15 | Protect | Protect `samples/audio/original/original.wav` at depth 1, then again at depth 8. Capture both, or the depth-8 one with the figures from depth 1 noted. | PSNR and largest sample change at the two depths |
| 10 | `10_audio_signature_invalid.png` | 15–18 | Attack Lab | Load `samples/audio/stego/stego.wav` and run *Corrupt the signed record*. | Observed `SIGNATURE_INVALID` on audio |
| 11 | `11_payload_missing.png` | 18–21 | Verify | Verify the file from shot 3 with a **wrong** start secret. | `PAYLOAD_MISSING` and the note that a wrong secret, wrong depth, absent payload and corruption cannot be told apart |
| 12 | `12_tampered.png` | 18–21 | Attack Lab | Run *Edit the companion manifest* with the field set to `message_length`. | Observed `TAMPERED`, and *Fields that disagree: message_length* |
| 13 | `13_wrong_start_location.png` | 18–21 | Protect, then Verify | Protect with the start mode *Chosen manually* (for example location 100). Open the `.manifest.json` in a text editor, set `"start_location"` to `999999999`, save, then verify. | `WRONG_START_LOCATION` and *Start location usable: no* |
| 14 | `14_steganalysis_difference.png` | 21–23 | Steganalysis | Load `samples/images/stego/cover_stego.png` with `samples/images/original/cover.png` as the reference. | The amplified difference image, beside the bit planes and the distortion figures |
| 15 | `15_video_per_frame.png` | 21–23 | Video | Load `samples/video/stego/cover_stego.mkv` with its manifest, secret `demo-start-secret`, the sample key, and `samples/video/original/cover.mkv` as the reference. Press *Locate the payload frames* and step to a carrier frame. | The list of carrier frames and the per-frame difference view for a frame that carries payload |
| 16 | `16_video_clean_frame.png` | 21–23 | Video | Same as shot 15, stepped to a frame that carries no payload. | The difference view showing no change |

Shots 11 and 13 are deliberately separate. A wrong secret can never be proved to be
wrong, so it gives `PAYLOAD_MISSING`; only a declared location that cannot fit the
medium gives `WRONG_START_LOCATION`. Showing both side by side is the clearest
evidence that the verdicts claim no more than they can establish.

Before capturing, check that no screenshot shows a private key path, a passphrase in
clear text, or anything personal on the desktop.
