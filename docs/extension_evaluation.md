# Extension evaluation: measured benefits and failure cases

The report at [review-extension-evaluation.json](../evidence/results/review-extension-evaluation.json) evaluates steganalysis and repetition coding separately. These are controlled experiments, not a claim of general tamper detection or transformation resistance.

## Reproduce

From the repository root, choose a new output path:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_extensions.py --output output\extension-evaluation.json
```

The default seed is 2005. The synthetic image controls are an even-valued gradient, random noise, and an undersized flat image. Each has a clean case and low-level depth-1 embedding at 10%, 50%, and 90% of available payload capacity. These payloads isolate carrier/statistical behavior; they are not signed application envelopes.

To evaluate team-owned photographs without modifying the inputs:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_extensions.py --images "photo-one.png" "photo-two.bmp" --output output\photo-evaluation.json
```

Supply real file paths and document the photographs' source and permission to use them. Reports identify inputs by index and SHA-256 rather than personal filesystem paths. No natural-image evaluation has been claimed for the synthetic report.

## Steganalysis

The experiment uses the existing pair-of-values chi-square indicator. An illustrative rule flags an image if any usable color channel has statistic/degrees-of-freedom at or below 1.5. It returns inconclusive when no channel has sufficient data. The cutoff is fixed and uncalibrated; it is not a statistical confidence score or a production detector.

Recorded outcomes with the default seed:

| Known input class | Flagged | Not flagged | Inconclusive |
| --- | ---: | ---: | ---: |
| 3 clean controls | 1 false alarm | 1 correct negative | 1 |
| 9 embedded cases | 3 correct flags | 3 misses | 3 |

The clean random-noise control illustrates why balanced histogram pairs do not prove embedding. The gradient illustrates missed detections at some embedding densities. The small control demonstrates an insufficient-data outcome. Preserve these failures when presenting the results; do not select only successful flags.

The next empirical improvement is evaluation across independently chosen natural images, with recorded false alarms, misses, and inconclusive results. Tuning a threshold and reporting accuracy on the same images would overstate the result.

## Repetition under independent noise

Each mode uses the same 256-byte message, five bit-flip probabilities, and 50 trials per probability. Noise is sampled independently across every stored bit, including all three copies in repetition mode. Both modes receive the same probability; repetition consumes 768 bytes versus 256 bytes. They do not receive the same total number of bit flips.

| Bit-flip probability | Exact recovery, no repetition | Exact recovery, repetition-3 |
| --- | ---: | ---: |
| 0 | 50/50 | 50/50 |
| 0.001 | 9/50 | 50/50 |
| 0.01 | 0/50 | 29/50 |
| 0.05 | 0/50 | 0/50 |
| 0.1 | 0/50 | 0/50 |

The report also records recovered bit errors, so partial improvement is visible even when whole-message recovery fails. This is stronger evidence than exclusively choosing one damaged copy, but it still excludes carrier framing, signed-envelope verification, burst damage, compression, and resampling. The signed image/audio one-copy and two-copy cases in the R11 bundle remain the end-to-end demonstrations.

## How to present it

Describe repetition as bounded error recovery with a threefold storage cost. Describe steganalysis as measured indicators with demonstrated false alarms and misses. Neither experiment changes the meaning of `AUTHENTIC`: that verdict still requires the application's signature, signed-settings, and message-hash checks.
