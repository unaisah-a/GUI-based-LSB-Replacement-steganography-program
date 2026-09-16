## Audio LSB Round-Trip Test

Purpose:
Verify that audio payload embedding and extraction works for all
required LSB settings from 1 to 8.

Input:
- Audio format: PCM-16 WAV
- Payload: "INF2005 Audio LSB Test"
- Start location: 100

Procedure:
1. Create/load PCM-16 WAV.
2. Embed payload using selected LSB count.
3. Save stego WAV.
4. Extract using the same LSB count and start location.
5. Compare extracted payload with original payload.

Expected result:
Extracted payload must exactly match the original payload.

Results:

| LSB | Result |
|---:|---|
| 1 | PASS |
| 2 | PASS |
| 3 | PASS |
| 4 | PASS |
| 5 | PASS |
| 6 | PASS |
| 7 | PASS |
| 8 | PASS |

Conclusion:
Audio LSB embedding and extraction successfully operates across
all required selectable LSB values.