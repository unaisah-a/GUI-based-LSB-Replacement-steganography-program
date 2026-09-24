> Current scope: S01 removed steganalysis. [Current validation](../evidence/s01/README.md)
> supersedes historical suite totals and bundle counts below.

# Consolidated evidence index

Application/test baseline: T08 commit `2aa68adf83f0e57cefa8cff10b4a78f3ac4c4f41`.
T09 changes documentation and delivery records. Historical reports apply to their
recorded revisions, not separate current-suite totals. A live demo is still required.

| Claim/requirement | Evidence | Script time | Limit |
| --- | --- | --- | --- |
| FR1–FR2 image/audio input, picker/drop/playback | [T08 native checks](../evidence/t08/README.md), [T04 input tests](../evidence/t04/README.md) | 02–12 | Test actual demo hardware separately |
| FR3–FR4 record/signature, FR9 hash, FR10 verdicts | [T03 safeguards](../evidence/t03/README.md), [T08 suite](../evidence/t08/stable-full.txt) | 00–02, receiver/attacks | Payload scope and external key trust |
| FR5–FR8 embedding, starts, extraction, depths/capacity | [T07 isolation](../evidence/t07/README.md), [cases](../samples/t07/CASE_INDEX.md), T08 suite | 02–12 | Envelope overhead; HMAC is not encryption |
| FR11 positive/negative cases | T07 image-short, audio-long, image-payload-corruption, audio-signature-corruption, audio-repetition3-damage2 | 02–12, 15–19 | Capacity rejection/video do not replace mandatory-media negatives |
| FR12 reproducibility | [Bundle guide](sample_bundle.md), [Current package](../evidence/s01/README.md) | Transfer, 21–22 | Local isolation is not actual human transfer |
| FR13/four retained challenges | [T05](../evidence/t05/README.md), T07, [challenge guide](challenge_workflows.md) | 07–12, 15–22 | No universal robustness/detection claim |
| AES, trusted file preview/save | T03/T04 tests, T07 confidential/file cases, T08 native exact saves | 12–15 | Wrong passphrase withholds recovery |
| Size/properties | [T06 measurements](../evidence/t06/README.md) | 02–12, 19–20 | 66 cases; PNG matching 6/9; headers/codecs matter |
| Repetition recovery/failure | T07 audio repetition1/3 damage cases | 17–19 | Controlled logical damage; approximately triple storage |
| Video properties/playback/audio omission | T06/T07 and [T08 audio-bearing source](../evidence/t08/video-audio.txt)/native checks | 19–20 | Video-only FFV1; source audio omitted |
| Integrated validation | [1830 full tests](../evidence/t08/stable-full.txt), [932 repeated GUI tests](../evidence/t08/no-log-diagnostic.txt) | 21–22 | Supported --no-qt-log mitigation; native defect not proven |
| Human completion | [Records](submission_handoff.md), [contributions](contribution_statement.md), [AI use](ethics_and_ai_use.md) | Every member | Unfilled records are not evidence |

T07 `party-b/case-index.json` is authoritative for media/manifest/key/input mappings.
Checksums detect accidental damage, not key substitution. Do not mix legacy, T07
and newly generated keys.

T08 `stable-full.txt/xml` is the final full run. Baseline/retry/final-tests and
native-current-full logs retain historical failures; filenames alone do not imply
success. T08 source hashes describe validated working-tree bytes before Git line
ending normalisation; use the commit above for the committed baseline.

T09's report beside its ZIP records exact archive/extraction provenance. Keeping
it outside avoids a circular archive hash. Label prepared outputs/screenshots;
record actual transfer, rehearsal and submission only after they happen.
