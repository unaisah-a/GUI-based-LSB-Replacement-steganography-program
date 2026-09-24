> **Historical design reference, superseded by S01.** Detection statistics, bit-plane
> views and difference-image visualisation described here are no longer implemented.
> Current scope is in [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

# INF2005 ACW1 — Steganographic Media Integrity Verification

## Purpose and Status

This document is an internal planning reference for team members and AI coding assistants. It describes assignment requirements, team implementation decisions and optional extensions. It is not the submission README and does not indicate that features have already been implemented. The assignment brief takes precedence if any requirement conflicts.

Labels used throughout this reference:
- **Brief requirement:** functionality or evidence required by the assignment.
- **Team decision:** our proposed implementation approach, which may be revised by agreement.
- **Optional extension:** additional functionality to attempt after the mandatory workflows are stable.

**Brief requirement:** implement and justify at least one meaningful innovation beyond the simplest fixed-location LSB demonstration. Individual optional challenges are not all required.

**Team decision:** Python, PySide6, PNG and WAV/PCM are the baseline choices. The folder layout, shared interfaces, team ownership and Git workflow below are internal engineering decisions.

## Project Summary

This project is a GUI-based cybersecurity application for protecting and verifying media files using:

- LSB replacement steganography
- Cryptographic hashing
- Digital signatures
- Secure/derived payload start locations
- Image and audio cover objects as mandatory media types
- Video as an optional extension
- Positive and negative verification cases
- Optional robustness, steganalysis, attack simulation, and advanced start-location security

The recommended implementation is a **Python desktop application using PySide6**.

The application should feel like a usable media-security tool rather than a basic coursework script. It should support drag-and-drop, selectable LSB depth, clear media previews/playback, verification results, and attack/analysis tools.

---

# 1. Mandatory Assignment Scope

The mandatory implementation should support:

## Image
- Preferably PNG for the basic implementation
- LSB replacement embedding
- LSB extraction
- Adjustable LSB depth from **1 to 8**
- Capacity checking
- Selectable or derived payload start location
- Image preview before and after embedding
- Positive and negative verification cases

## Audio
- Preferably WAV/PCM for the basic implementation
- LSB replacement embedding
- LSB extraction
- Adjustable LSB depth from **1 to 8**
- Capacity checking
- Selectable or derived payload start location
- Playback of original and stego audio
- Positive and negative verification cases

## Security
The system should use:
- Cryptographic hashing
- Digital signatures
- Public/private key verification
- Nonce
- Media ID
- Timestamp
- Team-defined metadata
- Clear verification verdicts

Suggested verdicts:
- `AUTHENTIC`
- `TAMPERED`
- `SIGNATURE_INVALID`
- `PAYLOAD_MISSING`
- `WRONG_START_LOCATION`
- `CANNOT_VERIFY`

---

# 2. Suggested Security Workflow

## Baseline Hashing and Verification Decision

**Team decision:** hash the hidden message bytes with SHA-256. Include the message hash, media ID, timestamp, nonce, and extraction parameters in a deterministically serialised verification record, and digitally sign that record. Store the message and signed record in a versioned payload envelope with explicit lengths.

The receiver verifies the signature and recomputes the extracted message hash. Successful verification establishes the integrity and authenticity of the signed message record relative to a trusted public key. It does **not** establish that every part of the cover media is unchanged, nor does it by itself prevent replay.

Do not compare the original file hash directly with the stego file hash: embedding changes the cover. Detecting cover changes outside the payload requires a separately defined media-integrity scheme. Until that exists, describe `AUTHENTIC` in the GUI as verified message/record authenticity, not whole-media authenticity.

**Team decision:** a hidden start location is not encryption. For the custom confidentiality demonstration, use authenticated encryption for the message, with encryption secrets shared separately. Specify the algorithm, key handling, nonce handling and signature/encryption order before implementing that extension to the baseline. Hash the recovered plaintext message bytes for the baseline message-integrity check.


## Protect / Sender Side

```text
Original media
    ↓
Calculate SHA-256 of message bytes
    ↓
Create verification payload
    ↓
Digitally sign payload or payload hash
    ↓
Derive/select payload start location
    ↓
Optional robust encoding / error correction
    ↓
LSB embedding
    ↓
Stego media
```

## Verify / Receiver Side

```text
Received stego media
    ↓
Recover/derive start location
    ↓
Extract embedded payload + signature
    ↓
Verify digital signature
    ↓
Recompute SHA-256 of extracted message bytes
    ↓
Compare values
    ↓
Return clear verification verdict
```

---

# 3. Suggested Payload Structure

Use one common payload structure across image, audio and video.

Example:

```json
{
  "media_id": "IMG-001",
  "timestamp": "2026-09-13T23:00:00+08:00",
  "message_hash": "SHA256_OF_MESSAGE_BYTES_HERE",
  "nonce": "RANDOM_NONCE_HERE",
  "media_type": "image",
  "metadata": {
    "team": "P?-?",
    "lsb_depth": 1,
    "start_method": "HMAC_PRF"
  }
}
```

Recommended design:
1. Define exact message encoding (UTF-8 for text) and a versioned envelope with explicit record, message and signature lengths.
2. Serialise the verification record deterministically and sign its exact bytes.
3. Store the message, record and signature in the media; include any encryption framing when encryption is enabled.
4. Verify using a trusted public key, then compare the recomputed message hash with the signed value.
5. Bind all extraction parameters to the signed record and compare them with the companion manifest after extraction.

The JSON above is illustrative, not a complete wire-format specification. Agree on the complete schema before implementation.

---

# 4. Recommended Technology Stack

**Team decision:** these are proposed libraries, not assignment-mandated dependencies. Add optional media/analysis libraries only when needed.

## Language
**Python 3**

## Desktop GUI
**PySide6**

Recommended because the project needs:
- Drag-and-drop
- File pickers
- Image preview
- Audio/video playback
- Sliders/dropdowns
- Tabs
- Charts
- Status indicators
- Direct local file access

## Media
- `Pillow`
- `opencv-python`
- `numpy`
- Python `wave` module
- `ffmpeg` / `ffmpeg-python` if needed for video
- `PySide6.QtMultimedia` for playback

## Cryptography
- Python `hashlib`
- `cryptography`

## Analysis
- `numpy`
- `matplotlib`
- optionally `scipy`

## Testing
- `pytest`

---

# 5. Recommended Project Folder Structure

**Team decision:** this is a proposed layout, not a list of implemented modules. Create optional modules when their features are taken on.

```text
INF2005-ACW1/
│
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── app/
│   ├── __init__.py
│   │
│   ├── gui/
│   │   ├── main_window.py
│   │   ├── protect_tab.py
│   │   ├── verify_tab.py
│   │   ├── attack_tab.py
│   │   ├── steganalysis_tab.py
│   │   ├── video_tab.py
│   │   └── widgets/
│   │       ├── drop_zone.py
│   │       ├── media_preview.py
│   │       ├── file_info_panel.py
│   │       └── result_panel.py
│   │
│   ├── stego/
│   │   ├── image_stego.py
│   │   ├── audio_stego.py
│   │   ├── video_stego.py
│   │   ├── capacity.py
│   │   └── bit_utils.py
│   │
│   ├── crypto/
│   │   ├── hashing.py
│   │   ├── signatures.py
│   │   ├── key_manager.py
│   │   ├── payload.py
│   │   └── start_location.py
│   │
│   ├── verification/
│   │   ├── verifier.py
│   │   ├── verdicts.py
│   │   └── media_compare.py
│   │
│   ├── attacks/
│   │   ├── image_attacks.py
│   │   ├── audio_attacks.py
│   │   ├── video_attacks.py
│   │   └── payload_attacks.py
│   │
│   ├── analysis/
│   │   ├── image_analysis.py
│   │   ├── audio_analysis.py
│   │   ├── steganalysis.py
│   │   └── quality_metrics.py
│   │
│   ├── robustness/
│   │   ├── error_correction.py
│   │   └── redundancy.py
│   │
│   └── utils/
│       ├── file_utils.py
│       ├── media_utils.py
│       ├── constants.py
│       └── logging_utils.py
│
├── assets/
│   ├── icons/
│   └── styles/
│
├── samples/
│   ├── images/
│   │   ├── original/
│   │   ├── stego/
│   │   └── tampered/
│   ├── audio/
│   │   ├── original/
│   │   ├── stego/
│   │   └── tampered/
│   └── video/
│       ├── original/
│       ├── stego/
│       └── tampered/
│
├── keys/
│   ├── public/
│   └── demo_private/
│
├── tests/
│   ├── test_image_stego.py
│   ├── test_audio_stego.py
│   ├── test_crypto.py
│   ├── test_verification.py
│   └── test_attacks.py
│
├── evidence/
│   ├── screenshots/
│   ├── logs/
│   └── results/
│
└── docs/
    ├── demo_plan.md
    ├── architecture.md
    ├── test_cases.md
    ├── limitations.md
    └── contribution_statement.md
```

---

# 6. Architecture Principle

Keep the GUI separate from the security and steganography logic.

```text
PySide6 GUI
    ↓
Application / verification logic
    ↓
Steganography + cryptography modules
    ↓
Media files
```

Do **not** place large LSB algorithms directly inside GUI event handlers.

Bad:

```python
def on_protect_clicked():
    # 100+ lines of LSB code
    ...
```

Better:

```python
def on_protect_clicked():
    result = embed_image(
        input_path=input_path,
        output_path=output_path,
        payload=payload,
        lsb_count=lsb_count,
        start_location=start_location
    )
```

The actual algorithm belongs in `app/stego/image_stego.py`.

---

# 7. Shared Module Interfaces

Agree on interfaces before each member starts coding.

## Image

```python
def embed_image(
    input_path: str,
    output_path: str,
    payload: bytes,
    lsb_count: int,
    start_location: int
):
    ...

def extract_image(
    input_path: str,
    lsb_count: int,
    start_location: int
) -> bytes:
    ...
```

## Audio

```python
def embed_audio(
    input_path: str,
    output_path: str,
    payload: bytes,
    lsb_count: int,
    start_location: int
):
    ...

def extract_audio(
    input_path: str,
    lsb_count: int,
    start_location: int
) -> bytes:
    ...
```

## Video

```python
def embed_video(...):
    ...

def extract_video(...):
    ...
```

## Crypto

```python
def create_payload(...):
    ...

def hash_data(...):
    ...

def sign_payload(...):
    ...

def verify_signature(...):
    ...

def derive_start_location(...):
    ...
```

## Verification

```python
def verify_media(...):
    ...
```

Suggested result:

```python
{
    "payload_found": True,
    "signature_valid": True,
    "hash_valid": True,
    "start_location_valid": True,
    "verdict": "AUTHENTIC"
}
```

---

# 8. Team Roles

## Member 1 — Cryptography & Payload Security
Responsible for:
- Payload creation
- Hashing
- Digital signatures
- Public/private key handling
- Nonce generation
- Secure/derived start-location method
- Explaining why the verification payload can be trusted

Primary folder:
```text
app/crypto/
```

## Member 2 — Image Steganography & Image Steganalysis
Responsible for:
- PNG/BMP LSB embedding
- PNG/BMP extraction
- Adjustable 1–8 LSB depth
- Capacity checking
- Image quality comparison
- Bit-plane visualisation
- Difference images
- Image steganalysis

Primary areas:
```text
app/stego/image_stego.py
app/analysis/image_analysis.py
```

## Member 3 — Audio Steganography & Robust Embedding
Responsible for:
- WAV/PCM LSB embedding
- WAV extraction
- Adjustable 1–8 LSB depth
- Audio capacity checking
- Playback verification
- Measuring/distinguishing audio distortion
- Error correction / redundancy
- Robust embedding experiments

Primary areas:
```text
app/stego/audio_stego.py
app/analysis/audio_analysis.py
app/robustness/
```

## Member 4 — GUI & System Integration
Responsible for:
- PySide6 GUI
- Drag-and-drop
- File selection
- Image preview
- Audio/video playback
- LSB controls
- Start-location controls
- Verification status display
- Connecting all modules together

Primary areas:
```text
app/gui/
main.py
```

## Member 5 — Verification, Attack Simulation, Video & Media Comparison
Responsible for:
- Final verification logic
- Verdict generation
- Attack simulator
- Wrong key / wrong start / corrupted payload tests
- Tampered media tests
- Video steganography extension
- Media property comparison
- File size / duration / resolution / frame-rate comparison

Primary areas:
```text
app/verification/
app/attacks/
app/stego/video_stego.py
```

---

# 9. Optional Challenges

**Team decision:** complete the mandatory workflows first. Implement and justify at least one meaningful innovation; attempt further extensions as time permits. The following challenges are individually optional.

## 9.1 Video Cover Object
Possible approaches:
- Selected-frame embedding
- Embedding into a lossless/uncompressed track
- Controlled frame extraction and reconstruction

Important:
- Lossy MP4/H.264/H.265 recompression can destroy LSB data.
- Implement video only after image/audio are stable.

## 9.2 Robust Embedding
Possible approaches:
- Repetition coding
- Majority voting
- Hamming codes
- Reed-Solomon error correction

Suggested workflow:

```text
Payload
    ↓
Error correction encoding
    ↓
LSB embedding
    ↓
Minor corruption/noise
    ↓
Extract
    ↓
Error correction
    ↓
Recovered payload
```

## 9.3 Attack Simulation
Suggested attacks:
- Corrupt hidden payload
- Modify image pixels
- Modify audio samples
- Wrong public key
- Wrong secret/start location
- Random bit corruption
- Replay/substitution
- Payload truncation

Use the attack module for negative test cases.

## 9.4 Advanced Start-Location Security
Recommended design:

```text
secret key
    +
media ID
    +
nonce
    ↓
HMAC-SHA256
    ↓
pseudo-random integer
    ↓
valid embedding range
    ↓
payload start location
```

This avoids a simple fixed start such as byte/pixel 0. Define the valid range using the encoded payload length and selected LSB depth, and reject insufficient capacity before deriving a location.

### Extraction Bootstrap

**Team decision:** use a small companion manifest containing non-secret extraction parameters: format version, media ID, nonce, LSB depth, start-location method and the length information needed to derive the valid embedding range. Send this manifest with the stego file. Share the start-location secret separately; never put it in the manifest.

The receiver reads these parameters before extraction. Media ID and nonce cannot exist only inside the hidden payload if they are needed to locate that same payload.

Include the manifest parameters in the signed verification record and compare them after extraction. Treat manifest values as untrusted until then: validate supported settings, lengths and bounds before using them. Tampering may prevent extraction; report a clear failure without claiming the exact cause is known.

A keyed start location makes guessing harder but does not itself encrypt the message. Document its limitations, the separate secret-sharing procedure and public-key trust assumptions.

## 9.5 Steganalysis
Possible features:
- Difference image
- Bit-plane visualisation
- LSB distribution
- Histogram comparison
- Simple statistical indicators
- PSNR/MSE
- Audio waveform difference
- SNR

Do not claim perfect steganography detection unless it is actually supported by testing.

---

# 10. Professor Feedback / Stretch Goals

These are internal stretch goals attributed to professor feedback in this planning reference; they are not independently established by the supplied brief. Adjustable LSB depth and required media comparison/playback are already baseline requirements, not optional polish.

The team should aim for:

## Flexible UI
- Drag-and-drop
- Adjustable LSB depth
- Simple navigation
- Media preview/playback
- Clear status feedback
- File/property comparison

## File Size Preservation
Investigate whether output can preserve original file size.

### WAV/PCM
Usually straightforward because existing sample bytes are replaced rather than additional samples being added.

### BMP
Usually straightforward because pixel storage is fixed-size.

### PNG
Harder because PNG is compressed.

Changing LSB values can change DEFLATE compression efficiency.

Possible experiment:
1. Re-encode with multiple compression parameters.
2. If stego PNG is smaller than target size, use legal PNG ancillary/padding data to reach the original size.
3. Record when exact size preservation succeeds or fails.
4. Do not claim this is guaranteed for every PNG unless testing proves it.

### Video
Exact file-size preservation is difficult with lossy codecs because recompression changes stream size.

---

# 11. Reversibility / Recovering the Original Media

Normal LSB replacement overwrites original bits.

Example:

```text
Original: 10110110
Stego:    10110111
```

After extracting the payload bit, the decoder cannot automatically know whether the original bit was `0` or `1`.

Therefore standard LSB replacement is **not inherently reversible**.

Stretch possibilities:
- Store overwritten bits as recovery metadata
- Investigate reversible data hiding
- Explore histogram-shifting or other reversible techniques
- Treat reversible recovery as an optional innovation rather than replacing the required LSB implementation

Important distinction:

```text
visually identical
≠
pixel-identical
≠
byte-for-byte file-identical
```

A PNG may be pixel-identical after reconstruction but still have a different file hash because compression, filtering, metadata or chunk order changed.

---

# 12. LSB Depth and Media Quality

The GUI should make the LSB trade-off visible.

```text
More LSBs
    ↓
More payload capacity
    ↓
More media modification
    ↓
More visible/audible distortion
    ↓
Potentially easier steganalysis
```

For audio, higher LSB settings generally increase modification, but audibility depends on sample width, signal content and embedding density. Measure and demonstrate the effect instead of guaranteeing audible distortion at every setting.

Suggested UI:

```text
LSB depth:  [1 ─────●──── 8]

Capacity:
Payload size:
Capacity used:

Original file size:
Stego file size:

Quality:
MSE:
PSNR/SNR:
```

---

# 13. Media Comparison Module

Recommended comparisons:

## Image
- File size
- Width
- Height
- Channel count
- Pixel equality
- MSE
- PSNR
- SHA-256

## Audio
- File size
- Duration
- Sample rate
- Channel count
- Sample width
- Frame count
- MSE/SNR
- SHA-256

## Video
- File size
- Resolution
- Duration
- Frame rate
- Frame count
- Codec
- Audio properties
- SHA-256

Example result:

```text
Original                 Stego

Size       8.42 MB       8.42 MB       ✓
Duration   12.04 s       12.04 s       ✓
FPS        30            30            ✓
Resolution 1920x1080     1920x1080     ✓
```

---

# 14. Suggested GUI Layout

```text
┌─────────────────────────────────────────────────────┐
│ Media Integrity & Steganography Tool                │
├─────────────────────────────────────────────────────┤
│ Protect │ Verify │ Attack Lab │ Steganalysis │ Video│
├─────────────────────────────────────────────────────┤
│                                                     │
│       Drag image / audio / video here               │
│                                                     │
│               [ Select File ]                       │
│                                                     │
├─────────────────────────┬───────────────────────────┤
│ Embedding Settings      │ Media Information         │
│                         │                           │
│ LSB Depth   [━━●━━] 3   │ Original: 4.21 MB        │
│ Start Mode  HMAC-PRF ▼  │ Output:   4.21 MB        │
│ Secret      •••••••••   │ Capacity: 921 kB         │
│                         │ Payload:  12 kB           │
│ Payload                 │                           │
│ [...................]   │ Quality metrics          │
│                         │                           │
│ [ Protect & Sign ]      │                           │
└─────────────────────────┴───────────────────────────┘
```

---

# 15. Positive and Negative Test Cases

The assignment requires at least:
- 2 positive cases overall
- 3 negative cases overall
- At least 1 positive and 1 negative case for image
- At least 1 positive and 1 negative case for audio

Suggested cases:

## Mandatory Demo Checklist

**Brief requirement:**
- Show party A sending a stego file to party B, who downloads it to their own folder, extracts the message and verifies its integrity and signature. Include the companion manifest used by our design.
- Demonstrate a short message taken from a Learning Objective, a longer message using the Project Overview paragraph, and a relevant custom payload addressing confidentiality and integrity.
- Demonstrate capacity checks and GUI-selectable LSB depth from 1 to 8.
- Explain start-location selection/derivation, receiver recovery and protection for both image and audio.
- Display or play cover/stego objects for comparison before and after encoding and decoding, and display/play recovered payloads where applicable. Do not automatically execute arbitrary extracted content.
- Identify the implemented innovation, its practical benefit and its limitations.

Keep insufficient capacity as an input-validation case. Use actual verification failures for the minimum three negative cases.

## Positive
1. PNG protected and verified successfully
2. WAV protected and verified successfully
3. Optional video protected and verified successfully

## Negative
1. Corrupted embedded message in an image: hash mismatch or decoding failure
2. Corrupted embedded record/signature in audio: signature or decoding failure
3. Wrong public key: signature verification fails
4. Wrong start secret: extraction cannot verify the payload
5. Missing payload: extraction cannot verify the payload

Additional checks:
- Payload exceeds available capacity: reject before embedding (input validation).
- Modified cover outside embedded data: may pass baseline message verification; demonstrate this limitation honestly.
- Replay/substitution: only claim detection if an explicit freshness or media-binding check exists. A timestamp and nonce alone do not reject a replay.

Do not label all extraction failures `WRONG_START_LOCATION`: corruption, incorrect settings and missing payloads may be indistinguishable. Use `CANNOT_VERIFY` when the cause is uncertain.

---

# 16. Demo Considerations

Target maximum demo duration:
**25 minutes**

Suggested flow:

```text
0–3 min
Architecture + security design

3–7 min
Image positive case

7–10 min
Image attack / negative case

10–15 min
Audio positive case + LSB distortion demo

15–18 min
Audio negative case

18–21 min
Digital signature + start-location security

21–23 min
Optional challenges / innovation

23–25 min
Limitations + conclusion
```

All members should understand the complete workflow even if they each own different modules.

---

# 17. Git / GitHub Workflow

## Recommended branch strategy

Do **not** create permanent branches named after each person.

Avoid:

```text
gabriel
member2
member3
member4
member5
```

This becomes confusing when one person works on multiple features or several members need to collaborate on one feature.

Use **feature/area-based branches** instead.

Recommended:

```text
main
develop

feature/crypto
feature/image-stego
feature/audio-stego
feature/gui
feature/verification
feature/attack-simulator
feature/video
feature/steganalysis
feature/robust-embedding
feature/media-comparison
```

For smaller tasks, create narrower temporary branches:

```text
feature/gui-drag-drop
feature/gui-audio-player
feature/png-capacity-check
feature/wav-lsb-extraction
feature/hmac-start-location
feature/video-frame-embedding
```

---

# 18. Git Branch Rules

## `main`
Should contain only:
- Stable code
- Demo-ready versions
- Release milestones

Do not develop directly on `main`.

## `develop`
Integration branch.

Completed features merge here first.

```text
feature branch
    ↓
pull request
    ↓
develop
    ↓
integration testing
    ↓
main
```

## Feature Branches
Each branch should represent a feature or technical area, not a person.

Examples:

```bash
git checkout develop
git pull

git checkout -b feature/image-stego
```

After implementation:

```bash
git add .
git commit -m "Implement PNG LSB embedding and extraction"
git push origin feature/image-stego
```

Then create a Pull Request into `develop`.

---

# 19. Suggested Ownership vs Branches

Ownership and branches are separate concepts.

Example:

```text
Member 1 owns crypto
but may work on:
feature/crypto
feature/hmac-start-location

Member 4 owns GUI
but may work on:
feature/gui-drag-drop
feature/gui-media-preview
```

A feature can also have multiple members working on it.

This is better than assigning one permanent branch per member.

---

# 20. Commit Message Style

Use meaningful commit messages.

Good:

```text
Add WAV capacity calculation
Implement RSA signature verification
Fix PNG extraction offset
Add drag-and-drop media selection
Add wrong-key attack case
```

Bad:

```text
update
changes
final
fix
test
```

Optional conventional style:

```text
feat: add WAV LSB embedding
fix: correct payload extraction offset
test: add tampered image verification case
docs: update architecture diagram
refactor: move shared bit utilities
```

---

# 21. Pull Request Checklist

Before merging to `develop`:

- [ ] Code runs
- [ ] Tests pass
- [ ] No hard-coded local file paths
- [ ] No secret/private production keys committed
- [ ] Function interfaces still match agreed API
- [ ] README/docs updated if behaviour changed
- [ ] Feature tested with sample media
- [ ] Another member has reviewed the code

---

# 22. `.gitignore` Suggestions

```gitignore
# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
.venv/
venv/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Temporary/generated media
output/
temp/
*.tmp

# Logs
*.log

# Private keys
keys/private/
*.pem
*.key
```

Do not accidentally commit genuine private keys.

---

# 23. Recommended Development Order

Do not start all optional challenges immediately.

Recommended order:

```text
1. Shared architecture/interfaces
2. Image LSB
3. Audio LSB
4. Payload + crypto
5. Verification
6. Basic GUI
7. Positive/negative cases
8. Secure start location
9. Attack simulator
10. Steganalysis
11. Robust embedding
12. Video
13. File-size preservation experiments
14. Reversibility experiments
15. UI polish
```

Core image/audio/signature verification must be stable before video work becomes a priority.

---

# 24. Questions the Team Should Agree on Early

Before coding:

1. What exactly gets hashed?
2. How is the payload serialised?
3. Which digital-signature algorithm is used?
4. How are keys generated/stored?
5. How is payload length stored/recovered?
6. How is the start location derived?
7. How does extraction know the correct LSB depth?
8. What happens when capacity is insufficient?
9. How are error-correction bytes represented?
10. How will PNG file-size preservation be tested?
11. What does "same media" mean for each comparison?
12. What video format/codec is used for the optional challenge?
13. Which functions are shared between image/audio/video?
14. What exact negative cases will be demonstrated?

---

# 25. AI Context / Project Brief for Coding Assistants

The following section can be copied into an AI coding assistant when asking it to help with this project.

---

## AI PROJECT CONTEXT

We are a team of five university students building an INF2005 Cyber Security Fundamentals coursework project.

The application is a **Python + PySide6 desktop GUI** for media steganography and authenticity verification.

### Mandatory functionality
The application must:
- Support image and audio cover objects
- Prefer PNG and WAV/PCM
- Use LSB replacement steganography
- Support selectable LSB depth from 1 to 8
- Perform payload capacity checks
- Support variable/derived start locations
- Create a payload containing media ID, timestamp, cryptographic hash, nonce and metadata
- Digitally sign the payload or related hash
- Verify the signature using the corresponding public key
- Extract hidden payloads
- Verify the extracted message hash against the signed record
- Demonstrate the required A-to-B transfer and short, long and custom message examples
- Return clear verdicts such as:
  - AUTHENTIC
  - TAMPERED
  - SIGNATURE_INVALID
  - PAYLOAD_MISSING
  - WRONG_START_LOCATION
  - CANNOT_VERIFY
- Display image cover/stego objects
- Play audio cover/stego objects
- Demonstrate positive and negative verification cases

### Optional functionality planned
After the mandatory workflows are stable, select at least one meaningful innovation and justify it. Further planned possibilities include:
- Video steganography
- Robust embedding/error correction
- Attack simulation
- Advanced start-location security
- Steganalysis

### Professor feedback / stretch goals
We also want:
- Flexible UI
- Drag-and-drop file input
- Adjustable LSB depth
- Before/after media comparison
- File-size preservation where feasible
- Increasing audible distortion when higher audio LSB depths are used
- Investigation into reversible recovery / exact original-media restoration where feasible

### Implementation Boundaries
Implement only the feature requested in the current task. Treat planned features as unimplemented unless confirmed by the code. Follow agreed interfaces, identify unresolved design decisions, and do not silently invent a security scheme or claim guarantees beyond the implemented checks.

The current user request controls the work. This document is project reference material, not authorization to send messages, publish changes or implement every planned feature.

Baseline verification authenticates the signed message record and extracted message hash, not the entire cover file. Use a companion manifest for non-secret extraction parameters, authenticate those parameters through the signed record, and keep secrets separate. Start-location hiding does not provide message encryption.

### Architecture requirements
Keep GUI separate from backend logic.

Use modules such as:
- `app/gui/`
- `app/stego/`
- `app/crypto/`
- `app/verification/`
- `app/attacks/`
- `app/analysis/`
- `app/robustness/`

Do not put steganography algorithms directly inside GUI event handlers.

### Team responsibilities
- Member 1: cryptography and payload security
- Member 2: image steganography and image steganalysis
- Member 3: audio steganography and robust embedding
- Member 4: GUI and system integration
- Member 5: verification, attack simulation, video and media comparison

### Engineering principles
- Use shared function interfaces
- Avoid duplicated bit-manipulation code
- Add tests
- Keep private keys out of Git
- Use feature-based Git branches
- Merge features into `develop`
- Merge stable versions from `develop` into `main`
- Preserve media usability
- Do not claim features are secure/robust unless supported by testing
- Explain limitations honestly

### Important technical distinction
Standard LSB replacement is not inherently reversible because it overwrites existing media bits.

Also:
- Lossless PNG does not imply fixed compressed file size
- WAV/PCM is easier for exact file-size preservation
- BMP is easier for exact file-size preservation
- Lossy video codecs can destroy LSB payloads
- Pixel-identical media and byte-for-byte identical files are different goals

When generating code, keep all modules compatible with the shared interfaces and avoid rewriting unrelated parts of the project.

---

# 26. Final Project Goal

The finished application should feel like a small media-security laboratory rather than a single-purpose steganography script.

A user should be able to:

```text
Drag in media
    ↓
Inspect media properties
    ↓
Choose LSB/security options
    ↓
Protect/sign media
    ↓
Preview/play output
    ↓
Send output
    ↓
Receiver drags file in
    ↓
Extract/verify
    ↓
Receive clear verdict
    ↓
Optionally run attacks/steganalysis
```

The project should prioritise correctness and explainability over adding features that are unreliable.
