# Demo study guide: learn the app from zero

This guide assumes no knowledge of the lecture materials. It teaches the concepts you need to operate the app, explain its design and answer demo questions. You do not need to memorise source code or open the lectures to understand it.

**Current scope:** image and audio steganography, signatures, optional encryption, manual and secret-derived starts, repetition coding, Attack Lab, video, quality comparisons and file recovery. Steganalysis was removed; quality comparisons remain. **GUI** means graphical user interface: the app's windows, tabs, fields and buttons.

Checked against application revision `8922a743c86cb7bf6d86cd68d09fe60dba34e349`. Presenter preparation follows your team's adopted `INF2005_ACW1_Demo_Script_and_Presentation_Split_.pdf`, with the operational corrections in section 17. Examples marked **expected** describe intended results, not a claim that you or your team have rehearsed them.

## External payload hash: contract and comparisons implemented

H02 now requires version 2 manifests. The original plaintext/file hash is copied
from the embedded signed record into external `message_hash`; `stego_sha256`
describes the entire output media file. These are different hashes. H03 implements
the comparisons and GUI. Practice paths below use H04's verified version 2 bundle;
old version 1 fixtures are preserved separately. H05 release validation remains.

The external `message_hash` is checked against the authenticated record and recovered bytes. Here,
"payload hash" means SHA-256 of the original text/file bytes before encryption,
not the complete envelope. After signature verification and any decryption, Verify
shows the expected manifest hash and the recomputed plaintext hash, plus whether
the manifest value agrees with the authenticated signed record. A mismatch in the
manifest hash rejects verification. Checks not reached say **Not performed**.

Keeping a hash outside the media makes the reference easier to inspect; location
alone does not authenticate it. The signature and cross-check prevent acceptance
of an attacker-replaced message/hash pair. The new public plaintext digest also
allows candidate-message guessing without extracting the hidden record, even when
the message is encrypted. It does not protect every cover pixel or audio sample.

The verifier now rejects old manifests and requires fresh output/manifest
pairs. The `samples/hash-manifest-v2` bundle passed independent receiver checks. See the
[implementation plan](IMPLEMENTATION_PLAN.md#external-payload-hash-agreed-target-not-implemented)
for acceptance criteria. Explain the expected-versus-recomputed comparison and
signature separately. These rows are implemented; rehearsal and release validation remain pending.

## How to use this guide

1. Read sections 1–10 in order. They build the foundations and explain the complete workflow.
2. Read sections 11–14 for the extra features and design questions.
3. Practise section 15 in the actual app. Predict each result before clicking.
4. Use sections 16–18 to prepare your speaking part and test your understanding.
5. Use section 19 for your final revision.

The goal is to answer three questions about each feature: **What does it do? Why did we choose it? When does it fail?**

## Contents

- [1. What the app is trying to achieve](#1-what-the-app-is-trying-to-achieve)
- [2. Bits, bytes, images and sound](#2-bits-bytes-images-and-sound)
- [3. Hiding data with LSB replacement](#3-hiding-data-with-lsb-replacement)
- [4. Capacity and file formats](#4-capacity-and-file-formats)
- [5. Hashing: a fingerprint of data](#5-hashing-a-fingerprint-of-data)
- [6. Signatures, keys and trust](#6-signatures-keys-and-trust)
- [7. Encryption and shared secrets](#7-encryption-and-shared-secrets)
- [8. The record, envelope and manifest](#8-the-record-envelope-and-manifest)
- [9. Finding the start location](#9-finding-the-start-location)
- [10. The complete sender and receiver workflow](#10-the-complete-sender-and-receiver-workflow)
- [11. Robustness through repetition coding](#11-robustness-through-repetition-coding)
- [12. Video, quality and file sizes](#12-video-quality-and-file-sizes)
- [13. Reading results and using Attack Lab](#13-reading-results-and-using-attack-lab)
- [14. Design decisions and honest limitations](#14-design-decisions-and-honest-limitations)
- [15. Practise with the actual app](#15-practise-with-the-actual-app)
- [16. Lecture foundations and additional features](#16-lecture-foundations-and-additional-features)
- [17. What each presenter should prepare](#17-what-each-presenter-should-prepare)
- [18. Practice questions and model answers](#18-practice-questions-and-model-answers)
- [19. Final revision sheet](#19-final-revision-sheet)
- [20. Sources and further reading](#20-sources-and-further-reading)

## 1. What the app is trying to achieve

Imagine Alice wants to send Bob a picture containing a hidden message: `Meet at 10`.

- Alice is **Party A**, the sender.
- Bob is **Party B**, the receiver.
- The original picture is the **cover object**.
- The message she wants to hide is the **payload**.
- The picture after embedding is the **stego object**.
- **Embedding** means putting data into the cover. **Extraction** means reading it back out.

Your app also packages verification information and a digital signature with the message. Consequently, the complete embedded package is larger than the message itself. In this guide, **message** means the user's text/file bytes; **embedded package** includes the extra verification data.

Bob needs more than readable text. He needs to check that the message matches what was signed and that the signature verifies with the expected key.

### Four different goals

| Goal | Plain meaning | What provides it here |
| --- | --- | --- |
| Concealment | Make the message less obvious in the media | Steganography and, optionally, a secret-derived start |
| Confidentiality | Prevent someone without the required secret from reading the message | Optional encryption, subject to the limits in section 7 |
| Integrity | Detect changes to protected data | A signed hash and signature verification |
| Authenticity | Establish that the signed data matches the supplied signing identity/key | Digital signature plus independently trusted public key |

**Availability** means being able to access a service or data when needed. It is the third part of the security **CIA triad**: Confidentiality, Integrity and Availability. This prototype mainly addresses confidentiality and payload integrity/authenticity; it cannot stop someone deleting the file.

Do not confuse **steganography** with **steganalysis**. Steganography hides data. Steganalysis investigates whether media contains hidden data. Your current app performs steganography but has no steganalysis feature.

**Say it aloud:** “We embed a signed message inside media. The receiver extracts it and checks its signature and hash. Encryption can additionally protect the message contents.”

## 2. Bits, bytes, images and sound

A **bit** is a 0 or 1. A **byte** contains eight bits. Files are sequences of bytes, whether they contain text, pictures, sound or something else.

Binary uses powers of two. In an eight-bit value, the positions have these weights:

```text
Bit position:   7    6    5    4    3    2    1    0
Weight:       128   64   32   16    8    4    2    1
Example:        1    0    1    0    1    1    0    0
```

That example, `10101100`, means `128 + 32 + 8 + 4 = 172`.

The rightmost bit has the smallest weight, so it is the **least significant bit (LSB)**. The leftmost bit has the largest weight, so it is the **most significant bit (MSB)**.

Text has an encoding that maps characters into bytes. **UTF-8** is the encoding used for typed text here. Many English characters use one byte each, but some characters use several. Therefore, character count is not always byte count. The app measures bytes.

### Images

A **pixel** is one point in an image. A typical colour image stores red, green and blue (**RGB**) channel values for each pixel. An eight-bit channel ranges from 0 to 255. For example, a pixel might have RGB values `(172, 80, 200)`.

An RGB image of width 320 and height 240 has `320 × 240 × 3 = 230,400` channel values available to the embedding scheme. Images can also contain an **alpha channel**, which controls transparency. The app excludes alpha from embedding to preserve transparency.

### Audio

Digital audio records measurements of a sound wave over time. Each measurement is a **sample**. **PCM**, pulse-code modulation, stores those measurements directly as numbers.

The app supports **16-bit PCM WAV**, with sample values from -32,768 to 32,767. **Sample rate** is the number of measurements per second per channel. **Mono** has one channel; **stereo** has two.

Two seconds of mono sound at 22,050 samples per second contains 44,100 scalar samples. Stereo at the same rate and duration contains 88,200 scalar samples, ordered left, right, left, right. An audio **frame** contains one sample from each channel at a particular time; it is not a video frame.

## 3. Hiding data with LSB replacement

**LSB replacement** writes payload bits into the lowest bits of successive cover samples.

At depth 1, suppose the cover channel is 172 and the next payload bit is 1:

```text
Original channel: 10101100 = 172
Payload bit:            1
Stego channel:    10101101 = 173
```

If the payload bit were 0, this sample would stay 172. Embedding does not necessarily change every sample it uses.

The decoder reads the last bit from the same samples in the same order, joins those bits into bytes and rebuilds the hidden package. The app uses the same basic process for image channels, audio samples and decoded video channels.

### What the depth slider means

**Depth** is the number of lowest bits replaced in each sample. Depth 2 replaces the last two bits, not just “bit number 2”.

```text
Original:        10101100 = 172
Next two bits:         11
At depth 2:      10101111 = 175
```

| Depth | Hidden bits per sample | Largest possible change in that sample's numerical value |
| --- | --- | --- |
| 1 | 1 | 1 |
| 2 | 2 | 3 |
| 4 | 4 | 15 |
| 8 | 8 | 255 |

The maximum is `2^depth - 1`. The symbol `^` means “raised to the power of”. These are bounds, not guaranteed changes in every sample.

More depth provides more space but allows greater distortion. At depth 8, an affected eight-bit image channel is completely replaced. For a 16-bit audio sample, only its lower eight bits are replaced. Changes may be noticeable depending on the content, depth and amount embedded; never promise invisibility or inaudibility.

The user chooses a depth from 1–8. The app does not silently increase it when a message is too large.

### Replacement, matching and reversibility

The lecture also describes **LSB matching**, which changes a sample up or down when its low bit does not match the required bit. Your app uses **replacement**, as required by the assignment. It also does not implement **Bit-Plane Complexity Segmentation (BPCS)**, a different scheme that hides data in complex image regions. A **bit plane** groups the bits at one position across image samples, such as all their lowest bits.

Replacement destroys the original low bits it overwrites. You can recover the embedded message, but you cannot reconstruct the exact original cover from the stego file alone. The sender's original file remains available because the app writes a separate output.

**Check yourself:** Why can a decoder recover the payload but not the old cover bits? Because the payload bits are stored; the displaced cover bits are not.

## 4. Capacity and file formats

**Capacity** is how much hidden data fits. It depends on usable samples and embedding settings, not simply the cover's file size on disk.

For a manually selected start:

```text
Raw bit capacity = (total usable samples - start index) × depth
Raw byte capacity = whole-number part of (raw bit capacity / 8)
```

An **index** is a numbered position, starting at zero. Starting later leaves fewer samples. The app never wraps from the end back to the beginning.

For the 320 × 240 RGB sample image, depth 1 and start 0:

```text
230,400 samples × 1 bit = 230,400 bits
230,400 / 8 = 28,800 raw bytes
```

That is **not** 28,800 bytes of user message. Space is also needed for:

- The four-byte outer length header, which tells the decoder how much to read.
- The verification record and package structure.
- The digital signature.
- Encryption data, if enabled.
- Extra copies, if repetition coding is enabled.

At start 37, the same image has 28,795 whole raw bytes, leaving 28,791 bytes after the four-byte outer header. The remaining package overhead reduces message capacity further. Use the app's readout for the actual message limit.

An image with many identical pixels might compress to a tiny PNG while retaining many pixel samples. This is why comparing payload bytes directly with the PNG's disk size gives the wrong capacity test.

### Why these cover formats?

**Lossless compression** preserves the exact decoded sample values. **Lossy compression** may discard detail and change them. Tiny changes to low bits can corrupt hidden data even when the media still looks or sounds similar.

| Cover | Supported approach | What to explain |
| --- | --- | --- |
| Image | PNG and supported BMP inputs | Their stored samples can be preserved. Not every image subtype is accepted; for example, palette/grayscale BMP is rejected. |
| Audio | 16-bit PCM WAV | The app changes sample bits without changing the sample rate or channel count. MP3 is not a supported audio cover. |
| Video | Supported MKV/AVI inputs; FFV1/MKV output | Codec and timing constraints apply. Arbitrary video files are not guaranteed to work. |

A **container** is the file wrapper, such as WAV or MKV. A **codec** specifies how media data is encoded, such as FFV1. An extension alone does not guarantee the contents are supported.

**Cover restrictions differ from payload restrictions.** A JPEG could be embedded as an opaque payload file inside a PNG if it fits, even though JPEG is not an accepted image cover. “Opaque” here means the embedding layer carries the bytes without interpreting their contents. The file selector also applies a 64 MiB payload input limit; that does not mean the cover can hold that much.

## 5. Hashing: a fingerprint of data

A **cryptographic hash function** converts bytes of any length into a fixed-length result called a **hash** or **digest**. Your app uses **SHA-256**, which produces 256 bits: 32 bytes, usually displayed as 64 hexadecimal characters.

**Hexadecimal**, or hex, writes numbers using `0–9` and `a–f`. Two hex characters represent one byte. The GUI's hex view is another way of displaying recovered bytes; it is not encryption.

Useful hash properties are:

- Identical input bytes always produce the same digest.
- Changing the input usually produces a very different digest.
- Finding an input for a chosen digest should be computationally impractical.
- Finding two different inputs with the same digest should be computationally impractical.

Two inputs sharing a digest is called a **collision**. Collisions must exist because the output size is fixed; security relies on their being difficult to find. Do not say every hash is mathematically unique.

Hashing is not reversible encryption. There is no hash “decryption key”. However, someone can guess an input, hash the guess and compare it with a known digest. This matters for predictable messages or weak passwords.

### Why a hash alone is insufficient

Suppose Alice sends a message and its hash. An attacker replaces the message and calculates a new hash. Bob sees a matching pair but has no proof Alice supplied it. A **digital signature** prevents someone without the signing key from producing a valid replacement for the signed data.

The app hashes the **plaintext payload**, meaning the original unencrypted message/file bytes. This digest goes inside the signed record. After successful signature verification and any decryption, Bob recomputes the digest and compares it.

Why not directly compare a hash of the original cover with a hash of the stego file? Embedding itself changes the cover, so that comparison would fail for legitimate output. Authenticating an entire modified medium would need a different, explicitly defined scheme. This app authenticates its payload and signed settings.

## 6. Signatures, keys and trust

A **key** is data used by a cryptographic operation. In **asymmetric cryptography**, two mathematically related keys form a pair:

- The **private key** stays with the signer. The app uses it to create a signature.
- The **public key** can be shared. The receiver uses it to verify that signature.

A digital signature is a cryptographic value tied to particular signed bytes. Changing those bytes or using the wrong public key makes verification fail. It does not prevent somebody editing the file; it lets the receiver detect an invalid result.

The app generates **RSA-3072** key pairs and uses **RSA-PSS with SHA-256** for signatures. RSA is the public-key algorithm; 3072 is its key length in bits; PSS is the signature scheme used with it. PSS includes randomness, so signing the same bytes twice need not produce identical signatures. Both can be valid.

For the demo, describe this as **signing with the private key and verifying with the public key**. Do not describe this implementation as encrypting a message with a private key. Signing does not make its contents unreadable.

### What gets signed?

The signature covers the verification record, the stored message and relevant envelope framing. When encryption is enabled, the stored message is ciphertext. The outer four-byte stego length header is outside this signed envelope.

### Public key trust

A valid signature against a random supplied key does not automatically prove “this came from Alice”. An attacker could send their own file and their own public key.

Bob must establish that the key really is Alice's, for example by comparing its **fingerprint** through a trusted separate channel. Here the fingerprint is a SHA-256 digest of a standard representation of the public key. The app displays it for comparison; it does not verify the owner's identity for you. There is no certificate authority, identity directory or key-revocation system in this prototype.

If Alice's private key is stolen, someone else can sign as that key. Generated demo private keys are stored unencrypted locally; this is a demonstration arrangement, not complete production key management.

**Say it aloud:** “A matching hash alone cannot authenticate the sender. We sign the record and payload, verify using the expected public key, and establish trust in that key separately.”

## 7. Encryption and shared secrets

**Encryption** transforms readable plaintext into **ciphertext** using a key. **Decryption** recovers the plaintext with the correct key. Unlike hashing, this is intentionally reversible for an authorised receiver.

**Symmetric encryption** uses the same secret key on both sides. Your app uses **AES-256-GCM**:

- AES, Advanced Encryption Standard, is the encryption algorithm.
- 256 is the secret key's bit length.
- GCM, Galois/Counter Mode, is the mode that also produces an **authentication tag**, a check used to reject invalid encrypted data or an incorrect decryption key.

AES-256 and RSA-3072 are different kinds of cryptography. Their key lengths cannot be directly compared as if the larger number alone meant greater security.

### From a passphrase to an AES key

Users enter a **passphrase**, a secret string they can remember. The app uses **scrypt**, a password-based key derivation function, to turn the passphrase into an AES key. A **key derivation function (KDF)** is a procedure for producing key material from an input such as a password.

Scrypt deliberately costs time and memory, making repeated password guesses more expensive. It also uses a random **salt**. A salt is public additional input that makes derived keys vary across encryptions even if the same passphrase is reused. It is not another password and does not rescue a weak passphrase.

AES-GCM uses a separate **nonce**, a value that must not repeat with the same encryption key. The app generates a fresh random GCM nonce. Its tag and nonce travel with the ciphertext. They do not need to be secret.

The record also has a per-file nonce used for start derivation. **The record nonce, GCM nonce and scrypt salt serve different purposes.** None is the passphrase.

### Signing plus encryption

AES-GCM checks encrypted data using a shared secret. A digital signature lets someone holding the public key check the signer. These are different roles, so the app uses both when confidentiality is requested.

The app **encrypts first, then signs** the stored ciphertext and record. The receiver verifies the signature before attempting decryption. This helps distinguish an invalid signature from a correctly signed file whose message cannot be decrypted with the supplied passphrase.

### Limits you should understand

- Hiding a message does not encrypt it. Without encryption, someone who finds the embedded package can read the message.
- The start secret and encryption passphrase are independent inputs. Knowing one does not supply the other.
- Real secrets need a secure sharing arrangement outside the app. The app does not perform a secret-key exchange for you.
- The record and manifest expose metadata. In particular, the unencrypted record includes the plaintext hash: after extracting it, someone can test guesses of a very short or predictable message. Encryption does not conceal all information about the payload.

The lecture principle behind this is **Kerckhoffs's principle**: assume an attacker knows the algorithm; cryptographic security should depend on the secret key. Publishing your source code is not supposed to break AES or RSA.

## 8. The record, envelope and manifest

These names describe three different pieces of data.

### The verification record

This is a structured description that travels inside the signed package. It includes:

| Field | Purpose |
| --- | --- |
| Media ID and type | Label the item and identify image, audio or video |
| Timestamp | Record the sender's stated protection time |
| Record nonce | Supply fresh per-file variation, including for start derivation |
| Plaintext hash and length | Check recovered message bytes |
| Depth and start method | Bind important embedding settings to the signature |
| Manual start, when used | Record the explicit index; derived starts are calculated separately |
| Encryption and repetition settings | Describe how to recover the message |
| Metadata | Additional information, such as a payload file's name and type |

**Metadata** means information about the data. A media ID is a label, not a cryptographic fingerprint of the whole cover. A timestamp is not proof of freshness or a trusted clock.

The record uses **JSON**, a text format containing named fields and values. The app serialises it consistently so signing and checking use the intended bytes.

### The envelope

The **envelope** is the package containing the record, stored message, signature and structure needed to separate them. It contains an identifying marker and version so the receiver can recognise its format.

Explicit lengths let the app carry arbitrary bytes. The lecture's simple text example uses a special end marker; that would be unsuitable for general files because the same marker could occur naturally in the data.

Outside the envelope, the stego layer puts a four-byte length header before the embedded package. Damage to this header can stop extraction before signature verification is possible. Neither its presence nor the format marker proves authenticity.

### The companion manifest

This is the separate file named like `example.png.manifest.json`. It supplies the receiver with initial parameters needed to find and read the package, including depth, start method and length. It does not contain the real start secret or encryption passphrase.

The manifest is **unsigned in this design**. Treat it as untrusted instructions for attempting extraction. Once the embedded signature verifies, the receiver checks the relevant settings against the signed record and parsed package. Editing extraction settings may instead stop extraction before those comparisons are reached.

Do not claim that every manifest field is signed. Its whole-stego-file hash, for example, is only a transport check: an attacker who changes both file and manifest can replace that hash. A separate signed manifest would be a possible alternative design, but this app does not implement it.

**Trade-off:** the manifest makes receiver setup reproducible, but the receiver needs it and it advertises that a hidden package exists. It also publishes a manual start. With a derived start, the secret remains separate. This is not a promise of covert communication to anyone who sees both files.

## 9. Finding the start location

Both parties must agree where to begin reading. A **start location** is a sample index, not necessarily a pixel number or a position in the compressed file's bytes.

| Medium | What one indexed sample means |
| --- | --- |
| Image | One colour/grayscale channel value; alpha excluded |
| Audio | One scalar 16-bit channel sample, in interleaved order |
| Video | One decoded colour channel value, in frame and pixel order |

At depth 1, three RGB channel samples carry three bits per pixel. A start index of 37 therefore does not mean “pixel 37”.

### Manual start

The user selects an index. The manifest publishes it, and the record signs it. The receiver reads the index rather than requiring a secret. This meets the selectable-location use case but does not hide the location.

### Start derived from a secret

**HMAC**, hash-based message authentication code, combines a secret key with data using a hash function. In this app HMAC-SHA256 is used as a **keyed pseudorandom function**: a reproducible calculation whose output is hard to predict without the secret.

The app combines the start secret with the media ID/type, record nonce, total sample count, depth, encoded package length and a fixed scheme label/version. It turns the HMAC output into an integer and maps it into the valid range of start positions.

```text
Same secret + same public inputs
                |
                v
       Same HMAC calculation
                |
                v
        Same valid start index
```

The range excludes positions where the complete package would run beyond the end. After selecting the start, embedding proceeds consecutively. **The app does not randomly scatter individual payload bits around the whole cover.**

The record nonce changes between protection operations, which changes the derivation input. Because the position range is finite, different operations or different secrets can still land at the same position. A wrong secret does not mathematically guarantee a different start; Attack Lab's wrong-start action deliberately finds a different derived location.

The receiver gets public inputs from the manifest and media, receives the secret separately and repeats the calculation. HMAC start derivation offers concealment of the position, not message encryption. Someone can search possible starts and depths, so sensitive contents still need encryption.

## 10. The complete sender and receiver workflow

### Sender: Protect & Sign

1. Load a supported cover and the message, either typed text or a file.
2. Choose a media ID, depth, manual/derived start, optional encryption and optional repetition coding.
3. Hash the original plaintext message. If requested, encrypt it using the passphrase-derived key.
4. Build the verification record, including the plaintext hash and the chosen settings.
5. Sign the record, stored message and relevant envelope structure using the private key.
6. If enabled, repeat the signed envelope three times.
7. Check the full size, resolve the actual start and embed the length header plus package into the cover's samples.
8. Save a new stego file and its companion manifest. Display the result and available comparisons.

For a derived start, its numerical value is computed after the package length is known. The signed record describes the derivation settings rather than storing that numerical start.

### Receiver: Verify

1. Load the stego file, its manifest and the sender's trusted public key. Supply any required start secret/passphrase.
2. Validate the manifest's structure, measure the media and resolve the start.
3. Extract the bytes. If repetition coding was used, reconstruct the envelope by majority vote.
4. Parse the package structure and verify its signature. Parsing alone does not make the contents trusted.
5. Validate the signed record and decrypt the message if necessary.
6. Hash the recovered plaintext and compare its digest and length with the signed values.
7. Check the relevant manifest parameters against the signed record and package.
8. Report the verdict. Enable trusted recovered-payload preview/save only for `AUTHENTIC`.

Bob does not need Alice's private key or the original cover to authenticate the payload. The original is optional for quality/property comparison. The app does need the matching manifest for its normal receiver workflow.

**Say it aloud:** “We verify the signature before trusting the record or decrypting. After decryption, we check the recovered message against its signed hash and cross-check the extraction parameters.”

## 11. Robustness through repetition coding

**Robustness** means surviving some damage while still recovering the intended data. Encryption and signatures do not repair damaged bytes. The optional **error-correcting code (ECC)** tries to reconstruct them before verification.

Your GUI offers **repetition factor 3**. The complete signed envelope is stored three times, with the copies one after another. The receiver votes separately at each corresponding bit position.

```text
Original bit:        1
Stored copies:      1  1  1
One damaged copy:   1  0  1  -> majority is 1: recovered correctly
Two damaged copies: 0  0  1  -> majority is 0: recovered incorrectly
```

The app repeats whole sequences, rather than putting all three instances of each bit side by side. Separating corresponding bits can help when a short damaged region affects one copy. Long or widespread damage can still affect multiple copies.

### Why this design?

It is easy to explain, works across media and protects the record and signature as well as the message. Reconstructing the envelope before checking its signature means a damaged signature can sometimes be repaired too. The signature then checks whether the reconstructed package is authentic.

The price is capacity: the envelope uses three times its uncoded space, plus the outer length header. Available message capacity falls to approximately a third, with additional metadata overhead. The outer length header is not protected by this repetition coding.

The correction report counts bit positions where the copies disagreed. Do not treat that count alone as proof of successful repair: a majority can be wrong. Read it alongside the final verification verdict.

**Limits:** repetition does not make LSB data reliably survive JPEG/MP3 conversion, audio resampling or widespread changes. It also does not stop a deliberate attacker changing all copies consistently. The app demonstrates a specific controlled recovery, not universal damage resistance.

**Say it aloud:** “We trade space for redundancy. Majority voting can recover a bit when one of its three copies is wrong. Two wrong copies can defeat it, and the final signature check tells us whether the reconstructed data passes verification.”

## 12. Video, quality and file sizes

### Video uses the same embedding idea

A video is a sequence of pictures called frames. The app treats their decoded colour-channel values as one long sample sequence. A start index therefore identifies both a frame and a position within it; the package can occupy one or several frames.

Protection writes **FFV1**, a lossless video codec, inside an **MKV/Matroska** container. This preserves the embedded sample values. The OpenCV media library supplies this processing, so the normal application does not require a separate FFmpeg installation.

The implementation streams frames rather than loading the whole decoded clip into memory. It checks frame/timing properties and reads back the protected video to check payload extraction before successful publication.

**Source audio is omitted.** The chosen pipeline processes video frames and does not copy the audio track. The sample video is already silent, so playing that sample cannot demonstrate the removal of a soundtrack. State the limitation explicitly.

The Video tab shows clip properties, playback and a **claimed payload frame range** from the supplied parameters. That display is not an independent authentication check. Use Verify to authenticate the embedded package.

Lossy re-encoding, frame removal and incompatible timing can prevent recovery. The app rejects unsupported timing/dimensions rather than promising support for every clip. Keep the known short sample for the live demonstration.

### Quality is different from authenticity

Quality comparisons measure differences between a chosen original and a protected file. A valid signature does not mean no visible changes; tiny visual differences do not mean a signature is valid.

| Displayed measurement | How to read it |
| --- | --- |
| MSE: mean squared error | Square the sample differences, then average them. Zero means no difference in the samples measured. Lower usually means less distortion. |
| RMSE: root mean squared error | The square root of MSE, expressed in the sample-value scale. |
| MAE: mean absolute error | Average the sizes of the sample differences, ignoring their signs. |
| PSNR: peak signal-to-noise ratio | Relates the maximum signal scale to the error. Higher usually means less distortion; identical measured samples give infinity. |
| SNR: signal-to-noise ratio | Relates the original audio's signal energy to the change introduced. Higher usually means less relative noise. |
| Changed samples and maximum difference | Show how many measured values changed and the largest observed change. |

For example, sample errors of 0 and 2 have MSE `(0² + 2²) / 2 = 2`. PSNR/SNR use **decibels (dB)**, a logarithmic ratio scale; you do not need to derive their formulas for the demo.

Only applicable measurements appear for each medium. Metrics have different scales and assumptions, so do not compare an audio PSNR directly with an image PSNR as a universal quality ranking. Overall image MSE/PSNR exclude alpha, which is not used for embedding.

These measurements require a reference original. They do not detect unknown hidden messages, prove a file is safe or guarantee that no person can see/hear a difference. They are retained quality comparisons, not the removed steganalysis feature.

### Why the file size can change

An unchanged image width/height or audio duration does not mean an unchanged file size. PNG compresses its pixels; changing low bits can make them less compressible. WAV/BMP headers or metadata can also change when files are saved. Video is re-encoded, so output size reflects codec/container changes as well as embedding.

**Match the cover's file size where possible** is an optional PNG experiment. The app tries compression levels and, when a suitable result is smaller, can add a valid padding chunk to reach the desired size. If every candidate is already larger, it reports that matching was not achieved. It does not truncate the payload to force a match.

The manifest occupies additional storage and is reported separately. Same-sized media does not mean the total transfer size stayed the same. Padding can also look unusual, so size matching is not proof of better concealment.

## 13. Reading results and using Attack Lab

The verdict summarises what the checks established. A failure is useful evidence if it occurs for the expected reason.

| Verdict | Meaning | Important distinction |
| --- | --- | --- |
| `AUTHENTIC` | Signature, recovered-message checks and relevant parameter checks passed | Does not authenticate every cover byte, establish the owner's identity automatically or reject replay |
| `SIGNATURE_INVALID` | A readable package's signature did not verify with the supplied public key | Could be modified signed bytes or the wrong key; the result alone does not identify which |
| `PAYLOAD_MISSING` | A usable package was not recovered at the supplied location/settings | Could be wrong settings/secret, damaged framing or no embedded payload |
| `WRONG_START_LOCATION` | The declared location is unusable for this medium/package | Used for a provable location/range problem; it is not a general label for a wrong secret |
| `CANNOT_VERIFY` | Verification could not be completed | Read the reason: examples include missing inputs or a decryption failure |
| `TAMPERED` | A later consistency check failed after signature verification | For example, relevant manifest settings disagree with the signed record. Ordinary unsigned message corruption normally fails the signature first. |

The **Checks** panel reports payload found, signature valid, message hash matches, start location usable and manifest agreement. **Not established** means the app never reached that check; it does not mean the check ran and failed.

### Five focused Attack Lab actions

Load an authentic stego file and its correct verification inputs before attacking it. Read both expected and observed verdicts.

| Action | What it changes | Expected result for the prepared uncoded cases |
| --- | --- | --- |
| Corrupt the message | Changes embedded signed message bytes | `SIGNATURE_INVALID` |
| Corrupt the signature | Changes signature bytes | `SIGNATURE_INVALID` |
| Verify with the wrong public key | Re-verifies the same file using a different key | `SIGNATURE_INVALID` |
| Verify with the wrong start secret | Uses a genuinely different derived location | Verification rejected; exact failure category can vary |
| Modify pixels/samples outside the payload | Changes media beyond the embedded package | Can remain `AUTHENTIC` |

Wrong-key and wrong-start actions change receiver inputs and create no tampered media file. Wrong-start requires a derived-start case. The physical-edit actions use modified copies. Use **Save as evidence...** to save the actual attack log.

The outside-payload case is deliberate: it demonstrates the boundary of the signature. It is not a failure to authenticate the data the app actually signs.

### GUI features you should explain

- **Select File and drag-and-drop:** two routes to the same input validation. Unsupported inputs are rejected rather than silently treated as valid covers.
- **Original and stego previews:** show or play the media before/after embedding. The original is optional on the receiver side for comparison.
- **Typed text and A file:** select the message source. File bytes are preserved; supported recovered images/audio can be previewed internally.
- **Show as text / Show as hex:** two inert representations of recovered bytes. Hex is useful when bytes are not readable text.
- **Save recovered payload...:** enabled only for successful authenticated recovery. A signature is not a malware scan; the app does not execute recovered files.
- **Background processing:** lengthy operations run away from the interface's drawing work so the window remains responsive. Stale results are discarded when relevant inputs change.
- **Safe output handling:** the sender rejects source/output path conflicts and stages its output files. Caught failures can roll back replacements; this is not a guarantee against every power loss or concurrent write.

## 14. Design decisions and honest limitations

These are useful short answers when the professor asks why the app was built this way.

| Decision | Reason | Cost or boundary |
| --- | --- | --- |
| LSB replacement | Meets the assignment and has a clear capacity/distortion trade-off | Fragile under media transformations; overwrites original low bits |
| One package format for all media | Reuses signing, encryption and verification rules | Each medium still needs its own sample reading/writing |
| SHA-256 | Supplies a fixed-length digest without relying on the broken collision resistance of MD5/SHA-1 | Hashing alone is not authentication or secrecy |
| RSA-PSS signatures | Uses an established library-supported signing scheme and public-key verification | Private-key protection and public-key trust remain necessary |
| AES-GCM plus scrypt | Adds message encryption, an authentication tag and a password-to-key step | Requires a separate passphrase; weak passwords remain guessable |
| Encrypt, then sign | Lets signature verification precede decryption and separate some failure stages | More structure and processing; metadata remains visible |
| Companion manifest | Makes extraction parameters available before reading the hidden record | A required extra file; exposes package existence and public settings |
| HMAC-derived start | Makes the start reproducible without publishing the secret or explicit position | Finite position search space; not encryption |
| Whole-envelope repetition | Can repair damage to the record/message/signature before verification | About triple envelope storage; outer length header remains vulnerable |
| FFV1 video | Preserves exact decoded samples in the output | Codec constraints, re-encoding cost and omitted audio |
| Separate GUI and processing layers | Allows the same backend checks to support GUI and automated tests | More internal structure, but no need to explain every class during the demo |

### Statements to avoid

| Do not say | Say instead |
| --- | --- |
| “Authentic means the whole image is untouched.” | “The embedded payload and signed settings passed verification.” |
| “The hash proves Alice sent it.” | “The signature verifies against Alice's independently trusted key.” |
| “The start secret encrypts the message.” | “It derives the location; encryption uses a separate passphrase.” |
| “Encryption hides everything.” | “It encrypts the message; metadata and the plaintext digest remain exposed.” |
| “The timestamp stops replay.” | “It records time, but we do not enforce freshness or track reused records.” |
| “Three copies survive any corruption.” | “Majority voting only helps when enough corresponding copies remain correct.” |
| “Same file size means no detectable change.” | “It only establishes the measured byte length.” |
| “Every failed extraction proves tampering.” | “Wrong inputs, missing data and damage can have the same symptoms.” |
| “We invented AES/RSA/HMAC.” | “We integrated established algorithms into the application.” |
| “The programme can restore the original cover.” | “It recovers the message; the old overwritten cover bits are not recoverable from stego alone.” |

**Replay** means resending a previously valid item. **Key substitution** means convincing the receiver to use an attacker's key. **Brute force** means trying many candidate keys, passwords or positions. Be able to identify which of these your design addresses and which still needs an external defence.

Using a library avoids writing your own cryptographic primitive, but does not automatically make the surrounding workflow secure. The application's contribution is its integration, checks, interface and demonstrations. Describe your own contribution and any AI assistance truthfully; presenting a component does not establish that you wrote it.

## 15. Practise with the actual app

This section connects the theory to visible actions. It is a practice route, not a replacement for the team's timed presentation plan.

### Start the app

On the current Windows checkout, open PowerShell in the repository root and run:

```powershell
.\.venv-t08\Scripts\python.exe main.py
```

That interpreter was checked as Python 3.11.16 for this guide. On another machine, install Python 3.11 and the dependencies following the [README](../README.md), then use that machine's environment path. No Python environment is transferred with the project archive.

For the steps below, **A** means `samples/hash-manifest-v2/party-a` and **B** means `samples/hash-manifest-v2/party-b`, both relative to the repository root. These are folder abbreviations, not commands.

### First, verify something already prepared

1. In **Verify**, select `B/protected/image-short.png`.
2. Confirm **Manifest** is `B/protected/image-short.png.manifest.json`.
3. Set **Public key** to `B/sender-public.pem`. This is the fixture key, not your locally generated demo key.
4. Leave the start secret and passphrase blank: this image case uses a manual start.
5. Optionally select `B/original/image.png` as **Original cover**.
6. Click **Verify**. Expected: `AUTHENTIC`, recovered Learning Outcome text and successful checks.
7. Use text/hex views and **Save recovered payload...** to understand what each does.

Explain aloud why the private key and original cover are unnecessary for this verification.

### Next, create your own protected image

1. Use **Keys → Generate demo key pair**. Note the displayed private/public paths and fingerprint.
2. In **Protect**, load `A/original/image.png` by drag-and-drop.
3. Enter a short message, such as `Practice message`, and choose a media ID.
4. Choose depth 2, **Chosen manually**, and start location 37. Leave encryption/repetition off for this first attempt.
5. Confirm the selected signing key is the generated private key. Choose a fresh PNG output path and click **Protect & Sign**.
6. In **Verify**, select your new output and its new manifest. Explicitly select the matching generated public key; an existing fixture key may remain in the field.
7. Verify and compare the recovered text. Expected: `AUTHENTIC` with your exact message.

Move the depth slider and watch capacity change. Temporarily set a late manual start or enter an oversized message: expected protection refusal, not a silently shortened message. Restore valid settings. Try **Match the cover's file size where possible** and explain the actual result.

If the professor supplies a different payload, repeat protection with that payload. You can reuse the original cover if it has capacity. Every newly protected file needs its matching newly produced manifest. Existing signed fixtures do not automatically become fixtures for a new message.

### Exercise the other features

| Exercise | Inputs/actions | What to check and explain |
| --- | --- | --- |
| Audio | Protect `A/original/audio-mono.wav` with `A/messages/long.txt`, depth 2 and a chosen HMAC start secret | Verify with matching key/secret; play cover and stego, and demonstrate pause, seek and stop. Explain samples, sample rate and distortion. |
| BMP | Protect `A/original/image.bmp` with a short message | Same signed-message workflow with another supported image format. |
| Encryption | Protect a short custom message with **Encrypt the message (AES-256-GCM)** enabled | Correct passphrase succeeds. Try a wrong passphrase with other inputs correct: expect `CANNOT_VERIFY` and no trusted payload save. |
| File payload | Choose `A/messages/payload.png`, then try `A/messages/payload.wav`; use a cover/depth with sufficient capacity | Verify, preview/play and save the recovered file. Explain byte recovery and signed file metadata. |
| Repetition | Enable **Apply repetition coding (factor 3)** and observe capacity | Explain the cost, then use the prepared damage cases below to show recovery and failure. |
| Video | Protect `A/original/video.mkv` with a short message and supported settings | Verify the output, then open it in **Video**, play it and **Locate the payload frames** with its manifest and any required secret. State that audio is omitted. |
| Attack evidence | Load a prepared authentic image/audio in Attack Lab with the fixture key and correct inputs | Run the focused actions individually, explain before/after results and use **Save as evidence...**. |

### Public demonstration inputs for prepared fixtures

These values are published in the supplied bundle and protect no real secret:

| Input | Public demo value |
| --- | --- |
| Normal fixture public key | `B/sender-public.pem` |
| Deliberately wrong public key | `B/unrelated-public.pem` |
| HMAC fixture start secret | `t07-public-demo-start` |
| Encrypted fixture passphrase | `t07-public-demo-passphrase` |
| Deliberately wrong start secret | `t07-public-wrong-start-0` |
| Deliberately wrong passphrase | `t07-deliberately-wrong-passphrase` |

Use your generated matching key and your selected secrets for fresh outputs instead. Manual fixture cases require no start secret. Only encrypted cases need a passphrase.

**Reset inputs when switching demonstrations.** The fresh image/audio outputs from Chanel's key pair need that pair's public key. The prepared Party B fixtures need `B/sender-public.pem`. Do not assume the GUI replaces an already populated key field. Select each media file's matching manifest, then set or clear its start secret and passphrase as appropriate. The three prepared repetition-damage cases use manual starts and need no start secret.

**Two ways to show wrong inputs:** in **Verify**, deliberately select `B/unrelated-public.pem` or enter the wrong start secret. In **Attack Lab**, keep the correct public key, manifest and start secret, then select the wrong-key or wrong-start action. Attack Lab first requires an `AUTHENTIC` baseline and supplies the changed verification input itself. Putting the wrong input into its baseline fields defeats that sequence.

### Prepared success and failure cases

Paths in this table are relative to **B**. For each damaged file, explicitly select the listed original manifest. All use `sender-public.pem` unless stated otherwise.

| Media file | Manifest to select | Additional input | Expected result |
| --- | --- | --- | --- |
| `protected/audio-long.wav` | `protected/audio-long.wav.manifest.json` | Normal start secret | `AUTHENTIC`; recovered Project Overview text |
| `protected/image-confidential.png` | `protected/image-confidential.png.manifest.json` | Normal start secret and passphrase | `AUTHENTIC`; encrypted custom message recovered |
| `protected/image-file.png` | `protected/image-file.png.manifest.json` | Normal start secret | `AUTHENTIC`; image payload preview/save |
| `protected/audio-file.wav` | `protected/audio-file.wav.manifest.json` | Normal start secret | `AUTHENTIC`; audio payload playback/save |
| `tampered/image-payload-corruption.png` | `protected/image-short.png.manifest.json` | None | `SIGNATURE_INVALID`; mandatory image negative |
| `tampered/audio-signature-corruption.wav` | `protected/audio-long.wav.manifest.json` | Normal start secret | `SIGNATURE_INVALID`; mandatory audio negative |
| `tampered/audio-repetition1-damage1.wav` | `protected/audio-uncoded.wav.manifest.json` | None | `SIGNATURE_INVALID`; no redundancy to repair damage |
| `tampered/audio-repetition3-damage1.wav` | `protected/audio-robust.wav.manifest.json` | None | `AUTHENTIC` with a correction report |
| `tampered/audio-repetition3-damage2.wav` | `protected/audio-robust.wav.manifest.json` | None | `SIGNATURE_INVALID`; third mandatory-media negative |
| `tampered/image-outside-payload.png` | `protected/image-short.png.manifest.json` | None | `AUTHENTIC` despite changed cover samples |
| `protected/audio-long.wav` | `protected/audio-long.wav.manifest.json` | Normal start secret, wrong public key | `SIGNATURE_INVALID` |
| `protected/audio-long.wav` | `protected/audio-long.wav.manifest.json` | Correct key, deliberately wrong start secret | Rejected: `PAYLOAD_MISSING`, `CANNOT_VERIFY` or `SIGNATURE_INVALID` |
| `protected/image-confidential.png` | `protected/image-confidential.png.manifest.json` | Normal start secret, wrong passphrase | `CANNOT_VERIFY` |
| `protected/video-positive.mkv` | `protected/video-positive.mkv.manifest.json` | Normal start secret | `AUTHENTIC`; ready-made video fallback |

The sample recovery experiment changes a corresponding signature bit in one stored copy, then in two copies. It leaves the framing intact. This is a controlled logical-bit comparison, not a claim that any random corruption at the same percentage will behave identically.

### Receiver transfer and troubleshooting

Transfer the **stego file, matching manifest and public key**. The private key stays with the sender. Real secrets need a separate secure channel. Send files without resizing, recompressing or converting them; media-sharing services can transform attachments. The receiver downloads them into their own folder and selects the correct paths.

If verification unexpectedly fails, check the file/manifest pairing, public key, start secret and passphrase before assuming a software bug. A locally copied folder is useful practice but is not evidence that another person performed the required receiver demonstration.

The current bundle contains 20 indexed verification cases and two capacity checks. Capacity rejection demonstrates input validation; do not count it as a successful execution of one of the three required receiver negative cases. Section 17 maps your adopted presentation script to the missing live actions; this guide supplies the concepts needed to understand them.

## 16. Lecture foundations and additional features

“Beyond the lectures” describes teaching coverage, not necessarily extra credit. Some requirements go beyond the lecture example but are compulsory in the assignment.

| Category | Topics/features | How to describe them |
| --- | --- | --- |
| Lecture foundations | Bits and image channels; steganography versus cryptography; LSB replacement/matching; lossless constraints; symmetric/public-key crypto; AES/RSA; hashes and signatures; salts and passphrases | Established concepts the app applies |
| Mandatory project development beyond the simple example | Audio LSB, GUI depth selection 1–8, variable starts, signed verification records, receiver workflow, comparisons, positive/negative cases | Assignment requirements; do not present all of them as optional innovations |
| Four retained optional challenges | HMAC-derived starts, Attack Lab, repetition coding, video | Explain each implemented benefit and its limitation |
| Specific cryptographic implementation choices | RSA-PSS, AES-GCM, scrypt and encrypt-then-sign | Details beyond the introductory decks; established schemes selected by the team |
| Additional application work | Binary envelope/manifest, arbitrary file payloads, safe recovered-file handling, key fingerprints, drag-and-drop, numerical quality metrics, PNG size matching, evidence export | Practical improvements and integration, with scope depending on the brief |
| Taught but absent from the app | LSB matching, BPCS and steganalysis | Know the distinction; do not claim a live demonstration of them |

The assignment requires a custom confidentiality/integrity demonstration. Encryption is optional as an individual app setting, but you should still show it in the planned custom-message demo.

## 17. What each presenter should prepare

Everyone should know the cover/payload distinction, sender/receiver flow, key roles, meaning of `AUTHENTIC` and major limitations. The allocation below follows the teammate PDF you said the team will use. It supersedes the older numbered-member allocation in `demo_plan.md` for your preparation. Presentation roles are not evidence of who wrote the code.

| Presenter | Main preparation | Questions to be ready for |
| --- | --- | --- |
| Chanel: cryptography and payload security | Sections 5–10 and 14 | Why hash and sign? What exactly is signed? Which key is shared? How do encryption and start hiding differ? |
| Tristan: image, capacity and quality | Sections 2–4, 8–10 and 12 | How does replacement work? How is capacity calculated? Why can PNG size change? What do quality metrics establish? |
| Unaisah: audio, derived starts and robustness | Sections 2–4 and 9–13 | What is an audio sample? How is the start reproduced? What can majority voting repair? Why does the two-copy damage fail? |
| Angelline: GUI, receiver workflow and file recovery | Sections 6–8, 10 and 13–15 | Why are preview/save gated? What happens with the wrong passphrase? Which files and secrets must the receiver have? |
| Gin: verification, attacks and video | Sections 6, 8–10 and 12–15; section 11 for the recovery boundary | What does each verdict establish? Why can a changed cover pass? Why does Attack Lab need an authentic baseline? Why FFV1 and no audio? |

### Adopted speaking schedule

| Time | Presenter | Segment in the teammate PDF |
| --- | --- | --- |
| 0:00–1:15 | Angelline | Overview and GUI integration |
| 1:15–4:00 | Chanel | Cryptography, keys and payload |
| 4:00–8:00 | Tristan | Image, capacity, depth and comparisons |
| 8:00–12:00 | Unaisah | Audio, derived start, playback and robustness |
| 12:00–15:00 | Angelline | Receiver verification, encryption and file recovery |
| 15:00–19:30 | Gin | Verification and attack cases |
| 19:30–21:00 | Gin | Video |
| 21:00–22:00 | All five | Wrap-up |
| 22:00–25:00 | All | Buffer and questions |

This is a sensible split by technical topic. The underlying explanations in this guide still apply. However, the PDF needs the following practical additions before it is a complete demonstration plan. These are review corrections, not actions already present in the PDF or claims of a successful rehearsal.

### Corrections to make when following the PDF

| PDF location | Gap or ambiguity | Concrete action to add or clarify |
| --- | --- | --- |
| Pages 3–6: sender/receiver handover | Selecting pre-existing Party B samples does not demonstrate the required A-to-B transfer | Tristan and Unaisah produce the fresh image/audio outputs. Transfer those outputs, their matching manifests and the corresponding public key to the receiver's own folder. Angelline verifies the downloaded copies and shows the recovered short Learning Outcome and long Project Overview. Share required secrets separately. A pre-staged fixture is a fallback, not evidence of this handover. |
| Page 3: keys and signing | “Fresh” keys may be reused; signing is described too narrowly | The menu creates demo keys if missing and otherwise reuses them. Show the actual status and fingerprint. Say the signature covers the verification record **and stored message with framing**; for encryption, the stored message is ciphertext. |
| Pages 3 and 5–6: confidentiality | Wrong/correct passphrase verification is explicit, but enabling encryption during protection is not | Show **Encrypt the message (AES-256-GCM)** and the custom message during protection, then demonstrate wrong and correct passphrases with that output or the clearly identified prepared encrypted fixture. |
| Pages 5–6: recovered file features | Showing a disabled/enabled control or describing preview/save is not the same as exercising it | Use `B/protected/image-file.png` and `B/protected/audio-file.wav` with their own manifests, fixture public key and normal start secret. Verify, display/play the recovered payloads and actually save them. Show file-payload selection during a suitable Protect segment. |
| Pages 5–7: sample switching | Fresh outputs and prepared fixtures use different key contexts | Use the input-reset rule in section 15. For all three repetition fixtures, explicitly select the original uncoded/robust manifest from the case table and the fixture public key. |
| Pages 6–7: wrong key and wrong start | The text can be read as entering bad inputs into Attack Lab before the baseline | Choose one method: change inputs directly in **Verify**, or keep correct inputs in **Attack Lab** and select its wrong-input action. Explain baseline and after-attack results. |
| Page 7: outside-payload editing | A prepared edited file and a newly run attack are different demonstrations | In Verify, load `B/tampered/image-outside-payload.png` with the original `image-short.png.manifest.json`. In Attack Lab, start with authentic `B/protected/image-short.png` and run the outside-payload action. Both illustrate the same security boundary. |
| Pages 6–7: evidence | Evidence export is retained but lacks an explicit action | After a completed attack, use **Save as evidence...** once and show where the report was saved. |
| Pages 7–8: video | Playback and frame lookup do not demonstrate the claimed protection and verification | Protect the short original video, verify the produced MKV with its matching manifest/key/secret, then play it and locate the payload frames. Clearly label a prepared `video-positive.mkv` as fallback if used. State that source audio is omitted. |
| Page 8: optional features as backup | Dropping video or another retained feature conflicts with the agreed all-features presentation scope | Keep all four retained challenges in the main plan. Shorten repeated narration and pre-stage inputs; keep backup media for technical failures. Rehearse the added actions rather than assuming they fit the existing timings. |

Also make the BMP workflow, drag-and-drop, normal picker, quality/size report and audio playback controls explicit in the team's action checklist. Section 15 gives the operations. Merely listing supported formats or buttons does not show that they work. Integrate these into existing segments; avoid a second explanation of the same underlying mechanism.

The tight sections are Unaisah's four minutes, Angelline's three-minute receiver segment and Gin's ninety-second video slot. Their actual feasibility needs a timed rehearsal with the transfer and added actions included. The three-minute buffer is not evidence that the missing steps fit. The source PDF has not been edited by this review.

### Gin's practical sequence and answers

Use [Gin's detailed demo script](gin_demo_script.md) for the complete click-by-click sequence, speaking lines, teammate handover, prepared fallback and professor-supplied payload instructions. It proposes reallocating time within Gin's existing six-minute slot; rehearsal is still required.

1. Start image message corruption from authentic `B/protected/image-short.png`, its manifest and `B/sender-public.pem`. Explain `AUTHENTIC` before and expected `SIGNATURE_INVALID` after.
2. Switch to authentic `B/protected/audio-long.wav`, its manifest and the normal start secret for signature corruption. Explain that signature failure occurs before a trusted message is released.
3. Show wrong key and wrong start using one of the two methods above. A wrong key does not prove the media changed. A wrong start may produce several rejection verdicts; do not promise one exact label.
4. Show the outside-payload case. Say: “We authenticate the embedded payload and signed settings; this result does not mean every cover sample is unchanged.”
5. Save one attack report. Keep Unaisah's unrecoverable audio damage as the third required image/audio negative; capacity refusal is a separate validation check.
6. Demonstrate video protection, verification, playback and payload-frame lookup. Say: “Lossless FFV1 preserves the sample values needed for extraction. This output omits source audio. Frame lookup reports a location; verification supplies the authenticity result.”

For Gin's questions, practise section 18 questions 4 and 7–16 in particular. Do not skip the opening foundations: the attack explanations depend on understanding signatures, extraction and the difference between the payload and its cover.

For your own contribution, prepare an accurate sentence about what you implemented, integrated, tested or documented, plus one design choice you can explain. Do not claim ownership merely because you are presenting that part.

## 18. Practice questions and model answers

Cover the answers and try speaking first. Understanding the explanation matters more than repeating the exact wording.

### 1. Explain the application in thirty seconds

“Our app hides a signed message or file inside an image, PCM WAV or supported video. We use LSB replacement, with selectable depth and either a manual or secret-derived start. The receiver extracts the package, verifies its digital signature and checks the recovered message hash. We can add encryption for message confidentiality and repetition coding for limited damage recovery. Authenticity applies to the embedded payload and signed settings, not every cover byte.”

### 2. What happens if the professor changes the payload?

If they supply a new message before protection, the app builds a fresh hash, record, signature, output and manifest. The original cover can be reused if the new package fits. If someone changes already embedded signed bytes without a valid new signature, verification should reject the result. Repetition may repair limited accidental damage before the signature is checked.

### 3. Why not use a hash without a signature?

Anyone can calculate a new hash for a replacement message. A signature prevents an attacker without the private key from making that replacement verify against the trusted public key.

### 4. Is the private key needed to read or decrypt?

The receiver needs the public key to verify. For this app, message encryption uses a passphrase-derived AES key, so an encrypted message also needs the passphrase. RSA is being used for signing, not to decrypt the message. A derived start additionally needs the start secret.

### 5. How much raw space does a 100 × 100 RGB image provide at depth 2?

`100 × 100 × 3 × 2 = 60,000` bits, or `7,500` raw bytes from start zero. Subtract the outer header and package overhead before deciding the maximum user message. Encryption and repetition can reduce it further.

### 6. Can a 10 KB payload fit inside a 5 KB PNG?

Possibly. PNG disk size reflects compression. Capacity depends on the decoded usable samples, depth, start and overhead. You must calculate capacity rather than compare the two disk sizes.

### 7. Why does the receiver get the same derived start?

HMAC is deterministic for the same secret and input bytes. The manifest/media supply the public inputs, and both parties use the same separately shared secret and valid-range calculation.

### 8. If a wrong start secret happens to work, is HMAC broken?

No. The full HMAC result is mapped into a smaller finite range of start positions, so different secrets can map to the same index. This is another reason location hiding must not be treated as encryption. Attack Lab searches for a secret that produces a different index for its test.

### 9. What if the manifest is altered or lost?

Altered extraction parameters can stop recovery, or inconsistent parameters can be detected against the signed record after recovery. An unsigned informational hash can be replaced by an attacker and is not decisive. If the manifest is missing, the normal app workflow cannot perform verification; it does not automatically search for all parameters.

### 10. Why does one tampering case still say AUTHENTIC?

The edit is outside the signed embedded package. The app checks the message and signed settings rather than signing every cover sample. This test demonstrates that limit explicitly.

### 11. Why does message corruption say SIGNATURE_INVALID rather than TAMPERED?

The signature covers the stored message. Its verification fails before the later hash/consistency checks. `TAMPERED` is a particular later-stage verdict, not a catch-all label for every modification.

### 12. Why can signature verification pass while decryption fails?

The sender signed the ciphertext and record. Those bytes can be authentic even if the receiver supplied the wrong passphrase. The app cannot complete recovery and reports `CANNOT_VERIFY` rather than releasing trusted plaintext.

### 13. Why use both a GCM tag and an RSA signature?

The GCM tag authenticates encrypted data under the symmetric key. The RSA signature supports verification using a public key tied to the signer. Any holder of the shared symmetric key could generate a valid GCM result; that is different from holding the signing private key.

### 14. Can the app distinguish an attacker from a damaged download?

Not generally. Both can change bytes. A wrong key can also cause an invalid signature. We report the checks and supported explanations rather than claim we know the intention or exact cause.

### 15. Is three-copy recovery guaranteed if one third of the data is damaged?

No. The location of the damage matters. For each logical bit, at least two corresponding copies must retain the correct value. A much smaller amount of carefully placed damage can corrupt the same bit in two copies. Framing damage may prevent decoding altogether.

### 16. Is this production-ready security?

It is a demonstrable prototype with explicit limits: demo private keys are unencrypted, key ownership and secret sharing are external, there is no replay prevention, the manifest exposes metadata, and LSB data is fragile. A production design would need stronger key management, a defined threat model and appropriate operational controls. A **threat model** states whom you are defending against, what they can do and what you aim to protect.

### 17. What is your innovation if you used existing libraries?

The team did not invent the cryptographic algorithms. Explain a concrete integration: for example, using the same HMAC-derived valid start calculation across media, protecting the signed envelope with repetition and demonstrating correction/failure, or extending the shared workflow to video. Show the working feature, its benefit and its remaining limits.

### 18. What would you say if asked a code question?

Explain the relevant data flow and responsibility first: the GUI collects inputs, media handling reads/writes samples, cryptographic functions sign/encrypt, and verification decides the result. You need not recite code from memory. If asked for a detail you cannot recall, say so and refer to the implementation rather than inventing it. The brief assesses credible technical understanding and does not promise that code-related questions are excluded.

## 19. Final revision sheet

Read this after the full explanations, not as a substitute for learning them.

### Twelve facts to remember

1. **Cover + embedded package = stego object.** The package includes more than the user's message.
2. **Depth is low bits per sample.** More depth gives more capacity and potentially more distortion.
3. **Capacity comes from sample count, start and depth.** Deduct framing, record, signature, encryption and repetition overhead.
4. **Hashing is a fixed-length fingerprint.** It does not encrypt or independently authenticate the sender.
5. **Private key signs; public key verifies.** Key ownership still needs independent trust.
6. **AES-GCM encrypts the message.** Scrypt derives its key from the passphrase and salt.
7. **HMAC derives a location.** The start secret is separate from the encryption passphrase.
8. **The manifest is required and initially untrusted.** Relevant settings are cross-checked; its file hash is informational.
9. **Verify the signature before decryption.** Then check the plaintext hash and parameter consistency.
10. **Repetition-3 means majority voting.** It costs space and only repairs some patterns of damage.
11. **Video output is FFV1/MKV with no source audio.** Frame-span display alone does not authenticate anything.
12. **AUTHENTIC has a limited meaning.** It does not prove an unchanged cover, a fresh message, safe content or a trusted key owner.

### Practical readiness check

- [ ] I can identify cover, message, stego output, manifest and the required keys/secrets.
- [ ] I can protect a new professor-supplied message without reusing an old output manifest.
- [ ] I can demonstrate capacity rejection and explain the depth trade-off.
- [ ] I can get successful image/audio verification and explain each result flag.
- [ ] I can show the three required image/audio negatives and the controlled repetition recovery.
- [ ] I can explain wrong key, wrong start, wrong passphrase and outside-payload outcomes.
- [ ] I can preview/play/save recovered file payloads and explain why success is required first.
- [ ] I can explain every retained extra that appears in my segment.
- [ ] I can describe my actual contribution and how I checked it, including relevant AI assistance.
- [ ] I have practised my section aloud on the presentation machine and checked its actual duration.

These boxes are intentionally unchecked. Tick them only after doing the work.

## 20. Sources and further reading

You do not need these sources open while studying. They identify where the requirements and behaviour were checked.

### Project references

- Adopted team script: `Project/INF2005_ACW1_Demo_Script_and_Presentation_Split_.pdf` in the course directory; all eight pages reviewed. Section 17 records its named roles/timings and the corrections needed to follow it. The PDF itself is unchanged.
- [Earlier repository demo script](demo_plan.md): useful feature/action coverage, but its numbered-member allocation differs from the team's adopted PDF. Use section 17 for your current speaking preparation.
- [Sample bundle guide](sample_bundle.md) and [case index](../samples/hash-manifest-v2/CASE_INDEX.md): files, inputs and expected results.
- [Implementation plan](IMPLEMENTATION_PLAN.md): authorised scope and historical/current evidence.
- [Architecture](architecture.md) and [limitations](limitations.md): broader design background. Some historical sections describe backend experiments or earlier states rather than the current GUI.
- [Evidence index](evidence_index.md): recorded validation and its limits. This guide does not claim a fresh full test run or a completed team rehearsal.

Implementation cross-checks used the current [verifier](../app/verification/verifier.py), [payload construction](../app/crypto/payload.py), [signature scheme](../app/crypto/signatures.py), [encryption](../app/crypto/encryption.py), [start derivation](../app/crypto/start_location.py), [manifest checks](../app/crypto/manifest.py), [repetition coding](../app/robustness/redundancy.py), [GUI](../app/gui/main_window.py) and [media constants](../app/utils/constants.py). These links are for checking details, not required code reading.

### Course material checked

PDF page numbers refer to positions in each file. The course directory is `Cyber Security Fundamentals` in the user's SIT materials; the filenames below are provided for optional lookup, without making the guide depend on that directory existing elsewhere.

| Source | Relevant pages | Used for |
| --- | --- | --- |
| `Lecture/Steganography.pdf` | 7, 10–12, 17–25, 31–34, 45–56 | Terminology, replacement/matching, simple encoder/decoder, bit planes and the distinction from steganalysis |
| `Lecture/CyberSec_Crypto1_KeyConcepts.pdf` | 5–13, 25–26, 29, 32–33 | Encryption, symmetric keys, AES, key secrecy and randomness |
| `Lecture/CyberSec_Crypto2_PK_Attacks.pdf` | 2–9, 17–22, 26–27 | Public/private keys, RSA, hashes, signatures and brute force |
| `Lecture/CSF Intro.pdf` | 11–12 | CIA triad and threat vocabulary |
| `Lecture/Access Control.pdf` | 19–21 | Passphrases and salts |
| `Project/INF2005-ACW1-spec_v5-f2f.pdf` | 1–4 | Mandatory features, optional challenges, demo scope and individual technical explanation |

This guide explains the actual RSA-PSS signing workflow rather than treating the introductory “private-key encryption” analogy as a literal implementation. Its explanations are paraphrased and adapted to the current app.
