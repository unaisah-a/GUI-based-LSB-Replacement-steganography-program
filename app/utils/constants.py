"""Cross-layer constants.

This module is the lowest layer of the application. It imports nothing from
``app`` and holds only literal values, so any module may import it without
creating a cycle.

Where a value also exists in a lower-level library module — the LSB depth bounds
live in :mod:`app.stego.bit_utils`, for instance — the value is *restated* here
rather than imported, to keep this module dependency-free. That duplication is
deliberate but not unchecked: ``tests/test_utils.py`` asserts the two definitions
agree, so a future divergence fails the suite instead of causing a subtle
mismatch between what the GUI offers and what the stego layer accepts.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------- #
# Application identity
# --------------------------------------------------------------------------- #

APP_NAME: Final[str] = "Media Integrity & Steganography Tool"
APP_SHORT_NAME: Final[str] = "INF2005 ACW1"
APP_VERSION: Final[str] = "1.0.0"


# --------------------------------------------------------------------------- #
# Media types
# --------------------------------------------------------------------------- #

MEDIA_IMAGE: Final[str] = "image"
MEDIA_AUDIO: Final[str] = "audio"
MEDIA_VIDEO: Final[str] = "video"

MEDIA_TYPES: Final[tuple[str, ...]] = (MEDIA_IMAGE, MEDIA_AUDIO, MEDIA_VIDEO)

#: Container formats this application can carry a payload in, per media type.
CONTAINER_PNG: Final[str] = "PNG"
CONTAINER_BMP: Final[str] = "BMP"
CONTAINER_WAV: Final[str] = "WAV"
CONTAINER_MKV: Final[str] = "MKV"

SUPPORTED_CONTAINERS: Final[dict[str, tuple[str, ...]]] = {
    MEDIA_IMAGE: (CONTAINER_PNG, CONTAINER_BMP),
    MEDIA_AUDIO: (CONTAINER_WAV,),
    MEDIA_VIDEO: (CONTAINER_MKV,),
}

#: The file extension written for each container. Note that the image layer
#: selects its output container from the *detected content* of the cover, not
#: from the output extension (Requirement 1.3), so these are used for building
#: suggested output names, never for deciding how to encode.
CONTAINER_EXTENSIONS: Final[dict[str, str]] = {
    CONTAINER_PNG: ".png",
    CONTAINER_BMP: ".bmp",
    CONTAINER_WAV: ".wav",
    CONTAINER_MKV: ".mkv",
}

#: Extensions offered in file-picker filters. Content sniffing still decides what
#: a file actually is, so a mislabelled file is handled correctly regardless.
OPEN_FILE_EXTENSIONS: Final[dict[str, tuple[str, ...]]] = {
    MEDIA_IMAGE: (".png", ".bmp"),
    MEDIA_AUDIO: (".wav",),
    MEDIA_VIDEO: (".mkv", ".avi"),
}

#: Formats that are recognised well enough to be *rejected with a clear reason*
#: rather than reported as an unknown file. Lossy compression destroys LSB data.
LOSSY_FORMAT_NAMES: Final[tuple[str, ...]] = (
    "JPEG",
    "JPEG2000",
    "GIF",
    "WEBP",
    "MP3",
    "AAC",
    "OGG",
    "FLAC",
    "MP4",
)


# --------------------------------------------------------------------------- #
# LSB embedding parameters
# --------------------------------------------------------------------------- #

#: Restated from app.stego.bit_utils; see the module docstring.
MIN_LSB_DEPTH: Final[int] = 1
MAX_LSB_DEPTH: Final[int] = 8
LSB_DEPTHS: Final[tuple[int, ...]] = tuple(range(MIN_LSB_DEPTH, MAX_LSB_DEPTH + 1))

#: The stego framing's big-endian payload length header.
LENGTH_HEADER_BYTES: Final[int] = 4

#: Sample widths in bits: 8 for image and decoded video channels, 16 for PCM audio.
IMAGE_SAMPLE_WIDTH_BITS: Final[int] = 8
AUDIO_SAMPLE_WIDTH_BITS: Final[int] = 16
VIDEO_SAMPLE_WIDTH_BITS: Final[int] = 8


# --------------------------------------------------------------------------- #
# Start-location derivation
# --------------------------------------------------------------------------- #

START_METHOD_MANUAL: Final[str] = "manual"
START_METHOD_HMAC: Final[str] = "hmac_prf"
START_METHODS: Final[tuple[str, ...]] = (START_METHOD_MANUAL, START_METHOD_HMAC)

#: Domain-separation prefix for the HMAC start-location derivation. Including a
#: fixed label and a version means a future scheme change cannot collide with
#: locations derived by this one.
START_LOCATION_DOMAIN: Final[str] = "INF2005-START"
START_LOCATION_SCHEME_VERSION: Final[int] = 1


# --------------------------------------------------------------------------- #
# Payload envelope
# --------------------------------------------------------------------------- #

#: Envelope magic. Eight bytes, chosen so a wrong start location, a wrong LSB
#: depth or an absent payload almost never produces a matching prefix.
#:
#: The magic lives inside the payload the stego layer carries, NOT in the stego
#: framing itself. Both the image and audio layers write a bare 4-byte length
#: header and treat everything after it as opaque bytes, which keeps the
#: "stego layer carries opaque bytes" boundary of the image-layer specification
#: (Requirement 4.5) intact while still giving all three media one shared,
#: versioned, self-describing format.
ENVELOPE_MAGIC: Final[bytes] = b"INF2005E"
ENVELOPE_VERSION: Final[int] = 1

#: Envelope flag bits.
ENVELOPE_FLAG_ENCRYPTED: Final[int] = 0b0000_0001
ENVELOPE_FLAG_ECC: Final[int] = 0b0000_0010

#: Width of each length field inside the envelope, in bytes (big-endian).
ENVELOPE_LENGTH_FIELD_BYTES: Final[int] = 4

#: Size of the per-file nonce recorded in the verification record and published
#: in the companion manifest. 128 bits, so two independently protected files
#: colliding is not a practical concern. The nonce is not a secret: it is one of
#: the start-location derivation inputs the receiver must know.
RECORD_NONCE_BYTES: Final[int] = 16

#: Refuse to allocate for a declared section longer than this. A corrupt or
#: hostile length field must not be able to request a multi-gigabyte buffer.
MAX_ENVELOPE_SECTION_BYTES: Final[int] = 64 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Signatures and keys
# --------------------------------------------------------------------------- #

SIGNATURE_ALGORITHM: Final[str] = "RSA-PSS-SHA256"
RSA_KEY_SIZE_DEFAULT: Final[int] = 3072
RSA_PUBLIC_EXPONENT: Final[int] = 65537

#: Smallest modulus this application will generate. Verification accepts any
#: size the underlying library accepts, so an older 2048-bit demo key still
#: verifies.
RSA_MIN_KEY_SIZE: Final[int] = 2048

DEMO_PRIVATE_KEY_DIR: Final[str] = "keys/demo_private"
PUBLIC_KEY_DIR: Final[str] = "keys/public"
DEMO_PRIVATE_KEY_NAME: Final[str] = "demo_private.pem"
DEMO_PUBLIC_KEY_NAME: Final[str] = "demo_public.pem"


# --------------------------------------------------------------------------- #
# Message encryption
# --------------------------------------------------------------------------- #

CIPHER_AES_256_GCM: Final[str] = "AES-256-GCM"
AES_KEY_BYTES: Final[int] = 32
GCM_NONCE_BYTES: Final[int] = 12
GCM_TAG_BYTES: Final[int] = 16

KDF_SCRYPT: Final[str] = "scrypt"
SCRYPT_N: Final[int] = 1 << 15
SCRYPT_R: Final[int] = 8
SCRYPT_P: Final[int] = 1
SCRYPT_SALT_BYTES: Final[int] = 16


# --------------------------------------------------------------------------- #
# Error correction
# --------------------------------------------------------------------------- #

ECC_NONE: Final[str] = "none"
ECC_REPETITION: Final[str] = "repetition"
ECC_SCHEMES: Final[tuple[str, ...]] = (ECC_NONE, ECC_REPETITION)

#: Repetition factors must be odd so a majority vote can never tie.
ECC_REPETITION_DEFAULT_FACTOR: Final[int] = 3


# --------------------------------------------------------------------------- #
# Companion manifest
# --------------------------------------------------------------------------- #

MANIFEST_VERSION: Final[int] = 1
MANIFEST_SUFFIX: Final[str] = ".manifest.json"


# --------------------------------------------------------------------------- #
# Verification verdicts
# --------------------------------------------------------------------------- #
#
# Defined here so the GUI can render the vocabulary without importing the
# verification layer. app.verification.verdicts imports these rather than
# restating them.

VERDICT_AUTHENTIC: Final[str] = "AUTHENTIC"
VERDICT_TAMPERED: Final[str] = "TAMPERED"
VERDICT_SIGNATURE_INVALID: Final[str] = "SIGNATURE_INVALID"
VERDICT_PAYLOAD_MISSING: Final[str] = "PAYLOAD_MISSING"
VERDICT_WRONG_START_LOCATION: Final[str] = "WRONG_START_LOCATION"
VERDICT_CANNOT_VERIFY: Final[str] = "CANNOT_VERIFY"

VERDICTS: Final[tuple[str, ...]] = (
    VERDICT_AUTHENTIC,
    VERDICT_TAMPERED,
    VERDICT_SIGNATURE_INVALID,
    VERDICT_PAYLOAD_MISSING,
    VERDICT_WRONG_START_LOCATION,
    VERDICT_CANNOT_VERIFY,
)


# --------------------------------------------------------------------------- #
# Honesty notices
# --------------------------------------------------------------------------- #
#
# Displayed verbatim by the GUI. Kept here so the wording cannot drift between
# the interface, the tests and the documentation.

AUTHENTIC_SCOPE_NOTICE: Final[str] = (
    "AUTHENTIC means the signed verification record and the recovered message "
    "match, and the signature verified against the supplied public key. It does "
    "not mean every part of the cover media is unchanged, and it does not by "
    "itself reject a replayed file."
)

AMBIGUOUS_FAILURE_NOTICE: Final[str] = (
    "An extraction failure does not identify its cause. A wrong LSB depth, a "
    "wrong start location or secret, an absent payload and sample corruption "
    "produce indistinguishable bit streams."
)

START_LOCATION_NOTICE: Final[str] = (
    "A derived start location conceals where the payload begins. It is not "
    "encryption and provides no confidentiality on its own."
)

DEMO_KEY_NOTICE: Final[str] = (
    "Demo key pair. The private key is stored unencrypted (PKCS#8, no "
    "passphrase) so the demonstration can run unattended. Never use this key "
    "arrangement for anything real."
)

FILE_CHANGED_NOTICE: Final[str] = (
    "This file is not byte-for-byte the one that was protected: its SHA-256 differs "
    "from the digest in the manifest. The verdict concerns the embedded payload "
    "only, and a change outside the payload region does not affect it. The manifest "
    "is unsigned, so this is a transport check, not proof of tampering."
)

EXTRACTED_CONTENT_NOTICE: Final[str] = (
    "Recovered content is displayed as inert text or a hex dump, and a recognised "
    "image or audio file is previewed inside this application. It is never "
    "executed, and never handed to the operating system to open."
)
