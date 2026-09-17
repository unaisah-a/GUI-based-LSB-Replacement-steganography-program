"""The companion manifest: non-secret extraction parameters, sent with the file.

Why it exists
-------------
The receiver has to locate the payload before it can read it, and locating it
needs the LSB depth, the start method and — for the keyed method — the media
identifier, the nonce and the envelope length. Those values cannot live only
inside the hidden payload, because they are what the receiver needs in order to
find that payload. The manifest is where they live instead.

It is a plain JSON sidecar written next to the stego file as
``<stego file name>.manifest.json``, and the two travel together. Party A sends
both; party B needs both.

What is not in it
-----------------
No secrets. Not the start-location secret, not the encryption passphrase, not the
private key. Those are shared out of band. ``tests/test_manifest.py`` asserts that
a manifest built from a protect operation contains neither secret anywhere in its
serialised form.

Trust
-----
**Manifest content is untrusted.** It arrives alongside the file and nothing
authenticates it on its own. Two separate mechanisms handle that:

1. :func:`read_manifest` validates every field for type, range and supported
   value *before* any of it is used to drive extraction. A depth of 99 or a
   negative length is rejected here rather than reaching the stego layer.
2. :func:`cross_check` compares the manifest against the signed verification
   record *after* the signature has verified, and reports every field that
   disagrees. This is what makes the manifest's claims trustworthy in retrospect:
   the values that matter are all present in the signed record, so a modified
   manifest either fails extraction outright or is caught by the comparison.

Tampering with the manifest therefore produces a clear failure, not a false
``AUTHENTIC``. It does not, however, always reveal *which* field was changed: a
modified depth or length usually makes extraction fail with no payload found,
which is indistinguishable from several other causes.

``stego_sha256`` is a transport aid only
----------------------------------------
The recorded digest of the stego file lets a receiver notice a truncated download
before spending time on extraction. It is not an integrity guarantee: anyone who
modifies the stego file can recompute it. The signature over the verification
record is the guarantee; this field is a convenience.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Final, Mapping

from app.crypto import envelope as envelope_module
from app.crypto.envelope import EncryptionParameters, ErrorCorrectionParameters
from app.crypto.errors import ManifestError
from app.utils import constants, file_utils

__all__ = [
    "SUPPORTED_MANIFEST_VERSIONS",
    "Manifest",
    "cross_check",
    "read_manifest",
    "write_manifest",
]

SUPPORTED_MANIFEST_VERSIONS: Final[tuple[int, ...]] = (constants.MANIFEST_VERSION,)

#: Refuse an absurd declared envelope length before it reaches the stego layer.
_MAX_ENVELOPE_LENGTH: Final[int] = constants.MAX_ENVELOPE_SECTION_BYTES


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #


def _require(data: Mapping[str, Any], key: str, kind: type) -> Any:
    if key not in data:
        raise ManifestError(f"manifest is missing the required field {key!r}")
    value = data[key]
    if kind is int and isinstance(value, bool):
        raise ManifestError(f"manifest field {key!r} must be an integer, got a boolean")
    if not isinstance(value, kind):
        raise ManifestError(
            f"manifest field {key!r} must be {kind.__name__}, got "
            f"{type(value).__name__}"
        )
    return value


def _require_hex(value: str, key: str, *, expected_length: int | None = None) -> str:
    if expected_length is not None and len(value) != expected_length:
        raise ManifestError(
            f"manifest field {key!r} must be {expected_length} hexadecimal "
            f"characters, got {len(value)}"
        )
    if not value or len(value) % 2 != 0:
        raise ManifestError(
            f"manifest field {key!r} must be a non-empty even-length hexadecimal "
            f"string"
        )
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ManifestError(
            f"manifest field {key!r} is not valid hexadecimal"
        ) from exc
    return value


def _require_bounded_int(
    data: Mapping[str, Any], key: str, *, minimum: int, maximum: int
) -> int:
    value = _require(data, key, int)
    if not minimum <= value <= maximum:
        raise ManifestError(
            f"manifest field {key!r} must be from {minimum} to {maximum} inclusive, "
            f"got {value}"
        )
    return value


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Manifest:
    """Non-secret parameters a receiver needs before it can extract."""

    media_id: str
    media_type: str
    container_format: str
    nonce_hex: str
    lsb_depth: int
    start_method: str
    envelope_length: int
    message_length: int
    encrypted: bool
    start_location: int | None = None
    encryption: EncryptionParameters | None = None
    ecc: ErrorCorrectionParameters | None = None
    stego_file_name: str | None = None
    stego_sha256: str | None = None
    created: str | None = None
    format_version: int = constants.MANIFEST_VERSION

    # -- construction ----------------------------------------------------- #

    @classmethod
    def from_record(
        cls,
        record: envelope_module.VerificationRecord,
        *,
        envelope_length: int,
        container_format: str,
        resolved_start_location: int | None = None,
        stego_file_name: str | None = None,
        stego_sha256: str | None = None,
        created: str | None = None,
    ) -> "Manifest":
        """Build a manifest from a signed record and the values it cannot carry.

        ``envelope_length`` is supplied rather than read from the record because
        the record cannot contain it: the length depends on the record's own
        serialised size. See :class:`app.crypto.envelope.VerificationRecord`.

        ``resolved_start_location`` is published only for the manual method. For
        the keyed method the location is derived by the receiver, and writing it
        here would hand an attacker the one value the secret is meant to protect.
        """
        publish_start = (
            resolved_start_location
            if record.start_method == constants.START_METHOD_MANUAL
            else None
        )
        return cls(
            media_id=record.media_id,
            media_type=record.media_type,
            container_format=container_format,
            nonce_hex=record.nonce_hex,
            lsb_depth=record.lsb_depth,
            start_method=record.start_method,
            envelope_length=envelope_length,
            message_length=record.message_length,
            encrypted=record.encrypted,
            start_location=publish_start,
            encryption=record.encryption,
            ecc=record.ecc,
            stego_file_name=stego_file_name,
            stego_sha256=stego_sha256,
            created=created if created is not None else envelope_module.utc_timestamp(),
        )

    # -- serialisation ---------------------------------------------------- #

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON structure written to disk."""
        return {
            "format_version": self.format_version,
            "media_id": self.media_id,
            "media_type": self.media_type,
            "container_format": self.container_format,
            "nonce": self.nonce_hex,
            "lsb_depth": self.lsb_depth,
            "start_method": self.start_method,
            "start_location": self.start_location,
            "envelope_length": self.envelope_length,
            "message_length": self.message_length,
            "encrypted": self.encrypted,
            "encryption": self.encryption.as_dict() if self.encryption else None,
            "ecc": self.ecc.as_dict() if self.ecc else None,
            "stego_file": self.stego_file_name,
            "stego_sha256": self.stego_sha256,
            "created": self.created,
            "notice": constants.START_LOCATION_NOTICE,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Manifest":
        """Validate untrusted manifest content and build a manifest.

        Every check here happens before any value is used to drive extraction, so
        a hostile or corrupt manifest is rejected rather than passed down to the
        stego layer.
        """
        if not isinstance(data, Mapping):
            raise ManifestError(
                f"manifest must be a JSON object, got {type(data).__name__}"
            )

        version = _require(data, "format_version", int)
        if version not in SUPPORTED_MANIFEST_VERSIONS:
            raise ManifestError(
                f"manifest format version {version} is not supported; this build "
                f"understands {SUPPORTED_MANIFEST_VERSIONS}"
            )

        media_type = _require(data, "media_type", str)
        if media_type not in constants.MEDIA_TYPES:
            raise ManifestError(
                f"manifest field 'media_type' must be one of "
                f"{constants.MEDIA_TYPES}, got {media_type!r}"
            )

        container = _require(data, "container_format", str)
        permitted = constants.SUPPORTED_CONTAINERS[media_type]
        if container not in permitted:
            raise ManifestError(
                f"manifest field 'container_format' must be one of {permitted} for "
                f"{media_type} media, got {container!r}"
            )

        start_method = _require(data, "start_method", str)
        if start_method not in constants.START_METHODS:
            raise ManifestError(
                f"manifest field 'start_method' must be one of "
                f"{constants.START_METHODS}, got {start_method!r}"
            )

        lsb_depth = _require_bounded_int(
            data,
            "lsb_depth",
            minimum=constants.MIN_LSB_DEPTH,
            maximum=constants.MAX_LSB_DEPTH,
        )
        envelope_length = _require_bounded_int(
            data,
            "envelope_length",
            minimum=envelope_module.MIN_ENVELOPE_SIZE,
            maximum=_MAX_ENVELOPE_LENGTH,
        )
        message_length = _require_bounded_int(
            data, "message_length", minimum=0, maximum=_MAX_ENVELOPE_LENGTH
        )

        if "start_location" not in data:
            raise ManifestError(
                "manifest is missing the required field 'start_location'"
            )
        start_location = data["start_location"]
        if start_method == constants.START_METHOD_MANUAL:
            if isinstance(start_location, bool) or not isinstance(start_location, int):
                raise ManifestError(
                    f"manifest field 'start_location' must be an integer for the "
                    f"{constants.START_METHOD_MANUAL!r} start method, got "
                    f"{type(start_location).__name__}"
                )
            if start_location < 0:
                raise ManifestError(
                    f"manifest field 'start_location' must not be negative, got "
                    f"{start_location}"
                )
        elif start_location is not None:
            # Publishing a derived location would defeat the secret.
            raise ManifestError(
                f"manifest field 'start_location' must be null for the "
                f"{constants.START_METHOD_HMAC!r} start method, because the "
                f"receiver derives it from the shared secret"
            )

        encrypted = _require(data, "encrypted", bool)
        encryption_data = data.get("encryption")
        if encryption_data is not None and not isinstance(encryption_data, Mapping):
            raise ManifestError(
                f"manifest field 'encryption' must be an object or null, got "
                f"{type(encryption_data).__name__}"
            )
        if encrypted and encryption_data is None:
            raise ManifestError(
                "manifest declares the message is encrypted but carries no "
                "'encryption' parameters, so the key could not be derived"
            )
        if not encrypted and encryption_data is not None:
            raise ManifestError(
                "manifest carries 'encryption' parameters but declares the message "
                "is not encrypted"
            )

        ecc_data = data.get("ecc")
        if ecc_data is not None and not isinstance(ecc_data, Mapping):
            raise ManifestError(
                f"manifest field 'ecc' must be an object or null, got "
                f"{type(ecc_data).__name__}"
            )

        digest = data.get("stego_sha256")
        if digest is not None:
            if not isinstance(digest, str):
                raise ManifestError(
                    f"manifest field 'stego_sha256' must be a string or null, got "
                    f"{type(digest).__name__}"
                )
            _require_hex(digest, "stego_sha256", expected_length=64)

        for optional in ("stego_file", "created"):
            value = data.get(optional)
            if value is not None and not isinstance(value, str):
                raise ManifestError(
                    f"manifest field {optional!r} must be a string or null, got "
                    f"{type(value).__name__}"
                )

        try:
            encryption = (
                EncryptionParameters.from_dict(encryption_data)
                if encryption_data is not None
                else None
            )
            ecc = (
                ErrorCorrectionParameters.from_dict(ecc_data)
                if ecc_data is not None
                else None
            )
        except Exception as exc:
            # RecordError from the shared sub-structure validators; re-raised as a
            # ManifestError so a caller handling manifest input sees one category.
            raise ManifestError(f"manifest parameter block is invalid: {exc}") from exc

        return cls(
            media_id=_require(data, "media_id", str),
            media_type=media_type,
            container_format=container,
            nonce_hex=_require_hex(_require(data, "nonce", str), "nonce"),
            lsb_depth=lsb_depth,
            start_method=start_method,
            envelope_length=envelope_length,
            message_length=message_length,
            encrypted=encrypted,
            start_location=(
                start_location
                if start_method == constants.START_METHOD_MANUAL
                else None
            ),
            encryption=encryption,
            ecc=ecc,
            stego_file_name=data.get("stego_file"),
            stego_sha256=digest,
            created=data.get("created"),
            format_version=version,
        )


# --------------------------------------------------------------------------- #
# Reading and writing
# --------------------------------------------------------------------------- #


def write_manifest(
    manifest: Manifest,
    path: str | os.PathLike[str] | None = None,
    *,
    stego_path: str | os.PathLike[str] | None = None,
    overwrite: bool = False,
) -> str:
    """Write *manifest* as a JSON sidecar and return the path written.

    Supply either an explicit *path* or the *stego_path* it accompanies, in which
    case the conventional ``<stego file name>.manifest.json`` name is used.
    Written atomically, so an interrupted run cannot leave a half-written manifest
    that would later be rejected as malformed.
    """
    if not isinstance(manifest, Manifest):
        raise ManifestError(
            f"manifest must be a Manifest, got {type(manifest).__name__}"
        )
    if path is None and stego_path is None:
        raise ManifestError("either path or stego_path must be supplied")

    target = (
        os.fspath(path)
        if path is not None
        else file_utils.manifest_path_for(stego_path)  # type: ignore[arg-type]
    )
    try:
        return file_utils.write_json_atomic(
            target, manifest.as_dict(), overwrite=overwrite
        )
    except FileExistsError as exc:
        raise ManifestError(
            f"manifest path is already occupied: "
            f"{file_utils.display_name(target)}; pass overwrite=True to replace it"
        ) from exc
    except OSError as exc:
        raise ManifestError(
            f"manifest could not be written to "
            f"{file_utils.display_name(target)} "
            f"({exc.strerror or type(exc).__name__})"
        ) from exc


def read_manifest(path: str | os.PathLike[str]) -> Manifest:
    """Read and validate a manifest sidecar.

    :raises ManifestError: the file is missing or unreadable, is not valid JSON,
        or carries a field that fails validation.
    """
    target = os.fspath(path)
    name = file_utils.display_name(target)

    try:
        payload = file_utils.read_json(target)
    except FileNotFoundError as exc:
        raise ManifestError(
            f"companion manifest not found: {name}. The manifest is sent alongside "
            f"the stego file and is required to locate the payload"
        ) from exc
    except IsADirectoryError as exc:
        raise ManifestError(f"manifest path is a directory, not a file: {name}") from exc
    except PermissionError as exc:
        raise ManifestError(f"read access denied for manifest: {name}") from exc
    except UnicodeDecodeError as exc:
        raise ManifestError(f"manifest {name} is not valid UTF-8") from exc
    except ValueError as exc:
        # json.JSONDecodeError is a ValueError subclass.
        raise ManifestError(f"manifest {name} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ManifestError(
            f"manifest could not be read: {name} "
            f"({exc.strerror or type(exc).__name__})"
        ) from exc

    return Manifest.from_dict(payload)


# --------------------------------------------------------------------------- #
# Cross-checking against the signed record
# --------------------------------------------------------------------------- #


def cross_check(
    manifest: Manifest,
    record: envelope_module.VerificationRecord,
    *,
    envelope_length: int | None = None,
) -> tuple[str, ...]:
    """Return the names of manifest fields that disagree with the signed record.

    Call this only after the envelope signature has verified. Before that the
    record is as untrusted as the manifest and comparing them establishes nothing.

    An empty result means every parameter the manifest published matches what the
    sender signed. Pass *envelope_length* — recomputed from the parsed envelope —
    to also confirm the published length, which is how a manifest length claim
    gets checked against the signed bytes without being inside the signature.
    """
    if not isinstance(manifest, Manifest):
        raise ManifestError(
            f"manifest must be a Manifest, got {type(manifest).__name__}"
        )
    if not isinstance(record, envelope_module.VerificationRecord):
        raise ManifestError(
            f"record must be a VerificationRecord, got {type(record).__name__}"
        )

    mismatches: list[str] = []

    if manifest.media_id != record.media_id:
        mismatches.append("media_id")
    if manifest.media_type != record.media_type:
        mismatches.append("media_type")
    if manifest.nonce_hex != record.nonce_hex:
        mismatches.append("nonce")
    if manifest.lsb_depth != record.lsb_depth:
        mismatches.append("lsb_depth")
    if manifest.start_method != record.start_method:
        mismatches.append("start_method")
    if manifest.message_length != record.message_length:
        mismatches.append("message_length")
    if manifest.encrypted != record.encrypted:
        mismatches.append("encrypted")
    if manifest.encryption != record.encryption:
        mismatches.append("encryption")
    if manifest.ecc != record.ecc:
        mismatches.append("ecc")

    # Only the manual method publishes a location, and only then is the record's
    # copy non-null; see the VerificationRecord docstring for why.
    if record.start_method == constants.START_METHOD_MANUAL:
        if manifest.start_location != record.start_location:
            mismatches.append("start_location")

    if envelope_length is not None and manifest.envelope_length != envelope_length:
        mismatches.append("envelope_length")

    return tuple(mismatches)
