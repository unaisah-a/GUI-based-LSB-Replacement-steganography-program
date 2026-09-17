"""Application services that coordinate GUI-independent workflows."""

from app.services.protection import (
    ProtectionOptions,
    ProtectionResult,
    ProtectionCapacity,
    PublicationError,
    estimate_protection_capacity,
    protect_media,
)

__all__ = [
    "ProtectionOptions",
    "ProtectionResult",
    "ProtectionCapacity",
    "PublicationError",
    "estimate_protection_capacity",
    "protect_media",
]
