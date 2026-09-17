"""Application services that coordinate GUI-independent workflows."""

from app.services.protection import ProtectionOptions, ProtectionResult, protect_media

__all__ = ["ProtectionOptions", "ProtectionResult", "protect_media"]
