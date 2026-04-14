"""Verhoeff checksum for Aadhaar number validation.

Delegated to spanforge.redact — no local copy needed.
"""

from __future__ import annotations

from spanforge.redact import _verhoeff_check as _verhoeff_check  # re-export

__all__ = ["_verhoeff_check"]
