"""Luhn algorithm for credit card number validation.

Delegated to spanforge.redact — no local copy needed.
"""

from __future__ import annotations

from spanforge.redact import _luhn_check as _luhn_check  # re-export

__all__ = ["_luhn_check"]
