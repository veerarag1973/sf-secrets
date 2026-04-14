"""Thin wrapper around verify_chain() from spanforge.signing.

This module is intentionally kept lightweight: it reads a JSONL audit-log
file and delegates cryptographic verification to spanforge's own
verify_chain() so that the signing logic stays in one place.

If the upstream spanforge package is not installed, the function raises
ImportError with a clear message rather than silently skipping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def verify_chain_file(path: str | Path, org_secret: str) -> dict[str, Any]:
    """Verify an audit-chain JSONL file and return a result dict.

    Each line of *path* must be a JSON object with at least the fields
    required by ``spanforge.event.Event``.

    Args:
        path:       Path to the JSONL audit-log file.
        org_secret: HMAC signing key used when the chain was created.

    Returns:
        A dict with keys ``valid``, ``first_tampered``, ``gaps``,
        ``tampered_count``, and ``tombstone_count``.

    Raises:
        ImportError: If the ``spanforge`` package is not installed.
        FileNotFoundError: If *path* does not exist.
        ValueError: If any line is not valid JSON, is not valid UTF-8, exceeds
            the size limit, or cannot be deserialised into an ``Event``
            (e.g. missing required fields, wrong types).
    """
    try:
        from spanforge.signing import verify_chain  # type: ignore[import]
        from spanforge.event import Event  # type: ignore[import]
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "spanforge package is required for verify_chain_file. "
            "Install it with: pip install spanforge"
        ) from exc

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Audit log not found: {file_path}")

    # Guard against enormous files
    _max_bytes = 50 * 1024 * 1024  # 50 MB
    try:
        fsize = file_path.stat().st_size
    except OSError:
        fsize = 0
    if fsize > _max_bytes:
        raise ValueError(
            f"Audit log {file_path} is {fsize / (1024 * 1024):.0f} MB "
            f"which exceeds the {_max_bytes // (1024 * 1024)} MB limit."
        )

    try:
        text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Audit log {file_path} is not valid UTF-8: {exc}"
        ) from exc

    events: list[Any] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {lineno} of {file_path}: {exc}") from exc
        try:
            events.append(Event(**data))
        except Exception as exc:
            raise ValueError(
                f"Invalid event on line {lineno} of {file_path}: {exc}"
            ) from exc

    result = verify_chain(events, org_secret=org_secret)
    return {
        "valid": result.valid,
        "first_tampered": result.first_tampered,
        "gaps": result.gaps,
        "tampered_count": result.tampered_count,
        "tombstone_count": result.tombstone_count,
    }
