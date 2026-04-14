"""Core scanning engine for spanforge-secrets.

Provides:
    scan_payload()  — scan a nested dict/list structure (JSON payloads)
    scan_text()     — scan a raw string (prompt files, training JSONL lines)

Both functions return a :class:`PIIScanResult` with structured hit details.
Matched content itself is never returned — only type, path, count, and
sensitivity level.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from spanforge_secrets._luhn import _luhn_check
from spanforge_secrets._verhoeff import _verhoeff_check
from spanforge_secrets._patterns import (
    _API_KEY_PATTERNS,
    _PII_PATTERNS,
    _SENSITIVITY_MAP,
)
from spanforge.redact import _is_valid_ssn as _is_valid_ssn  # type: ignore[import]
from spanforge.redact import _is_valid_date as _is_valid_date  # type: ignore[import]


@dataclass(frozen=True)
class PIIScanHit:
    """A single detection hit produced by the scanner.

    Attributes:
        entity_type:  What was detected (e.g. ``"email"``, ``"openai_api_key"``).
        path:         Dot/bracket path inside the payload, or ``"<text>"`` for
                      raw-string scans.
        match_count:  Number of distinct matches of this type at this path.
        sensitivity:  ``"high"`` | ``"medium"`` | ``"low"``
        category:     ``"pii"`` or ``"api_key"``
    """

    entity_type: str
    path: str
    match_count: int
    sensitivity: str
    category: str


@dataclass(frozen=True)
class PIIScanResult:
    """Aggregated result of a scan operation.

    Attributes:
        hits:      All :class:`PIIScanHit` instances found.
        scanned:   Number of string values inspected.
        clean:     ``True`` when no hits were recorded.
        source:    Optional label — file path or ``"<stdin>"``
    """

    hits: list[PIIScanHit]
    scanned: int
    source: str = "<unknown>"

    @property
    def clean(self) -> bool:
        return len(self.hits) == 0

    @property
    def violation_count(self) -> int:
        return len(self.hits)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "source": self.source,
            "clean": self.clean,
            "violation_count": self.violation_count,
            "scanned_strings": self.scanned,
            "hits": [
                {
                    "entity_type": h.entity_type,
                    "path": h.path,
                    "match_count": h.match_count,
                    "sensitivity": h.sensitivity,
                    "category": h.category,
                }
                for h in self.hits
            ],
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _all_patterns() -> dict[str, tuple[re.Pattern[str], str]]:
    """Return merged {label: (pattern, category)} dict."""
    combined: dict[str, tuple[re.Pattern[str], str]] = {}
    for label, pat in _PII_PATTERNS.items():
        combined[label] = (pat, "pii")
    for label, pat in _API_KEY_PATTERNS.items():
        combined[label] = (pat, "api_key")
    return combined



def _check_string(
    value: str,
    path: str,
    patterns: dict[str, tuple[re.Pattern[str], str]],
    hits: list[PIIScanHit],
    sensitivity_map: dict[str, str] | None = None,
) -> None:
    """Test *value* against all patterns and append hits."""
    _sens = sensitivity_map if sensitivity_map is not None else _SENSITIVITY_MAP
    for label, (pat, category) in patterns.items():
        matches = list(pat.finditer(value))
        if not matches:
            continue

        # Post-validation: Luhn for credit card
        if label == "credit_card":
            matches = [m for m in matches if _luhn_check(m.group())]
            if not matches:
                continue

        # Post-validation: Verhoeff for Aadhaar
        if label == "aadhaar":
            matches = [m for m in matches if _verhoeff_check(m.group())]
            if not matches:
                continue

        # Post-validation: SSA range check for SSN
        if label == "ssn":
            matches = [m for m in matches if _is_valid_ssn(m.group())]
            if not matches:
                continue

        # Post-validation: calendar check for date_of_birth
        if label == "date_of_birth":
            matches = [m for m in matches if _is_valid_date(m.group())]
            if not matches:
                continue

        sensitivity = _sens.get(label, "medium")
        hits.append(
            PIIScanHit(
                entity_type=label,
                path=path,
                match_count=len(matches),
                sensitivity=sensitivity,
                category=category,
            )
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_payload(
    payload: dict[str, Any],
    *,
    extra_patterns: dict[str, re.Pattern[str]] | None = None,
    extra_sensitivity: dict[str, str] | None = None,
    max_depth: int = 10,
    source: str = "<payload>",
    scan_raw: bool = True,
) -> PIIScanResult:
    """Scan a nested dict/list payload for PII and exposed API keys.

    Walks the entire structure recursively (up to *max_depth*), testing every
    string value against the built-in PII and API-key pattern sets plus any
    caller-supplied *extra_patterns*.

    **Security**: matched values are never returned — only entity type, field
    path, match count, and sensitivity level.

    Args:
        payload:         The dictionary to scan.
        extra_patterns:      Additional ``{label: compiled_regex}`` patterns.
                             These are treated as category ``"pii"`` and default
                             sensitivity ``"medium"`` unless overridden via
                             *extra_sensitivity*.
        extra_sensitivity:   Optional ``{label: sensitivity}`` map to override
                             the default ``"medium"`` sensitivity for any label
                             in *extra_patterns*.  Valid values: ``"high"``,
                             ``"medium"``, ``"low"``.
        max_depth:           Maximum nesting depth to walk (default 10).
                             Must be ≥ 0.
        source:          Label for the result's ``source`` field.
        scan_raw:        When ``True`` (default), include raw string values
                         in addition to recognised Redactable wrappers.
                         Exists for API-compatibility with
                         ``spanforge.redact.contains_pii(scan_raw=…)``.

    Returns:
        :class:`PIIScanResult` with all detections.
    """
    if max_depth < 0:
        raise ValueError(f"max_depth must be >= 0, got {max_depth}")

    if not scan_raw:
        return PIIScanResult(hits=[], scanned=0, source=source)

    patterns = _all_patterns()
    _extra_sens: dict[str, str] = extra_sensitivity or {}

    # Extra caller patterns are tagged as pii; sensitivity defaults to medium
    # but can be overridden via extra_sensitivity.
    if extra_patterns:
        for label, pat in extra_patterns.items():
            patterns[label] = (pat, "pii")
            # Register custom sensitivity so _check_string picks it up
            if label not in _SENSITIVITY_MAP and label not in _extra_sens:
                _extra_sens.setdefault(label, "medium")

    # Temporarily extend the sensitivity map with caller overrides
    # (we shadow the module-level map via a local copy)
    effective_sensitivity = dict(_SENSITIVITY_MAP)
    effective_sensitivity.update(_extra_sens)

    hits: list[PIIScanHit] = []
    scanned = 0

    def _walk(obj: Any, path: str, depth: int) -> None:
        nonlocal scanned
        if depth > max_depth:
            return
        if isinstance(obj, str):
            scanned += 1
            _check_string(obj, path or "<root>", patterns, hits, effective_sensitivity)
        elif isinstance(obj, Mapping):
            for k, v in obj.items():
                _walk(v, f"{path}.{k}" if path else str(k), depth + 1)
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                _walk(v, f"{path}[{i}]", depth + 1)

    _walk(payload, "", 0)
    return PIIScanResult(hits=hits, scanned=scanned, source=source)


def scan_text(
    text: str,
    *,
    extra_patterns: dict[str, re.Pattern[str]] | None = None,
    extra_sensitivity: dict[str, str] | None = None,
    source: str = "<text>",
    scan_raw: bool = True,
) -> PIIScanResult:
    """Scan a raw string for PII and exposed API keys.

    Useful for scanning plain-text prompt files, JSONL lines that have
    already been decoded, or arbitrary training data strings.

    Args:
        text:              The text to scan.
        extra_patterns:    Additional ``{label: compiled_regex}`` patterns.
        extra_sensitivity: Optional ``{label: sensitivity}`` map to override
                           the default ``"medium"`` for *extra_patterns* labels.
        source:            Label for the result's ``source`` field.
        scan_raw:          When ``False``, returns a clean result immediately
                           (mirrors the ``scan_raw`` parameter on
                           :func:`scan_payload`).

    Returns:
        :class:`PIIScanResult` with all detections.
    """
    if not scan_raw:
        return PIIScanResult(hits=[], scanned=0, source=source)

    patterns = _all_patterns()
    _extra_sens: dict[str, str] = extra_sensitivity or {}
    if extra_patterns:
        for label, pat in extra_patterns.items():
            patterns[label] = (pat, "pii")
            _extra_sens.setdefault(label, "medium")

    effective_sensitivity = dict(_SENSITIVITY_MAP)
    effective_sensitivity.update(_extra_sens)

    hits: list[PIIScanHit] = []
    _check_string(text, "<text>", patterns, hits, effective_sensitivity)
    return PIIScanResult(hits=hits, scanned=1, source=source)
