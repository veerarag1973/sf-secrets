"""Compiled regex patterns for PII and API key detection.

All PII patterns (email, phone, ssn, credit_card, ip_address,
uk_national_insurance, date_of_birth, address, aadhaar, pan) are imported
directly from spanforge.redact -- no duplication.

API key patterns (openai, anthropic, aws, gcp) are unique to this package.
"""

from __future__ import annotations

import re
from typing import Final

# All PII patterns (including date_of_birth, address) + aadhaar/pan (DPDP)
# come from spanforge>=2.0.0 -- no local duplication.
from spanforge.redact import _PII_PATTERNS as _SF_PII_PATTERNS  # type: ignore[import]
from spanforge.redact import DPDP_PATTERNS as _SF_DPDP_PATTERNS  # type: ignore[import]

# Combined set exposed to the rest of the package.
_PII_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    **_SF_PII_PATTERNS,
    **_SF_DPDP_PATTERNS,
}

# ---------------------------------------------------------------------------
# API key patterns -- 4 platforms
# ---------------------------------------------------------------------------

_API_KEY_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    # OpenAI: sk-... (legacy 51-char) and sk-proj-... (project keys)
    "openai_api_key": re.compile(
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}(?:[A-Za-z0-9_-]{10,})?\b"
    ),
    # Anthropic: sk-ant-... (bounded to realistic key length)
    "anthropic_api_key": re.compile(
        r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,128}\b"
    ),
    # AWS Access Key ID -- always starts with AKIA or ASIA (20 upper-alphanum chars)
    "aws_access_key_id": re.compile(
        r"\b(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b"
    ),
    # AWS Secret Access Key -- 40 base64url chars following common context words
    # Context-sensitive: matches the value portion only when preceded by
    # typical key/value separators so we avoid excessive false positives.
    # Uses explicit separators [\s_-]* instead of .? to prevent ReDoS.
    "aws_secret_access_key": re.compile(
        r"(?:aws[\s_-]*secret[\s_-]*access[\s_-]*key|secret[\s_-]*access[\s_-]*key|secretaccesskey)"
        r"[\s\"'=:]+([A-Za-z0-9/+]{40})\b",
        re.IGNORECASE,
    ),
    # GCP service-account JSON private key marker
    "gcp_service_account_key": re.compile(
        r'"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----'
    ),
}

# ---------------------------------------------------------------------------
# Sensitivity map -- used to annotate hits
# ---------------------------------------------------------------------------

_SENSITIVITY_MAP: Final[dict[str, str]] = {
    # High -- directly identifies or grants access
    "ssn": "high",
    "credit_card": "high",
    "aadhaar": "high",
    "pan": "high",
    "openai_api_key": "high",
    "anthropic_api_key": "high",
    "aws_access_key_id": "high",
    "aws_secret_access_key": "high",
    "gcp_service_account_key": "high",
    # Medium -- quasi-identifying
    "email": "medium",
    "phone": "medium",
    "date_of_birth": "medium",
    "address": "medium",
    # Low -- may be identifying in combination
    "ip_address": "low",
    "uk_national_insurance": "low",
}
