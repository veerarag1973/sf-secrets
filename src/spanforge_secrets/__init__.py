"""spanforge-secrets — CI gate for PII and API key scanning.

Scans prompt files, training data, and arbitrary text/JSON for:
  * 10 PII entity types (email, phone, SSN, credit card, IP address,
    UK National Insurance, Aadhaar, PAN, date of birth, address)
  * Exposed API keys (OpenAI, Anthropic, AWS, GCP)

Exits 1 if any violation is found.  Outputs structured JSON with hit
details, file path, and sensitivity level.

CLI Gate 01 for the Spanforge compliance pipeline.
"""

from spanforge_secrets._patterns import (
    _API_KEY_PATTERNS,
    _PII_PATTERNS,
    _SENSITIVITY_MAP,
)
from spanforge_secrets._luhn import _luhn_check
from spanforge_secrets._verhoeff import _verhoeff_check
from spanforge_secrets.scanner import (
    PIIScanHit,
    PIIScanResult,
    scan_payload,
    scan_text,
)
from spanforge_secrets.chain import verify_chain_file

__all__ = [
    "_API_KEY_PATTERNS",
    "_PII_PATTERNS",
    "_SENSITIVITY_MAP",
    "_luhn_check",
    "_verhoeff_check",
    "PIIScanHit",
    "PIIScanResult",
    "scan_payload",
    "scan_text",
    "verify_chain_file",
]
