# Changelog

All notable changes to `spanforge-secrets` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-04-14

### Added

#### Scanning engine (`scanner.py`)
- `scan_payload()` — recursively scans nested dict/list structures (JSON payloads) for PII and API key leakage. Walks up to configurable `max_depth` (default 10).
- `scan_text()` — scans a raw string for PII and API keys. Useful for prompt files, JSONL lines, and arbitrary training data.
- `PIIScanHit` dataclass — frozen, with fields `entity_type`, `path`, `match_count`, `sensitivity`, `category`.
- `PIIScanResult` dataclass — frozen, with fields `hits`, `scanned`, `source`; properties `clean` and `violation_count`; method `to_dict()`.
- `extra_patterns` parameter on both scan functions for caller-supplied regex patterns.
- `extra_sensitivity` parameter to override sensitivity levels for custom patterns.
- `_is_valid_ssn()` — SSA range validation (area, group, serial) to eliminate false-positive SSNs.
- `_is_valid_date()` — Calendar validation for `date_of_birth` detections to eliminate impossible dates.

#### Pattern library (`_patterns.py`)
- 8 base PII patterns imported from `spanforge.redact` (email, phone, ssn, credit_card, ip_address, uk_national_insurance, aadhaar, pan) — no duplication.
- `date_of_birth` pattern — three formats: ISO 8601, European, US. Unique to this package.
- `address` pattern — house number + capitalised words + road suffix. Unique to this package.
- 5 API key patterns: `openai_api_key`, `anthropic_api_key`, `aws_access_key_id`, `aws_secret_access_key`, `gcp_service_account_key`.
- `_SENSITIVITY_MAP` — maps all 15 entity types to their sensitivity level.

#### Luhn / Verhoeff (`_luhn.py`, `_verhoeff.py`)
- Re-export shims that delegate to `spanforge.redact._luhn_check` and `spanforge.redact._verhoeff_check` without duplicating any algorithm code.

#### Audit chain verification (`chain.py`)
- `verify_chain_file()` — reads a JSONL audit log and delegates to `spanforge.signing.verify_chain()`.
- UTF-8 decoding, 50 MB size guard, blank-line skipping, per-line error reporting.
- Returns a normalised dict: `valid`, `first_tampered`, `gaps`, `tampered_count`, `tombstone_count`.

#### CLI (`cli.py`)
- `scan` sub-command: scans files, directories (recursive), or stdin.
- `verify-chain` sub-command: verifies HMAC audit chains.
- `--format json` (default) and `--format sarif` output modes.
- SARIF 2.1.0 output compatible with GitHub Advanced Security / Code Scanning.
- `--diff` mode: scans only `git diff --staged` added lines for use as a pre-commit hook.
- `--ignore-file` flag and auto-detection of `.spanforge-secretsignore`.
- Binary file detection (skips ~30 known binary extensions automatically).
- 50 MB file size guard.
- Non-UTF-8 file handling (skip with warning, not error).
- Exit codes: 0 (clean), 1 (violations or chain invalid), 2 (usage error), 3 (I/O/format error).

#### Packaging
- `spanforge>=2.0.0` declared as a required runtime dependency; this is a **reference implementation** of the spanforge framework.
- `py.typed` marker for PEP 561 type information.
- `python -m spanforge_secrets` entry point via `__main__.py`.

#### Tests
- 104 tests covering all entity types, validators, CLI commands, SARIF output, ignore files, diff mode, and chain verification.
- `TestVerifyChainFileIntegration` — 4 integration tests using real `spanforge.signing` and `spanforge.event` APIs, gated with `pytest.importorskip`.

---

## Pre-release development

### De-duplication

Removed all duplicated implementations of Luhn, Verhoeff, and the 8 base PII patterns — these are now imported directly from `spanforge.redact`. Only `date_of_birth` and `address` patterns are defined locally (not present in upstream `spanforge`).

### Packaging alignment

Corrected `pyproject.toml` to declare `spanforge` as a required (`dependencies`) rather than optional dependency, consistent with the reference implementation intent.

---

[1.0.0]: https://github.com/spanforge/spanforge-secrets/releases/tag/v1.0.0
