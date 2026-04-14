# spanforge-secrets Documentation

**spanforge-secrets** is CI Gate 01 for the [Spanforge](https://github.com/spanforge/spanforge) compliance pipeline. It scans prompt files, training data, and arbitrary text/JSON for PII (10 entity types) and exposed API keys, then exits `1` if any violation is found.

This package is a **reference implementation** built on top of the `spanforge` framework.

---

## Documentation Contents

| Document | Description |
|---|---|
| [Installation](installation.md) | Requirements, install commands, and dev setup |
| [Quickstart](quickstart.md) | Scan your first file in under 2 minutes |
| [Tutorial](tutorial.md) | Step-by-step hands-on guide covering all major features |
| [CLI Reference](cli-reference.md) | Full reference for all flags, sub-commands, and exit codes |
| [API Reference](api-reference.md) | Python API — `scan_payload()`, `scan_text()`, `verify_chain_file()` |
| [Entity Types](entity-types.md) | All 15 detectable entity types with examples and validators |
| [CI Integration](ci-integration.md) | GitHub Actions, GitLab CI, pre-commit hook setup |
| [Verify Chain](verify-chain.md) | HMAC audit-chain verification guide |
| [Ignore Patterns](ignore-patterns.md) | `.spanforge-secretsignore` file format and glob patterns |
| [Contributing](contributing.md) | Development workflow, tests, and code standards |
| [Changelog](changelog.md) | Version history and release notes |

---

## At a Glance

```bash
# Install
pip install spanforge-secrets spanforge

# Scan files
spanforge-secrets scan prompts/ training_data.jsonl

# Scan from stdin
echo "Contact alice@corp.com or 555-123-4567" | spanforge-secrets scan --stdin

# Verify an audit-chain log
spanforge-secrets verify-chain audit.jsonl --secret "$HMAC_SECRET"
```

Exit codes: `0` clean · `1` violations found · `2` usage error · `3` I/O / format error

---

## Architecture Overview

```
spanforge-secrets
├── scanner.py        Core scanning engine (scan_payload, scan_text)
├── chain.py          File I/O wrapper around spanforge.signing.verify_chain
├── cli.py            CLI entry point (scan + verify-chain sub-commands)
├── _patterns.py      Merged PII + API key patterns (extends spanforge.redact)
├── _luhn.py          Re-export shim → spanforge.redact._luhn_check
└── _verhoeff.py      Re-export shim → spanforge.redact._verhoeff_check
```

The scanner builds on `spanforge.redact` patterns (email, phone, SSN, credit card, IP, UKNI, Aadhaar, PAN, date of birth, address) and adds 5 API key patterns unique to this package.
