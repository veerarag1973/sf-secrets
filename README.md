# spanforge-secrets

**CI Gate 01** for the [Spanforge](https://github.com/spanforge/spanforge) compliance pipeline.
Scans prompt files, training data, and arbitrary text/JSON for **10 PII entity types** and
**5 exposed API key formats**. Exits `1` if any violation is found. Outputs structured JSON
with hit details, file path, and sensitivity level.

This is a **reference implementation** built on top of the `spanforge` framework.

---

## Quick install

```bash
pip install spanforge-secrets spanforge
```

## Quick scan

```bash
# Scan files
spanforge-secrets scan prompts/ data/training.jsonl

# Scan from stdin
echo "contact ceo@corp.com" | spanforge-secrets scan --stdin

# Verify an HMAC audit-chain log
spanforge-secrets verify-chain audit.jsonl --secret "$HMAC_SECRET"
```

Exit codes: `0` clean · `1` violations found · `2` usage error · `3` I/O error

---

## Documentation

| Document | Description |
|---|---|
| [docs/installation.md](docs/installation.md) | Requirements, install commands, dev setup |
| [docs/quickstart.md](docs/quickstart.md) | Scan your first file in 2 minutes |
| [docs/tutorial.md](docs/tutorial.md) | Step-by-step walkthrough of every feature |
| [docs/cli-reference.md](docs/cli-reference.md) | All flags, sub-commands, and exit codes |
| [docs/api-reference.md](docs/api-reference.md) | Python API — `scan_payload()`, `scan_text()`, `verify_chain_file()` |
| [docs/entity-types.md](docs/entity-types.md) | All 15 detectable entity types with examples |
| [docs/ci-integration.md](docs/ci-integration.md) | GitHub Actions, GitLab CI, pre-commit hooks |
| [docs/verify-chain.md](docs/verify-chain.md) | HMAC audit-chain verification guide |
| [docs/ignore-patterns.md](docs/ignore-patterns.md) | `.spanforge-secretsignore` file format |
| [docs/contributing.md](docs/contributing.md) | Development workflow and code standards |
| [docs/changelog.md](docs/changelog.md) | Version history |

---

## Detected entity types

### PII (10 types)

| Entity type             | Sensitivity | Validator              |
|-------------------------|-------------|------------------------|
| `email`                 | medium      | regex                  |
| `phone`                 | medium      | regex                  |
| `ssn`                   | high        | regex + SSA validation |
| `credit_card`           | high        | regex + Luhn           |
| `ip_address`            | low         | regex                  |
| `uk_national_insurance` | low         | regex                  |
| `aadhaar`               | high        | regex + Verhoeff       |
| `pan`                   | high        | regex                  |
| `date_of_birth`         | medium      | regex + calendar check |
| `address`               | medium      | regex                  |

### API Keys (5 platforms)

| Entity type                | Sensitivity | Pattern                       |
|----------------------------|-------------|-------------------------------|
| `openai_api_key`           | high        | `sk-...` / `sk-proj-...`      |
| `anthropic_api_key`        | high        | `sk-ant-...`                  |
| `aws_access_key_id`        | high        | `AKIA...` / `ASIA...`         |
| `aws_secret_access_key`    | high        | context-sensitive 40-char key |
| `gcp_service_account_key`  | high        | JSON private key marker       |

---

## CLI reference

```bash
# Scan one or more files (.txt, .json, .jsonl supported)
spanforge-secrets scan path/to/prompt.txt training_data.jsonl

# Scan a directory recursively
spanforge-secrets scan data/

# Read from stdin
echo "contact ceo@corp.com" | spanforge-secrets scan --stdin

# SARIF output for GitHub Advanced Security
spanforge-secrets scan data/ --format sarif > results.sarif

# Scan only staged git changes (pre-commit hook)
spanforge-secrets scan --diff

# Exclude files matching patterns
spanforge-secrets scan data/ --ignore-file ci/secrets-ignore.txt

# Verify an HMAC audit-chain log
spanforge-secrets verify-chain audit.jsonl --secret "$HMAC_SECRET"
```

### Exit codes

| Code | Meaning                                         |
|------|-------------------------------------------------|
| `0`  | All inputs clean                                |
| `1`  | At least one violation detected                 |
| `2`  | Usage / argument error                          |
| `3`  | I/O or format error (unreadable file, bad JSON) |

---

## JSON output format

```json
{
  "gate": "CI-Gate-01",
  "clean": false,
  "total_violations": 2,
  "results": [
    {
      "source": "prompts/user_prompt.txt",
      "clean": false,
      "violation_count": 2,
      "scanned_strings": 5,
      "hits": [
        {
          "entity_type": "email",
          "path": "<text>",
          "match_count": 1,
          "sensitivity": "medium",
          "category": "pii"
        },
        {
          "entity_type": "openai_api_key",
          "path": "<text>",
          "match_count": 1,
          "sensitivity": "high",
          "category": "api_key"
        }
      ]
    }
  ]
}
```

Matched values are never included — only type, path, count, and sensitivity level.

---

## Python API

```python
from spanforge_secrets import scan_payload, scan_text

# Scan a dict payload (parsed training JSONL, config files, etc.)
result = scan_payload({"user": {"email": "alice@example.com"}})
if not result.clean:
    for hit in result.hits:
        print(hit.entity_type, hit.path, hit.sensitivity, hit.category)

# Scan raw text (prompt files, arbitrary strings)
result = scan_text(open("prompt.txt").read(), source="prompt.txt")
print(result.clean, result.violation_count)

# Add custom patterns
import re
result = scan_text(
    "Assigned to EMP-001234.",
    extra_patterns={"employee_id": re.compile(r"\bEMP-\d{6}\b")},
    extra_sensitivity={"employee_id": "medium"},
)
```

See [docs/api-reference.md](docs/api-reference.md) for the full API including `verify_chain_file()`.

---

## CI integration (GitHub Actions)

```yaml
- name: Spanforge Secrets Gate
  run: |
    pip install spanforge-secrets spanforge
    spanforge-secrets scan prompts/ data/training.jsonl
```

The step fails automatically when exit code is `1`.

### With SARIF upload

```yaml
- name: Run scan (SARIF)
  run: spanforge-secrets scan prompts/ data/ --format sarif > secrets.sarif
  continue-on-error: true

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secrets.sarif

- name: Fail on violations
  run: spanforge-secrets scan prompts/ data/
```

See [docs/ci-integration.md](docs/ci-integration.md) for GitLab CI and pre-commit hook setups.

---

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: spanforge-secrets
        name: Spanforge Secrets Gate
        language: system
        entry: spanforge-secrets scan --diff
        pass_filenames: false
        stages: [pre-commit]
```

---

## Platform source

Built on top of:
- `spanforge.redact` — base PII patterns, Luhn check, Verhoeff check
- `spanforge.signing` — `verify_chain()` for audit-chain verification

Extensions unique to this package: `date_of_birth` pattern, `address` pattern,
5 API key patterns, `scan_text()`, `PIIScanHit.category`, `PIIScanResult.source`,
file I/O chain verification, and the complete CLI.

This package is a reference implementation of the `spanforge` framework.
`spanforge>=2.0.0` is a required runtime dependency.
