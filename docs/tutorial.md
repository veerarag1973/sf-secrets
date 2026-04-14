# Tutorial

This tutorial walks through every major feature of `spanforge-secrets` from first install through advanced Python API usage and CI integration.

**Prerequisites**: Python 3.9+, `pip`, a terminal.

---

## Part 1 — Install and verify

### 1.1 Install

```bash
pip install spanforge-secrets spanforge
```

Check that the CLI is on your PATH:

```bash
spanforge-secrets --help
```

You should see the main help text listing `scan` and `verify-chain` sub-commands.

---

## Part 2 — Scanning text files

### 2.1 Create a sample prompt file

Save the following as `prompts/user_prompt.txt`:

```
You are a helpful assistant. My name is Alice Johnson and I live at
42 Maple Street, Springfield. My email is alice.johnson@example.com
and my phone is +1-555-867-5309. Please keep this confidential.
```

### 2.2 Run the scanner

```bash
spanforge-secrets scan prompts/user_prompt.txt
```

Expected output (formatted for readability):

```json
{
  "gate": "CI-Gate-01",
  "clean": false,
  "total_violations": 3,
  "results": [
    {
      "source": "prompts/user_prompt.txt",
      "clean": false,
      "violation_count": 3,
      "scanned_strings": 1,
      "hits": [
        { "entity_type": "address",       "path": "<text>", "match_count": 1, "sensitivity": "medium", "category": "pii" },
        { "entity_type": "email",         "path": "<text>", "match_count": 1, "sensitivity": "medium", "category": "pii" },
        { "entity_type": "phone",         "path": "<text>", "match_count": 1, "sensitivity": "medium", "category": "pii" }
      ]
    }
  ]
}
```

> The exact set of hits depends on the spanforge version you have installed.

The process exits with code **1** (violations found).

### 2.3 Clean input exits 0

```bash
echo "The capital of France is Paris." | spanforge-secrets scan --stdin
echo "Exit code: $?"   # should print: Exit code: 0
```

---

## Part 3 — Scanning JSON / JSONL training data

### 3.1 Create a JSONL training file

Save as `data/training.jsonl`:

```jsonl
{"role": "user",      "content": "My SSN is 123-45-6789."}
{"role": "assistant", "content": "I cannot help with that."}
{"role": "user",      "content": "Call me on +44 7911 123456."}
```

### 3.2 Scan the file

```bash
spanforge-secrets scan data/training.jsonl
```

Each line is parsed independently. The output `source` field includes the line number (e.g. `data/training.jsonl:1`).

### 3.3 Scan a JSON object file

Create `data/config.json`:

```json
{
  "api_key": "sk-proj-abc123XYZ456abcdefghijklmnopqrstuvwxyz0123456789",
  "user": {
    "email": "bob@example.com",
    "aadhaar": "9999 8888 7777"
  }
}
```

```bash
spanforge-secrets scan data/config.json
```

The scanner walks the entire nested structure. Paths in the output reflect the dot/bracket notation:

```json
{ "entity_type": "email",         "path": "user.email",   ... }
{ "entity_type": "openai_api_key","path": "api_key",      ... }
{ "entity_type": "aadhaar",       "path": "user.aadhaar", ... }
```

---

## Part 4 — Scanning a directory recursively

### 4.1 Scan the whole data/ folder

```bash
spanforge-secrets scan data/
```

All files under `data/` are visited recursively. Binary files (images, ZIPs, etc.) are automatically skipped.

### 4.2 Ignore specific files

Create `.spanforge-secretsignore` in the project root:

```
# Test fixtures — may contain intentional PII for unit tests
tests/fixtures/*

# Vendor / third-party data not owned by this project
vendor/**

# Specific file
data/legacy_export.jsonl
```

The ignore file is auto-detected when present in the current directory. You can also pass it explicitly:

```bash
spanforge-secrets scan data/ --ignore-file ci/secrets-ignore.txt
```

See [Ignore Patterns](ignore-patterns.md) for the full format reference.

---

## Part 5 — SARIF output for GitHub Code Scanning

### 5.1 Generate SARIF

```bash
spanforge-secrets scan data/ --format sarif > results.sarif
```

### 5.2 Upload to GitHub Advanced Security

```yaml
- name: Spanforge Secrets Gate
  run: spanforge-secrets scan data/ --format sarif > results.sarif || true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings appear as pull-request annotations in the **Security** → **Code scanning** tab.

---

## Part 6 — Pre-commit hook (diff mode)

Instead of scanning every file on every commit, scan only the **lines you are about to commit**.

### 6.1 Install pre-commit

```bash
pip install pre-commit
```

### 6.2 Add to `.pre-commit-config.yaml`

```yaml
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

### 6.3 Install the hook

```bash
pre-commit install
```

Now `git commit` will automatically run the scanner against your staged diff. The commit is blocked if a violation is found.

---

## Part 7 — Python API

### 7.1 Scan a dict payload

```python
from spanforge_secrets import scan_payload

data = {
    "user": {
        "name": "Alice",
        "email": "alice@example.com",
        "ssn": "123-45-6789",
    }
}

result = scan_payload(data, source="user_profile")
if not result.clean:
    print(f"Found {result.violation_count} violation(s) in '{result.source}':")
    for hit in result.hits:
        print(f"  [{hit.sensitivity}] {hit.entity_type} at {hit.path} ({hit.category})")
```

Output:

```
Found 2 violation(s) in 'user_profile':
  [medium] email at user.email (pii)
  [high]   ssn   at user.ssn   (pii)
```

### 7.2 Scan raw text

```python
from spanforge_secrets import scan_text

text = open("prompts/system_prompt.txt").read()
result = scan_text(text, source="system_prompt.txt")

print("clean:", result.clean)
print("scanned strings:", result.scanned)
```

### 7.3 Add custom patterns

```python
import re
from spanforge_secrets import scan_text

# Flag any internal employee IDs (EMP-XXXXXX)
custom = {"employee_id": re.compile(r"\bEMP-\d{6}\b")}

result = scan_text(
    "Assigned to EMP-001234.",
    extra_patterns=custom,
    extra_sensitivity={"employee_id": "medium"},
    source="ticket.txt",
)

for hit in result.hits:
    print(hit.entity_type, hit.sensitivity)   # employee_id  medium
```

### 7.4 Inspect the result object

```python
result = scan_payload({"key": "value"})

result.clean            # bool
result.violation_count  # int
result.scanned          # int — number of string values inspected
result.source           # str — label you passed in
result.hits             # list[PIIScanHit]
result.to_dict()        # JSON-serialisable dict
```

Each `PIIScanHit` has:

| Field | Type | Description |
|---|---|---|
| `entity_type` | `str` | e.g. `"email"`, `"openai_api_key"` |
| `path` | `str` | Dot-path inside JSON, or `"<text>"` for raw strings |
| `match_count` | `int` | Number of distinct matches at this path |
| `sensitivity` | `str` | `"high"`, `"medium"`, or `"low"` |
| `category` | `str` | `"pii"` or `"api_key"` |

---

## Part 8 — Verifying an audit chain

`spanforge-secrets verify-chain` checks the HMAC integrity of an audit log produced by `spanforge.signing`.

### 8.1 The audit log format

Each line must be a JSON object with at least the fields required by `spanforge.event.Event` (including an `sig` field written by `spanforge.signing.sign()`).

### 8.2 Verify

```bash
spanforge-secrets verify-chain audit.jsonl --secret "$AUDIT_HMAC_SECRET"
```

Output on a valid chain:

```json
{
  "valid": true,
  "first_tampered": null,
  "gaps": [],
  "tampered_count": 0,
  "tombstone_count": 0
}
```

Exit code is `0` for a valid chain and `1` if tampering or gaps are detected.

See [Verify Chain](verify-chain.md) for a detailed guide including tamper-detection examples.

---

## Part 9 — Putting it all together: pipeline integration

A complete GitHub Actions workflow that gates on secrets, emits SARIF, and uploads findings:

```yaml
name: Secrets Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install scanners
        run: pip install spanforge-secrets spanforge

      - name: Run Spanforge Secrets Gate
        run: |
          spanforge-secrets scan prompts/ data/ --format sarif > secrets.sarif
        continue-on-error: true   # let the upload step always run

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: secrets.sarif

      - name: Fail on violations
        run: spanforge-secrets scan prompts/ data/
```

---

## Summary

You have learned how to:

- Scan text files, JSON, and JSONL data from the CLI
- Recursively scan directories with ignore patterns
- Emit SARIF for GitHub Code Scanning
- Use diff mode as a pre-commit hook
- Call `scan_payload()` and `scan_text()` from Python
- Add custom patterns with `extra_patterns`
- Verify HMAC audit chains with `verify-chain`
- Compose a complete CI/CD pipeline

Next steps:

- [CLI Reference](cli-reference.md) — complete flag documentation
- [API Reference](api-reference.md) — type signatures and advanced parameters
- [Entity Types](entity-types.md) — understand each detector and its validators
