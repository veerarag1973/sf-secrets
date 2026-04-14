# CI Integration

Integrate `spanforge-secrets` into your CI/CD pipeline to automatically block merges or deployments that contain PII or exposed API keys.

---

## GitHub Actions

### Basic gate (fail on violations)

```yaml
# .github/workflows/secrets-gate.yml
name: Secrets Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    name: PII & Secrets Scan
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install scanners
        run: pip install spanforge-secrets spanforge

      - name: Run Spanforge Secrets Gate
        run: spanforge-secrets scan prompts/ data/
```

The job fails automatically when the scanner exits with code `1`.

---

### With SARIF upload (GitHub Advanced Security)

Upload findings to GitHub Code Scanning so they appear as pull-request annotations and in the **Security** tab.

```yaml
name: Secrets Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    name: PII & Secrets Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write    # required for upload-sarif
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install scanners
        run: pip install spanforge-secrets spanforge

      - name: Run scan (SARIF output)
        # continue-on-error so the upload step always runs
        run: spanforge-secrets scan prompts/ data/ --format sarif > secrets.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: secrets.sarif

      - name: Fail on violations
        run: spanforge-secrets scan prompts/ data/
```

SARIF severity mapping:

| Sensitivity | SARIF level | GitHub annotation |
|---|---|---|
| `high` | `error` | Red blocking annotation |
| `medium` | `warning` | Yellow annotation |
| `low` | `note` | Blue informational annotation |

---

### Caching pip dependencies

```yaml
      - name: Cache pip
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{ runner.os }}-pip-spanforge-${{ hashFiles('**/requirements*.txt') }}

      - name: Install scanners
        run: pip install spanforge-secrets spanforge
```

---

### Pin to a specific version

```yaml
      - name: Install scanners
        run: pip install "spanforge-secrets==1.0.0" "spanforge>=2.0.0"
```

---

## GitLab CI

### Basic gate

```yaml
# .gitlab-ci.yml
secrets-gate:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install spanforge-secrets spanforge
  script:
    - spanforge-secrets scan prompts/ data/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### With artifact upload

```yaml
secrets-gate:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install spanforge-secrets spanforge
  script:
    - spanforge-secrets scan prompts/ data/ --format sarif > secrets.sarif || true
    - spanforge-secrets scan prompts/ data/
  artifacts:
    when: always
    paths:
      - secrets.sarif
    expire_in: 7 days
```

---

## Pre-commit hook

### Setup

Install `pre-commit`:

```bash
pip install pre-commit
```

Add to `.pre-commit-config.yaml`:

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

Install the hook:

```bash
pre-commit install
```

The scanner now runs automatically on every `git commit` and blocks the commit if violations are found in the staged diff.

### Run manually against all files

```bash
pre-commit run spanforge-secrets --all-files
```

---

## Docker image

Build a lightweight scanner image:

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir spanforge-secrets spanforge

ENTRYPOINT ["spanforge-secrets"]
```

Build and run:

```bash
docker build -t spanforge-secrets:latest .
docker run --rm -v "$PWD:/workspace" -w /workspace spanforge-secrets:latest scan data/
```

---

## Exit code handling

All CI systems that treat non-zero exit codes as failures will work correctly out of the box:

| Scenario | Exit code | CI result |
|---|---|---|
| No violations found | `0` | Pass |
| PII or API key found | `1` | Fail |
| Wrong arguments | `2` | Fail |
| Unreadable file / bad JSON | `3` | Fail |

---

## Suppressing known violations

Use an [ignore file](ignore-patterns.md) to exclude known false positives or intentional test fixtures:

```
# .spanforge-secretsignore

# Test fixtures contain intentional PII for unit tests
tests/fixtures/*
tests/data/*

# Anonymised sample data — reviewed and approved
data/samples/anonymised_chats.jsonl
```

The ignore file is auto-detected in the current working directory, or pass it explicitly:

```bash
spanforge-secrets scan data/ --ignore-file ci/secrets-ignore.txt
```

---

## Combine scan + verify-chain in one workflow

```yaml
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install
        run: pip install spanforge-secrets spanforge

      - name: PII & Secrets Gate
        run: spanforge-secrets scan prompts/ data/

      - name: Verify Audit Chain
        run: |
          spanforge-secrets verify-chain audit.jsonl --secret "${{ secrets.AUDIT_HMAC_SECRET }}"
        env:
          AUDIT_HMAC_SECRET: ${{ secrets.AUDIT_HMAC_SECRET }}
```
