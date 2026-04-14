# Ignore Patterns

`spanforge-secrets` supports ignore files with glob patterns to exclude files from scanning. This is useful for excluding test fixtures, vendor data, and other files that are known to contain intentional PII.

---

## Auto-detection

The scanner automatically looks for `.spanforge-secretsignore` in the **current working directory** when you run a scan:

```bash
# Auto-detects .spanforge-secretsignore in $PWD
spanforge-secrets scan data/
```

Additionally, when scanning a directory, the scanner also looks for `.spanforge-secretsignore` **inside that directory root**.

---

## Explicit ignore file

Pass any file path with `--ignore-file`:

```bash
spanforge-secrets scan data/ --ignore-file ci/secrets-ignore.txt
spanforge-secrets scan data/ --ignore-file /etc/spanforge/global-ignore.txt
```

---

## File format

`.spanforge-secretsignore` is a plain text file:

- One glob pattern per line
- Lines starting with `#` are comments and are ignored
- Blank lines are ignored
- Patterns are matched with Python's `fnmatch` module (not full `gitignore` path matching)

### Example

```
# Test fixtures — contain intentional PII for unit tests
tests/fixtures/*
tests/data/*

# Vendor / third-party data not owned by this project
vendor/**
third_party/**

# Specific known-safe files
data/samples/anonymised_export.jsonl
data/legacy/reviewed_2024.json

# Ignore all CSV files everywhere
*.csv

# Ignore anything in any __pycache__ directory
**/__pycache__/*
```

---

## Pattern matching rules

Patterns are tested against two forms of each file path:

1. **Filename only** — just the last component (`sample.csv`)
2. **Relative path from the scan root** — using forward slashes (`data/samples/sample.csv`)

| Pattern | Matches |
|---|---|
| `*.csv` | Any file named `*.csv` regardless of directory |
| `tests/*` | Files directly inside `tests/` (not nested further) |
| `tests/**` | All files inside `tests/` at any depth |
| `vendor/**` | All files inside `vendor/` recursively |
| `fixtures/pii_test.jsonl` | Only that exact relative path from the scan root |
| `__pycache__/*` | Files inside any `__pycache__` directory (matched by filename of parent, not recursively) |

> **Note**: `fnmatch` does not support `**` for recursive matching in the same way as `gitignore`. The pattern `tests/**` matches files where the relative path starts with `tests/` — but for deep nesting, list sub-paths explicitly or use `tests/*` patterns if only immediate children matter.

---

## Combining multiple ignore sources

The scanner merges patterns from:
1. The explicit `--ignore-file` (if provided), **or** the auto-detected `.spanforge-secretsignore` in the CWD
2. An additional `.spanforge-secretsignore` found inside the scanned directory root

Both sets are applied uniformly across all files in the scan.

---

## Warnings on stderr

When a file is excluded by an ignore pattern, a message is written to stderr (not stdout, so it does not affect the JSON output):

```
spanforge-secrets: ignoring data/samples/reviewed.jsonl
```

This is intentional — it lets you audit what was excluded in CI logs.

---

## Checking your ignore patterns

Run a dry scan and look for `ignoring` messages on stderr:

```bash
spanforge-secrets scan data/ 2>&1 | grep ignoring
```

Or redirect stderr to a file for review:

```bash
spanforge-secrets scan data/ 2>scan-log.txt
grep "ignoring" scan-log.txt
```

---

## Common patterns reference

```
# Exclude test fixtures
tests/fixtures/*
tests/data/*

# Exclude vendor dependencies
vendor/**
node_modules/**
.venv/**

# Exclude build outputs
dist/**
build/**
__pycache__/**
*.pyc

# Exclude log files
*.log
logs/**

# Exclude large binary-like data files that are already skipped but also noisy
*.parquet
*.pkl
*.npy

# Exclude a specific reviewed file
data/exports/legacy_anonymised.jsonl
```
