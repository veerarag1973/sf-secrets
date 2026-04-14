# CLI Reference

Full reference for the `spanforge-secrets` command-line interface.

---

## Usage

```
spanforge-secrets COMMAND [OPTIONS] [ARGS]
```

### Commands

| Command | Description |
|---|---|
| [`scan`](#scan) | Scan files or stdin for PII and exposed API keys |
| [`verify-chain`](#verify-chain) | Verify the HMAC audit chain of a JSONL event log |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All inputs are clean — no violations found |
| `1` | At least one violation detected (PII or exposed API key); or the audit chain is invalid / tampered |
| `2` | Usage or argument error (e.g. no paths supplied, unknown flag) |
| `3` | I/O or format error (unreadable file, invalid JSON, `git` not found) |

---

## `scan`

Scan one or more files, directories, or stdin for PII and API key leakage.

```
spanforge-secrets scan [OPTIONS] [PATH ...]
```

### Positional arguments

| Argument | Description |
|---|---|
| `PATH ...` | Files or directories to scan. Directories are walked recursively. Omit when using `--stdin` or `--diff`. |

### Options

#### `--stdin`

Read from standard input instead of files. Treats the entire input as a plain UTF-8 text blob.

```bash
echo "alice@example.com" | spanforge-secrets scan --stdin
cat prompts.txt | spanforge-secrets scan --stdin
```

Mutually exclusive with `PATH` and `--diff`.

---

#### `--diff`

Scan only the lines added in `git diff --staged`. Designed for use as a pre-commit hook. Only lines beginning with `+` (excluding `+++` diff headers) are scanned.

```bash
spanforge-secrets scan --diff
```

Requires `git` to be installed and the working directory to be inside a git repository. Exits `3` if `git` is not found or returns a non-zero status.

---

#### `--format {json,sarif}`

Output format. Default: `json`.

| Value | Description |
|---|---|
| `json` | CI-Gate-01 JSON summary (default) — see [JSON Output Format](#json-output-format) |
| `sarif` | SARIF 2.1.0 document — see [SARIF Output Format](#sarif-output-format) |

```bash
spanforge-secrets scan data/ --format sarif > results.sarif
```

---

#### `--ignore-file FILE`

Path to a file containing fnmatch glob patterns to ignore (one pattern per line). Lines starting with `#` are treated as comments.

```bash
spanforge-secrets scan data/ --ignore-file ci/secrets-ignore.txt
```

If this flag is omitted, the scanner auto-detects `.spanforge-secretsignore` in the current working directory. See [Ignore Patterns](ignore-patterns.md).

---

#### `--no-scan-raw`

Disable raw string regex scanning. Returns a clean (empty) result for all inputs. Default is enabled (`--scan-raw`).

> **Note**: this flag exists for API compatibility with `spanforge.redact.contains_pii(scan_raw=False)`. In normal usage, leave raw scanning enabled (the default).

---

#### `--scan-raw`

Explicitly enable raw string regex scanning (this is the default and does not need to be specified).

---

### Supported file types

| Extension | Handling |
|---|---|
| `.json` | Parsed as a JSON object; entire structure is walked recursively |
| `.jsonl`, `.ndjson` | Parsed line-by-line; each line is a separate JSON object |
| Anything else | Treated as UTF-8 plain text |

Files with known binary extensions (`.png`, `.pdf`, `.zip`, `.exe`, etc.) are automatically skipped. Files larger than 50 MB are also skipped with a warning on stderr.

Non-UTF-8 files produce a warning on stderr and are skipped (not an error).

---

## `verify-chain`

Verify the HMAC integrity of a JSONL audit-log file.

```
spanforge-secrets verify-chain AUDIT_LOG --secret HMAC_SECRET
```

### Positional arguments

| Argument | Description |
|---|---|
| `AUDIT_LOG` | Path to the JSONL audit log. Each line must be a valid JSON object representing a `spanforge.event.Event`. Blank lines are skipped. |

### Options

#### `--secret HMAC_SECRET`

The HMAC signing secret that was used when the audit chain was created. This is passed directly to `spanforge.signing.verify_chain(org_secret=...)`. If omitted, the `SPANFORGE_HMAC_SECRET` environment variable is used. Exits `2` if neither is provided.

---

### Output

Prints a JSON object to stdout:

```json
{
  "valid": true,
  "first_tampered": null,
  "gaps": [],
  "tampered_count": 0,
  "tombstone_count": 0
}
```

| Field | Type | Description |
|---|---|---|
| `valid` | `bool` | `true` if the chain is intact |
| `first_tampered` | `int \| null` | 0-based index of the first tampered event, or `null` |
| `gaps` | `list[int]` | List of positions where chain linkage breaks |
| `tampered_count` | `int` | Number of events with invalid signatures |
| `tombstone_count` | `int` | Number of tombstone events in the chain |

Exit code is `0` when `valid` is `true`, `1` otherwise.

---

## JSON Output Format

The `scan` sub-command emits a single JSON object to stdout.

```json
{
  "gate": "CI-Gate-01",
  "clean": false,
  "total_violations": 3,
  "results": [
    {
      "source": "data/training.jsonl",
      "clean": false,
      "violation_count": 2,
      "scanned_strings": 120,
      "hits": [
        {
          "entity_type": "email",
          "path": "messages[3].content",
          "match_count": 1,
          "sensitivity": "medium",
          "category": "pii"
        },
        {
          "entity_type": "ssn",
          "path": "messages[7].content",
          "match_count": 1,
          "sensitivity": "high",
          "category": "pii"
        }
      ]
    },
    {
      "source": "prompts/system.txt",
      "clean": false,
      "violation_count": 1,
      "scanned_strings": 1,
      "hits": [
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

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `gate` | `string` | Always `"CI-Gate-01"` |
| `clean` | `bool` | `true` when `total_violations == 0` |
| `total_violations` | `int` | Sum of all per-file violation counts |
| `results` | `array` | One entry per scanned source |

### Per-result fields

| Field | Type | Description |
|---|---|---|
| `source` | `string` | File path, `"<stdin>"`, or `"diff:path/to/file"` |
| `clean` | `bool` | `true` when this source has no violations |
| `violation_count` | `int` | Number of hits for this source |
| `scanned_strings` | `int` | Number of string values inspected |
| `hits` | `array` | Detection hits — see below |

### Hit fields

| Field | Type | Values |
|---|---|---|
| `entity_type` | `string` | `email`, `phone`, `ssn`, `credit_card`, `ip_address`, `uk_national_insurance`, `aadhaar`, `pan`, `date_of_birth`, `address`, `openai_api_key`, `anthropic_api_key`, `aws_access_key_id`, `aws_secret_access_key`, `gcp_service_account_key` |
| `path` | `string` | Dot/bracket JSON path, or `"<text>"` for raw strings |
| `match_count` | `int` | Number of distinct regex matches |
| `sensitivity` | `string` | `"high"`, `"medium"`, or `"low"` |
| `category` | `string` | `"pii"` or `"api_key"` |

> **Privacy**: matched values are never included in the output — only type, path, count, and sensitivity level.

---

## SARIF Output Format

The SARIF 2.1.0 output is compatible with **GitHub Advanced Security / Code Scanning**. When uploaded via `actions/upload-sarif`, findings appear as pull-request annotations.

```bash
spanforge-secrets scan data/ --format sarif > results.sarif
```

The SARIF document maps sensitivity levels to SARIF severities:

| Sensitivity | SARIF level |
|---|---|
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |

See [CI Integration](ci-integration.md) for a complete GitHub Actions workflow that uploads SARIF results.

---

## Stderr messages

The CLI writes informational messages to stderr (not captured in the JSON output):

| Message | Cause |
|---|---|
| `skipping binary file: <path>` | File has a binary extension |
| `skipping <path> (X MB > 50 MB limit)` | File exceeds the 50 MB size guard |
| `skipping non-UTF-8 file: <path>` | File cannot be decoded as UTF-8 |
| `ignoring <path>` | File matches an ignore pattern |

Errors (fatal) are written to stderr and cause a non-zero exit:

```
spanforge-secrets: error: <message>
```
