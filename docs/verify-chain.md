# Verify Chain

`spanforge-secrets verify-chain` reads a JSONL audit-log file and delegates cryptographic verification to `spanforge.signing.verify_chain()`. It checks every event's HMAC signature and the `prev_id` chain linkage.

---

## Overview

A `spanforge` audit chain is a sequence of `Event` objects where each event contains:
- A unique `event_id`
- A `prev_id` pointing to the previous event's `event_id`
- An `sig` HMAC signature that signs the event content

Any modification to an event (content, ordering, or deletion) breaks the chain. `verify-chain` detects:

- **Tampered events** — events whose HMAC signature does not match
- **Gaps in the chain** — events where `prev_id` does not match the previous event's `event_id`

---

## CLI usage

```bash
spanforge-secrets verify-chain AUDIT_LOG --secret HMAC_SECRET
```

### Arguments

| Argument | Description |
|---|---|
| `AUDIT_LOG` | Path to the JSONL file. Each non-blank line must be a valid JSON object. |
| `--secret` | The HMAC signing key used when the chain was created. If omitted, falls back to the `SPANFORGE_HMAC_SECRET` environment variable. Exits `2` if neither is provided. |

### Output

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
| `valid` | `bool` | `true` if the entire chain is intact |
| `first_tampered` | `int \| null` | 0-based index of the first tampered event |
| `gaps` | `list[int]` | Positions where `prev_id` chain linkage breaks |
  | `tampered_count` | `int` | Number of events with invalid HMAC signatures |
| `tombstone_count` | `int` | Number of tombstone events in the log |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Chain is valid |
| `1` | Chain has tampering or gaps |
| `3` | File not found, file too large, not valid UTF-8, invalid JSON, or `spanforge` not installed |

---

## Store the HMAC secret securely

The HMAC secret must match what was used during chain creation. Store it as a CI/CD secret:

```bash
# Pass via --secret flag
spanforge-secrets verify-chain audit.jsonl --secret "$AUDIT_HMAC_SECRET"

# Or set the environment variable (--secret can be omitted)
export SPANFORGE_HMAC_SECRET="$AUDIT_HMAC_SECRET"
spanforge-secrets verify-chain audit.jsonl

# GitHub Actions — either approach works
spanforge-secrets verify-chain audit.jsonl --secret "${{ secrets.AUDIT_HMAC_SECRET }}"
```

Never hard-code the HMAC secret in scripts or workflows committed to source control.

---

## Tamper detection example

Given an audit log where the second event's content has been modified, the output will be:

```json
{
  "valid": false,
  "first_tampered": 1,
  "gaps": [],
  "tampered_count": 1,
  "tombstone_count": 0
}
```

- `first_tampered: 1` — the event at 0-based index 1 has an invalid signature
- `gaps: []` — the chain linkage is intact (only the content was modified, not the ordering)

---

## Gap detection example

If an event was deleted from the middle of the log, `gaps` will be non-empty:

```json
{
  "valid": false,
  "first_tampered": 0,
  "gaps": [2],
  "tampered_count": 3,
  "tombstone_count": 0
}
```

Interpretation: the event at position 2 is missing, and all subsequent events fail verification because their `prev_id` no longer matches.

---

## Python API

```python
from spanforge_secrets import verify_chain_file

result = verify_chain_file("audit.jsonl", org_secret="my-secret-key")

if result["valid"]:
    print("Audit chain is intact.")
else:
    print(f"Chain integrity failure!")
    print(f"  tampered_count  : {result['tampered_count']}")
    print(f"  first_tampered  : {result['first_tampered']}")
    print(f"  gaps            : {result['gaps']}")
```

### Error handling

```python
from spanforge_secrets import verify_chain_file

try:
    result = verify_chain_file("audit.jsonl", org_secret="my-secret-key")
except FileNotFoundError:
    print("Audit log file not found.")
except ValueError as e:
    print(f"Invalid audit log: {e}")
except ImportError:
    print("spanforge package is required. Install with: pip install spanforge")
```

---

## File format

Each line of the JSONL file must be a JSON object with the fields required by `spanforge.event.Event`. Blank lines are silently skipped.

Example (2-event chain):

```jsonl
{"event_id": "evt-001", "prev_id": null, "kind": "llm.request", "ts": 1700000001.0, "payload": {}, "sig": "abc123..."}
{"event_id": "evt-002", "prev_id": "evt-001", "kind": "llm.response", "ts": 1700000002.0, "payload": {}, "sig": "def456..."}
```

### File size limit

Files larger than 50 MB are rejected with a `ValueError`. This prevents accidentally loading enormous logs into memory.

---

## Integration in GitHub Actions

```yaml
- name: Verify Audit Chain
  run: |
    spanforge-secrets verify-chain logs/audit.jsonl --secret "$AUDIT_HMAC_SECRET"
  env:
    AUDIT_HMAC_SECRET: ${{ secrets.AUDIT_HMAC_SECRET }}
```

This step fails (`exit 1`) if the chain is tampered, blocking deployment of unverified audit logs.
