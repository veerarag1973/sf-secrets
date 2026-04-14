# Quickstart

Get up and running in under 2 minutes.

## 1. Install

```bash
pip install spanforge-secrets spanforge
```

## 2. Scan a file

Create a test file:

```bash
echo "Contact sales@acme.com or call 555-867-5309" > sample.txt
```

Scan it:

```bash
spanforge-secrets scan sample.txt
```

Output:

```json
{
  "gate": "CI-Gate-01",
  "clean": false,
  "total_violations": 2,
  "results": [
    {
      "source": "sample.txt",
      "clean": false,
      "violation_count": 2,
      "scanned_strings": 1,
      "hits": [
        {
          "entity_type": "email",
          "path": "<text>",
          "match_count": 1,
          "sensitivity": "medium",
          "category": "pii"
        },
        {
          "entity_type": "phone",
          "path": "<text>",
          "match_count": 1,
          "sensitivity": "medium",
          "category": "pii"
        }
      ]
    }
  ]
}
```

The process exits with code `1` (violations found).

## 3. Scan from stdin

```bash
echo "My SSN is 123-45-6789" | spanforge-secrets scan --stdin
```

## 4. Scan a directory

```bash
spanforge-secrets scan data/
```

Directories are walked recursively. Binary files and files larger than 50 MB are skipped automatically.

## 5. Use in a CI pipeline

```yaml
# .github/workflows/secrets-gate.yml
- name: Spanforge Secrets Gate
  run: |
    pip install spanforge-secrets spanforge
    spanforge-secrets scan prompts/ data/
```

The step fails automatically when exit code is `1`.

---

## What's next?

- [Tutorial](tutorial.md) — step-by-step walkthrough of every feature
- [Entity Types](entity-types.md) — what the scanner detects and how
- [CI Integration](ci-integration.md) — GitHub Actions, GitLab CI, pre-commit hooks
- [CLI Reference](cli-reference.md) — all flags and options
