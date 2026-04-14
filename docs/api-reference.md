# API Reference

Complete Python API for `spanforge_secrets`.

---

## Installation

```python
from spanforge_secrets import scan_payload, scan_text, verify_chain_file
from spanforge_secrets import PIIScanHit, PIIScanResult
```

---

## `scan_payload()`

Scan a nested dict/list structure (JSON payloads) for PII and exposed API keys.

```python
def scan_payload(
    payload: dict[str, Any],
    *,
    extra_patterns: dict[str, re.Pattern[str]] | None = None,
    extra_sensitivity: dict[str, str] | None = None,
    max_depth: int = 10,
    source: str = "<payload>",
    scan_raw: bool = True,
) -> PIIScanResult:
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `payload` | `dict[str, Any]` | — | The dictionary to scan. Lists and nested dicts are walked recursively. |
| `extra_patterns` | `dict[str, Pattern] \| None` | `None` | Additional compiled regex patterns. Keys become `entity_type` values in hits. Treated as category `"pii"` with `"medium"` sensitivity unless overridden. |
| `extra_sensitivity` | `dict[str, str] \| None` | `None` | Sensitivity overrides for labels in `extra_patterns`. Valid values: `"high"`, `"medium"`, `"low"`. |
| `max_depth` | `int` | `10` | Maximum nesting depth to walk. Must be ≥ 0. Raises `ValueError` if negative. |
| `source` | `str` | `"<payload>"` | Label written to the `source` field of the returned `PIIScanResult`. |
| `scan_raw` | `bool` | `True` | When `False`, returns a clean empty result immediately (exists for API-compatibility with `spanforge.redact.contains_pii`). |

### Returns

`PIIScanResult` — see [PIIScanResult](#piiscanresult).

### Raises

| Exception | When |
|---|---|
| `ValueError` | `max_depth < 0` |

### Example

```python
from spanforge_secrets import scan_payload

data = {
    "user": {
        "name": "Alice",
        "email": "alice@example.com",
        "credit_card": "4111 1111 1111 1111",
    },
    "metadata": {
        "api_key": "sk-proj-abc123XYZdefghijklmnopqrstuvwxyz0123456789AB",
    }
}

result = scan_payload(data, source="user_record")

print(result.clean)           # False
print(result.violation_count) # 3

for hit in result.hits:
    print(f"{hit.path:30} {hit.entity_type:20} [{hit.sensitivity}]")
# user.email                     email                [medium]
# user.credit_card               credit_card          [high]
# metadata.api_key               openai_api_key       [high]
```

### Walk path notation

| Structure | Path example |
|---|---|
| Top-level key | `user` |
| Nested key | `user.email` |
| List element | `messages[2]` |
| Nested list element | `messages[2].content` |
| Top-level list element (root is a list) | `__root__[0]` |

---

## `scan_text()`

Scan a raw string for PII and exposed API keys.

```python
def scan_text(
    text: str,
    *,
    extra_patterns: dict[str, re.Pattern[str]] | None = None,
    extra_sensitivity: dict[str, str] | None = None,
    source: str = "<text>",
    scan_raw: bool = True,
) -> PIIScanResult:
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `text` | `str` | — | The text to scan. |
| `extra_patterns` | `dict[str, Pattern] \| None` | `None` | Additional compiled regex patterns. |
| `extra_sensitivity` | `dict[str, str] \| None` | `None` | Sensitivity overrides for labels in `extra_patterns`. |
| `source` | `str` | `"<text>"` | Label written to the `source` field of the returned result. |
| `scan_raw` | `bool` | `True` | When `False`, returns a clean empty result immediately. |

### Returns

`PIIScanResult`. Hits always have `path = "<text>"`.

### Example

```python
from spanforge_secrets import scan_text

text = """
System prompt for customer service bot.
Do not share internal keys. The staging key is sk-ant-api03-abc123XYZ.
"""

result = scan_text(text, source="system_prompt.txt")

print(result.clean)                  # False
print(result.hits[0].entity_type)    # anthropic_api_key
print(result.hits[0].sensitivity)    # high
print(result.hits[0].category)       # api_key
```

### Adding custom patterns

```python
import re
from spanforge_secrets import scan_text

custom = {
    "employee_id": re.compile(r"\bEMP-\d{6}\b"),
    "project_code": re.compile(r"\bPROJ-[A-Z]{3}\d{4}\b"),
}

result = scan_text(
    "Assigned to EMP-001234 on project PROJ-ABC0001.",
    extra_patterns=custom,
    extra_sensitivity={"employee_id": "medium", "project_code": "low"},
)

for hit in result.hits:
    print(hit.entity_type, hit.sensitivity)
# employee_id  medium
# project_code low
```

---

## `verify_chain_file()`

Verify an audit-chain JSONL file and return a result dict.

```python
def verify_chain_file(
    path: str | pathlib.Path,
    org_secret: str,
) -> dict[str, Any]:
```

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `path` | `str \| Path` | Path to the JSONL audit-log file. |
| `org_secret` | `str` | HMAC signing key used when the chain was created. |

### Returns

A `dict` with the following keys:

| Key | Type | Description |
|---|---|---|
| `valid` | `bool` | `True` if the entire chain is intact |
| `first_tampered` | `int \| None` | 0-based index of the first tampered event, or `None` |
| `gaps` | `list[int]` | Positions where chain linkage breaks |
| `tampered_count` | `int` | Number of events with invalid signatures |
| `tombstone_count` | `int` | Number of tombstone events |

### Raises

| Exception | When |
|---|---|
| `ImportError` | `spanforge` package is not installed |
| `FileNotFoundError` | `path` does not exist |
| `ValueError` | File is not valid UTF-8, exceeds 50 MB, contains invalid JSON, or an event cannot be deserialised |

### Example

```python
from spanforge_secrets import verify_chain_file

result = verify_chain_file("audit.jsonl", org_secret="my-secret-key")

if result["valid"]:
    print("Chain is intact.")
else:
    print(f"Tampering detected! {result['tampered_count']} event(s) affected.")
    print(f"First tampered index: {result['first_tampered']}")
    print(f"Gaps at positions: {result['gaps']}")
```

---

## `PIIScanHit`

A frozen dataclass representing a single detection hit.

```python
@dataclasses.dataclass(frozen=True)
class PIIScanHit:
    entity_type: str
    path: str
    match_count: int
    sensitivity: str
    category: str
```

### Fields

| Field | Type | Values |
|---|---|---|
| `entity_type` | `str` | See [Entity Types](entity-types.md) |
| `path` | `str` | Dot/bracket JSON path, or `"<text>"` for raw-string scans |
| `match_count` | `int` | Number of distinct regex matches at this path |
| `sensitivity` | `str` | `"high"` \| `"medium"` \| `"low"` |
| `category` | `str` | `"pii"` \| `"api_key"` |

---

## `PIIScanResult`

A frozen dataclass aggregating the results of a scan operation.

```python
@dataclasses.dataclass(frozen=True)
class PIIScanResult:
    hits: list[PIIScanHit]
    scanned: int
    source: str = "<unknown>"
```

### Fields

| Field | Type | Description |
|---|---|---|
| `hits` | `list[PIIScanHit]` | All detection hits |
| `scanned` | `int` | Number of string values inspected |
| `source` | `str` | Label passed via the `source` parameter |

### Properties

#### `clean`

```python
@property
def clean(self) -> bool: ...
```

`True` when `len(hits) == 0`.

#### `violation_count`

```python
@property
def violation_count(self) -> int: ...
```

`len(hits)`.

### Methods

#### `to_dict()`

```python
def to_dict(self) -> dict[str, Any]: ...
```

Returns a JSON-serialisable representation matching the per-result block in the CLI JSON output:

```python
{
    "source": "data/file.jsonl",
    "clean": False,
    "violation_count": 2,
    "scanned_strings": 45,
    "hits": [
        {
            "entity_type": "email",
            "path": "user.contact",
            "match_count": 1,
            "sensitivity": "medium",
            "category": "pii"
        }
    ]
}
```

---

## Pattern constants

The following are exported from `spanforge_secrets` for introspection and extension, but are primarily intended for internal use.

| Name | Type | Description |
|---|---|---|
| `_PII_PATTERNS` | `dict[str, re.Pattern]` | 10 compiled PII regex patterns |
| `_API_KEY_PATTERNS` | `dict[str, re.Pattern]` | 5 compiled API key regex patterns |
| `_SENSITIVITY_MAP` | `dict[str, str]` | Maps entity type → sensitivity string |
| `_luhn_check` | `callable` | Re-exported from `spanforge.redact` |
| `_verhoeff_check` | `callable` | Re-exported from `spanforge.redact` |

> **Note**: names prefixed with `_` are internal. They are exported as a convenience for reference implementations but may change without notice between minor versions.
