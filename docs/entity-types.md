# Entity Types

`spanforge-secrets` detects 15 entity types: 10 PII types and 5 API key types. This page describes each detector, its sensitivity level, regex pattern logic, post-regex validators, and example matches.

---

## PII Entity Types

### `email`

| Property | Value |
|---|---|
| Sensitivity | `medium` |
| Validator | Regex only |
| Category | `pii` |
| Source | `spanforge.redact` |

Detects standard email addresses.

**Matches:**
- `alice@example.com`
- `user.name+tag@sub.domain.org`
- `support@acme.co.uk`

---

### `phone`

| Property | Value |
|---|---|
| Sensitivity | `medium` |
| Validator | Regex only |
| Category | `pii` |
| Source | `spanforge.redact` |

Detects international and domestic phone numbers including formats with spaces, dashes, dots, and country codes.

**Matches:**
- `+1-555-867-5309`
- `+44 7911 123456`
- `(800) 555-0123`
- `555.867.5309`

---

### `ssn`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex + SSA range validation |
| Category | `pii` |
| Source | `spanforge.redact` (regex) + `spanforge-secrets` (validator) |

Detects US Social Security Numbers in `AAA-GG-SSSS` format. After regex matching, the SSA range validator rejects:
- Area `000`, `666`, or `900–999`
- Group `00`
- Serial `0000`

**Matches:**
- `123-45-6789`
- `078-05-1120`

**Does not match:**
- `000-45-6789` (invalid area)
- `123-00-6789` (invalid group)
- `999-45-0000` (invalid serial + area)

---

### `credit_card`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex + Luhn checksum |
| Category | `pii` |
| Source | `spanforge.redact` |

Detects 13–19 digit card numbers with optional spaces or dashes. The Luhn algorithm is run after regex matching to eliminate false positives.

**Matches:**
- `4111 1111 1111 1111` (Visa test card — passes Luhn)
- `5500-0000-0000-0004` (Mastercard test card)
- `378282246310005` (AmEx test card)

**Does not match:**
- `1234 5678 9012 3456` (fails Luhn)

---

### `ip_address`

| Property | Value |
|---|---|
| Sensitivity | `low` |
| Validator | Regex only |
| Category | `pii` |
| Source | `spanforge.redact` |

Detects IPv4 addresses. Each octet is bounded to `0–255`.

**Matches:**
- `192.168.1.1`
- `10.0.0.1`
- `203.0.113.42`

---

### `uk_national_insurance`

| Property | Value |
|---|---|
| Sensitivity | `low` |
| Validator | Regex only |
| Category | `pii` |
| Source | `spanforge.redact` |

Detects UK National Insurance numbers in the format `AB 12 34 56 C`.

**Matches:**
- `AB 12 34 56 C`
- `QQ123456C`

---

### `aadhaar`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex + Verhoeff checksum |
| Category | `pii` |
| Source | `spanforge.redact` (DPDP patterns) |

Detects 12-digit Aadhaar numbers (India's national ID) with optional spaces after every 4 digits. The Verhoeff algorithm (a dihedral group checksum) is applied after regex matching to eliminate false positives.

**Matches:**
- `9999 8888 7777`
- `499118665246` (valid Verhoeff checksum)

---

### `pan`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex only |
| Category | `pii` |
| Source | `spanforge.redact` (DPDP patterns) |

Detects Indian Permanent Account Numbers (PAN) in the format `AAAAA0000A` — 5 letters, 4 digits, 1 letter.

**Matches:**
- `ABCDE1234F`
- `AABCP1234K`

---

### `date_of_birth`

| Property | Value |
|---|---|
| Sensitivity | `medium` |
| Validator | Regex + calendar validation |
| Category | `pii` |
| Source | `spanforge.redact` (upstream) |

Detects dates in three common formats. After regex matching, a calendar check discards structurally valid but impossible dates (e.g. February 30).

**Supported formats:**
- `YYYY-MM-DD` — ISO 8601 (`1990-07-15`)
- `DD/MM/YYYY` — European format (`15/07/1990`)
- `MM/DD/YYYY` — US format (`07/15/1990`)

**Matches:**
- `1990-07-15`
- `15/07/1990`
- `07/15/1990`

**Does not match:**
- `1990-02-30` (February 30 — calendar invalid)
- `13/13/1990` (month 13 — calendar invalid)

> **Context sensitivity**: dates in general text may produce false positives (version numbers, timestamps, etc.). Use `extra_patterns` to narrow detection if needed.

---

### `address`

| Property | Value |
|---|---|
| Sensitivity | `medium` |
| Validator | Regex only |
| Category | `pii` |
| Source | `spanforge.redact` (upstream) |

Detects US-style street addresses with a house number, at least one capitalised word, and a recognised road suffix.

**Recognised suffixes:** `Street`, `St`, `Avenue`, `Ave`, `Boulevard`, `Blvd`, `Road`, `Rd`, `Drive`, `Dr`, `Lane`, `Ln`, `Court`, `Ct`, `Place`, `Pl`, `Way`, `Terrace`, `Terr`, `Circle`, `Cir`

**Matches:**
- `42 Maple Street`
- `1600 Pennsylvania Avenue`
- `221B Baker St`

**Does not match:**
- `42 street` (no capitalised word before suffix)
- `Maple Street` (no house number)

---

## API Key Entity Types

### `openai_api_key`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex only |
| Category | `api_key` |

Detects OpenAI API keys in both legacy (`sk-...`) and project (`sk-proj-...`) formats.

**Matches:**
- `sk-abc123XYZdefghijklmnopqrstuvwxyz0123456789AB`
- `sk-proj-abc123XYZdefghijklmnopqrstuvwxyz0123456789AB`

---

### `anthropic_api_key`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex only |
| Category | `api_key` |

Detects Anthropic API keys starting with `sk-ant-`.

**Matches:**
- `sk-ant-abc123XYZdefghijklmnopqrstuvwxyz0123456`
- `sk-ant-api03-abc123XYZdefghijklmnopqrstuvwxyz`

---

### `aws_access_key_id`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex only |
| Category | `api_key` |

Detects AWS access key IDs. The pattern requires one of the known AWS key prefixes followed by exactly 16 uppercase alphanumeric characters.

**Recognised prefixes:** `AKIA`, `ASIA`, `AROA`, `AIDA`, `ANPA`, `ANVA`, `APKA`

**Matches:**
- `AKIAIOSFODNN7EXAMPLE`
- `ASIAXXX0123456789AB`

---

### `aws_secret_access_key`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Context-sensitive regex |
| Category | `api_key` |

Detects AWS secret access keys only when preceded by a context keyword (`aws_secret_access_key`, `secret_access_key`, `secretaccesskey`) and a separator (`=`, `:`, `"`). This reduces false positives from random 40-character base64 strings.

**Matches (value portion only is flagged):**
- `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
- `"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`

---

### `gcp_service_account_key`

| Property | Value |
|---|---|
| Sensitivity | `high` |
| Validator | Regex only |
| Category | `api_key` |

Detects the `"private_key"` field marker inside a GCP service account JSON key file.

**Matches:**
- `"private_key": "-----BEGIN RSA PRIVATE KEY-----`
- `"private_key": "-----BEGIN PRIVATE KEY-----`

---

## Sensitivity Levels

| Level | Meaning | Entity types |
|---|---|---|
| `high` | Regulated data; regulatory / financial / credential exposure risk | `ssn`, `credit_card`, `aadhaar`, `pan`, `openai_api_key`, `anthropic_api_key`, `aws_access_key_id`, `aws_secret_access_key`, `gcp_service_account_key` |
| `medium` | Personal data; identity linkage risk | `email`, `phone`, `date_of_birth`, `address` |
| `low` | Infrastructure data; lower direct risk but useful for mapping | `ip_address`, `uk_national_insurance` |

In SARIF output, these map to `error`, `warning`, and `note` respectively.
