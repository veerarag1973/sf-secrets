# Installation

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.9 or later |
| spanforge | 2.0.2 or later |

`spanforge` is a required runtime dependency. `spanforge-secrets` is a reference implementation built on top of it.

---

## Install from PyPI

```bash
pip install spanforge-secrets spanforge
```

Both packages are published on PyPI and can be installed together in a single command.

---

## Install in a virtual environment (recommended)

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install spanforge-secrets spanforge
```

Verify the installation:

```bash
spanforge-secrets --help
```

---

## Install for development

Clone the repository and install with the `dev` extras:

```bash
git clone https://github.com/veerarag1973/sf-secrets.git
cd spanforge-secrets
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]" spanforge
```

The `dev` extras install:

| Package | Purpose |
|---|---|
| `pytest >= 8.0` | Test runner |
| `pytest-cov >= 5.0` | Coverage reporting |
| `ruff >= 0.4.0` | Linter / formatter |
| `mypy >= 1.10` | Static type checker |

---

## Running tests

```bash
python -m pytest tests/ -q
```

All 111 tests should pass. Tests that exercise spanforge internals directly are gated with `pytest.importorskip("spanforge")` and are automatically skipped if `spanforge` is not installed.

---

## Upgrading

```bash
pip install --upgrade spanforge-secrets spanforge
```

---

## Docker / container environments

Add the following to your `Dockerfile` or CI image:

```dockerfile
RUN pip install spanforge-secrets spanforge
```

Or pin specific versions for reproducibility:

```dockerfile
RUN pip install "spanforge-secrets==1.0.0" "spanforge>=2.0.2"
```

---

## Verify the install

```bash
echo "test@example.com" | spanforge-secrets scan --stdin
```

Expected output (abbreviated):

```json
{
  "gate": "CI-Gate-01",
  "clean": false,
  "total_violations": 1,
  ...
}
```

Exit code will be `1` (violation found). A clean input returns exit code `0`.
