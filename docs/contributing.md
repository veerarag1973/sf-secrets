# Contributing

Thank you for your interest in contributing to `spanforge-secrets`! This document covers the development workflow, code standards, and how to submit changes.

---

## Development setup

### Prerequisites

- Python 3.9 or later
- `git`

### Clone and install

```bash
git clone https://github.com/veerarag1973/sf-secrets.git
cd spanforge-secrets
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]" spanforge
```

The `dev` extras install `pytest`, `pytest-cov`, `ruff`, and `mypy`.

---

## Running tests

```bash
python -m pytest tests/ -q
```

All 111 tests must pass before submitting a pull request. If you've added new functionality, add tests for it.

### Coverage report

```bash
python -m pytest tests/ --cov=spanforge_secrets --cov-report=term-missing
```

### Run a specific test file or test

```bash
python -m pytest tests/test_spanforge_secrets.py -k "TestSSN" -v
```

---

## Code style

This project uses **ruff** for linting and formatting.

```bash
# Check for issues
ruff check src/ tests/

# Auto-fix where possible
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/
```

### Key rules

- Line length: 99 characters
- Import style: `isort`-compatible (`I` rules)
- No `print()` statements in library code (use the CLI layer for output)
- No bare `except:` — always catch specific exception types
- Type annotations on all public functions and methods

---

## Type checking

```bash
mypy src/
```

The project is typed with `mypy --strict`. All new code must be fully annotated.

---

## Project structure

```
src/spanforge_secrets/
├── __init__.py       Public API exports
├── __main__.py       python -m spanforge_secrets entry point
├── py.typed          PEP 561 typed package marker
├── scanner.py        Core scanning engine
├── chain.py          Audit chain verification wrapper
├── cli.py            CLI argument parsing and sub-commands
├── _patterns.py      PII + API key regex patterns
├── _luhn.py          Re-export of spanforge.redact._luhn_check
└── _verhoeff.py      Re-export of spanforge.redact._verhoeff_check

tests/
└── test_spanforge_secrets.py   All tests (111 total)
```

---

## What to contribute

### Good candidates for contribution

- **New entity types**: additional PII types or API key formats that complement the existing set
- **Improved validators**: post-regex validation (e.g. range checks, format validation) that reduces false positives
- **Bug fixes**: incorrect regex patterns, false positives/negatives with reproducible examples
- **Documentation**: corrections, clarifications, additional examples
- **Performance**: scanner optimisations (measured with benchmarks)

### What belongs upstream in `spanforge`

If you want to add a PII pattern that is generic and not specific to secrets scanning (e.g. `passport_number`, `driver_license`), consider contributing it to the main `spanforge` repository in `spanforge.redact` instead. This package imports those patterns and extends them.

### What does not belong here

- Features unrelated to PII/secrets scanning
- Dependency additions beyond `spanforge`
- Features that duplicate existing `spanforge` functionality

---

## Submitting a pull request

1. Fork the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. Make your changes. Keep commits focused and atomic.

3. Ensure all tests pass:
   ```bash
   python -m pytest tests/ -q
   ```

4. Check types and linting:
   ```bash
   mypy src/
   ruff check src/ tests/
   ```

5. Update documentation in `docs/` if you've changed behaviour or added a feature.

6. Open a pull request against `main`. Describe what changed and why.

---

## Reporting bugs

Open an issue at https://github.com/veerarag1973/sf-secrets/issues with:

- Python version and OS
- `spanforge-secrets` and `spanforge` version (`pip show spanforge-secrets spanforge`)
- Minimal reproducible example (file content + command)
- Actual vs expected output

---

## Security issues

Please do **not** report security vulnerabilities in public issues. Email the maintainers directly. See the repository's SECURITY.md for the responsible disclosure process.

---

## Dependency policy

`spanforge` is the only runtime dependency and this is intentional. `spanforge-secrets` is a reference implementation; it uses `spanforge`'s patterns and cryptographic primitives directly, avoiding duplication.

New runtime dependencies will not be accepted. New `dev` extras dependencies (test tools, linters) are acceptable.
