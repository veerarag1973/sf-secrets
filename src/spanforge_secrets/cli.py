"""CLI entry point for spanforge-secrets — CI Gate 01.

Usage
-----
::

    # Scan one or more files
    spanforge-secrets scan path/to/prompt.txt training_data.jsonl

    # Scan raw text piped from stdin
    echo "contact alice@example.com" | spanforge-secrets scan --stdin

    # Read from stdin explicitly and disable raw scanning
    spanforge-secrets scan --stdin --no-scan-raw

    # Verify an audit-chain JSONL file
    spanforge-secrets verify-chain audit.jsonl --secret my-hmac-key

Exit codes
----------
* 0 — all inputs are clean
* 1 — at least one violation detected (PII or exposed API key)
* 2 — usage / argument error
* 3 — I/O or format error (unreadable file, invalid JSON)
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from spanforge_secrets.scanner import PIIScanResult, scan_payload, scan_text

# Package version — single source of truth from package metadata.
_VERSION: str = _pkg_version("spanforge-secrets")

# Binary extensions that should never be scanned as text.
_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class", ".wasm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".avi", ".mov", ".mkv",
    ".sqlite", ".db", ".pkl", ".npy", ".npz", ".pt", ".onnx",
})

# Maximum file size to load in memory (50 MB).
_MAX_FILE_BYTES: int = 50 * 1024 * 1024

# Default ignore-file name auto-detected in directory roots.
_DEFAULT_IGNORE_FILE: str = ".spanforge-secretsignore"


# ---------------------------------------------------------------------------
# Ignore-pattern helpers
# ---------------------------------------------------------------------------

def _load_ignore_patterns(ignore_file: Path | None) -> list[str]:
    """Load fnmatch glob patterns from *ignore_file*.

    Lines starting with ``#`` and blank lines are skipped.
    Returns an empty list when the file does not exist or is ``None``.
    """
    if ignore_file is None or not ignore_file.exists():
        return []
    patterns: list[str] = []
    try:
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    except (OSError, UnicodeDecodeError):
        pass
    return patterns


def _is_ignored(path: Path, patterns: list[str], root: Path) -> bool:
    """Return ``True`` if *path* matches any ignore pattern.

    Patterns are matched against:
    * the filename alone (e.g. ``*.pyc``)
    * the path relative to *root* using forward slashes (e.g. ``dist/**``)
    """
    if not patterns:
        return False
    name = path.name
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.as_posix()
    for pat in patterns:
        if fnmatch.fnmatch(name, pat):
            return True
        if fnmatch.fnmatch(rel, pat):
            return True
    return False

def _scan_file(path: Path, *, scan_raw: bool) -> PIIScanResult:
    """Scan a single file path.

    * ``.json`` files are parsed and passed to :func:`scan_payload`.
    * ``.jsonl`` / ``.ndjson`` files are scanned line-by-line; each parsed
      JSON object is passed to :func:`scan_payload`.
    * All other files are treated as UTF-8 text and passed to
      :func:`scan_text`.

    Returns a combined :class:`PIIScanResult` with ``source`` set to the
    file path string.
    """
    suffix = path.suffix.lower()

    # Skip known binary extensions
    if suffix in _BINARY_EXTENSIONS:
        print(f"spanforge-secrets: skipping binary file: {path}", file=sys.stderr)
        return PIIScanResult(hits=[], scanned=0, source=str(path))

    # Guard against loading huge files into memory
    try:
        fsize = path.stat().st_size
    except OSError:
        fsize = 0
    if fsize > _MAX_FILE_BYTES:
        print(
            f"spanforge-secrets: skipping {path} "
            f"({fsize / (1024 * 1024):.0f} MB > {_MAX_FILE_BYTES // (1024 * 1024)} MB limit)",
            file=sys.stderr,
        )
        return PIIScanResult(hits=[], scanned=0, source=str(path))

    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print(f"spanforge-secrets: skipping non-UTF-8 file: {path}", file=sys.stderr)
        return PIIScanResult(hits=[], scanned=0, source=str(path))
    except OSError as exc:
        _die(f"Cannot read {path}: {exc}", code=3)

    combined_hits: list[Any] = []
    total_scanned = 0

    if suffix == ".json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            _die(f"Invalid JSON in {path}: {exc}", code=3)
        if not isinstance(data, dict):
            # Wrap non-dict JSON in a container so scan_payload can walk it
            data = {"__root__": data}
        result = scan_payload(data, source=str(path), scan_raw=scan_raw)
        combined_hits.extend(result.hits)
        total_scanned += result.scanned

    elif suffix in (".jsonl", ".ndjson"):
        for lineno, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                _die(f"Invalid JSON on line {lineno} of {path}: {exc}", code=3)
            if not isinstance(data, dict):
                data = {"__root__": data}
            result = scan_payload(
                data,
                source=f"{path}:{lineno}",
                scan_raw=scan_raw,
            )
            combined_hits.extend(result.hits)
            total_scanned += result.scanned

    else:
        # Plain text / prompt file / training data
        result = scan_text(content, source=str(path), scan_raw=scan_raw)
        combined_hits.extend(result.hits)
        total_scanned += result.scanned

    return PIIScanResult(hits=combined_hits, scanned=total_scanned, source=str(path))


def _scan_stdin(*, scan_raw: bool) -> PIIScanResult:
    """Read stdin to EOF and scan as plain text."""
    try:
        content = sys.stdin.read()
    except KeyboardInterrupt:
        sys.exit(2)
    return scan_text(content, source="<stdin>", scan_raw=scan_raw)


def _scan_diff(*, scan_raw: bool) -> list[PIIScanResult]:
    """Run ``git diff --staged`` and scan only the added lines.

    Each hunk of added lines is treated as a single text blob tagged with the
    ``+++ b/<file>`` path from the diff header.  This lets the tool be used as
    a lightweight pre-commit hook that only inspects what is about to be
    committed.

    Returns a (possibly empty) list of :class:`PIIScanResult` — one per file
    that contributed at least one added line in the diff.

    Raises :class:`SystemExit` with code 3 if ``git`` is unavailable or not in
    a git repository.
    """
    import subprocess as _sp

    try:
        proc = _sp.run(
            ["git", "diff", "--staged"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        _die("git not found — install git to use --diff mode", code=3)

    if proc.returncode != 0:
        _die(f"git diff --staged failed: {proc.stderr.strip()}", code=3)

    diff_text = proc.stdout
    if not diff_text.strip():
        return []

    # Parse diff output: collect added lines per file
    file_lines: dict[str, list[str]] = {}
    current_file: str = "<diff>"
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            if current_file not in file_lines:
                file_lines[current_file] = []
        elif line.startswith("+") and not line.startswith("+++"):
            file_lines.setdefault(current_file, []).append(line[1:])

    results: list[PIIScanResult] = []
    for fname, lines in file_lines.items():
        blob = "\n".join(lines)
        results.append(scan_text(blob, source=f"diff:{fname}", scan_raw=scan_raw))
    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _sarif_uri(source: str) -> tuple[str, "int | None"]:
    """Normalise a :attr:`PIIScanResult.source` into ``(artifact_uri, start_line)``.

    Handles the three forms produced by this module:

    * ``"diff:path/to/file.py"`` — strip prefix; URI is the bare relative path.
    * ``"/abs/path/file.jsonl:42"`` — split the ``:lineno`` suffix; return it
      as ``start_line`` so callers can emit a SARIF ``region``.
    * ``"/abs/path/file.txt"`` — convert to a path relative to the current
      working directory when possible (required by GitHub Code Scanning so
      results are annotated on the correct source lines in PRs).
    * ``"<stdin>"`` — returned unchanged with ``start_line=None``.
    """
    # Diff mode attaches a "diff:" prefix to signal the file came from a patch.
    if source.startswith("diff:"):
        return source[5:], None

    line_num: int | None = None
    path_str = source

    # Split ":lineno" suffix — only when every character after the last ":"
    # is a digit (avoids splitting Windows drive-letter colons, e.g. "C:\...").
    last_colon = source.rfind(":")
    if last_colon > 1:  # index > 1 skips "C:" at position 1
        suffix = source[last_colon + 1:]
        if suffix.isdigit():
            path_str = source[:last_colon]
            line_num = int(suffix)

    # Prefer a path relative to cwd — GitHub Code Scanning resolves URIs
    # relative to %SRCROOT% (the repo root), so relative paths work correctly.
    try:
        uri = Path(path_str).relative_to(Path.cwd()).as_posix()
    except ValueError:
        uri = Path(path_str).as_posix()

    return uri, line_num


def _emit_json(results: list[PIIScanResult]) -> None:
    """Print a single JSON object summarising all results to stdout."""
    total_violations = sum(r.violation_count for r in results)
    output = {
        "gate": "CI-Gate-01",
        "clean": total_violations == 0,
        "total_violations": total_violations,
        "results": [r.to_dict() for r in results],
    }
    print(json.dumps(output, indent=2))


def _emit_sarif(results: list[PIIScanResult]) -> None:
    """Print SARIF 2.1.0 JSON to stdout.

    The emitted document is compatible with GitHub Advanced Security / Code
    Scanning so that findings appear as pull-request annotations when the
    output is uploaded via ``actions/upload-sarif``.
    """
    # Build the tool rules table (one rule per entity type)
    seen_rules: dict[str, dict[str, Any]] = {}
    for result in results:
        for hit in result.hits:
            if hit.entity_type not in seen_rules:
                severity_map = {"high": "error", "medium": "warning", "low": "note"}
                seen_rules[hit.entity_type] = {
                    "id": hit.entity_type,
                    "name": hit.entity_type.replace("_", " ").title(),
                    "shortDescription": {
                        "text": f"Potential {hit.entity_type.replace('_', ' ')} detected."
                    },
                    "defaultConfiguration": {
                        "level": severity_map.get(hit.sensitivity, "warning")
                    },
                    "properties": {
                        "tags": [hit.category],
                    },
                }

    rules = list(seen_rules.values())
    rule_index = {r["id"]: i for i, r in enumerate(rules)}

    # Build results list
    sarif_results: list[dict[str, Any]] = []
    for scan_result in results:
        file_uri, file_line = _sarif_uri(scan_result.source)
        for hit in scan_result.hits:
            phys_loc: dict[str, Any] = {
                "artifactLocation": {
                    "uri": file_uri,
                    "uriBaseId": "%SRCROOT%",
                }
            }
            if file_line is not None:
                phys_loc["region"] = {"startLine": file_line}
            sarif_results.append({
                "ruleId": hit.entity_type,
                "ruleIndex": rule_index[hit.entity_type],
                "level": seen_rules[hit.entity_type]["defaultConfiguration"]["level"],
                "message": {
                    "text": (
                        f"Found {hit.match_count} instance(s) of {hit.entity_type} "
                        f"(sensitivity: {hit.sensitivity}) at path '{hit.path}'."
                    )
                },
                "locations": [{"physicalLocation": phys_loc}],
            })

    sarif_doc: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "spanforge-secrets",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/veerarag1973/sf-secrets",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    print(json.dumps(sarif_doc, indent=2))


def _die(message: str, *, code: int = 1) -> None:
    print(f"spanforge-secrets: error: {message}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Sub-command: scan
# ---------------------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    """Run the scan sub-command.  Returns exit code."""
    scan_raw: bool = args.scan_raw  # True by default (fixed)

    results: list[PIIScanResult] = []

    # Load ignore patterns: explicit --ignore-file flag, or auto-detect in cwd
    ignore_file_path: Path | None = None
    if hasattr(args, "ignore_file") and args.ignore_file:
        ignore_file_path = Path(args.ignore_file)
    else:
        default_ignore = Path.cwd() / _DEFAULT_IGNORE_FILE
        if default_ignore.exists():
            ignore_file_path = default_ignore
    ignore_patterns = _load_ignore_patterns(ignore_file_path)

    if args.stdin:
        results.append(_scan_stdin(scan_raw=scan_raw))
    elif getattr(args, "diff", False):
        results.extend(_scan_diff(scan_raw=scan_raw))
    else:
        if not args.paths:
            _die("provide at least one PATH or use --stdin", code=2)
        for raw_path in args.paths:
            p = Path(raw_path)
            if not p.exists():
                _die(f"path not found: {p}", code=3)
            if p.is_dir():
                # Recurse into directories, honouring ignore patterns
                root = p
                # Also auto-detect a .spanforge-secretsignore inside the dir root
                dir_patterns = ignore_patterns + _load_ignore_patterns(p / _DEFAULT_IGNORE_FILE)
                for child in sorted(p.rglob("*")):
                    if child.is_file():
                        if _is_ignored(child, dir_patterns, root):
                            print(
                                f"spanforge-secrets: ignoring {child}",
                                file=sys.stderr,
                            )
                            continue
                        results.append(_scan_file(child, scan_raw=scan_raw))
            else:
                # Single file: honour ignore patterns just as directories do.
                if _is_ignored(p, ignore_patterns, p.parent):
                    print(
                        f"spanforge-secrets: ignoring {p}",
                        file=sys.stderr,
                    )
                else:
                    results.append(_scan_file(p, scan_raw=scan_raw))

    fmt: str = getattr(args, "format", "json")
    if fmt == "sarif":
        _emit_sarif(results)
    else:
        _emit_json(results)

    total_violations = sum(r.violation_count for r in results)
    return 0 if total_violations == 0 else 1


# ---------------------------------------------------------------------------
# Sub-command: verify-chain
# ---------------------------------------------------------------------------

def _cmd_verify_chain(args: argparse.Namespace) -> int:
    """Run the verify-chain sub-command.  Returns exit code."""
    from spanforge_secrets.chain import verify_chain_file  # local import

    # Resolve secret: --secret flag takes priority, then env var.
    secret: str | None = getattr(args, "secret", None)
    if not secret:
        secret = os.environ.get("SPANFORGE_HMAC_SECRET")
    if not secret:
        _die(
            "HMAC secret is required. Pass --secret or set the "
            "SPANFORGE_HMAC_SECRET environment variable.",
            code=2,
        )

    try:
        result = verify_chain_file(args.audit_log, org_secret=secret)
    except ImportError as exc:
        _die(str(exc), code=3)
    except (FileNotFoundError, ValueError) as exc:
        _die(str(exc), code=3)

    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spanforge-secrets",
        description=(
            "CI Gate 01 — scan for PII (10 entity types) and exposed API keys.\n"
            "Exits 1 if any violation is found."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ---- scan ----
    scan_p = sub.add_parser(
        "scan",
        help="Scan files or stdin for PII and API key leakage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Scan one or more files (or stdin) for PII and API key leakage.\n\n"
            "Supported file types:\n"
            "  .json       parsed as JSON object\n"
            "  .jsonl      scanned line-by-line\n"
            "  .ndjson     same as .jsonl\n"
            "  anything else  treated as plain UTF-8 text\n\n"
            "Directories are walked recursively.\n\n"
            "Output is always a single JSON object on stdout.\n"
            "Exit code 0 = clean, 1 = violations found."
        ),
    )
    scan_p.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Files or directories to scan.",
    )
    scan_p.add_argument(
        "--stdin",
        action="store_true",
        default=False,
        help="Read from stdin instead of files.",
    )

    # --scan-raw is True by default (the upstream bug was that it defaulted
    # to False; this CLI fixes that).  Users can opt-out with --no-scan-raw.
    scan_p.add_argument(
        "--scan-raw",
        dest="scan_raw",
        action="store_true",
        default=True,
        help="Enable raw-string regex scanning (default: enabled).",
    )
    scan_p.add_argument(
        "--no-scan-raw",
        dest="scan_raw",
        action="store_false",
        help="Disable raw-string regex scanning (check Redactable wrappers only).",
    )
    scan_p.add_argument(
        "--ignore-file",
        dest="ignore_file",
        metavar="FILE",
        default=None,
        help=(
            "Path to an ignore file with fnmatch patterns (one per line). "
            f"Defaults to auto-detecting '.{_DEFAULT_IGNORE_FILE}' "
            "in the current directory."
        ),
    )
    scan_p.add_argument(
        "--diff",
        dest="diff",
        action="store_true",
        default=False,
        help=(
            "Scan only lines added in 'git diff --staged'. "
            "Useful as a pre-commit hook. Requires git."
        ),
    )
    scan_p.add_argument(
        "--format",
        dest="format",
        choices=["json", "sarif"],
        default="json",
        help=(
            "Output format. 'json' (default) emits the CI-Gate-01 summary. "
            "'sarif' emits SARIF 2.1.0 for GitHub Code Scanning integration."
        ),
    )

    # ---- verify-chain ----
    vc_p = sub.add_parser(
        "verify-chain",
        help="Verify the HMAC audit chain of a JSONL event log.",
        description=(
            "Read a JSONL audit-log file and verify each event's HMAC\n"
            "signature and prev_id chain linkage.\n\n"
            "Exit code 0 = chain valid, 1 = tampering or gaps detected."
        ),
    )
    vc_p.add_argument(
        "audit_log",
        metavar="AUDIT_LOG",
        help="Path to the JSONL audit log.",
    )
    vc_p.add_argument(
        "--secret",
        required=False,
        default=None,
        metavar="HMAC_SECRET",
        help=(
            "HMAC signing secret used when the chain was created. "
            "If omitted, the SPANFORGE_HMAC_SECRET environment variable is used."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """Parse arguments and dispatch to the appropriate sub-command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        sys.exit(2)

    if args.command == "scan":
        sys.exit(_cmd_scan(args))
    elif args.command == "verify-chain":
        sys.exit(_cmd_verify_chain(args))
    else:
        _die(f"unknown command: {args.command}", code=2)


if __name__ == "__main__":
    main()
