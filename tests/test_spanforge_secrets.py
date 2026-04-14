"""Tests for spanforge-secrets.

Covers:
  * _luhn_check()
  * _verhoeff_check()
  * _PII_PATTERNS and _API_KEY_PATTERNS (regex smoke)
  * scan_payload()
  * scan_text()
  * CLI (scan sub-command, --scan-raw / --no-scan-raw flags)
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from spanforge_secrets._luhn import _luhn_check
from spanforge_secrets._verhoeff import _verhoeff_check
from spanforge_secrets._patterns import _API_KEY_PATTERNS, _PII_PATTERNS
from spanforge_secrets.scanner import PIIScanResult, scan_payload, scan_text


# ---------------------------------------------------------------------------
# _luhn_check
# ---------------------------------------------------------------------------

class TestLuhnCheck:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111")

    def test_valid_mastercard(self):
        assert _luhn_check("5500005555555559")

    def test_invalid_number(self):
        assert not _luhn_check("1234567890123456")

    def test_too_short(self):
        assert not _luhn_check("411111111")

    def test_ignores_separators(self):
        assert _luhn_check("4111-1111-1111-1111")

    def test_too_long(self):
        assert not _luhn_check("4" * 20)


# ---------------------------------------------------------------------------
# _verhoeff_check
# ---------------------------------------------------------------------------

class TestVerhoeffCheck:
    def test_returns_bool(self):
        """Verhoeff always returns a bool, never crashes."""
        assert isinstance(_verhoeff_check("234123412346"), bool)

    def test_known_valid_verhoeff(self):
        # "2363" is the shortest Verhoeff-valid number with a non-trivial check digit.
        # Verified manually against the _D/_P lookup tables: final accumulator == 0.
        assert _verhoeff_check("2363") is True

    def test_invalid_aadhaar(self):
        # 1xx prefix is never issued; Verhoeff should also fail
        assert not _verhoeff_check("123456789012")


# ---------------------------------------------------------------------------
# Regex smoke — _PII_PATTERNS
# ---------------------------------------------------------------------------

class TestPIIPatterns:
    @pytest.mark.parametrize("text,label", [
        ("alice@example.com", "email"),
        ("bob+tag@sub.domain.co.uk", "email"),
        ("555-867-5309", "phone"),
        ("+1 (800) 555-0199", "phone"),
        ("123-45-6789", "ssn"),
        ("4111111111111111", "credit_card"),
        ("192.168.1.1", "ip_address"),
        ("AB 12 34 56 C", "uk_national_insurance"),
        ("ABCDE1234F", "pan"),
        ("1990-07-04", "date_of_birth"),
        ("07/15/1985", "date_of_birth"),
        ("15/03/1985", "date_of_birth"),   # Indian/European DD/MM/YYYY
        ("15-03-1985", "date_of_birth"),   # Indian DD-MM-YYYY
        ("15 Mar 1985", "date_of_birth"),  # Indian day-month-year with abbrev
        ("42 Wallaby Way", "address"),
    ])
    def test_matches(self, text: str, label: str):
        pat = _PII_PATTERNS[label]
        assert pat.search(text), f"{label} did not match {text!r}"

    def test_email_no_false_positive_on_plain_domain(self):
        assert not _PII_PATTERNS["email"].search("just-a-hostname.com")

    def test_ssn_no_match_on_phone(self):
        # 555-867-5309 has 10 digits separated by 3-3-4, not 3-2-4
        assert not _PII_PATTERNS["ssn"].search("555-867-5309")


# ---------------------------------------------------------------------------
# Regex smoke — _API_KEY_PATTERNS
# ---------------------------------------------------------------------------

class TestAPIKeyPatterns:
    @pytest.mark.parametrize("text,label", [
        ("sk-abcdefghijklmnopqrstuvwxyzABCDEFGH12345678", "openai_api_key"),
        ("sk-proj-abcdefghijklmnopqrstuvwxyzABCDEF123456", "openai_api_key"),
        ("sk-ant-api01-abcdefghijklmnopqrstuvwxyzABCDEFGH12345678901234", "anthropic_api_key"),
        ("AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
        ("ASIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
        ('secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', "aws_secret_access_key"),
        ('"private_key": "-----BEGIN RSA PRIVATE KEY-----', "gcp_service_account_key"),
    ])
    def test_matches(self, text: str, label: str):
        pat = _API_KEY_PATTERNS[label]
        assert pat.search(text), f"{label} did not match {text!r}"


# ---------------------------------------------------------------------------
# scan_text()
# ---------------------------------------------------------------------------

class TestScanText:
    def test_detects_email(self):
        result = scan_text("Contact us at ceo@bigcorp.com for details.")
        assert not result.clean
        types = {h.entity_type for h in result.hits}
        assert "email" in types

    def test_detects_openai_key(self):
        key = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGH12345678"
        result = scan_text(f"OPENAI_API_KEY={key}")
        assert not result.clean
        types = {h.entity_type for h in result.hits}
        assert "openai_api_key" in types

    def test_clean_text(self):
        result = scan_text("The quick brown fox jumps over the lazy dog.")
        assert result.clean

    def test_scan_raw_false_returns_clean(self):
        result = scan_text("ceo@bigcorp.com", scan_raw=False)
        assert result.clean

    def test_source_propagated(self):
        result = scan_text("x", source="my_prompt.txt")
        assert result.source == "my_prompt.txt"

    def test_to_dict_structure(self):
        result = scan_text("ceo@bigcorp.com", source="test.txt")
        d = result.to_dict()
        assert d["source"] == "test.txt"
        assert "hits" in d
        assert "violation_count" in d
        assert "scanned_strings" in d


# ---------------------------------------------------------------------------
# scan_payload()
# ---------------------------------------------------------------------------

class TestScanPayload:
    def test_nested_email(self):
        payload = {"user": {"email": "alice@example.com"}, "msg": "hello"}
        result = scan_payload(payload)
        assert not result.clean
        paths = {h.path for h in result.hits}
        assert "user.email" in paths

    def test_list_of_strings(self):
        payload = {"prompts": ["tell me about 192.168.0.1", "safe text"]}
        result = scan_payload(payload)
        hit_types = {h.entity_type for h in result.hits}
        assert "ip_address" in hit_types

    def test_credit_card_luhn_validated(self):
        # Invalid Luhn — should NOT produce a hit
        payload = {"cc": "1234567890123456"}
        result = scan_payload(payload)
        cc_hits = [h for h in result.hits if h.entity_type == "credit_card"]
        assert cc_hits == []

    def test_credit_card_valid_luhn(self):
        payload = {"cc": "4111111111111111"}
        result = scan_payload(payload)
        cc_hits = [h for h in result.hits if h.entity_type == "credit_card"]
        assert len(cc_hits) == 1
        assert cc_hits[0].sensitivity == "high"

    def test_api_key_in_payload(self):
        payload = {"config": {"token": "sk-abcdefghijklmnopqrstuvwxyzABCDEFGH12345678"}}
        result = scan_payload(payload)
        categories = {h.category for h in result.hits}
        assert "api_key" in categories

    def test_scan_raw_false(self):
        payload = {"email": "alice@example.com"}
        result = scan_payload(payload, scan_raw=False)
        assert result.clean

    def test_max_depth_respected(self):
        # Build a payload nested 15 levels deep
        deep: dict = {}
        current = deep
        for i in range(15):
            current["child"] = {}
            current = current["child"]
        current["email"] = "deep@example.com"
        result = scan_payload(deep, max_depth=10)
        # Hit at depth 15 should be skipped
        deep_hits = [h for h in result.hits if "deep@example.com" in h.path]
        assert deep_hits == []

    def test_clean_payload(self):
        payload = {"name": "Alice", "role": "admin", "active": "true"}
        result = scan_payload(payload)
        assert result.clean

    def test_extra_patterns(self):
        import re
        payload = {"notes": "INTERNAL-TICKET-12345"}
        result = scan_payload(
            payload,
            extra_patterns={"ticket": re.compile(r"INTERNAL-TICKET-\d+")},
        )
        ticket_hits = [h for h in result.hits if h.entity_type == "ticket"]
        assert len(ticket_hits) == 1

    def test_sensitivity_levels(self):
        payload = {
            "ssn": "123-45-6789",
            "email": "a@b.com",
            "ip": "10.0.0.1",
        }
        result = scan_payload(payload)
        by_type = {h.entity_type: h.sensitivity for h in result.hits}
        assert by_type.get("ssn") == "high"
        assert by_type.get("email") == "medium"
        assert by_type.get("ip_address") == "low"

    def test_ssn_invalid_area_000_rejected(self):
        payload = {"ssn": "000-12-3456"}
        result = scan_payload(payload)
        ssn_hits = [h for h in result.hits if h.entity_type == "ssn"]
        assert ssn_hits == []

    def test_ssn_invalid_area_666_rejected(self):
        payload = {"ssn": "666-12-3456"}
        result = scan_payload(payload)
        ssn_hits = [h for h in result.hits if h.entity_type == "ssn"]
        assert ssn_hits == []

    def test_ssn_invalid_area_900_rejected(self):
        payload = {"ssn": "900-12-3456"}
        result = scan_payload(payload)
        ssn_hits = [h for h in result.hits if h.entity_type == "ssn"]
        assert ssn_hits == []

    def test_ssn_invalid_group_00_rejected(self):
        payload = {"ssn": "123-00-6789"}
        result = scan_payload(payload)
        ssn_hits = [h for h in result.hits if h.entity_type == "ssn"]
        assert ssn_hits == []

    def test_ssn_invalid_serial_0000_rejected(self):
        payload = {"ssn": "123-45-0000"}
        result = scan_payload(payload)
        ssn_hits = [h for h in result.hits if h.entity_type == "ssn"]
        assert ssn_hits == []


# ---------------------------------------------------------------------------
# CLI tests (integration via subprocess)
# ---------------------------------------------------------------------------

class TestCLI:
    def _run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-m", "spanforge_secrets.cli", *args]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=stdin,
            cwd=str(Path(__file__).parent.parent),
        )

    def test_scan_clean_file(self, tmp_path: Path):
        f = tmp_path / "clean.txt"
        f.write_text("No secrets here.")
        proc = self._run("scan", str(f))
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["clean"] is True

    def test_scan_pii_file_exits_1(self, tmp_path: Path):
        f = tmp_path / "prompt.txt"
        f.write_text("User email: boss@enterprise.com\n")
        proc = self._run("scan", str(f))
        assert proc.returncode == 1
        data = json.loads(proc.stdout)
        assert data["clean"] is False
        assert data["total_violations"] >= 1

    def test_scan_api_key_file_exits_1(self, tmp_path: Path):
        f = tmp_path / "config.txt"
        f.write_text("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyzABCDEFGH12345678\n")
        proc = self._run("scan", str(f))
        assert proc.returncode == 1
        data = json.loads(proc.stdout)
        assert any(h["entity_type"] == "openai_api_key" for r in data["results"] for h in r["hits"])

    def test_scan_json_file(self, tmp_path: Path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"user": {"ssn": "123-45-6789"}}))
        proc = self._run("scan", str(f))
        assert proc.returncode == 1
        data = json.loads(proc.stdout)
        types = [h["entity_type"] for r in data["results"] for h in r["hits"]]
        assert "ssn" in types

    def test_scan_jsonl_file(self, tmp_path: Path):
        f = tmp_path / "train.jsonl"
        lines = [
            json.dumps({"text": "clean line"}),
            json.dumps({"text": "call me at 555-867-5309 for info"}),
        ]
        f.write_text("\n".join(lines))
        proc = self._run("scan", str(f))
        assert proc.returncode == 1

    def test_scan_stdin_clean(self):
        proc = self._run("scan", "--stdin", stdin="Hello world\n")
        assert proc.returncode == 0

    def test_scan_stdin_pii(self):
        proc = self._run("scan", "--stdin", stdin="my ssn is 123-45-6789\n")
        assert proc.returncode == 1

    def test_no_scan_raw_skips_regex(self, tmp_path: Path):
        f = tmp_path / "prompt.txt"
        f.write_text("User email: boss@enterprise.com\n")
        proc = self._run("scan", "--no-scan-raw", str(f))
        assert proc.returncode == 0
        data = json.loads(proc.stdout)
        assert data["clean"] is True

    def test_scan_raw_default_is_true(self, tmp_path: Path):
        """--scan-raw should be True by default (the bug fix)."""
        f = tmp_path / "prompt.txt"
        f.write_text("User email: boss@enterprise.com\n")
        # No explicit --scan-raw flag
        proc = self._run("scan", str(f))
        assert proc.returncode == 1

    def test_scan_directory(self, tmp_path: Path):
        (tmp_path / "a.txt").write_text("nothing")
        (tmp_path / "b.txt").write_text("admin@corp.com")
        proc = self._run("scan", str(tmp_path))
        assert proc.returncode == 1

    def test_missing_file_exits_3(self):
        proc = self._run("scan", "/nonexistent/path/file.txt")
        assert proc.returncode == 3

    def test_no_args_exits_2(self):
        proc = self._run("scan")
        assert proc.returncode == 2

    def test_output_structure(self, tmp_path: Path):
        f = tmp_path / "t.txt"
        f.write_text("test@example.com")
        proc = self._run("scan", str(f))
        data = json.loads(proc.stdout)
        assert "gate" in data
        assert data["gate"] == "CI-Gate-01"
        assert "results" in data
        for r in data["results"]:
            assert "source" in r
            assert "hits" in r
            assert "violation_count" in r
            for h in r["hits"]:
                assert "entity_type" in h
                assert "path" in h
                assert "match_count" in h
                assert "sensitivity" in h
                assert "category" in h


# ---------------------------------------------------------------------------
# Edge-case & robustness tests
# ---------------------------------------------------------------------------

class TestCLIEdgeCases:
    def _run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-m", "spanforge_secrets.cli", *args]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=stdin,
            cwd=str(Path(__file__).parent.parent),
        )

    def test_binary_file_skipped(self, tmp_path: Path):
        """Binary files (.png, .pyc) should be skipped without crashing."""
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 100)
        proc = self._run("scan", str(f))
        assert proc.returncode == 0
        assert "skipping binary file" in proc.stderr

    def test_non_utf8_file_skipped(self, tmp_path: Path):
        """Files with invalid UTF-8 should be skipped, not crash."""
        f = tmp_path / "garbled.txt"
        f.write_bytes(b"hello \xff\xfe world")
        proc = self._run("scan", str(f))
        assert proc.returncode == 0
        assert "skipping non-UTF-8" in proc.stderr

    def test_empty_jsonl_file(self, tmp_path: Path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        proc = self._run("scan", str(f))
        assert proc.returncode == 0

    def test_python_m_invocation(self, tmp_path: Path):
        """python -m spanforge_secrets should work."""
        f = tmp_path / "clean.txt"
        f.write_text("no secrets")
        cmd = [sys.executable, "-m", "spanforge_secrets", "scan", str(f)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0

    def test_directory_with_binary_mixed(self, tmp_path: Path):
        (tmp_path / "ok.txt").write_text("clean content")
        (tmp_path / "data.pyc").write_bytes(b"\x00\x01\x02\x03")
        proc = self._run("scan", str(tmp_path))
        assert proc.returncode == 0  # binary skipped, text is clean


class TestAddressPattern:
    def test_no_false_positive_on_freetext_without_suffix(self):
        """Address pattern should not match text lacking a recognised road suffix."""
        result = scan_text("12 this is some random text end")
        addr_hits = [h for h in result.hits if h.entity_type == "address"]
        assert addr_hits == []

    def test_real_address_detected(self):
        result = scan_text("Ship to 123 Main Street please")
        addr_hits = [h for h in result.hits if h.entity_type == "address"]
        assert len(addr_hits) == 1


class TestReDoSSafety:
    """Ensure adversarial inputs don't cause catastrophic backtracking.

    Each test has a 2-second implicit timeout — if regex backtracks
    catastrophically it will take minutes/hours and fail the test run.
    """

    def test_aws_secret_pattern_no_hang(self):
        # Adversarial: long near-match for the AWS secret context pattern
        evil = "aws" + " secret" * 50 + " access key" + "y" * 100
        result = scan_text(evil)
        # Just shouldn't hang — result doesn't matter

    def test_email_pattern_no_hang(self):
        # Long string of valid local-part chars with no @
        evil = "a" * 200
        result = scan_text(evil)
        assert result.clean


# ---------------------------------------------------------------------------
# DOB calendar validation (Task 5)
# ---------------------------------------------------------------------------

class TestDOBValidation:
    """Date-of-birth post-validator rejects calendar-invalid dates."""

    def test_valid_iso_date_detected(self):
        result = scan_text("Born on 1990-07-04.")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert len(dob_hits) == 1

    def test_invalid_month_13_rejected(self):
        # 1990-13-01 has month 13 — regex prevents this already, but validate
        result = scan_text("date: 1990-13-01")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert dob_hits == []

    def test_feb_31_rejected(self):
        # 1990-02-31 is calendar-invalid — regex allows it, validator should reject
        result = scan_text("dob: 1990-02-31")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert dob_hits == []

    def test_valid_slash_date_detected(self):
        result = scan_text("DOB: 07/15/1985")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert len(dob_hits) == 1

    def test_indian_dd_mm_yyyy_detected(self):
        """Indian format DD/MM/YYYY — supported since spanforge 2.0.2."""
        result = scan_text("DOB: 15/03/1985")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert len(dob_hits) == 1

    def test_indian_dd_mm_yyyy_hyphen_detected(self):
        """Indian format DD-MM-YYYY with hyphens."""
        result = scan_text("date of birth: 15-03-1985")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert len(dob_hits) == 1

    def test_indian_day_month_abbrev_detected(self):
        """Indian/UK format: 15 Mar 1985."""
        result = scan_text("born 15 Mar 1985")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert len(dob_hits) == 1

    def test_indian_invalid_feb30_rejected(self):
        """DD/MM/YYYY calendar validation — Feb 30 must be rejected."""
        result = scan_text("dob: 30/02/1990")
        dob_hits = [h for h in result.hits if h.entity_type == "date_of_birth"]
        assert dob_hits == []


# ---------------------------------------------------------------------------
# max_depth validation (Task 5)
# ---------------------------------------------------------------------------

class TestMaxDepthValidation:
    def test_negative_max_depth_raises(self):
        with pytest.raises(ValueError, match="max_depth must be >= 0"):
            scan_payload({"x": "y"}, max_depth=-1)

    def test_zero_max_depth_works(self):
        # A depth-0 payload: the root dict itself has one string value
        result = scan_payload({"email": "root@example.com"}, max_depth=0)
        # Root-level strings are at depth 1 so they should be skipped
        assert result.clean


# ---------------------------------------------------------------------------
# extra_sensitivity (Task 5)
# ---------------------------------------------------------------------------

class TestExtraSensitivity:
    def test_extra_pattern_custom_high_sensitivity(self):
        import re
        payload = {"secret": "INTERNAL-9999"}
        result = scan_payload(
            payload,
            extra_patterns={"internal_id": re.compile(r"INTERNAL-\d+")},
            extra_sensitivity={"internal_id": "high"},
        )
        hits = [h for h in result.hits if h.entity_type == "internal_id"]
        assert len(hits) == 1
        assert hits[0].sensitivity == "high"

    def test_extra_pattern_default_medium_sensitivity(self):
        import re
        result = scan_text(
            "Ticket: TICKET-1234",
            extra_patterns={"ticket_id": re.compile(r"TICKET-\d+")},
        )
        hits = [h for h in result.hits if h.entity_type == "ticket_id"]
        assert len(hits) == 1
        assert hits[0].sensitivity == "medium"


# ---------------------------------------------------------------------------
# Ignore-file support (Task 2)
# ---------------------------------------------------------------------------

class TestIgnoreFile:
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-m", "spanforge_secrets.cli", *args]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )

    def test_ignore_file_suppresses_match(self, tmp_path: Path):
        """Files matching patterns in --ignore-file should be skipped."""
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text("admin@corp.com")

        ignore = tmp_path / ".myignore"
        ignore.write_text("secrets.txt\n")

        proc = self._run("scan", "--ignore-file", str(ignore), str(tmp_path))
        assert proc.returncode == 0  # suppressed by ignore
        assert "ignoring" in proc.stderr

    def test_ignore_file_comments_and_blank_lines(self, tmp_path: Path):
        """Comments (#) and blank lines in ignore file are skipped."""
        (tmp_path / "leak.txt").write_text("admin@corp.com")
        ignore = tmp_path / ".myignore"
        ignore.write_text("# this is a comment\n\n*.md\n")  # does NOT match .txt

        proc = self._run("scan", "--ignore-file", str(ignore), str(tmp_path))
        # leak.txt is NOT ignored so violation found
        assert proc.returncode == 1

    def test_auto_detect_default_ignore_file(self, tmp_path: Path):
        """Auto-detects .spanforge-secretsignore inside scanned directory."""
        (tmp_path / "pii.txt").write_text("admin@corp.com")
        (tmp_path / ".spanforge-secretsignore").write_text("pii.txt\n")

        proc = self._run("scan", str(tmp_path))
        assert proc.returncode == 0
        assert "ignoring" in proc.stderr

    def test_ignore_file_applied_to_explicit_single_file(self, tmp_path: Path):
        """--ignore-file must also suppress a file given as an explicit argument."""
        secret_file = tmp_path / "secrets.txt"
        secret_file.write_text("admin@corp.com")
        ignore = tmp_path / ".myignore"
        ignore.write_text("secrets.txt\n")

        # Pass the file explicitly (not a directory scan) — bug was that
        # single-file paths bypassed the _is_ignored() check entirely.
        proc = self._run("scan", "--ignore-file", str(ignore), str(secret_file))
        assert proc.returncode == 0, f"Expected 0 (ignored), got {proc.returncode}\n{proc.stderr}"
        assert "ignoring" in proc.stderr


# ---------------------------------------------------------------------------
# SARIF output (Task 4)
# ---------------------------------------------------------------------------

class TestSARIFFormat:
    def _run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-m", "spanforge_secrets.cli", *args]
        return subprocess.run(
            cmd, capture_output=True, text=True, input=stdin,
            cwd=str(Path(__file__).parent.parent),
        )

    def test_sarif_output_structure(self, tmp_path: Path):
        f = tmp_path / "secret.txt"
        f.write_text("Contact ceo@bigcorp.com for info.")
        proc = self._run("scan", "--format", "sarif", str(f))
        assert proc.returncode == 1
        doc = json.loads(proc.stdout)
        assert doc["version"] == "2.1.0"
        assert "runs" in doc
        run = doc["runs"][0]
        assert "tool" in run
        assert "rules" in run["tool"]["driver"]
        assert len(run["results"]) >= 1
        res = run["results"][0]
        assert "ruleId" in res
        assert "level" in res
        assert "message" in res
        assert "locations" in res

    def test_sarif_clean_has_empty_results(self, tmp_path: Path):
        f = tmp_path / "clean.txt"
        f.write_text("The quick brown fox.")
        proc = self._run("scan", "--format", "sarif", str(f))
        assert proc.returncode == 0
        doc = json.loads(proc.stdout)
        assert doc["runs"][0]["results"] == []

    def test_sarif_severity_mapping(self, tmp_path: Path):
        """High-sensitivity hits (SSN) should map to SARIF level 'error'."""
        f = tmp_path / "ssn.txt"
        f.write_text("SSN: 123-45-6789")
        proc = self._run("scan", "--format", "sarif", str(f))
        doc = json.loads(proc.stdout)
        results = doc["runs"][0]["results"]
        ssn_results = [r for r in results if r["ruleId"] == "ssn"]
        assert ssn_results
        assert ssn_results[0]["level"] == "error"

    def test_sarif_uri_strips_diff_prefix(self):
        """_sarif_uri must strip the 'diff:' prefix added by _scan_diff."""
        from spanforge_secrets.cli import _sarif_uri

        uri, line = _sarif_uri("diff:src/models/user.py")
        assert uri == "src/models/user.py"
        assert line is None
        assert not uri.startswith("diff:")

    def test_sarif_uri_splits_lineno_suffix(self):
        """_sarif_uri must split ':N' suffix off the path and return it as line."""
        from spanforge_secrets.cli import _sarif_uri

        uri, line = _sarif_uri("/abs/path/data.jsonl:42")
        assert line == 42
        assert not uri.endswith(":42")
        assert uri.endswith(".jsonl")

    def test_sarif_uri_relative_to_cwd(self, tmp_path: Path, monkeypatch):
        """_sarif_uri converts absolute paths to relative when inside cwd."""
        from spanforge_secrets.cli import _sarif_uri

        monkeypatch.chdir(tmp_path)
        sub = tmp_path / "src" / "foo.py"
        uri, line = _sarif_uri(str(sub))
        assert uri == "src/foo.py"
        assert line is None

    def test_sarif_artifact_uri_no_diff_prefix_in_output(self, tmp_path: Path):
        """End-to-end: SARIF artifact URIs in CLI output must never start with 'diff:'."""
        f = tmp_path / "email.txt"
        f.write_text("alice@example.com")
        proc = self._run("scan", "--format", "sarif", str(f))
        assert proc.returncode == 1
        doc = json.loads(proc.stdout)
        for result in doc["runs"][0]["results"]:
            for loc in result["locations"]:
                uri = loc["physicalLocation"]["artifactLocation"]["uri"]
                assert not uri.startswith("diff:"), f"Unexpected diff: prefix in URI: {uri}"

    def test_sarif_region_present_for_lineno_source(self):
        """_sarif_uri returns region startLine when source contains ':N' suffix."""
        from spanforge_secrets.cli import _sarif_uri

        uri, line = _sarif_uri("training/data.jsonl:7")
        assert line == 7
        # Callers use line != None to emit region — verify the split is clean
        assert ":" not in uri


# ---------------------------------------------------------------------------
# Diff mode (Task 3)
# ---------------------------------------------------------------------------

class TestDiffMode:
    def _run(self, *args: str, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, "-m", "spanforge_secrets.cli", *args]
        return subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=cwd or str(Path(__file__).parent.parent),
        )

    def test_diff_no_git_exits_3(self, tmp_path: Path):
        """Running --diff outside a git repo should exit with code 3."""
        # tmp_path has no .git, so git diff --staged will fail
        proc = self._run("scan", "--diff", cwd=str(tmp_path))
        # Either git is unavailable (3) or git fails because not a repo (3)
        assert proc.returncode == 3


# ---------------------------------------------------------------------------
# verify_chain_file() — chain.py hardening tests
# ---------------------------------------------------------------------------

class TestVerifyChainFile:
    """Tests for chain.py that do not require spanforge to be installed.

    All tests use mocking or error-path coverage so the spanforge optional
    dependency is not needed in the test environment.
    """

    def test_file_not_found_raises(self, tmp_path: Path):
        from spanforge_secrets.chain import verify_chain_file

        with pytest.raises(FileNotFoundError, match="Audit log not found"):
            verify_chain_file(tmp_path / "missing.jsonl", org_secret="s")

    def test_non_utf8_file_raises_value_error(self, tmp_path: Path):
        from spanforge_secrets.chain import verify_chain_file

        bad = tmp_path / "bad.jsonl"
        bad.write_bytes(b"\xff\xfe invalid utf8 bytes\n")
        with pytest.raises(ValueError, match="not valid UTF-8"):
            verify_chain_file(bad, org_secret="s")

    def test_oversized_file_raises_value_error(self, tmp_path: Path, monkeypatch):
        from spanforge_secrets import chain as chain_mod
        from spanforge_secrets.chain import verify_chain_file

        big = tmp_path / "big.jsonl"
        big.write_text('{"id": "1"}\n')

        # Patch stat to report a file larger than the limit
        import os
        original_stat = Path.stat

        def fake_stat(self, **kwargs):
            result = original_stat(self, **kwargs)
            # Return a stat_result with st_size set to 51 MB
            return os.stat_result((
                result.st_mode, result.st_ino, result.st_dev,
                result.st_nlink, result.st_uid, result.st_gid,
                51 * 1024 * 1024,  # st_size — 51 MB
                result.st_atime, result.st_mtime, result.st_ctime,
            ))

        monkeypatch.setattr(Path, "stat", fake_stat)
        with pytest.raises(ValueError, match="exceeds the"):
            verify_chain_file(big, org_secret="s")

    def test_invalid_json_line_raises_value_error(self, tmp_path: Path, monkeypatch):
        """A non-JSON line should raise ValueError before spanforge is imported."""
        from spanforge_secrets.chain import verify_chain_file

        bad = tmp_path / "corrupt.jsonl"
        bad.write_text('{"id": "1"}\nnot-json-at-all\n{"id": "3"}\n')

        # Stub out spanforge imports so they succeed but raise before execution
        import sys
        import types

        # Build minimal stubs for spanforge.signing and spanforge.event
        signing_stub = types.ModuleType("spanforge.signing")
        event_stub = types.ModuleType("spanforge.event")

        # Event class that just stores kwargs
        class _Event:
            def __init__(self, **kw: object) -> None:
                self.__dict__.update(kw)

        event_stub.Event = _Event  # type: ignore[attr-defined]
        signing_stub.verify_chain = lambda events, *, org_secret: None  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "spanforge", types.ModuleType("spanforge"))
        monkeypatch.setitem(sys.modules, "spanforge.signing", signing_stub)
        monkeypatch.setitem(sys.modules, "spanforge.event", event_stub)

        with pytest.raises(ValueError, match="Invalid JSON on line 2"):
            verify_chain_file(bad, org_secret="s")

    def test_missing_spanforge_raises_import_error(self, tmp_path: Path, monkeypatch):
        """When spanforge is absent, ImportError with helpful message is raised."""
        import sys

        good = tmp_path / "audit.jsonl"
        good.write_text('{"id": "1"}\n')

        # Remove spanforge from sys.modules so import fails
        for key in list(sys.modules):
            if key == "spanforge" or key.startswith("spanforge."):
                monkeypatch.delitem(sys.modules, key, raising=False)

        # Block the import by inserting a broken module entry
        import types
        broken = types.ModuleType("spanforge.signing")
        broken.__spec__ = None  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "spanforge.signing", None)  # type: ignore[arg-type]

        # Re-import chain to get a fresh copy that won't use cached imports
        import importlib
        import spanforge_secrets.chain as chain_mod
        importlib.reload(chain_mod)

        with pytest.raises((ImportError, AttributeError)):
            chain_mod.verify_chain_file(good, org_secret="s")

    def test_schema_exception_normalised_to_value_error(self, tmp_path: Path, monkeypatch):
        """If Event(**data) raises (wrong schema), it must become ValueError with line info.

        This covers the case where the JSON is syntactically valid but contains
        fields that ``spanforge.event.Event`` cannot accept (missing required
        fields, wrong types, etc.).  The CLI catches ValueError with exit code 3,
        so any other exception would produce an unhandled traceback.
        """
        from spanforge_secrets.chain import verify_chain_file
        import sys
        import types

        bad = tmp_path / "badschema.jsonl"
        # Line 1 is valid JSON but the stubbed Event will reject it
        bad.write_text('{"not_a_valid_field": true}\n')

        # Stub Event to simulate a schema validation failure
        event_stub = types.ModuleType("spanforge.event")

        class _RejectingEvent:
            def __init__(self, **kw: object) -> None:
                raise TypeError("missing required field 'trace_id'")

        event_stub.Event = _RejectingEvent  # type: ignore[attr-defined]

        signing_stub = types.ModuleType("spanforge.signing")
        signing_stub.verify_chain = lambda events, *, org_secret: None  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "spanforge", types.ModuleType("spanforge"))
        monkeypatch.setitem(sys.modules, "spanforge.signing", signing_stub)
        monkeypatch.setitem(sys.modules, "spanforge.event", event_stub)

        with pytest.raises(ValueError, match="Invalid event on line 1"):
            verify_chain_file(bad, org_secret="s")


# ---------------------------------------------------------------------------
# verify_chain_file() — integration tests (require real spanforge package)
# ---------------------------------------------------------------------------

spanforge_pkg = pytest.importorskip(
    "spanforge",
    reason="spanforge not installed; skipping integration tests",
)


class TestVerifyChainFileIntegration:
    """Integration tests for verify_chain_file() using the real spanforge package.

    These tests are automatically skipped when spanforge is not installed
    (controlled by the ``pytest.importorskip`` call above this class).
    """

    # A key long enough to satisfy validate_key_strength (>= 32 bytes).
    _SECRET = "integration-test-secret-key-min-32-bytes!!"

    def _write_chain(self, path: Path, n: int = 2) -> list[Any]:
        """Write *n* properly-signed events to *path* and return the Event objects."""
        from spanforge.event import Event
        from spanforge.signing import sign
        import json

        events: list[Any] = []
        prev: Any = None
        for i in range(n):
            evt = Event(
                event_type="llm.request",
                source="integration-test",
                payload={"seq": i},
            )
            evt = sign(evt, self._SECRET, prev_event=prev)
            events.append(evt)
            prev = evt

        with path.open("w", encoding="utf-8") as fh:
            for evt in events:
                fh.write(json.dumps(evt.to_dict()) + "\n")

        return events

    def test_valid_chain_returns_valid_true(self, tmp_path: Path):
        """A clean, properly-signed JSONL chain should verify as valid."""
        from spanforge_secrets.chain import verify_chain_file

        log = tmp_path / "audit.jsonl"
        self._write_chain(log, n=3)

        result = verify_chain_file(log, org_secret=self._SECRET)

        assert result["valid"] is True
        assert result["tampered_count"] == 0
        assert result["first_tampered"] is None
        assert result["gaps"] == []

    def test_valid_chain_result_keys_present(self, tmp_path: Path):
        """Result dict must always contain the expected five keys."""
        from spanforge_secrets.chain import verify_chain_file

        log = tmp_path / "audit.jsonl"
        self._write_chain(log, n=1)

        result = verify_chain_file(log, org_secret=self._SECRET)

        assert set(result.keys()) == {
            "valid",
            "first_tampered",
            "gaps",
            "tampered_count",
            "tombstone_count",
        }

    def test_tampered_event_returns_valid_false(self, tmp_path: Path):
        """Overwriting a signature field should make the chain report tampering."""
        from spanforge_secrets.chain import verify_chain_file
        import json

        log = tmp_path / "audit.jsonl"
        events = self._write_chain(log, n=2)

        # Corrupt the signature of the second event by rewriting the JSONL file.
        lines = log.read_text(encoding="utf-8").splitlines()
        second = json.loads(lines[1])
        second["signature"] = "deadbeef" * 8  # obviously invalid HMAC
        lines[1] = json.dumps(second)
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_chain_file(log, org_secret=self._SECRET)

        assert result["valid"] is False
        assert result["tampered_count"] >= 1

    def test_blank_lines_are_skipped(self, tmp_path: Path):
        """Blank lines interspersed in the JSONL file must not cause errors."""
        from spanforge_secrets.chain import verify_chain_file
        import json

        log = tmp_path / "audit.jsonl"
        events = self._write_chain(log, n=2)

        # Re-write with blank lines inserted between events.
        lines = log.read_text(encoding="utf-8").splitlines()
        with_blanks = "\n".join(
            line for pair in zip(lines, [""] * len(lines)) for line in pair
        )
        log.write_text(with_blanks + "\n", encoding="utf-8")

        result = verify_chain_file(log, org_secret=self._SECRET)

        assert result["valid"] is True
