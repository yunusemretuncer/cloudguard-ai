"""
test_tools.py — pytest test suite for log_analyzer's three @tool functions...

Test categories:
  1. Helper functions (_is_internal, _parse_iso, _ct_user_of)
  2. Smoke tests (each tool returns valid markdown, doesn't crash)
  3. CloudTrail detections — every branch fires exactly as designed
  4. VPC detections
  5. Auth detections
  6. Edge cases (missing file, empty data, threshold boundaries)
  7. Cross-correlation (VPC SSH brute IP appears in auth findings)

Run with:  pytest test_tools.py -v
Or:        pytest test_tools.py::TestCloudTrail -v
"""

import json
import os
import re
import sys
from pathlib import Path

import pytest

# Make log_analyzer importable. In real project this is handled by
# pytest discovery from project root; locally we add the path explicitly.
sys.path.insert(0, str(Path(__file__).parent))

# Point log_analyzer at our sample data BEFORE importing it.
# The module reads CLOUDGUARD_DATA_DIR at import time.
_TEST_DATA_DIR = Path(__file__).parent
os.environ["CLOUDGUARD_DATA_DIR"] = str(_TEST_DATA_DIR)

import log_analyzer  # noqa: E402
from log_analyzer import (  # noqa: E402
    analyze_cloudtrail_logs,
    analyze_vpc_flow_logs,
    analyze_auth_logs,
    _is_internal,
    _parse_iso,
    _ct_user_of,
    INTERNAL_PREFIXES,
    MITRE,
)


# ----------------------------------------------------------------------------
# Helper: invoke a @tool-wrapped function the way LangChain agents do.
# ----------------------------------------------------------------------------

def call(tool_obj, query="all"):
    """Invoke a tool, supporting both LangChain BaseTool and bare callables."""
    if hasattr(tool_obj, "invoke"):
        return tool_obj.invoke({"query": query})
    return tool_obj(query)


# ============================================================================
# Section 1: Helper function tests
# ============================================================================

class TestHelpers:

    @pytest.mark.parametrize("ip,expected", [
        ("10.0.1.50",      True),
        ("10.255.255.255", True),
        ("172.16.0.1",     True),
        ("172.31.255.1",   True),
        ("192.168.1.1",    True),
        ("8.8.8.8",        False),
        ("203.0.113.45",   False),
        ("198.51.100.77",  False),
        ("172.32.0.1",     False),  # outside 172.16-31 range
    ])
    def test_is_internal(self, ip, expected):
        assert _is_internal(ip) == expected

    def test_parse_iso(self):
        dt = _parse_iso("2026-04-21T13:00:00Z")
        assert dt.year == 2026 and dt.month == 4 and dt.day == 21
        assert dt.hour == 13 and dt.minute == 0

    def test_ct_user_of_iam_user(self):
        record = {"userIdentity": {"type": "IAMUser", "userName": "alice"}}
        assert _ct_user_of(record) == "alice"

    def test_ct_user_of_assumed_role(self):
        record = {"userIdentity": {
            "type": "AssumedRole",
            "sessionContext": {"sessionIssuer": {"userName": "ci-bot"}}
        }}
        assert _ct_user_of(record) == "ci-bot"

    def test_ct_user_of_unknown(self):
        assert _ct_user_of({"userIdentity": {}}) == "unknown"
        assert _ct_user_of({}) == "unknown"


# ============================================================================
# Section 2: Smoke tests
# ============================================================================

class TestSmoke:
    """Each tool should return valid markdown and not crash on real data."""

    def test_cloudtrail_returns_markdown(self):
        result = call(analyze_cloudtrail_logs)
        assert isinstance(result, str) and len(result) > 100
        assert result.startswith("## CloudTrail Analysis")
        assert "Total events analyzed:" in result

    def test_vpc_returns_markdown(self):
        result = call(analyze_vpc_flow_logs)
        assert isinstance(result, str) and len(result) > 100
        assert result.startswith("## VPC Flow Logs Analysis")

    def test_auth_returns_markdown(self):
        result = call(analyze_auth_logs)
        assert isinstance(result, str) and len(result) > 100
        assert result.startswith("## Auth Logs Analysis")


# ============================================================================
# Section 3: CloudTrail detection tests
# ============================================================================

class TestCloudTrail:
    """Each detection branch should fire on the sample data exactly as designed."""

    @pytest.fixture(scope="class")
    def report(self):
        return call(analyze_cloudtrail_logs)

    def test_brute_force_detected(self, report):
        # Sample S1: 6 failed logins from 203.0.113.45 → HIGH severity
        assert "BRUTE_FORCE_CONSOLE_LOGIN" in report
        assert "203.0.113.45" in report
        assert "6 failed ConsoleLogin" in report

    def test_brute_force_severity_high(self, report):
        # 6 attempts ≥ HIGH threshold (5)
        m = re.search(r"BRUTE_FORCE_CONSOLE_LOGIN.*?Severity:\*\*\s*(\w+)",
                       report, re.DOTALL)
        assert m and m.group(1) == "HIGH"

    def test_privesc_count_seven(self, report):
        # 5 attack events + 2 legitimate (false positives) = 7 PRIVILEGE_ESCALATION
        count = report.count("PRIVILEGE_ESCALATION:")
        # Each finding has the type appear in section header AND as detail string
        # Counting "Finding #N: PRIVILEGE_ESCALATION" is more precise:
        finding_count = len(re.findall(r"Finding #\d+: PRIVILEGE_ESCALATION", report))
        assert finding_count == 7, f"Expected 7 privesc findings, got {finding_count}"

    def test_privesc_includes_false_positives(self, report):
        # The 2 legitimate IAM events from senior-admin must be flagged
        # (this is a known limitation, intentionally surfaced)
        assert "senior-admin" in report
        assert "new-employee-jane" in report  # the onboarded user

    def test_privesc_attack_chain(self, report):
        # All 5 dev-user privesc events present
        for event in ("CreateAccessKey", "AttachUserPolicy", "CreateRole",
                      "UpdateAssumeRolePolicy", "PutUserPolicy"):
            assert f"PRIVILEGE_ESCALATION:{event}" in report

    def test_unauthorized_count_four(self, report):
        # S4 has 4 Unauthorized errors (ListUsers, ListRoles, RunInstances, CreateUser)
        count = len(re.findall(r"Finding #\d+: UNAUTHORIZED_ACCESS", report))
        assert count == 4

    def test_unauthorized_actor_is_aws_deploy_bot(self, report):
        # All 4 unauthorized events came from aws-deploy-bot (S4 leaked-key incident)
        unauth_section = re.search(
            r"UNAUTHORIZED_ACCESS.*?(?=Finding #|\Z)", report, re.DOTALL)
        assert unauth_section and "aws-deploy-bot" in unauth_section.group(0)

    def test_s3_public_bucket_detected(self, report):
        # PutBucketPolicy with Principal:"*" should fire CRITICAL
        assert "S3_PUBLIC_BUCKET_EXPOSURE" in report
        assert "prod-customer-data" in report

    def test_s3_mass_object_access_detected(self, report):
        # 3 GetObjects from dev-user within 10 seconds
        assert "S3_MASS_OBJECT_ACCESS" in report
        assert "downloaded 3 S3 objects" in report

    def test_total_findings_count(self, report):
        # 1 brute force + 7 privesc + 4 unauthorized + 1 S3 public + 1 S3 mass = 14
        m = re.search(r"Findings:\*\*\s*(\d+)", report)
        assert m and int(m.group(1)) == 14

    def test_mitre_mappings_present(self, report):
        # Each detection should include its MITRE technique ID
        for tid in ("T1110", "T1098", "T1078", "T1530"):
            assert tid in report

    def test_normal_users_not_flagged(self, report):
        # Pure normal users (data-analyst, ops-engineer, ci-pipeline-bot)
        # should NOT appear in any finding.
        # (senior-admin is flagged due to onboarding false-positive — that's expected)
        assert "data-analyst" not in report
        assert "ops-engineer" not in report
        assert "ci-pipeline-bot" not in report

    def test_dev_user_normal_baseline_not_flagged(self, report):
        # dev-user's morning activity from office IP 198.18.0.50 is benign.
        # The afternoon compromise from 203.0.113.45 IS flagged.
        # Make sure no finding cites the office IP as malicious.
        assert "198.18.0.50" not in report


# ============================================================================
# Section 4: VPC detection tests
# ============================================================================

class TestVPC:

    @pytest.fixture(scope="class")
    def report(self):
        return call(analyze_vpc_flow_logs)

    def test_port_scan_detected(self, report):
        assert "PORT_SCAN" in report
        assert "198.51.100.200" in report
        assert "12 distinct ports" in report

    def test_port_scan_reject_ratio(self, report):
        assert "75% REJECT" in report

    def test_ssh_brute_force_detected(self, report):
        assert "SSH_BRUTE_FORCE_NETWORK" in report
        assert "45.142.213.50" in report
        assert "8 SSH connections" in report

    def test_ssh_brute_references_auth_logs(self, report):
        # The detail message hints at cross-source correlation
        assert "auth_logs" in report

    def test_exfiltration_three_flows(self, report):
        count = len(re.findall(r"Finding #\d+: DATA_EXFILTRATION", report))
        assert count == 3

    def test_exfiltration_severity_critical(self, report):
        m = re.search(r"DATA_EXFILTRATION.*?Severity:\*\*\s*(\w+)",
                       report, re.DOTALL)
        assert m and m.group(1) == "CRITICAL"

    def test_exfiltration_targets_attacker_c2(self, report):
        assert "45.155.205.99" in report

    def test_internal_ssh_not_flagged(self, report):
        # No legitimate internal traffic (10.0.x.x → 10.0.x.x) should be flagged
        # ssh_brute_force only fires for external sources
        assert "internal" in report.lower() or "Internal" in report  # only in DATA_EXFILTRATION
        # Specifically, no internal IP should appear as a brute-force *source*
        bf_section = re.search(r"SSH_BRUTE_FORCE_NETWORK.*?(?=Finding #|\Z)",
                               report, re.DOTALL)
        if bf_section:
            for prefix in INTERNAL_PREFIXES:
                # Source IP line shouldn't start with internal prefix
                assert f"Source IP:** {prefix}" not in bf_section.group(0)

    def test_total_findings_five(self, report):
        m = re.search(r"Findings:\*\*\s*(\d+)", report)
        assert m and int(m.group(1)) == 5


# ============================================================================
# Section 5: Auth detection tests
# ============================================================================

class TestAuth:

    @pytest.fixture(scope="class")
    def report(self):
        return call(analyze_auth_logs)

    def test_ssh_brute_force_detected(self, report):
        assert "SSH_BRUTE_FORCE" in report
        assert "45.142.213.50" in report
        assert "7 failed SSH auth attempts" in report

    def test_ssh_compromise_detected(self, report):
        # Failure → success from same IP within window = CRITICAL
        assert "SSH_COMPROMISE_AFTER_BRUTE_FORCE" in report
        assert "ubuntu" in report
        assert "web-server-01" in report

    def test_ssh_compromise_severity_critical(self, report):
        m = re.search(r"SSH_COMPROMISE_AFTER_BRUTE_FORCE.*?Severity:\*\*\s*(\w+)",
                       report, re.DOTALL)
        assert m and m.group(1) == "CRITICAL"

    def test_sudo_escalation_detected(self, report):
        assert "SUDO_ESCALATION_ATTEMPTS" in report
        # Both failed sudo commands present
        assert "/bin/su -" in report
        assert "/bin/bash" in report

    def test_a4_noise_not_flagged(self, report):
        # Two single-attempt failed logins (91.234.56.78 and 178.62.13.5)
        # are below brute-force threshold (3) → must NOT trigger.
        assert "91.234.56.78" not in report
        assert "178.62.13.5" not in report

    def test_normal_users_not_flagged(self, report):
        # Trusted users with successful SSH should not appear in any finding
        for user in ("senior-admin", "devops-eng", "sre-oncall", "ci-deploy"):
            assert user not in report

    def test_total_findings_three(self, report):
        m = re.search(r"Findings:\*\*\s*(\d+)", report)
        assert m and int(m.group(1)) == 3


# ============================================================================
# Section 6: Edge case tests
# ============================================================================

class TestEdgeCases:

    def test_missing_file_returns_error(self, tmp_path, monkeypatch):
        """Tool should return an error string, not crash, when log file missing."""
        monkeypatch.setattr(log_analyzer, "DATA_DIR", tmp_path)
        result = call(analyze_cloudtrail_logs)
        assert "Error" in result or "❌" in result

    def test_empty_records_handled(self, tmp_path, monkeypatch):
        """Empty 'Records' array should produce a clean 'no findings' message."""
        empty_file = tmp_path / "cloudtrail_sample.json"
        empty_file.write_text(json.dumps({"Records": []}))
        monkeypatch.setattr(log_analyzer, "DATA_DIR", tmp_path)
        result = call(analyze_cloudtrail_logs)
        assert "No records found" in result or "No suspicious activity" in result

    def test_no_findings_clean_message(self, tmp_path, monkeypatch):
        """A log with only normal activity should report 'no suspicious activity'."""
        clean = {"Records": [{
            "eventName": "DescribeInstances",
            "eventTime": "2026-04-21T10:00:00Z",
            "sourceIPAddress": "10.0.1.20",
            "userIdentity": {"type": "IAMUser", "userName": "ops-user"},
            "responseElements": None,
            "requestParameters": {},
        }]}
        f = tmp_path / "cloudtrail_sample.json"
        f.write_text(json.dumps(clean))
        monkeypatch.setattr(log_analyzer, "DATA_DIR", tmp_path)
        result = call(analyze_cloudtrail_logs)
        assert "No suspicious activity detected" in result

    def test_brute_force_threshold_boundary(self, tmp_path, monkeypatch):
        """2 failed logins = below threshold (3); should NOT fire."""
        records = [
            {
                "eventName": "ConsoleLogin",
                "eventTime": f"2026-04-21T10:0{i}:00Z",
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {"type": "IAMUser", "userName": "test"},
                "responseElements": {"ConsoleLogin": "Failure"},
                "requestParameters": {},
            }
            for i in range(2)
        ]
        f = tmp_path / "cloudtrail_sample.json"
        f.write_text(json.dumps({"Records": records}))
        monkeypatch.setattr(log_analyzer, "DATA_DIR", tmp_path)
        result = call(analyze_cloudtrail_logs)
        assert "BRUTE_FORCE" not in result


# ============================================================================
# Section 7: Cross-source correlation tests
# ============================================================================

class TestCrossCorrelation:
    """The same incident should surface in both VPC and auth log analyses."""

    def test_ssh_brute_ip_in_both_reports(self):
        """45.142.213.50 should appear in both VPC SSH brute and auth SSH brute."""
        vpc_report = call(analyze_vpc_flow_logs)
        auth_report = call(analyze_auth_logs)
        assert "45.142.213.50" in vpc_report
        assert "45.142.213.50" in auth_report

    def test_compromised_host_appears_in_vpc_exfil(self):
        """web-server-01 (10.0.1.50) is compromised in auth logs and is the
        source of the VPC exfil flows. The same host should appear in both."""
        auth_report = call(analyze_auth_logs)
        vpc_report = call(analyze_vpc_flow_logs)
        assert "web-server-01" in auth_report
        assert "10.0.1.50" in vpc_report  # in DATA_EXFILTRATION findings


# ============================================================================
# Section 8: MITRE mapping tests
# ============================================================================

class TestMITREMapping:

    def test_all_mitre_keys_have_full_mapping(self):
        """Every entry in MITRE dict has exactly (id, tactic, name)."""
        for key, value in MITRE.items():
            assert isinstance(value, tuple) and len(value) == 3
            tid, tactic, name = value
            assert tid.startswith("T") and tid[1:].isdigit()
            assert tactic and name

    def test_mitre_appears_in_findings(self):
        """Each tool's report should reference the relevant MITRE technique."""
        ct = call(analyze_cloudtrail_logs)
        assert "MITRE ATT&CK:" in ct
        assert "T1110" in ct  # brute force

        vpc = call(analyze_vpc_flow_logs)
        assert "MITRE ATT&CK:" in vpc
        assert "T1046" in vpc  # network service discovery

        auth = call(analyze_auth_logs)
        assert "MITRE ATT&CK:" in auth
        assert "T1078" in auth  # valid accounts (compromise)