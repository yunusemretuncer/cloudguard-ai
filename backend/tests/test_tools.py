"""
test_tools.py — pytest test suite for log_analyzer's three @tool functions.

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

# --- Path & data-directory setup --------------------------------------------
# This test file lives at backend/tests/test_tools.py.
# log_analyzer.py lives at backend/app/agent/tools/log_analyzer.py.
# Sample data lives at backend/data/sample_logs/.
#
# Resolve both relative to this file so the suite works regardless of
# where pytest is invoked from (CI runs from backend/, locally we may
# run from the repo root or the tests/ dir).

_THIS_DIR    = Path(__file__).resolve().parent          # .../backend/tests
_BACKEND_DIR = _THIS_DIR.parent                          # .../backend
_TOOLS_DIR   = _BACKEND_DIR / "app" / "agent" / "tools"  # .../backend/app/agent/tools
_DATA_DIR    = _BACKEND_DIR / "data" / "sample_logs"     # .../backend/data/sample_logs

sys.path.insert(0, str(_TOOLS_DIR))

# Point log_analyzer at our real sample data BEFORE importing it.
# The module reads CLOUDGUARD_DATA_DIR at import time.
os.environ["CLOUDGUARD_DATA_DIR"] = str(_DATA_DIR)

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
        # Counting "Finding #N: PRIVILEGE_ESCALATION" matches each finding
        # exactly once (the type appears in section headers).
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


# ============================================================================
# Section 9: config_auditor tests
# ============================================================================

import config_auditor  # noqa: E402
from config_auditor import audit_cloud_config  # noqa: E402


class TestConfigAuditor:

    @pytest.fixture(scope="class")
    def report_all(self):
        return call(audit_cloud_config, "all") if False else \
               (audit_cloud_config.invoke({"check_type": "all"})
                if hasattr(audit_cloud_config, "invoke")
                else audit_cloud_config("all"))

    # ---- Smoke -------------------------------------------------------------

    def test_returns_markdown(self, report_all):
        assert isinstance(report_all, str)
        assert report_all.startswith("## AWS Configuration Audit")

    def test_total_finding_count(self, report_all):
        # 6 S3 + 2 SG + 5 IAM + 3 RDS = 16
        m = re.search(r"\*\*Total findings:\*\*\s*(\d+)", report_all)
        assert m and int(m.group(1)) == 16

    # ---- S3 ----------------------------------------------------------------

    def test_s3_public_bucket_critical(self, report_all):
        assert "prod-customer-data" in report_all
        assert "publicly accessible" in report_all
        # Cross-correlation hint must appear
        assert "CloudTrail S3 chain" in report_all

    def test_s3_no_encryption_high(self, report_all):
        assert "no encryption at rest" in report_all

    def test_s3_weak_encryption_low(self, report_all):
        assert "SSE-S3 instead of KMS" in report_all
        assert "app-config" in report_all

    def test_s3_versioning_disabled(self, report_all):
        # Both prod-customer-data and deployment-logs should have this finding
        count = report_all.count("versioning is disabled")
        assert count == 2

    def test_s3_compliance_archive_clean(self, report_all):
        # The properly-configured bucket should NEVER appear as a problem
        # (it CAN appear in a "no findings" section, but shouldn't be in any
        # CRITICAL/HIGH/MEDIUM/LOW finding header)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"{sev} — `compliance-archive`" not in report_all

    # ---- Security Groups ---------------------------------------------------

    def test_sg_ssh_open(self, report_all):
        assert "sg-web-public" in report_all
        assert "SSH (port 22) open" in report_all
        assert "Auth logs" in report_all  # cross-correlation

    def test_sg_db_port_open(self, report_all):
        assert "sg-rds-1" in report_all
        assert "Database port 5432" in report_all

    def test_sg_internal_clean(self, report_all):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"{sev} — `sg-app-internal`" not in report_all

    def test_sg_bastion_clean(self, report_all):
        # SSH restricted to office CIDR is a best practice — must not flag
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"{sev} — `sg-bastion`" not in report_all

    # ---- IAM ---------------------------------------------------------------

    def test_iam_admin_no_mfa(self, report_all):
        # admin-user and dev-user are both admins without MFA
        mfa_findings = report_all.count("does not have MFA enabled")
        assert mfa_findings == 2

    def test_iam_old_key_rotation(self, report_all):
        # admin-user (689 days), dev-user (402 days) → HIGH
        # aws-deploy-bot (200 days) → MEDIUM
        assert "689 days" in report_all
        assert "402 days" in report_all
        assert "200 days old" in report_all

    def test_iam_correlation_hints(self, report_all):
        assert "CloudTrail S2 — attacker AttachUserPolicy" in report_all
        assert "CloudTrail S4 — this user's access key was leaked" in report_all

    def test_iam_well_managed_admin_clean(self, report_all):
        # senior-admin has MFA + recently-rotated key — must NOT trigger
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"{sev} — `senior-admin`" not in report_all

    def test_iam_readonly_clean(self, report_all):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"{sev} — `data-analyst`" not in report_all

    def test_iam_service_account_no_mfa_finding(self, report_all):
        # aws-deploy-bot is a service account; the MFA check should NOT
        # fire for it (service accounts don't use console)
        # The user should ONLY have the key-rotation finding, not MFA.
        # Since MFA-finding text is shared, we can't grep it directly;
        # instead, we confirm aws-deploy-bot doesn't appear in an MFA section.
        # Build a per-user view:
        for line in report_all.split("\n"):
            if "aws-deploy-bot" in line and "MFA" in line:
                pytest.fail(f"Service account flagged for MFA: {line}")

    # ---- RDS ---------------------------------------------------------------

    def test_rds_public_critical(self, report_all):
        assert "prod-customer-db" in report_all
        assert "publicly accessible" in report_all

    def test_rds_unencrypted(self, report_all):
        assert "DB storage is not encrypted" in report_all

    def test_rds_short_backup(self, report_all):
        assert "Backup retention is only 1 day" in report_all

    def test_rds_clean_instance(self, report_all):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert f"{sev} — `analytics-db`" not in report_all

    # ---- Scope filtering ---------------------------------------------------

    def test_scope_s3_only(self):
        result = (audit_cloud_config.invoke({"check_type": "s3"})
                  if hasattr(audit_cloud_config, "invoke")
                  else audit_cloud_config("s3"))
        assert "S3 Buckets" in result
        assert "Security Groups" not in result
        assert "IAM Users" not in result
        assert "RDS Instances" not in result

    def test_scope_iam_only(self):
        result = (audit_cloud_config.invoke({"check_type": "iam"})
                  if hasattr(audit_cloud_config, "invoke")
                  else audit_cloud_config("iam"))
        assert "IAM Users" in result
        assert "S3 Buckets" not in result

    def test_scope_invalid(self):
        result = (audit_cloud_config.invoke({"check_type": "lambda"})
                  if hasattr(audit_cloud_config, "invoke")
                  else audit_cloud_config("lambda"))
        assert "Error" in result and "invalid" in result.lower()

    # ---- Edge cases --------------------------------------------------------

    def test_missing_file_returns_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config_auditor, "DATA_DIR", tmp_path)
        result = (audit_cloud_config.invoke({"check_type": "all"})
                  if hasattr(audit_cloud_config, "invoke")
                  else audit_cloud_config("all"))
        assert "Error" in result or "❌" in result

    def test_empty_snapshot_handled(self, tmp_path, monkeypatch):
        empty = {"snapshot_time": "2026-04-21T12:00:00Z",
                 "account_id": "111", "region": "eu-west-1",
                 "resources": {"s3_buckets": [], "security_groups": [],
                               "iam_users": [], "rds_instances": []}}
        f = tmp_path / "aws_config_sample.json"
        f.write_text(json.dumps(empty))
        monkeypatch.setattr(config_auditor, "DATA_DIR", tmp_path)
        result = (audit_cloud_config.invoke({"check_type": "all"})
                  if hasattr(audit_cloud_config, "invoke")
                  else audit_cloud_config("all"))
        assert "No misconfigurations detected" in result

    # ---- Cross-correlation with other tools --------------------------------

    def test_cross_correlation_s3_with_cloudtrail(self, report_all):
        """The bucket flagged here as public is the same bucket the
        cloudtrail S3 mass-access finding cites."""
        ct = call(analyze_cloudtrail_logs)
        # Both should mention the same bucket
        assert "prod-customer-data" in report_all
        assert "prod-customer-data" in ct

    def test_cross_correlation_sg_with_auth(self, report_all):
        """The SSH-open SG flagged here is the network-layer enabler of the
        auth_logs SSH brute-force compromise."""
        auth = call(analyze_auth_logs)
        assert "sg-web-public" in report_all
        # auth_logs report identifies web-server-01 as the compromised host;
        # config_auditor identifies the SG that backs it.
        assert "web-server-01" in auth


# ============================================================================
# Section 10: remediation tests
# ============================================================================

import remediation  # noqa: E402,F401  (imported for monkeypatching in tests if needed)
from remediation import get_remediation, PLAYBOOKS, _normalize, _parse_context  # noqa: E402


class TestRemediation:

    # ---- Helper functions --------------------------------------------------

    def test_normalize_known_high_level(self):
        assert _normalize("BRUTE_FORCE") == "BRUTE_FORCE"
        assert _normalize("S3_PUBLIC_EXPOSURE") == "S3_PUBLIC_EXPOSURE"

    def test_normalize_specific_to_category(self):
        assert _normalize("BRUTE_FORCE_CONSOLE_LOGIN") == "BRUTE_FORCE"
        assert _normalize("SSH_BRUTE_FORCE_NETWORK") == "BRUTE_FORCE"
        assert _normalize("S3_PUBLIC_BUCKET_EXPOSURE") == "S3_PUBLIC_EXPOSURE"
        assert _normalize("S3_MASS_OBJECT_ACCESS") == "DATA_EXFILTRATION"
        assert _normalize("SSH_COMPROMISE_AFTER_BRUTE_FORCE") == "SSH_COMPROMISE"

    def test_normalize_strips_colon_suffix(self):
        # log_analyzer emits "PRIVILEGE_ESCALATION:CreateRole" etc.
        assert _normalize("PRIVILEGE_ESCALATION:CreateRole") == "PRIVILEGE_ESCALATION"
        assert _normalize("PRIVILEGE_ESCALATION:AttachUserPolicy") == "PRIVILEGE_ESCALATION"

    def test_normalize_case_insensitive(self):
        assert _normalize("brute_force") == "BRUTE_FORCE"
        assert _normalize("Brute_Force") == "BRUTE_FORCE"

    def test_normalize_empty_or_unknown(self):
        assert _normalize("") == ""
        assert _normalize("NONEXISTENT") == ""

    # ---- Context parsing --------------------------------------------------

    def test_parse_context_simple(self):
        ctx = _parse_context("ip=1.2.3.4")
        assert ctx == {"ip": "1.2.3.4"}

    def test_parse_context_multiple(self):
        ctx = _parse_context("ip=1.2.3.4, user=alice, bucket=mydata")
        assert ctx == {"ip": "1.2.3.4", "user": "alice", "bucket": "mydata"}

    def test_parse_context_whitespace_separated(self):
        ctx = _parse_context("ip=1.2.3.4 user=alice")
        assert ctx == {"ip": "1.2.3.4", "user": "alice"}

    def test_parse_context_drops_unknown_keys(self):
        ctx = _parse_context("ip=1.2.3.4, xyz=foo")
        assert "ip" in ctx
        assert "xyz" not in ctx  # 'xyz' is not in PLACEHOLDER_KEYS

    def test_parse_context_empty(self):
        assert _parse_context("") == {}
        assert _parse_context(None) == {}

    # ---- Tool invocation: each playbook ------------------------------------

    @pytest.mark.parametrize("finding_type,expected_mitre", [
        ("BRUTE_FORCE",                    "T1110"),
        ("PRIVILEGE_ESCALATION",           "T1098"),
        ("SSH_COMPROMISE",                 "T1078"),
        ("SUDO_ESCALATION",                "T1548"),
        ("UNAUTHORIZED_ACCESS",            "T1078"),
        ("S3_PUBLIC_EXPOSURE",             "T1530"),
        ("DATA_EXFILTRATION",              "T1048"),
        ("NETWORK_RECON",                  "T1046"),
        ("SECURITY_GROUP_MISCONFIG",       "T1133"),
        ("IAM_HYGIENE",                    "T1078"),
        ("RDS_EXPOSURE",                   "T1530"),
    ])
    def test_each_playbook_returns_full_structure(self, finding_type, expected_mitre):
        r = (get_remediation.invoke({"finding_type": finding_type})
             if hasattr(get_remediation, "invoke")
             else get_remediation(finding_type))
        assert "Remediation Playbook" in r
        assert expected_mitre in r
        assert "Immediate" in r
        assert "Investigation" in r
        assert "Long-term" in r
        assert "NIST SP 800-61" in r

    # ---- Specific finding types from other tools work ---------------------

    def test_specific_finding_type_routes_correctly(self):
        # log_analyzer emits this exact string; remediation must handle it
        r = (get_remediation.invoke({"finding_type": "PRIVILEGE_ESCALATION:CreateAccessKey"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("PRIVILEGE_ESCALATION:CreateAccessKey"))
        assert "T1098" in r

    def test_s3_mass_access_routes_to_exfiltration(self):
        r = (get_remediation.invoke({"finding_type": "S3_MASS_OBJECT_ACCESS"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("S3_MASS_OBJECT_ACCESS"))
        assert "Data Exfiltration" in r
        assert "T1048" in r

    # ---- Context substitution ---------------------------------------------

    def test_context_substitution_ip(self):
        r = (get_remediation.invoke({"finding_type": "BRUTE_FORCE",
                                      "context": "ip=203.0.113.45"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("BRUTE_FORCE", "ip=203.0.113.45"))
        assert "203.0.113.45" in r
        assert "<IP>" not in r  # placeholder should be replaced

    def test_context_substitution_multiple(self):
        r = (get_remediation.invoke({
                "finding_type": "PRIVILEGE_ESCALATION",
                "context": "user=dev-user, key_id=AKIATEST123"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("PRIVILEGE_ESCALATION",
                                  "user=dev-user, key_id=AKIATEST123"))
        assert "dev-user" in r
        assert "AKIATEST123" in r
        assert "<USER>" not in r
        assert "<KEY_ID>" not in r

    def test_context_substitution_bucket(self):
        r = (get_remediation.invoke({"finding_type": "S3_PUBLIC_EXPOSURE",
                                      "context": "bucket=prod-customer-data"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("S3_PUBLIC_EXPOSURE", "bucket=prod-customer-data"))
        assert "prod-customer-data" in r
        assert "<BUCKET>" not in r

    def test_no_context_keeps_placeholders(self):
        # Without context, placeholders should remain visible (still useful
        # as a copy-paste template the user fills in)
        r = (get_remediation.invoke({"finding_type": "SSH_COMPROMISE"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("SSH_COMPROMISE"))
        assert "<HOST>" in r or "<USER>" in r

    # ---- Error handling ---------------------------------------------------

    def test_unknown_finding_type_helpful_error(self):
        r = (get_remediation.invoke({"finding_type": "TOTALLY_MADE_UP"})
             if hasattr(get_remediation, "invoke")
             else get_remediation("TOTALLY_MADE_UP"))
        assert "❌" in r
        assert "TOTALLY_MADE_UP" in r
        assert "Available playbooks" in r

    def test_empty_finding_type_returns_error(self):
        r = (get_remediation.invoke({"finding_type": ""})
             if hasattr(get_remediation, "invoke")
             else get_remediation(""))
        assert "❌" in r

    # ---- Structural checks ------------------------------------------------

    def test_all_playbooks_have_required_fields(self):
        for key, pb in PLAYBOOKS.items():
            assert "title" in pb,         f"{key} missing title"
            assert "mitre_id" in pb,      f"{key} missing mitre_id"
            assert "mitre_tactic" in pb,  f"{key} missing mitre_tactic"
            assert "mitre_technique" in pb, f"{key} missing mitre_technique"
            assert "immediate" in pb and len(pb["immediate"]) >= 1
            assert "investigation" in pb and len(pb["investigation"]) >= 1
            assert "long_term" in pb and len(pb["long_term"]) >= 1

    def test_aws_cli_commands_present(self):
        # At least the most common playbooks should include CLI commands
        r_brute = (get_remediation.invoke({"finding_type": "BRUTE_FORCE"})
                   if hasattr(get_remediation, "invoke")
                   else get_remediation("BRUTE_FORCE"))
        assert "aws " in r_brute  # AWS CLI command(s)

        r_s3 = (get_remediation.invoke({"finding_type": "S3_PUBLIC_EXPOSURE"})
                if hasattr(get_remediation, "invoke")
                else get_remediation("S3_PUBLIC_EXPOSURE"))
        assert "aws s3api" in r_s3


# ============================================================================
# Section 11: alert_generator tests
# ============================================================================
# These tests stub out the DB layer with an in-memory SQLite so they
# can run without the full backend wired up (CI doesn't need to spin
# up the FastAPI app to test tool logic).

class TestAlertGenerator:

    @pytest.fixture(autouse=True)
    def isolated_db(self, monkeypatch, tmp_path):
        """Replace the project DB with an in-memory SQLite + create the
        Alert table fresh for each test. Auto-applied to every test in
        this class via autouse=True."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker, DeclarativeBase

        # Build a minimal Base + Alert model in isolation (decoupled
        # from the project's app.db.* — those imports may not resolve
        # in CI's working directory).
        class _Base(DeclarativeBase):
            pass

        from sqlalchemy import DateTime, Integer, String, Text
        from sqlalchemy.orm import Mapped, mapped_column
        from datetime import datetime, timezone

        class _Alert(_Base):
            __tablename__ = "alerts"
            id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
            created_at: Mapped[datetime] = mapped_column(
                DateTime(timezone=True),
                default=lambda: datetime.now(timezone.utc),
                index=True,
            )
            alert_type: Mapped[str] = mapped_column(String(64), index=True)
            severity: Mapped[str] = mapped_column(String(16), index=True)
            details: Mapped[str] = mapped_column(Text)
            mitre_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
            mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
            mitre_technique: Mapped[str | None] = mapped_column(String(128), nullable=True)
            source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
            user_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
            resource_id: Mapped[str | None] = mapped_column(String(256), nullable=True)

        engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
        _Base.metadata.create_all(bind=engine)
        TestSession = sessionmaker(bind=engine)

        # Patch the import targets that alert_generator._persist_alert uses.
        # We construct fake `app.db.database` and `app.db.models` modules
        # so the production import path inside _persist_alert resolves to
        # our test session and Alert class.
        import sys
        import types
        fake_db_pkg = types.ModuleType("app.db")
        fake_db_module = types.ModuleType("app.db.database")
        fake_db_module.SessionLocal = TestSession
        fake_models_module = types.ModuleType("app.db.models")
        fake_models_module.Alert = _Alert

        fake_app = types.ModuleType("app")
        fake_app.db = fake_db_pkg
        fake_db_pkg.database = fake_db_module
        fake_db_pkg.models = fake_models_module

        monkeypatch.setitem(sys.modules, "app", fake_app)
        monkeypatch.setitem(sys.modules, "app.db", fake_db_pkg)
        monkeypatch.setitem(sys.modules, "app.db.database", fake_db_module)
        monkeypatch.setitem(sys.modules, "app.db.models", fake_models_module)

        self._SessionLocal = TestSession
        self._Alert = _Alert
        yield
        # Cleanup happens automatically via tmp_path

    # ---- Smoke -------------------------------------------------------------

    def test_records_minimal_alert(self):
        from alert_generator import generate_alert
        result = (generate_alert.invoke({
            "finding_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "details": "test details",
        }) if hasattr(generate_alert, "invoke")
          else generate_alert("BRUTE_FORCE", "HIGH", "test details"))
        assert "Alert Recorded" in result
        assert "Alert ID:** #1" in result
        assert "T1110" in result

    def test_alert_persisted_to_db(self):
        from alert_generator import generate_alert
        if hasattr(generate_alert, "invoke"):
            generate_alert.invoke({
                "finding_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "details": "test",
                "source_ip": "203.0.113.45",
            })
        else:
            generate_alert("BRUTE_FORCE", "HIGH", "test", "203.0.113.45")
        # Verify row exists with correct values
        db = self._SessionLocal()
        try:
            rows = db.query(self._Alert).all()
            assert len(rows) == 1
            assert rows[0].alert_type == "BRUTE_FORCE"
            assert rows[0].severity == "HIGH"
            assert rows[0].source_ip == "203.0.113.45"
            assert rows[0].mitre_id == "T1110"
        finally:
            db.close()

    # ---- MITRE mapping -----------------------------------------------------

    @pytest.mark.parametrize("finding_type,expected_mitre", [
        ("BRUTE_FORCE",                        "T1110"),
        ("BRUTE_FORCE_CONSOLE_LOGIN",          "T1110"),
        ("SSH_BRUTE_FORCE_NETWORK",            "T1110"),
        ("PRIVILEGE_ESCALATION",               "T1098"),
        ("PRIVILEGE_ESCALATION:CreateRole",    "T1098"),
        ("PRIVILEGE_ESCALATION:AttachUserPolicy", "T1098"),
        ("UNAUTHORIZED_ACCESS",                "T1078"),
        ("SSH_COMPROMISE",                     "T1078"),
        ("SUDO_ESCALATION",                    "T1548"),
        ("S3_PUBLIC_EXPOSURE",                 "T1530"),
        ("S3_PUBLIC_BUCKET_EXPOSURE",          "T1530"),
        ("S3_MASS_OBJECT_ACCESS",              "T1048"),
        ("DATA_EXFILTRATION",                  "T1048"),
        ("PORT_SCAN",                          "T1046"),
        ("NETWORK_RECON",                      "T1046"),
        ("SECURITY_GROUP_MISCONFIG",           "T1133"),
        ("IAM_HYGIENE",                        "T1078"),
        ("RDS_EXPOSURE",                       "T1530"),
    ])
    def test_mitre_mapping_for_finding(self, finding_type, expected_mitre):
        from alert_generator import generate_alert
        result = (generate_alert.invoke({
            "finding_type": finding_type, "severity": "HIGH",
            "details": "test",
        }) if hasattr(generate_alert, "invoke")
          else generate_alert(finding_type, "HIGH", "test"))
        assert expected_mitre in result, \
            f"{finding_type} should map to {expected_mitre}; got: {result}"

    # ---- Severity validation ----------------------------------------------

    def test_invalid_severity_coerced_to_low(self):
        from alert_generator import generate_alert
        result = (generate_alert.invoke({
            "finding_type": "BRUTE_FORCE", "severity": "NUCLEAR",
            "details": "test",
        }) if hasattr(generate_alert, "invoke")
          else generate_alert("BRUTE_FORCE", "NUCLEAR", "test"))
        assert "Severity:** LOW" in result

    def test_lowercase_severity_accepted(self):
        from alert_generator import generate_alert
        result = (generate_alert.invoke({
            "finding_type": "BRUTE_FORCE", "severity": "high",
            "details": "test",
        }) if hasattr(generate_alert, "invoke")
          else generate_alert("BRUTE_FORCE", "high", "test"))
        assert "Severity:** HIGH" in result

    def test_empty_severity_defaults_to_low(self):
        from alert_generator import generate_alert
        result = (generate_alert.invoke({
            "finding_type": "BRUTE_FORCE", "severity": "",
            "details": "test",
        }) if hasattr(generate_alert, "invoke")
          else generate_alert("BRUTE_FORCE", "", "test"))
        assert "Severity:** LOW" in result

    # ---- Unknown finding type ----------------------------------------------

    def test_unknown_finding_records_without_mitre(self):
        from alert_generator import generate_alert
        result = (generate_alert.invoke({
            "finding_type": "TOTALLY_MADE_UP_THING", "severity": "MEDIUM",
            "details": "test",
        }) if hasattr(generate_alert, "invoke")
          else generate_alert("TOTALLY_MADE_UP_THING", "MEDIUM", "test"))
        # Alert is still recorded (DB row exists)
        assert "Alert Recorded" in result
        # But no MITRE mapping
        assert "MITRE ATT&CK" not in result
        # Row in DB should have nulls for mitre_*
        db = self._SessionLocal()
        try:
            row = db.query(self._Alert).first()
            assert row.mitre_id is None
            assert row.mitre_tactic is None
        finally:
            db.close()

    # ---- Optional context fields -------------------------------------------

    def test_empty_strings_stored_as_null(self):
        """LangChain passes "" for unfilled string params; we should store NULL."""
        from alert_generator import generate_alert
        if hasattr(generate_alert, "invoke"):
            generate_alert.invoke({
                "finding_type": "BRUTE_FORCE", "severity": "HIGH",
                "details": "test", "source_ip": "", "user_name": "",
                "resource_id": "",
            })
        else:
            generate_alert("BRUTE_FORCE", "HIGH", "test", "", "", "")
        db = self._SessionLocal()
        try:
            row = db.query(self._Alert).first()
            assert row.source_ip is None
            assert row.user_name is None
            assert row.resource_id is None
        finally:
            db.close()

    def test_all_context_fields_stored(self):
        from alert_generator import generate_alert
        if hasattr(generate_alert, "invoke"):
            generate_alert.invoke({
                "finding_type": "S3_PUBLIC_BUCKET_EXPOSURE",
                "severity": "CRITICAL",
                "details": "Bucket public",
                "source_ip": "203.0.113.45",
                "user_name": "dev-user",
                "resource_id": "prod-customer-data",
            })
        else:
            generate_alert("S3_PUBLIC_BUCKET_EXPOSURE", "CRITICAL",
                           "Bucket public", "203.0.113.45", "dev-user",
                           "prod-customer-data")
        db = self._SessionLocal()
        try:
            row = db.query(self._Alert).first()
            assert row.source_ip == "203.0.113.45"
            assert row.user_name == "dev-user"
            assert row.resource_id == "prod-customer-data"
        finally:
            db.close()

    # ---- Multiple alerts: IDs increment, no collision ----------------------

    def test_multiple_alerts_get_unique_ids(self):
        from alert_generator import generate_alert
        invoke = (generate_alert.invoke
                  if hasattr(generate_alert, "invoke")
                  else lambda d: generate_alert(**d))
        for i in range(3):
            invoke({
                "finding_type": "BRUTE_FORCE", "severity": "HIGH",
                "details": f"finding {i}",
            })
        db = self._SessionLocal()
        try:
            rows = db.query(self._Alert).order_by(self._Alert.id).all()
            ids = [r.id for r in rows]
            assert ids == [1, 2, 3]
        finally:
            db.close()

    # ---- Helper functions (no DB needed) -----------------------------------

    def test_normalize_finding_function(self):
        from alert_generator import _normalize_finding
        assert _normalize_finding("BRUTE_FORCE") == "BRUTE_FORCE"
        assert _normalize_finding("BRUTE_FORCE_CONSOLE_LOGIN") == "BRUTE_FORCE"
        assert _normalize_finding("PRIVILEGE_ESCALATION:CreateRole") == "PRIVILEGE_ESCALATION"
        assert _normalize_finding("S3_MASS_OBJECT_ACCESS") == "DATA_EXFILTRATION"
        assert _normalize_finding("") is None
        assert _normalize_finding("UNKNOWN_TYPE") is None

    def test_validate_severity_function(self):
        from alert_generator import _validate_severity
        assert _validate_severity("HIGH") == "HIGH"
        assert _validate_severity("low") == "LOW"
        assert _validate_severity("NUCLEAR") == "LOW"
        assert _validate_severity("") == "LOW"
        assert _validate_severity(None) == "LOW"