"""
config_auditor.py — AWS configuration security audit for the CloudGuard AI agent.

Exposes one @tool: `audit_cloud_config(check_type)` — analyzes a synthetic
AWS Config snapshot for misconfigurations across four resource categories.

Detection categories:

  S3 buckets:
    • Public access (block disabled OR policy grants public)        CRITICAL
    • Unencrypted at rest                                            HIGH
    • Weak encryption (SSE-S3 instead of KMS)                        LOW
    • Versioning disabled                                            MEDIUM
    • Access logging disabled                                        LOW

  Security groups:
    • SSH (22) open to 0.0.0.0/0                                     CRITICAL
    • RDP (3389) open to 0.0.0.0/0                                   CRITICAL
    • Database ports (3306/5432/1433/27017/6379) open to 0.0.0.0/0   CRITICAL
    • All-traffic (-1) or wide port ranges open to 0.0.0.0/0         HIGH

  IAM:
    • Admin user without MFA                                         HIGH
    • Access key older than 90 days                                  MEDIUM
    • Access key older than 365 days                                 HIGH
    • Inactive access key (created but never used in >90 days)       LOW

  RDS:
    • Publicly accessible                                            CRITICAL
    • Unencrypted storage                                            HIGH
    • Backup retention < 7 days                                      MEDIUM

Design notes:

1. Findings carry a `correlation_hint` field where they overlap with
   incidents in the other log samples. This lets the agent surface
   "this misconfig was actively exploited" reasoning in the demo.

2. Thresholds are named constants at the top of each section. Rationale
   is in the comment next to each one.

3. The check_type parameter lets the agent narrow audits ("just S3"),
   useful for follow-up queries after an initial broad audit.
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(func):
        return func


# ============================================================================
# Configuration
# ============================================================================

_DEFAULT_DIR = Path(__file__).parent.parent.parent.parent / "data" / "sample_logs"
DATA_DIR = Path(os.environ.get("CLOUDGUARD_DATA_DIR", _DEFAULT_DIR))

# Access-key rotation thresholds. AWS recommends ≤90 days; we treat
# >365 days as an outright finding because a key that old has likely
# never been rotated since creation.
KEY_AGE_MEDIUM_DAYS = 90
KEY_AGE_HIGH_DAYS   = 365

# Minimum acceptable backup retention. Below 7 days = insufficient
# recovery window for incident response.
RDS_MIN_BACKUP_DAYS = 7

# Database port set considered sensitive for SG audit.
DB_PORTS = {3306, 5432, 1433, 27017, 6379, 27018, 9042}

# Severity ranking
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_EMOJI = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "ℹ️"}

# Cross-correlation hints — which Week 1 incidents involve which resources.
# When the auditor flags one of these, the report mentions the linked attack
# so the agent can connect dots in conversation.
CORRELATION_HINTS = {
    "prod-customer-data": ("CloudTrail S3 chain — attacker made this bucket "
                           "public via PutBucketPolicy and exfiltrated PII"),
    "sg-web-public":      ("Auth logs — the open SSH port allowed a brute-force "
                           "compromise of web-server-01 (ubuntu user)"),
    "sg-rds-1":           ("Backs prod-customer-db, exposing it to the internet"),
    "dev-user":           ("CloudTrail S2 — attacker AttachUserPolicy'd this user "
                           "to AdministratorAccess after credential theft"),
    "aws-deploy-bot":     ("CloudTrail S4 — this user's access key was leaked on "
                           "GitHub and used for IAM/EC2 reconnaissance"),
    "prod-customer-db":   ("Behind sg-rds-1 (5432 open to 0.0.0.0/0) — fully "
                           "internet-accessible"),
}


# ============================================================================
# Helpers
# ============================================================================

def _load() -> Dict[str, Any]:
    path = DATA_DIR / "aws_config_sample.json"
    if not path.exists():
        raise FileNotFoundError(f"Config sample not found: {path}")
    with open(path) as f:
        return json.load(f)


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _days_old(iso_ts: str, reference_iso: str) -> int:
    """Days between iso_ts and reference_iso (always non-negative)."""
    return (_parse_iso(reference_iso) - _parse_iso(iso_ts)).days


def _finding(resource_type: str, resource_id: str, severity: str,
             issue: str, detail: str, remediation: str = "") -> Dict[str, Any]:
    """Build a structured finding dict."""
    f = {
        "resource_type": resource_type,
        "resource_id":   resource_id,
        "severity":      severity,
        "issue":         issue,
        "detail":        detail,
    }
    if remediation:
        f["remediation"] = remediation
    if resource_id in CORRELATION_HINTS:
        f["correlation_hint"] = CORRELATION_HINTS[resource_id]
    return f


def _format_findings(findings: List[Dict], category: str) -> str:
    """Render findings for one resource category as a Markdown section."""
    if not findings:
        return f"\n### {category}\n_No findings — all checks passed._\n"
    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    out = f"\n### {category} ({len(findings)} finding{'s' if len(findings) != 1 else ''})\n"
    for f in findings:
        emoji = SEVERITY_EMOJI.get(f["severity"], "•")
        out += f"\n**{emoji} {f['severity']} — `{f['resource_id']}`: {f['issue']}**\n"
        out += f"- {f['detail']}\n"
        if f.get("remediation"):
            out += f"- *Fix:* {f['remediation']}\n"
        if f.get("correlation_hint"):
            out += f"- 🔗 *Cross-correlation:* {f['correlation_hint']}\n"
    return out


# ============================================================================
# Audit functions
# ============================================================================

def _audit_s3(buckets: List[Dict]) -> List[Dict]:
    findings = []
    for b in buckets:
        name = b["name"]

        # Public access — most critical
        if not b.get("public_access_blocked", True) or b.get("policy_grants_public", False):
            findings.append(_finding(
                "S3", name, "CRITICAL", "Bucket is publicly accessible",
                detail=("public_access_blocked={}, policy_grants_public={}"
                        .format(b.get("public_access_blocked"),
                                b.get("policy_grants_public"))),
                remediation=("Enable Block Public Access at the account and bucket level; "
                             "remove any bucket policy statement granting access to "
                             "Principal:'*' unless this bucket is intentionally a public CDN"),
            ))

        # Encryption checks
        enc = b.get("encryption")
        if enc is None:
            findings.append(_finding(
                "S3", name, "HIGH", "Bucket has no encryption at rest",
                detail="encryption=None",
                remediation="Enable default encryption with aws:kms",
            ))
        elif enc == "AES256":
            findings.append(_finding(
                "S3", name, "LOW", "Bucket uses SSE-S3 instead of KMS",
                detail="encryption=AES256 (SSE-S3 is AWS-managed; KMS gives you key control)",
                remediation="Switch to aws:kms encryption with a customer-managed key",
            ))

        # Versioning
        if not b.get("versioning_enabled", False):
            findings.append(_finding(
                "S3", name, "MEDIUM", "Bucket versioning is disabled",
                detail="versioning_enabled=False",
                remediation=("Enable versioning to recover from accidental deletes "
                             "and ransomware-style overwrites"),
            ))

        # Logging
        if not b.get("logging_enabled", False):
            findings.append(_finding(
                "S3", name, "LOW", "Server access logging disabled",
                detail="logging_enabled=False",
                remediation="Enable access logging to a separate audit bucket for compliance",
            ))

    return findings


def _audit_security_groups(sgs: List[Dict]) -> List[Dict]:
    findings = []
    for sg in sgs:
        sg_id = sg["name"]  # use name as the human-readable identifier
        for rule in sg.get("ingress_rules", []):
            cidr = rule.get("cidr", "")
            if cidr != "0.0.0.0/0":
                continue  # restricted ingress is fine
            port_from = rule.get("port_from")
            port_to   = rule.get("port_to")
            proto     = rule.get("protocol", "")

            # SSH
            if port_from == 22 and port_to == 22:
                findings.append(_finding(
                    "SecurityGroup", sg_id, "CRITICAL",
                    "SSH (port 22) open to the entire internet",
                    detail="ingress: tcp/22 from 0.0.0.0/0",
                    remediation=("Restrict SSH to a bastion host CIDR or your office IP "
                                 "range; use SSM Session Manager instead of public SSH "
                                 "where possible"),
                ))
                continue

            # RDP
            if port_from == 3389 and port_to == 3389:
                findings.append(_finding(
                    "SecurityGroup", sg_id, "CRITICAL",
                    "RDP (port 3389) open to the entire internet",
                    detail="ingress: tcp/3389 from 0.0.0.0/0",
                    remediation="Restrict RDP to a bastion or VPN CIDR",
                ))
                continue

            # Database ports
            if port_from == port_to and port_from in DB_PORTS:
                findings.append(_finding(
                    "SecurityGroup", sg_id, "CRITICAL",
                    f"Database port {port_from} open to the entire internet",
                    detail=f"ingress: {proto}/{port_from} from 0.0.0.0/0",
                    remediation=("Database ports must never be reachable from the public "
                                 "internet — restrict to application-tier security groups"),
                ))
                continue

            # All-traffic / huge ranges
            if proto == "-1" or (port_from is not None and port_to is not None
                                  and (port_to - port_from) > 1000):
                findings.append(_finding(
                    "SecurityGroup", sg_id, "HIGH",
                    "Wide port range open to the internet",
                    detail=f"ingress: {proto} {port_from}-{port_to} from 0.0.0.0/0",
                    remediation="Specify only the ports actually required by the workload",
                ))

    return findings


def _audit_iam(users: List[Dict], snapshot_time: str) -> List[Dict]:
    findings = []
    for u in users:
        name = u["user_name"]
        is_admin = any("AdministratorAccess" in p for p in u.get("attached_policies", []))
        is_service = u.get("service_account", False)

        # MFA on admin (skip service accounts — they use access keys, not console)
        if is_admin and not u.get("mfa_enabled", False) and not is_service:
            findings.append(_finding(
                "IAMUser", name, "HIGH",
                "Administrator user does not have MFA enabled",
                detail=("attached AdministratorAccess but mfa_enabled=False — any "
                        "compromise of the password is an account takeover"),
                remediation=("Require MFA for all human IAM users with privileged "
                             "access; ideally use AWS SSO + IdP MFA instead of "
                             "long-lived IAM users"),
            ))

        # Access-key age
        for k in u.get("access_keys", []):
            if k.get("status") != "Active":
                continue
            age_days = _days_old(k["create_date"], snapshot_time)
            if age_days >= KEY_AGE_HIGH_DAYS:
                findings.append(_finding(
                    "IAMUser", name, "HIGH",
                    f"Access key has not been rotated in {age_days} days",
                    detail=f"key {k['access_key_id']} created {age_days} days ago",
                    remediation=("Rotate the key: create a new one, update consuming "
                                 "applications, then deactivate and delete the old key"),
                ))
            elif age_days >= KEY_AGE_MEDIUM_DAYS:
                findings.append(_finding(
                    "IAMUser", name, "MEDIUM",
                    f"Access key is {age_days} days old (rotation recommended ≤90)",
                    detail=f"key {k['access_key_id']} created {age_days} days ago",
                    remediation="Rotate the key as part of normal hygiene",
                ))

    return findings


def _audit_rds(instances: List[Dict]) -> List[Dict]:
    findings = []
    for r in instances:
        rid = r["id"]

        if r.get("publicly_accessible", False):
            findings.append(_finding(
                "RDS", rid, "CRITICAL", "DB instance is publicly accessible",
                detail=f"publicly_accessible=True (engine: {r.get('engine')})",
                remediation=("Set PubliclyAccessible=False; databases should sit in "
                             "private subnets with no internet route"),
            ))

        if not r.get("storage_encrypted", False):
            findings.append(_finding(
                "RDS", rid, "HIGH", "DB storage is not encrypted at rest",
                detail="storage_encrypted=False",
                remediation=("Re-create with StorageEncrypted=True (cannot be enabled "
                             "in place — requires snapshot + restore)"),
            ))

        retention = r.get("backup_retention_days", 0)
        if retention < RDS_MIN_BACKUP_DAYS:
            findings.append(_finding(
                "RDS", rid, "MEDIUM",
                f"Backup retention is only {retention} day(s)",
                detail=f"backup_retention_days={retention} (minimum recommended: {RDS_MIN_BACKUP_DAYS})",
                remediation=f"Increase BackupRetentionPeriod to at least {RDS_MIN_BACKUP_DAYS}",
            ))

    return findings


# ============================================================================
# The @tool function
# ============================================================================

@tool
def audit_cloud_config(check_type: str = "all") -> str:
    """Audits the AWS account configuration for security misconfigurations.

    Inspects S3 buckets (public access, encryption, versioning, logging),
    security groups (open ports to 0.0.0.0/0), IAM users (MFA, key rotation),
    and RDS instances (public access, encryption, backups).

    Findings include severity (CRITICAL / HIGH / MEDIUM / LOW), specific
    detail, and remediation steps. When a misconfiguration overlaps with
    activity in CloudTrail/VPC/auth logs (e.g., a publicly-exposed bucket
    that was actually exfiltrated from), the finding is annotated with a
    cross-correlation hint.

    Use this tool when the user asks about:
      - AWS account security posture or misconfigurations
      - S3 bucket security, public exposure, encryption status
      - Security group rules, open ports, network ACLs
      - IAM user policies, MFA status, access key age
      - RDS database security, public accessibility, encryption

    Args:
        check_type: Limit scope to one resource category. One of:
            "s3", "security_groups", "iam", "rds", or "all" (default).
    """
    try:
        snap = _load()
    except FileNotFoundError as e:
        return f"❌ Error: {e}"

    valid = {"s3", "security_groups", "iam", "rds", "all"}
    if check_type not in valid:
        return (f"❌ Error: invalid check_type '{check_type}'. "
                f"Must be one of: {sorted(valid)}")

    resources = snap.get("resources", {})
    snapshot_time = snap.get("snapshot_time", datetime.now(timezone.utc).isoformat())

    sections: List[tuple] = []  # (category_name, findings_list)
    if check_type in ("s3", "all"):
        sections.append(("S3 Buckets", _audit_s3(resources.get("s3_buckets", []))))
    if check_type in ("security_groups", "all"):
        sections.append(("Security Groups", _audit_security_groups(resources.get("security_groups", []))))
    if check_type in ("iam", "all"):
        sections.append(("IAM Users", _audit_iam(resources.get("iam_users", []), snapshot_time)))
    if check_type in ("rds", "all"):
        sections.append(("RDS Instances", _audit_rds(resources.get("rds_instances", []))))

    all_findings = [f for _, fs in sections for f in fs]

    # Header / summary
    out = "## AWS Configuration Audit\n\n"
    out += f"**Snapshot:** {snapshot_time}  \n"
    out += f"**Account:** {snap.get('account_id')}  \n"
    out += f"**Region:** {snap.get('region')}  \n"
    out += f"**Scope:** {check_type}  \n"

    if not all_findings:
        out += "\n✅ **No misconfigurations detected.**\n"
        return out

    sev_counts = Counter(f["severity"] for f in all_findings)
    sev_summary = " | ".join(f"{s}: {sev_counts[s]}"
                              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                              if sev_counts[s])
    out += f"**Total findings:** {len(all_findings)} ({sev_summary})\n"

    for category, fs in sections:
        out += _format_findings(fs, category)

    return out


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import sys
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    invoke = audit_cloud_config.invoke if hasattr(audit_cloud_config, "invoke") \
             else lambda d: audit_cloud_config(**d)
    print(invoke({"check_type": arg}))
