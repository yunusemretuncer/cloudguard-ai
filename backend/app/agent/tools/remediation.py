"""
remediation.py — Incident response playbooks for the CloudGuard AI agent.

Exposes one @tool: `get_remediation(finding_type, context)` — given a
finding type produced by another tool (log_analyzer / config_auditor /
ip_reputation), returns a structured 3-phase playbook:

  • IMMEDIATE   — actions to take within hours (containment)
  • INVESTIGATION — actions to take within 24-48h (scoping)
  • LONG_TERM   — actions to take within weeks (prevention)

This 3-phase structure mirrors the NIST SP 800-61 Incident Response
lifecycle (Containment → Eradication & Recovery → Post-Incident).

Each playbook entry includes:
  - Plain-language step
  - Optional AWS CLI / kubectl / shell command (`cmd`)
  - MITRE ATT&CK reference (technique ID + tactic)
  - Optional context-aware substitution: when the caller passes
    "bucket=prod-customer-data" or "ip=203.0.113.45", the playbook
    substitutes those values into commands.

Design notes:

1. Finding types are normalized to a category key (NORMALIZE_MAP) so
   both raw types like "BRUTE_FORCE_CONSOLE_LOGIN" and high-level
   types like "BRUTE_FORCE" map to the same playbook.

2. context is a simple key=value string. We deliberately keep parsing
   minimal — the agent already has the context from prior tool calls;
   we just need a way to feed it through.

3. CLI commands use placeholder names like <IP>, <USER>, <BUCKET> that
   get replaced when context provides them. Without context, the
   placeholders stay visible — still copy-pasteable, just needs editing.
"""

import re
from typing import Dict, List

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(func):
        return func


# ============================================================================
# Finding-type normalization
# ============================================================================
# Maps both broad categories and specific finding type strings to the
# playbook key. Lookup is case-insensitive.

NORMALIZE_MAP = {
    # Brute force family
    "BRUTE_FORCE":                       "BRUTE_FORCE",
    "BRUTE_FORCE_CONSOLE_LOGIN":         "BRUTE_FORCE",
    "SSH_BRUTE_FORCE":                   "BRUTE_FORCE",
    "SSH_BRUTE_FORCE_NETWORK":           "BRUTE_FORCE",

    # Privilege escalation family — handles "PRIVILEGE_ESCALATION:CreateRole" etc.
    "PRIVILEGE_ESCALATION":              "PRIVILEGE_ESCALATION",

    # SSH compromise
    "SSH_COMPROMISE":                    "SSH_COMPROMISE",
    "SSH_COMPROMISE_AFTER_BRUTE_FORCE":  "SSH_COMPROMISE",

    # Sudo escalation
    "SUDO_ESCALATION":                   "SUDO_ESCALATION",
    "SUDO_ESCALATION_ATTEMPTS":          "SUDO_ESCALATION",

    # Unauthorized API access
    "UNAUTHORIZED_ACCESS":               "UNAUTHORIZED_ACCESS",

    # S3
    "S3_PUBLIC_EXPOSURE":                "S3_PUBLIC_EXPOSURE",
    "S3_PUBLIC_BUCKET_EXPOSURE":         "S3_PUBLIC_EXPOSURE",
    "S3_MASS_OBJECT_ACCESS":             "DATA_EXFILTRATION",
    "S3_EXFILTRATION":                   "DATA_EXFILTRATION",

    # Data exfiltration
    "DATA_EXFILTRATION":                 "DATA_EXFILTRATION",

    # Network reconnaissance
    "PORT_SCAN":                         "NETWORK_RECON",

    # Config audit categories
    "SECURITY_GROUP_MISCONFIG":          "SECURITY_GROUP_MISCONFIG",
    "IAM_HYGIENE":                       "IAM_HYGIENE",
    "RDS_EXPOSURE":                      "RDS_EXPOSURE",
}


def _normalize(finding_type: str) -> str:
    """Map a finding type to its playbook key."""
    if not finding_type:
        return ""
    upper = finding_type.upper().strip()
    if upper in NORMALIZE_MAP:
        return NORMALIZE_MAP[upper]
    # Strip suffixes after colon: "PRIVILEGE_ESCALATION:CreateRole" → "PRIVILEGE_ESCALATION"
    head = upper.split(":", 1)[0]
    if head in NORMALIZE_MAP:
        return NORMALIZE_MAP[head]
    # Last resort: if the finding_type IS already a playbook key, accept it.
    # Covers categories like NETWORK_RECON, IAM_HYGIENE, RDS_EXPOSURE etc.
    # that aren't aliases for anything — they're top-level categories
    # callers may pass directly.
    if upper in PLAYBOOKS:
        return upper
    return ""


# ============================================================================
# Playbooks
# ============================================================================
# Structure: PLAYBOOKS[key] = {
#     "title": str,
#     "mitre_id": str, "mitre_tactic": str, "mitre_technique": str,
#     "immediate": [step, ...],
#     "investigation": [step, ...],
#     "long_term": [step, ...],
# }
# Each step is a dict with "text" (required), optional "cmd".

PLAYBOOKS: Dict[str, Dict] = {

    # ------------------------------------------------------------------------
    "BRUTE_FORCE": {
        "title": "Brute Force Attempt",
        "mitre_id": "T1110", "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "immediate": [
            {"text": "Block the source IP at the WAF/security group / network ACL level.",
             "cmd": "aws ec2 authorize-security-group-ingress --group-id <SG_ID> "
                    "--protocol tcp --port 22 --source-group <DENY_IP_LIST_SG>"},
            {"text": "Force a password reset on the targeted user(s) and disable the account "
                     "until verification is complete.",
             "cmd": "aws iam delete-login-profile --user-name <USER>"},
            {"text": "If MFA is not enabled on the targeted account, enforce it immediately."},
            {"text": "Capture the full attack window from CloudTrail / VPC flow logs / auth.log "
                     "for evidence preservation."},
        ],
        "investigation": [
            {"text": "Search all logs for any other activity from <IP> in the past 7 days "
                     "(other AWS API calls, lateral connection attempts).",
             "cmd": 'aws cloudtrail lookup-events --lookup-attributes '
                    'AttributeKey=SourceIPAddress,AttributeValue=<IP>'},
            {"text": "Verify whether any login attempt from <IP> ever succeeded — if so, "
                     "treat the corresponding session as compromised."},
            {"text": "Run check_ip_reputation on <IP> to determine if it appears in "
                     "AbuseIPDB / VirusTotal — known-bad IPs justify broader blocking."},
            {"text": "Check whether the same IP attempted other authentication surfaces "
                     "(VPN, SSH bastion, application logins)."},
        ],
        "long_term": [
            {"text": "Enable AWS GuardDuty if not already on — it auto-detects brute-force "
                     "patterns and produces native findings."},
            {"text": "Implement login rate limiting at the load balancer / WAF (e.g., "
                     "AWS WAF rate-based rules)."},
            {"text": "Move human IAM users to AWS SSO with IdP-enforced MFA — eliminates "
                     "password-based console login entirely."},
            {"text": "Subscribe affected employee credentials to a leaked-credential service "
                     "(Have I Been Pwned API, etc.) for proactive alerting."},
        ],
    },

    # ------------------------------------------------------------------------
    "PRIVILEGE_ESCALATION": {
        "title": "Privilege Escalation via IAM Modification",
        "mitre_id": "T1098", "mitre_tactic": "Persistence",
        "mitre_technique": "Account Manipulation",
        "immediate": [
            {"text": "Detach the policy that was added (commonly AdministratorAccess).",
             "cmd": "aws iam detach-user-policy --user-name <USER> "
                    "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"},
            {"text": "Deactivate any access keys created during the attack window.",
             "cmd": "aws iam update-access-key --user-name <USER> "
                    "--access-key-id <KEY_ID> --status Inactive"},
            {"text": "Delete any IAM roles created by the attacker (e.g., 'backup-admin-role')",
             "cmd": "aws iam delete-role --role-name <ROLE>"},
            {"text": "Disable console login for the compromised user until full review.",
             "cmd": "aws iam delete-login-profile --user-name <USER>"},
        ],
        "investigation": [
            {"text": "List ALL recent IAM actions by <USER> in CloudTrail — privesc "
                     "rarely happens alone, look for additional persistence mechanisms."},
            {"text": "Check whether the user assumed any roles after gaining admin — "
                     "AssumeRole creates session credentials that survive even after "
                     "the original key is revoked.",
             "cmd": "aws cloudtrail lookup-events --lookup-attributes "
                    "AttributeKey=Username,AttributeValue=<USER>"},
            {"text": "Audit any Lambda functions, EC2 user-data scripts, or CloudFormation "
                     "stacks created/modified by the user — these are common backdoor vectors."},
            {"text": "Review S3 buckets and Secrets Manager entries the user had access to — "
                     "data may have been exfiltrated."},
        ],
        "long_term": [
            {"text": "Implement least-privilege IAM with permission boundaries — even if "
                     "an attacker AttachUserPolicies AdministratorAccess, the boundary "
                     "caps actual permissions."},
            {"text": "Enable CloudTrail Insights to detect anomalous IAM activity patterns."},
            {"text": "Require MFA for all sensitive IAM actions via condition keys "
                     "(aws:MultiFactorAuthPresent: true)."},
            {"text": "Set up automated alerts on AttachUserPolicy / CreateAccessKey events "
                     "via EventBridge → SNS → on-call."},
        ],
    },

    # ------------------------------------------------------------------------
    "SSH_COMPROMISE": {
        "title": "SSH Account Compromise",
        "mitre_id": "T1078", "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
        "immediate": [
            {"text": "Isolate the compromised host from the network — modify its security "
                     "group to deny all ingress while you investigate.",
             "cmd": "aws ec2 modify-instance-attribute --instance-id <INSTANCE> "
                    "--groups <ISOLATION_SG>"},
            {"text": "Kill all active sessions for the compromised user.",
             "cmd": "ssh root@<HOST> 'pkill -KILL -u <USER>'"},
            {"text": "Disable the compromised user account on the host.",
             "cmd": "ssh root@<HOST> 'usermod -L <USER>'"},
            {"text": "Take a snapshot of the EBS volume(s) for forensic preservation "
                     "BEFORE doing anything destructive.",
             "cmd": "aws ec2 create-snapshot --volume-id <VOL> "
                    "--description 'forensic-<DATE>'"},
        ],
        "investigation": [
            {"text": "Review bash_history, /var/log/auth.log, /var/log/syslog, and any "
                     "application logs for actions taken during the compromise window.",
             "cmd": "ssh root@<HOST> 'cat /home/<USER>/.bash_history /var/log/auth.log'"},
            {"text": "Check for persistence: SSH authorized_keys modifications, cron jobs, "
                     "systemd units, modified PATH binaries.",
             "cmd": "ssh root@<HOST> 'find / -mtime -2 -type f 2>/dev/null | head'"},
            {"text": "Identify what data the compromised user had access to (file system "
                     "permissions, mounted volumes, IAM role attached to the instance)."},
            {"text": "Pivot to VPC flow logs: did any unusual outbound traffic leave the "
                     "host while the attacker was logged in?"},
        ],
        "long_term": [
            {"text": "Disable SSH password authentication entirely — keys only.",
             "cmd": "ssh root@<HOST> 'sed -i \"s/^#*PasswordAuthentication.*/"
                    "PasswordAuthentication no/\" /etc/ssh/sshd_config && systemctl reload sshd'"},
            {"text": "Replace public SSH access with AWS SSM Session Manager — no inbound "
                     "port 22 needed at all."},
            {"text": "Deploy fail2ban or equivalent on any host that must keep SSH open."},
            {"text": "Rotate all secrets the compromised user could have read — assume "
                     "everything in their access scope is leaked."},
        ],
    },

    # ------------------------------------------------------------------------
    "SUDO_ESCALATION": {
        "title": "Sudo Escalation Attempts",
        "mitre_id": "T1548", "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Abuse Elevation Control Mechanism",
        "immediate": [
            {"text": "Lock the offending user account on the host."},
            {"text": "Review the user's recent commands and consider the host suspect."},
        ],
        "investigation": [
            {"text": "Review /var/log/auth.log entries for the user — what commands did they "
                     "attempt with sudo?"},
            {"text": "Cross-reference with SSH logins — was this user logged in from an "
                     "unusual source?"},
            {"text": "Audit whether any sudo attempts succeeded (vs only the failures we see)."},
        ],
        "long_term": [
            {"text": "Apply principle of least privilege in /etc/sudoers — no NOPASSWD, "
                     "no ALL=(ALL) for normal users."},
            {"text": "Forward auth.log to a central SIEM so failed-sudo bursts trigger alerts."},
        ],
    },

    # ------------------------------------------------------------------------
    "UNAUTHORIZED_ACCESS": {
        "title": "Unauthorized API Access Attempts",
        "mitre_id": "T1078", "mitre_tactic": "Initial Access",
        "mitre_technique": "Valid Accounts",
        "immediate": [
            {"text": "Identify the principal making the unauthorized calls and deactivate "
                     "their credentials immediately if the activity looks malicious.",
             "cmd": "aws iam update-access-key --user-name <USER> "
                    "--access-key-id <KEY_ID> --status Inactive"},
            {"text": "If it's a service account, rotate the access key and update consumers."},
        ],
        "investigation": [
            {"text": "Look at the pattern of denied calls — many denials for IAM/EC2/S3 "
                     "enumeration suggest a compromised key being probed for permissions."},
            {"text": "Did the same principal succeed at ANY actions? Combine 'denied' "
                     "events with successful events for the same user/IP."},
            {"text": "Check whether the access key appears in known credential leak feeds "
                     "(GitGuardian, GitHub secret scanning history)."},
        ],
        "long_term": [
            {"text": "Move all programmatic access to short-lived credentials via IAM Roles "
                     "Anywhere or OIDC federation — no long-lived access keys."},
            {"text": "Enable git pre-commit hooks (gitleaks, trufflehog) to prevent "
                     "credential leaks at the source."},
            {"text": "Enable AWS GitHub secret scanning — it auto-revokes leaked AWS keys."},
        ],
    },

    # ------------------------------------------------------------------------
    "S3_PUBLIC_EXPOSURE": {
        "title": "S3 Bucket Public Exposure",
        "mitre_id": "T1530", "mitre_tactic": "Collection",
        "mitre_technique": "Data from Cloud Storage",
        "immediate": [
            {"text": "Enable Block Public Access on the bucket.",
             "cmd": "aws s3api put-public-access-block --bucket <BUCKET> "
                    '--public-access-block-configuration '
                    '"BlockPublicAcls=true,IgnorePublicAcls=true,'
                    'BlockPublicPolicy=true,RestrictPublicBuckets=true"'},
            {"text": "Remove any bucket policy statement granting Principal:'*'.",
             "cmd": "aws s3api delete-bucket-policy --bucket <BUCKET>"},
            {"text": "Enable default encryption with KMS if not already.",
             "cmd": "aws s3api put-bucket-encryption --bucket <BUCKET> "
                    '--server-side-encryption-configuration '
                    "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
                    "{\"SSEAlgorithm\":\"aws:kms\"}}]}'"},
        ],
        "investigation": [
            {"text": "Pull S3 server access logs (or CloudTrail data events) for the period "
                     "the bucket was public — every GetObject in that window may have "
                     "exfiltrated data."},
            {"text": "Inventory the bucket contents — what data was potentially exposed? "
                     "PII / financial / source code? Determine breach notification "
                     "obligations."},
            {"text": "Check whether the bucket was made public via PutBucketPolicy "
                     "(intentional misconfiguration) or via ACL — different attack chain."},
        ],
        "long_term": [
            {"text": "Enable Block Public Access at the ACCOUNT level — overrides any "
                     "individual bucket settings.",
             "cmd": "aws s3control put-public-access-block --account-id <ACCOUNT> "
                    '--public-access-block-configuration '
                    '"BlockPublicAcls=true,IgnorePublicAcls=true,'
                    'BlockPublicPolicy=true,RestrictPublicBuckets=true"'},
            {"text": "Use AWS Config rules (`s3-bucket-public-read-prohibited`, "
                     "`s3-bucket-public-write-prohibited`) for continuous monitoring."},
            {"text": "Adopt an explicit allowlist for buckets that legitimately need to "
                     "be public (CDN content, etc.) and require change-management approval."},
        ],
    },

    # ------------------------------------------------------------------------
    "DATA_EXFILTRATION": {
        "title": "Data Exfiltration",
        "mitre_id": "T1048", "mitre_tactic": "Exfiltration",
        "mitre_technique": "Exfiltration Over Alternative Protocol",
        "immediate": [
            {"text": "Block the destination IP at the egress level (route table or "
                     "outbound security group)."},
            {"text": "Identify the source host/user and contain it (isolate, revoke "
                     "credentials)."},
            {"text": "Snapshot evidence: VPC flow log entries, S3 access logs, "
                     "CloudTrail data events for the exfil window."},
        ],
        "investigation": [
            {"text": "Quantify what was taken: byte volume, object names/types, time window."},
            {"text": "Trace the attack chain backwards — how did the attacker get the "
                     "credentials/access that enabled the exfil?"},
            {"text": "Check logs at the destination perspective if you control it (e.g., "
                     "VPC flow logs from receiving account) for completeness."},
            {"text": "Engage legal / compliance — exfil of PII or regulated data "
                     "typically triggers breach notification rules (GDPR, HIPAA, etc.)."},
        ],
        "long_term": [
            {"text": "Implement egress filtering — VPC endpoints for AWS services, deny "
                     "list for known C2 IPs, allowlist for required external destinations."},
            {"text": "Set up volume-based anomaly alerts (AWS GuardDuty 'Exfiltration' "
                     "finding types, custom CloudWatch metrics on bytes-out)."},
            {"text": "Encrypt sensitive data at rest with customer-managed KMS keys — "
                     "exfiltrated ciphertext is useless without the key."},
            {"text": "Adopt DLP tooling for detecting sensitive data movement "
                     "(Macie for S3 PII detection)."},
        ],
    },

    # ------------------------------------------------------------------------
    "NETWORK_RECON": {
        "title": "Network Reconnaissance / Port Scan",
        "mitre_id": "T1046", "mitre_tactic": "Reconnaissance",
        "mitre_technique": "Network Service Discovery",
        "immediate": [
            {"text": "Block the scanning source IP at the WAF / NACL level."},
            {"text": "Verify your security groups are not overly permissive — the scan "
                     "may have found something."},
        ],
        "investigation": [
            {"text": "Did any of the scanned ports return ACCEPT? Those are the entry points "
                     "the attacker now knows about — review them carefully."},
            {"text": "Run check_ip_reputation on the source — opportunistic scanners are "
                     "often known-bad IPs that justify broader perimeter blocking."},
            {"text": "Check whether the scan was followed by targeted activity on any "
                     "of the open ports (SSH attempts, HTTP probing, etc.)."},
        ],
        "long_term": [
            {"text": "Reduce internet-facing attack surface — every port that doesn't "
                     "absolutely need to be public should be private."},
            {"text": "Deploy AWS Network Firewall or third-party IDS in front of "
                     "internet-facing subnets."},
            {"text": "Subscribe to threat-intel feeds and auto-block known scanner IP ranges."},
        ],
    },

    # ------------------------------------------------------------------------
    "SECURITY_GROUP_MISCONFIG": {
        "title": "Security Group Misconfiguration",
        "mitre_id": "T1133", "mitre_tactic": "Initial Access",
        "mitre_technique": "External Remote Services",
        "immediate": [
            {"text": "Revoke the overly-permissive ingress rule.",
             "cmd": "aws ec2 revoke-security-group-ingress --group-id <SG_ID> "
                    "--protocol tcp --port <PORT> --cidr 0.0.0.0/0"},
            {"text": "If port 22/3389 was world-open, audit the host(s) it protects "
                     "for compromise indicators (failed/successful login bursts)."},
            {"text": "Add a replacement rule limited to the actual required source CIDR "
                     "(office, VPN, bastion).",
             "cmd": "aws ec2 authorize-security-group-ingress --group-id <SG_ID> "
                    "--protocol tcp --port <PORT> --cidr <OFFICE_CIDR>"},
        ],
        "investigation": [
            {"text": "Determine HOW the rule got there — manual change, IaC drift, "
                     "compromised user. CloudTrail AuthorizeSecurityGroupIngress events "
                     "show who/when."},
            {"text": "Check VPC flow logs for connections that succeeded on the "
                     "now-closed port during the exposure window."},
            {"text": "Identify all other security groups in the account with similar "
                     "0.0.0.0/0 patterns — likely systemic issue."},
        ],
        "long_term": [
            {"text": "AWS Config rule `restricted-ssh` and `restricted-common-ports` for "
                     "automatic detection."},
            {"text": "All security group changes go through IaC (Terraform/CloudFormation) "
                     "with peer review — no manual console changes."},
            {"text": "Service Control Policies (SCPs) at the org level to outright forbid "
                     "0.0.0.0/0 ingress on database and SSH/RDP ports."},
        ],
    },

    # ------------------------------------------------------------------------
    "IAM_HYGIENE": {
        "title": "IAM Hygiene Issues (MFA, Key Rotation)",
        "mitre_id": "T1078", "mitre_tactic": "Persistence",
        "mitre_technique": "Valid Accounts",
        "immediate": [
            {"text": "If the user is missing MFA, require enrollment before next login.",
             "cmd": "aws iam list-mfa-devices --user-name <USER>"},
            {"text": "If a key is older than 365 days, deactivate (don't delete yet — "
                     "deactivate first to confirm nothing breaks).",
             "cmd": "aws iam update-access-key --user-name <USER> "
                    "--access-key-id <KEY_ID> --status Inactive"},
        ],
        "investigation": [
            {"text": "Review the user's recent activity — old keys that are still actively "
                     "used point to an unmanaged automation that needs migration to a role."},
            {"text": "Check if the same key appears in any code repositories you own "
                     "(grep for the AKIA prefix)."},
        ],
        "long_term": [
            {"text": "Enforce MFA for all human IAM users via IAM policy condition "
                     "(aws:MultiFactorAuthPresent: true)."},
            {"text": "Set up a quarterly access-key rotation schedule with automated "
                     "reminders (or use IAM Access Analyzer)."},
            {"text": "Migrate from long-lived IAM users to AWS SSO + IAM Roles — eliminates "
                     "the rotation problem entirely."},
        ],
    },

    # ------------------------------------------------------------------------
    "RDS_EXPOSURE": {
        "title": "RDS Public Exposure / Misconfiguration",
        "mitre_id": "T1530", "mitre_tactic": "Collection",
        "mitre_technique": "Data from Cloud Storage",
        "immediate": [
            {"text": "Disable PubliclyAccessible.",
             "cmd": "aws rds modify-db-instance --db-instance-identifier <DB> "
                    "--no-publicly-accessible --apply-immediately"},
            {"text": "Tighten the database's security group — DB ports should only be "
                     "reachable from application security groups, never 0.0.0.0/0."},
            {"text": "Rotate the database's master credentials — assume the password "
                     "may have been bruteforced while exposed."},
        ],
        "investigation": [
            {"text": "Pull RDS audit logs for connection attempts during the exposure "
                     "window — many failures from external IPs = brute force."},
            {"text": "Check RDS Performance Insights for unusual query patterns "
                     "(large table scans, dump-like patterns)."},
        ],
        "long_term": [
            {"text": "AWS Config rule `rds-instance-public-access-check` for continuous "
                     "monitoring."},
            {"text": "Encrypt all RDS instances at rest (StorageEncrypted=True) — "
                     "requires snapshot-and-restore for existing instances."},
            {"text": "Set BackupRetentionPeriod to at least 7 days — preferably 30."},
            {"text": "Enable IAM Database Authentication where the engine supports it — "
                     "removes password-based auth entirely."},
        ],
    },
}


# ============================================================================
# Context parsing
# ============================================================================
# Accept simple "key=value" or "key=value, key=value" strings.
# Used to substitute placeholders like <IP>, <USER>, <BUCKET> in commands.

PLACEHOLDER_KEYS = {
    "ip", "user", "host", "bucket", "sg_id", "key_id", "instance",
    "vol", "role", "db", "user_name", "account",
}


def _parse_context(context: str) -> Dict[str, str]:
    """Parse 'k1=v1, k2=v2' (or 'k1=v1 k2=v2') into a dict.

    Unknown keys are silently dropped — we only substitute values for
    placeholders we know about.
    """
    out: Dict[str, str] = {}
    if not context:
        return out
    # Accept comma- or whitespace-separated pairs
    for token in re.split(r"[,\s]+", context.strip()):
        if "=" not in token:
            continue
        k, _, v = token.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if not k or not v:
            continue
        if k in PLACEHOLDER_KEYS:
            out[k] = v
    return out


def _apply_context(text: str, ctx: Dict[str, str]) -> str:
    """Substitute <KEY> placeholders in text with values from ctx."""
    if not ctx or "<" not in text:
        return text
    for k, v in ctx.items():
        text = text.replace(f"<{k.upper()}>", v)
    return text


# ============================================================================
# Formatting
# ============================================================================

PHASE_HEADERS = {
    "immediate":     "🚨 Immediate (within hours — containment)",
    "investigation": "🔍 Investigation (24–48 hours — scoping)",
    "long_term":     "🛡️ Long-term (weeks — prevention)",
}


def _format_phase(phase_key: str, steps: List[Dict], ctx: Dict[str, str]) -> str:
    out = f"\n### {PHASE_HEADERS[phase_key]}\n"
    for i, step in enumerate(steps, 1):
        text = _apply_context(step["text"], ctx)
        out += f"\n{i}. {text}\n"
        if step.get("cmd"):
            cmd = _apply_context(step["cmd"], ctx)
            out += f"   ```\n   {cmd}\n   ```\n"
    return out


# ============================================================================
# The @tool function
# ============================================================================

@tool
def get_remediation(finding_type: str, context: str = "") -> str:
    """Returns a step-by-step incident response playbook for a security finding.

    Each playbook is structured in three phases following the NIST SP 800-61
    incident response lifecycle:
      • Immediate (hours) — contain the threat
      • Investigation (24-48h) — scope the impact
      • Long-term (weeks) — prevent recurrence

    Steps include AWS CLI commands where applicable. If context is provided
    (e.g., "ip=203.0.113.45, user=dev-user, bucket=prod-customer-data"),
    placeholder values like <IP>, <USER>, <BUCKET> in commands are
    substituted automatically.

    Use this tool when the user asks about:
      - How to respond to a specific security finding or alert
      - What steps to take after discovering brute force / privesc /
        compromise / data exfil / misconfiguration
      - Best-practice remediation for a particular MITRE ATT&CK technique
      - "What should I do?" follow-up questions after another tool reports
        a finding

    Args:
        finding_type: The category of finding to remediate. Accepts both
            high-level types ("BRUTE_FORCE", "PRIVILEGE_ESCALATION",
            "DATA_EXFILTRATION", "S3_PUBLIC_EXPOSURE", "SSH_COMPROMISE",
            "SECURITY_GROUP_MISCONFIG", "IAM_HYGIENE", "RDS_EXPOSURE",
            "NETWORK_RECON", "UNAUTHORIZED_ACCESS", "SUDO_ESCALATION") and
            specific finding names emitted by other tools (e.g.,
            "SSH_BRUTE_FORCE_NETWORK", "S3_PUBLIC_BUCKET_EXPOSURE",
            "PRIVILEGE_ESCALATION:CreateAccessKey").
        context: Optional 'key=value' pairs to substitute into commands.
            Recognized keys: ip, user, host, bucket, sg_id, key_id, instance,
            vol, role, db, user_name, account.
    """
    key = _normalize(finding_type)
    if not key or key not in PLAYBOOKS:
        known = sorted(set(PLAYBOOKS.keys()))
        return (f"❌ No playbook available for finding type '{finding_type}'.\n\n"
                f"Available playbooks:\n" +
                "\n".join(f"- {k}" for k in known))

    pb = PLAYBOOKS[key]
    ctx = _parse_context(context)

    out = f"## Remediation Playbook: {pb['title']}\n\n"
    out += (f"**MITRE ATT&CK:** {pb['mitre_id']} — {pb['mitre_technique']} "
            f"({pb['mitre_tactic']})\n")
    if ctx:
        ctx_summary = ", ".join(f"{k}={v}" for k, v in ctx.items())
        out += f"**Context applied:** {ctx_summary}\n"

    for phase in ("immediate", "investigation", "long_term"):
        steps = pb.get(phase, [])
        if steps:
            out += _format_phase(phase, steps, ctx)

    out += ("\n---\n*Reference: NIST SP 800-61 Incident Response lifecycle "
            "(Containment → Eradication & Recovery → Post-Incident).*\n")

    return out


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python remediation.py <FINDING_TYPE> [context]")
        print("\nAvailable finding types:")
        for k in sorted(PLAYBOOKS):
            print(f"  - {k}")
        sys.exit(0)

    finding_type = sys.argv[1]
    context = sys.argv[2] if len(sys.argv) > 2 else ""
    invoke = (get_remediation.invoke
              if hasattr(get_remediation, "invoke")
              else lambda d: get_remediation(**d))
    print(invoke({"finding_type": finding_type, "context": context}))