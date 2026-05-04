"""
alert_generator.py — Persists security findings to the alerts table.

Exposes one @tool: `generate_alert(finding_type, severity, details, ...)`
which the agent calls after another tool reports a finding it considers
worth recording. The tool:

  1. Normalizes the finding_type string to a canonical category
     (so 'PRIVILEGE_ESCALATION:CreateRole' and 'BRUTE_FORCE_CONSOLE_LOGIN'
     route to the right MITRE entry).
  2. Validates severity against the four allowed levels.
  3. Looks up MITRE ATT&CK metadata from MITRE_MAPPING.
  4. Inserts an Alert row via SQLAlchemy.
  5. Returns a Markdown summary including the assigned alert ID.

Design notes:

- We use the project's existing SQLAlchemy setup (`SessionLocal` from
  `app.db.database`). The tool opens its own session and closes it —
  no FastAPI dependency injection needed since tools run inside the
  agent loop, not inside an HTTP request.

- _normalize_finding() mirrors the logic in remediation.py — a finding
  type can be passed in raw form ("BRUTE_FORCE_CONSOLE_LOGIN") or
  with colon-suffix ("PRIVILEGE_ESCALATION:CreateRole"). Both should
  resolve to the same MITRE category. We don't import remediation's
  helper to avoid coupling between tools.

- MITRE_MAPPING is the same set used by log_analyzer and config_auditor
  (extended where needed). Single source of truth would be ideal but
  that means a new shared module — for now we replicate the constants
  with a comment explaining they must stay in sync.
"""

from typing import Optional

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(func):
        return func


# ============================================================================
# Constants
# ============================================================================

# MITRE ATT&CK mapping — superset of the table in sec-gorevler.md.
# Keys are the canonical category names. NORMALIZE_MAP funnels raw
# finding_type strings (which may have colon suffixes or specific
# variants) into one of these keys.
#
# IMPORTANT: This must stay aligned with log_analyzer.MITRE and the
# remediation.PLAYBOOKS keys. If you add a new finding category in
# either of those, mirror it here.

MITRE_MAPPING = {
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "PRIVILEGE_ESCALATION": {
        "tactic": "Persistence",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
    },
    "UNAUTHORIZED_ACCESS": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "SSH_COMPROMISE": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "SUDO_ESCALATION": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
    },
    "S3_PUBLIC_EXPOSURE": {
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
    },
    "DATA_EXFILTRATION": {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
    },
    "NETWORK_RECON": {
        "tactic": "Reconnaissance",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
    "SECURITY_GROUP_MISCONFIG": {
        "tactic": "Initial Access",
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
    },
    "IAM_HYGIENE": {
        "tactic": "Persistence",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
    },
    "RDS_EXPOSURE": {
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
    },
}

# Maps raw finding type strings to their canonical category in MITRE_MAPPING.
# Anything not here falls through colon-stripping then last-resort lookup.
NORMALIZE_MAP = {
    # Brute force family
    "BRUTE_FORCE":                       "BRUTE_FORCE",
    "BRUTE_FORCE_CONSOLE_LOGIN":         "BRUTE_FORCE",
    "BRUTE_FORCE_ATTEMPT":               "BRUTE_FORCE",
    "SSH_BRUTE_FORCE":                   "BRUTE_FORCE",
    "SSH_BRUTE_FORCE_NETWORK":           "BRUTE_FORCE",
    # Priv esc — handles ':' suffix in _normalize_finding
    "PRIVILEGE_ESCALATION":              "PRIVILEGE_ESCALATION",
    # SSH compromise
    "SSH_COMPROMISE":                    "SSH_COMPROMISE",
    "SSH_COMPROMISE_AFTER_BRUTE_FORCE":  "SSH_COMPROMISE",
    # Sudo
    "SUDO_ESCALATION":                   "SUDO_ESCALATION",
    "SUDO_ESCALATION_ATTEMPTS":          "SUDO_ESCALATION",
    # Unauthorized
    "UNAUTHORIZED_ACCESS":               "UNAUTHORIZED_ACCESS",
    # S3
    "S3_PUBLIC_EXPOSURE":                "S3_PUBLIC_EXPOSURE",
    "S3_PUBLIC_BUCKET_EXPOSURE":         "S3_PUBLIC_EXPOSURE",
    "S3_MASS_OBJECT_ACCESS":             "DATA_EXFILTRATION",
    "S3_EXFILTRATION":                   "DATA_EXFILTRATION",
    # Exfil
    "DATA_EXFILTRATION":                 "DATA_EXFILTRATION",
    # Network
    "PORT_SCAN":                         "NETWORK_RECON",
    "NETWORK_RECON":                     "NETWORK_RECON",
    # Config audit
    "SECURITY_GROUP_MISCONFIG":          "SECURITY_GROUP_MISCONFIG",
    "IAM_HYGIENE":                       "IAM_HYGIENE",
    "RDS_EXPOSURE":                      "RDS_EXPOSURE",
}

VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SEVERITY_EMOJI = {
    "CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "ℹ️",
}


# ============================================================================
# Helpers
# ============================================================================

def _normalize_finding(finding_type: str) -> Optional[str]:
    """Map a raw finding_type to a canonical MITRE_MAPPING key.

    Returns None if no mapping is found (caller decides whether to
    record the alert without MITRE metadata or reject it).
    """
    if not finding_type:
        return None
    key = finding_type.upper().strip()
    if key in NORMALIZE_MAP:
        return NORMALIZE_MAP[key]
    # Strip colon suffix: "PRIVILEGE_ESCALATION:CreateRole" → "PRIVILEGE_ESCALATION"
    head = key.split(":", 1)[0]
    if head in NORMALIZE_MAP:
        return NORMALIZE_MAP[head]
    if head in MITRE_MAPPING:
        return head
    return None


def _validate_severity(severity: str) -> str:
    """Coerce severity to one of the allowed values, defaulting to LOW."""
    if not severity:
        return "LOW"
    upper = severity.upper().strip()
    if upper in VALID_SEVERITIES:
        return upper
    return "LOW"


def _format_alert_response(alert_id: int, finding_type: str, severity: str,
                            title: str, detail: str, mitre: Optional[dict],
                            source_ip: Optional[str], user_name: Optional[str],
                            resource_id: Optional[str],
                            thread_id: Optional[str]) -> str:
    """Render a Markdown summary the agent can include in its reply."""
    emoji = SEVERITY_EMOJI.get(severity, "•")
    out = f"## Alert Recorded {emoji}\n\n"
    out += f"- **Alert ID:** #{alert_id}\n"
    out += f"- **Type:** {finding_type}\n"
    out += f"- **Severity:** {severity}\n"
    out += f"- **Title:** {title}\n"
    if mitre:
        out += (f"- **MITRE ATT&CK:** {mitre['technique_id']} — "
                f"{mitre['technique_name']} ({mitre['tactic']})\n")
    if source_ip:
        out += f"- **Source IP:** {source_ip}\n"
    if user_name:
        out += f"- **User:** {user_name}\n"
    if resource_id:
        out += f"- **Resource:** {resource_id}\n"
    if thread_id:
        out += f"- **Thread:** {thread_id}\n"
    out += f"\n**Detail:** {detail}\n"
    out += "\n*Saved to alerts table — visible in the dashboard alert panel.*\n"
    return out


# ============================================================================
# Database access
# ============================================================================

def _persist_alert(finding_type: str, severity: str, title: str, detail: str,
                   mitre: Optional[dict], source_ip: Optional[str],
                   user_name: Optional[str], resource_id: Optional[str],
                   thread_id: Optional[str]) -> int:
    """Insert an Alert row, return the new alert's ID.

    Imports the model + session inside the function to keep this module
    importable in environments where the DB layer isn't set up (tests
    and standalone tool development).
    """
    from app.db.database import SessionLocal
    from app.db.models import Alert

    alert = Alert(
        finding_type=finding_type,
        severity=severity,
        title=title,
        detail=detail,
        mitre_id=mitre["technique_id"] if mitre else None,
        mitre_tactic=mitre["tactic"] if mitre else None,
        mitre_technique=mitre["technique_name"] if mitre else None,
        source_ip=source_ip,
        user_name=user_name,
        resource_id=resource_id,
        thread_id=thread_id,
    )
    db = SessionLocal()
    try:
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert.id
    finally:
        db.close()


# ============================================================================
# The @tool function
# ============================================================================

@tool
def generate_alert(
    finding_type: str,
    severity: str,
    detail: str,
    title: str = "",
    source_ip: str = "",
    user_name: str = "",
    resource_id: str = "",
    thread_id: str = "",
) -> str:
    """Records a security finding as a structured alert in the database.

    Other tools (log_analyzer, config_auditor, ip_reputation) report
    findings inline; this tool persists them so the dashboard can
    display them and the user can review historical incidents.

    The MITRE ATT&CK metadata is looked up automatically from the
    finding_type (no need for the caller to provide it). Optional
    context (source_ip, user_name, resource_id, thread_id) lets the
    alert link back to the entity it concerns — fill these in when
    the finding naturally identifies one.

    Use this tool when:
      - Another tool reported a finding that warrants recording
        (HIGH/CRITICAL severity, or a finding the user explicitly
        asked to track)
      - The user asks to "log this", "save this alert", "create a ticket"
      - You want to make a finding visible in the dashboard

    Args:
        finding_type: Category of the finding. Accepts both broad keys
            ('BRUTE_FORCE', 'PRIVILEGE_ESCALATION') and specific
            variants from other tools ('BRUTE_FORCE_CONSOLE_LOGIN',
            'PRIVILEGE_ESCALATION:CreateRole'). MITRE mapping is
            applied via the canonical category.
        severity: One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'. Other
            values are coerced to 'LOW'.
        title: Short summary (≤256 chars) shown in the alert list,
            e.g., "Brute force from 203.0.113.45 (6 failed logins)".
        detail: Longer description shown in the alert detail panel
            (e.g., the full evidence: time window, targeted users, etc.)
        source_ip: Optional. The IP address involved, if applicable.
        user_name: Optional. The IAM user / Linux user involved.
        resource_id: Optional. The S3 bucket / SG / RDS / etc.
            identifier the alert concerns.
        thread_id: Optional. The chat thread that triggered this
            alert, for linking alerts back to their conversation.
    """
    # Normalize and validate inputs
    canonical = _normalize_finding(finding_type)
    severity = _validate_severity(severity)
    mitre = MITRE_MAPPING.get(canonical) if canonical else None

    # If title is empty (caller forgot), derive a short one from detail
    if not title:
        title = (detail[:200] + "…") if len(detail) > 200 else detail

    # Empty-string optional params come through as "" from LangChain;
    # convert them to None so they're stored as NULL in the DB.
    source_ip = source_ip or None
    user_name = user_name or None
    resource_id = resource_id or None
    thread_id = thread_id or None

    # Persist
    try:
        alert_id = _persist_alert(
            finding_type=finding_type,    # store original (un-normalized) for granularity
            severity=severity,
            title=title,
            detail=detail,
            mitre=mitre,
            source_ip=source_ip,
            user_name=user_name,
            resource_id=resource_id,
            thread_id=thread_id,
        )
    except Exception as e:
        # Don't crash the agent loop — return an error message it can relay
        return f"❌ Error recording alert: {e.__class__.__name__}: {e}"

    return _format_alert_response(
        alert_id=alert_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        detail=detail,
        mitre=mitre,
        source_ip=source_ip,
        user_name=user_name,
        resource_id=resource_id,
        thread_id=thread_id,
    )


# ============================================================================
# CLI for standalone smoke-testing (without the agent loop)
# ============================================================================

if __name__ == "__main__":
    # This requires the DB to be initialized. Run from the backend/
    # directory after the FastAPI app has started once (so init_db()
    # has created the table).
    import sys
    if len(sys.argv) < 5:
        print("Usage: python alert_generator.py <finding_type> <severity> "
              "<title> <detail> [source_ip] [user_name] [resource_id] [thread_id]")
        sys.exit(1)
    args = sys.argv[1:]
    invoke = (generate_alert.invoke
              if hasattr(generate_alert, "invoke")
              else lambda d: generate_alert(**d))
    payload = {
        "finding_type": args[0],
        "severity": args[1],
        "title": args[2],
        "detail": args[3],
        "source_ip":   args[4] if len(args) > 4 else "",
        "user_name":   args[5] if len(args) > 5 else "",
        "resource_id": args[6] if len(args) > 6 else "",
        "thread_id":   args[7] if len(args) > 7 else "",
    }
    print(invoke(payload))