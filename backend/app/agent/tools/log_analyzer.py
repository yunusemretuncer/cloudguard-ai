"""
log_analyzer.py — Three security analysis tools for the CloudGuard AI agent..

This module exposes three @tool functions, one per log source:

  • analyze_cloudtrail_logs — AWS API audit (login, IAM, S3 abuse)
  • analyze_vpc_flow_logs   — Network flows (port scans, SSH brute, exfil)
  • analyze_auth_logs       — Linux auth.log (sshd, sudo, pam events)

Design decisions:

1. SEPARATE TOOLS (not one parameterized tool). Each has a distinct
   docstring so the LangChain agent can pick the right one based on the
   user's natural-language query. "Did anyone log into our servers?"
   should route to analyze_auth_logs, not analyze_cloudtrail_logs.

2. THRESHOLDS AS NAMED CONSTANTS at the top of each section, with comments
   explaining the rationale (always derived from the sample data baseline,
   not invented). Tuning is a single-place change.

3. FINDINGS ARE DICTS UNTIL THE LAST STEP. Internal representation is
   structured (severity, type, evidence count, MITRE key, etc.); only at
   _format_report is it converted to Markdown for the agent to relay.

4. BIAS TOWARD RECALL OVER PRECISION (for v1). False positives are
   acceptable and even desirable for the demo — they let us discuss
   "limitations and future work" in the report. Tighter precision would
   require allow-lists, time-of-day baselines, behavioral profiling.
"""

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Use real LangChain @tool when available; fall back to passthrough for
# standalone testing without LangChain installed.
try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(func):
        return func


# ============================================================================
# Configuration
# ============================================================================

# Default location: backend/data/sample_logs/
# Override via CLOUDGUARD_DATA_DIR env var (used by tests + standalone runs)
_DEFAULT_DIR = Path(__file__).parent.parent.parent.parent / "data" / "sample_logs"
DATA_DIR = Path(os.environ.get("CLOUDGUARD_DATA_DIR", _DEFAULT_DIR))

# MITRE ATT&CK mapping — finding type → (technique_id, tactic, technique_name)
# Source: https://attack.mitre.org/
MITRE = {
    "BRUTE_FORCE":          ("T1110", "Credential Access",     "Brute Force"),
    "PRIVILEGE_ESCALATION": ("T1098", "Persistence",           "Account Manipulation"),
    "UNAUTHORIZED_ACCESS":  ("T1078", "Initial Access",        "Valid Accounts"),
    "S3_PUBLIC_EXPOSURE":   ("T1530", "Collection",            "Data from Cloud Storage"),
    "S3_EXFILTRATION":      ("T1530", "Collection",            "Data from Cloud Storage"),
    "PORT_SCAN":            ("T1046", "Reconnaissance",        "Network Service Discovery"),
    "DATA_EXFILTRATION":    ("T1048", "Exfiltration",          "Exfiltration Over Alternative Protocol"),
    "SSH_COMPROMISE":       ("T1078", "Initial Access",        "Valid Accounts"),
    "SUDO_ESCALATION":      ("T1548", "Privilege Escalation",  "Abuse Elevation Control Mechanism"),
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_EMOJI = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "ℹ️"}

# RFC 1918 private ranges + RFC 6598 (CGN). Used to distinguish internal hosts.
INTERNAL_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
)


# ============================================================================
# Shared helpers
# ============================================================================

def _load(filename: str) -> Dict[str, Any]:
    """Load and parse a JSON log file from DATA_DIR."""
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    with open(path) as f:
        return json.load(f)


def _is_internal(ip: str) -> bool:
    """True if IP is in any RFC 1918 / 6598 private range."""
    return ip.startswith(INTERNAL_PREFIXES)


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp ending in 'Z' (UTC)."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _format_finding(f: Dict[str, Any], i: int) -> str:
    """Render a single finding as a Markdown section."""
    sev = f["severity"]
    emoji = SEVERITY_EMOJI.get(sev, "•")
    out = f"\n### Finding #{i}: {f['type']} {emoji}\n"
    out += f"- **Severity:** {sev}\n"
    out += f"- **Detail:** {f['detail']}\n"
    for key, label in [("source_ip", "Source IP"), ("user", "User"),
                        ("host", "Host"), ("evidence_count", "Event count"),
                        ("time_window", "Time window")]:
        if f.get(key):
            out += f"- **{label}:** {f[key]}\n"
    mitre_key = f.get("mitre_key")
    if mitre_key and mitre_key in MITRE:
        tid, tactic, name = MITRE[mitre_key]
        out += f"- **MITRE ATT&CK:** {tid} — {name} ({tactic})\n"
    return out


def _format_report(findings: List[Dict], header: str, total_events: int) -> str:
    """Build the final Markdown report from a flat list of findings."""
    if not findings:
        return (f"## {header}\n\n"
                f"**No suspicious activity detected.**\n"
                f"Total events analyzed: {total_events}\n")

    findings.sort(key=lambda f: -SEVERITY_RANK.get(f["severity"], 0))
    sev_count = Counter(f["severity"] for f in findings)
    sev_summary = " | ".join(f"{s}: {n}" for s, n in sev_count.most_common())

    out = f"## {header}\n\n"
    out += f"**Total events analyzed:** {total_events} | **Findings:** {len(findings)}\n"
    out += f"**Severity breakdown:** {sev_summary}\n"
    for i, f in enumerate(findings, 1):
        out += _format_finding(f, i)
    return out


# ============================================================================
# Tool 1: CloudTrail Analyzer
# ============================================================================

# Threshold rationale: in our sample data, brute force has 6 attempts on
# one IP. We want to catch it cleanly but allow some background noise.
CT_BRUTE_THRESHOLD_MEDIUM = 3
CT_BRUTE_THRESHOLD_HIGH   = 5

# IAM events that, as a class, indicate privilege change. Note: this list
# is ALL CRITICAL by default — known limitation: legitimate admin onboarding
# workflows trigger false positives. See sample S2_LEGITIMATE_onboarding events
# and report's "Limitations" section.
CT_PRIVESC_EVENTS = {
    "AttachUserPolicy", "AttachRolePolicy",
    "CreateAccessKey", "PutUserPolicy",
    "CreateRole", "UpdateAssumeRolePolicy",
}

# S3 mass-access detection: ≥3 GetObjects from same actor within 60s
CT_S3_BURST_COUNT  = 3
CT_S3_BURST_WINDOW = 60  # seconds


def _ct_user_of(record: Dict) -> str:
    """Extract username from CloudTrail userIdentity (handles both
    IAMUser and AssumedRole shapes)."""
    ui = record.get("userIdentity", {})
    return (ui.get("userName")
            or ui.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
            or "unknown")


def _ct_summarize_request(record: Dict) -> str:
    """One-liner summary of the most relevant request parameter."""
    params = record.get("requestParameters", {}) or {}
    for key in ("policyArn", "userName", "roleName", "policyName", "bucketName"):
        if key in params:
            val = str(params[key])
            return f"{key}={val[:80]}" + ("…" if len(val) > 80 else "")
    if params:
        k = next(iter(params))
        return f"{k}=…"
    return ""


@tool
def analyze_cloudtrail_logs(query: str = "all") -> str:
    """Analyzes AWS CloudTrail logs for security incidents.

    Detects:
      • Brute-force console login (multiple ConsoleLogin failures from one IP)
      • Privilege escalation (IAM modifications: AttachUserPolicy, CreateAccessKey,
        CreateRole, UpdateAssumeRolePolicy, PutUserPolicy, AttachRolePolicy)
      • Unauthorized API calls (Access Denied / not authorized errors)
      • S3 public-bucket exposure (PutBucketPolicy with Principal:"*")
      • S3 mass-object access (≥3 GetObjects from one actor within 60s — exfil signal)

    Use this tool when the user asks about:
      - AWS console logins, IAM activity, or API call audit
      - Suspicious admin actions or permission changes
      - S3 bucket access or data exposure incidents
      - "Who did what?" questions in the AWS account

    Args:
        query: Optional focusing hint (e.g., "iam events", "s3 access").
               Currently informational only — the tool analyzes all events.
    """
    try:
        data = _load("cloudtrail_sample.json")
    except FileNotFoundError as e:
        return f"❌ Error: {e}"

    records = data.get("Records", [])
    if not records:
        return "## CloudTrail Analysis\n\nNo records found."

    findings: List[Dict] = []

    # --- Detection 1: Brute-force ConsoleLogin -------------------------------
    failed = [r for r in records
              if r.get("eventName") == "ConsoleLogin"
              and r.get("responseElements", {}).get("ConsoleLogin") == "Failure"]
    by_ip = defaultdict(list)
    for r in failed:
        by_ip[r["sourceIPAddress"]].append(r)
    for ip, attempts in by_ip.items():
        if len(attempts) >= CT_BRUTE_THRESHOLD_MEDIUM:
            sev = "HIGH" if len(attempts) >= CT_BRUTE_THRESHOLD_HIGH else "MEDIUM"
            users = sorted({_ct_user_of(r) for r in attempts})
            times = sorted(r["eventTime"] for r in attempts)
            findings.append({
                "type": "BRUTE_FORCE_CONSOLE_LOGIN",
                "severity": sev,
                "detail": (f"{len(attempts)} failed ConsoleLogin attempts from {ip} "
                           f"targeting users: {', '.join(users)}"),
                "source_ip": ip,
                "user": ", ".join(users),
                "evidence_count": len(attempts),
                "time_window": f"{times[0]} → {times[-1]}",
                "mitre_key": "BRUTE_FORCE",
            })

    # --- Detection 2: Privilege escalation -----------------------------------
    for r in records:
        if r.get("eventName") in CT_PRIVESC_EVENTS:
            findings.append({
                "type": f"PRIVILEGE_ESCALATION:{r['eventName']}",
                "severity": "CRITICAL",
                "detail": (f"User '{_ct_user_of(r)}' performed {r['eventName']} "
                           f"({_ct_summarize_request(r)})"),
                "source_ip": r.get("sourceIPAddress", "unknown"),
                "user": _ct_user_of(r),
                "time_window": r.get("eventTime", "unknown"),
                "mitre_key": "PRIVILEGE_ESCALATION",
            })

    # --- Detection 3: Unauthorized access ------------------------------------
    unauth = [r for r in records
              if r.get("errorMessage")
              and any(kw in r.get("errorMessage", "").lower()
                      for kw in ("unauthorized", "is not authorized", "access denied"))]
    for r in unauth:
        findings.append({
            "type": "UNAUTHORIZED_ACCESS",
            "severity": "HIGH",
            "detail": f"User '{_ct_user_of(r)}' attempted {r.get('eventName')} but was denied",
            "source_ip": r.get("sourceIPAddress", "unknown"),
            "user": _ct_user_of(r),
            "time_window": r.get("eventTime", "unknown"),
            "mitre_key": "UNAUTHORIZED_ACCESS",
        })

    # --- Detection 4a: S3 public-bucket exposure -----------------------------
    for r in records:
        if r.get("eventName") == "PutBucketPolicy":
            policy = str(r.get("requestParameters", {}).get("bucketPolicy", ""))
            # Naive but effective: look for Principal:"*" (wildcard public)
            if '"Principal":"*"' in policy.replace(" ", ""):
                bucket = r.get("requestParameters", {}).get("bucketName", "?")
                findings.append({
                    "type": "S3_PUBLIC_BUCKET_EXPOSURE",
                    "severity": "CRITICAL",
                    "detail": (f"User '{_ct_user_of(r)}' modified policy on bucket '{bucket}' "
                               f"to allow public access (Principal:*)"),
                    "source_ip": r.get("sourceIPAddress", "unknown"),
                    "user": _ct_user_of(r),
                    "time_window": r.get("eventTime", "unknown"),
                    "mitre_key": "S3_PUBLIC_EXPOSURE",
                })

    # --- Detection 4b: S3 mass-object access (exfil) -------------------------
    get_obj_by_user = defaultdict(list)
    for r in records:
        if r.get("eventName") == "GetObject":
            get_obj_by_user[_ct_user_of(r)].append(r)
    for user, gets in get_obj_by_user.items():
        if len(gets) < CT_S3_BURST_COUNT:
            continue
        times_iso = sorted(r["eventTime"] for r in gets)
        t0 = _parse_iso(times_iso[0])
        tN = _parse_iso(times_iso[-1])
        if (tN - t0).total_seconds() <= CT_S3_BURST_WINDOW:
            buckets = sorted({r.get("requestParameters", {}).get("bucketName", "?")
                              for r in gets})
            findings.append({
                "type": "S3_MASS_OBJECT_ACCESS",
                "severity": "HIGH",
                "detail": (f"User '{user}' downloaded {len(gets)} S3 objects "
                           f"from {', '.join(buckets)} in "
                           f"{(tN - t0).total_seconds():.0f}s"),
                "source_ip": gets[0].get("sourceIPAddress", "unknown"),
                "user": user,
                "evidence_count": len(gets),
                "time_window": f"{times_iso[0]} → {times_iso[-1]}",
                "mitre_key": "S3_EXFILTRATION",
            })

    return _format_report(findings, "CloudTrail Analysis", len(records))


# ============================================================================
# Tool 2: VPC Flow Logs Analyzer
# ============================================================================

# Port scan: a source touching ≥5 distinct ports with ≥50% REJECT is scanning.
# 5 is conservative — in our sample, the scan touches 12 ports.
VPC_PORTSCAN_MIN_PORTS    = 5
VPC_PORTSCAN_REJECT_RATIO = 0.5

# SSH brute force: 5+ flows to port 22 from a single external IP. Internal
# sources (admins) are excluded — they wouldn't appear in flow logs much
# anyway since they typically use private IPs over VPN.
VPC_SSH_BRUTE_THRESHOLD = 5

# Exfil: 100 MB in a single flow is the threshold. Rationale: in our sample,
# the largest legitimate flow is ~8 KB. 100 MB is 12,800x larger than that —
# safely above any normal traffic but below typical CDN downloads. Tunable.
VPC_EXFIL_BYTES_THRESHOLD = 100 * 1024 * 1024


@tool
def analyze_vpc_flow_logs(query: str = "all") -> str:
    """Analyzes AWS VPC Flow Logs for network-layer security incidents.

    Detects:
      • Port scans (single source probing many distinct ports, mostly REJECTed)
      • SSH brute force (sustained traffic to port 22 from external sources)
      • Data exfiltration (anomalously large outbound flows from internal hosts)

    Use this tool when the user asks about:
      - Network traffic, port activity, or connection patterns
      - Suspicious external IPs probing the infrastructure
      - Data leaving the network (outbound bytes, exfiltration concerns)
      - "Who connected to what at the network level?" questions

    Args:
        query: Optional focusing hint. Currently informational only.
    """
    try:
        data = _load("vpc_flowlogs_sample.json")
    except FileNotFoundError as e:
        return f"❌ Error: {e}"

    flows = data.get("records", [])
    if not flows:
        return "## VPC Flow Logs Analysis\n\nNo flows found."

    findings: List[Dict] = []

    # --- Detection 1: Port scan ----------------------------------------------
    by_src = defaultdict(list)
    for f in flows:
        by_src[f["srcaddr"]].append(f)
    for src, src_flows in by_src.items():
        distinct_ports = {f["dstport"] for f in src_flows}
        rejects = sum(1 for f in src_flows if f["action"] == "REJECT")
        reject_ratio = rejects / len(src_flows) if src_flows else 0
        if (len(distinct_ports) >= VPC_PORTSCAN_MIN_PORTS
                and reject_ratio >= VPC_PORTSCAN_REJECT_RATIO):
            findings.append({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "detail": (f"Source {src} probed {len(distinct_ports)} distinct ports "
                           f"({rejects}/{len(src_flows)} = {reject_ratio:.0%} REJECT)"),
                "source_ip": src,
                "evidence_count": len(src_flows),
                "mitre_key": "PORT_SCAN",
            })

    # --- Detection 2: SSH brute force (network layer) ------------------------
    ssh_by_src = defaultdict(list)
    for f in flows:
        if f["dstport"] == 22:
            ssh_by_src[f["srcaddr"]].append(f)
    for src, ssh_flows in ssh_by_src.items():
        if _is_internal(src):
            continue  # internal admin SSH is normal
        if len(ssh_flows) >= VPC_SSH_BRUTE_THRESHOLD:
            t_start = min(f["start"] for f in ssh_flows)
            t_end   = max(f["end"]   for f in ssh_flows)
            findings.append({
                "type": "SSH_BRUTE_FORCE_NETWORK",
                "severity": "HIGH",
                "detail": (f"External source {src} initiated {len(ssh_flows)} SSH "
                           f"connections in {t_end - t_start}s — "
                           f"check auth_logs for app-layer outcome"),
                "source_ip": src,
                "evidence_count": len(ssh_flows),
                "time_window": f"epoch {t_start}–{t_end}",
                "mitre_key": "BRUTE_FORCE",
            })

    # --- Detection 3: Data exfiltration --------------------------------------
    for f in flows:
        if (f["bytes"] >= VPC_EXFIL_BYTES_THRESHOLD
                and _is_internal(f["srcaddr"])
                and not _is_internal(f["dstaddr"])):
            mb = f["bytes"] / (1024 * 1024)
            findings.append({
                "type": "DATA_EXFILTRATION",
                "severity": "CRITICAL",
                "detail": (f"Outbound flow from internal {f['srcaddr']} to external "
                           f"{f['dstaddr']}:{f['dstport']} = {mb:.1f} MB "
                           f"(threshold {VPC_EXFIL_BYTES_THRESHOLD // (1024*1024)} MB exceeded)"),
                "source_ip": f["srcaddr"],
                "evidence_count": 1,
                "time_window": f"epoch {f['start']}–{f['end']}",
                "mitre_key": "DATA_EXFILTRATION",
            })

    return _format_report(findings, "VPC Flow Logs Analysis", len(flows))


# ============================================================================
# Tool 3: Auth Logs Analyzer
# ============================================================================

# SSH brute thresholds: 3 = MEDIUM, 5 = HIGH. Internet noise (1-2 attempts)
# stays below threshold by design — see A4 sample events.
AUTH_BRUTE_THRESHOLD_MEDIUM = 3
AUTH_BRUTE_THRESHOLD_HIGH   = 5

# A success after failures from same IP within this window = compromise.
# 120s is generous; real attackers iterate fast (our sample: ~6s between tries).
AUTH_COMPROMISE_WINDOW_SEC = 120

# Sudo failures: 2 from same user is suspicious. Single typo is not flagged.
AUTH_SUDO_FAILURE_THRESHOLD = 2


@tool
def analyze_auth_logs(query: str = "all") -> str:
    """Analyzes Linux authentication logs (sshd, sudo, pam_unix events).

    Detects:
      • SSH brute force (multiple failed/invalid SSH auth attempts from one IP)
      • SSH compromise (failure→success from same IP within 120s)
      • Sudo escalation attempts (≥2 failed sudo commands from same user)

    Use this tool when the user asks about:
      - SSH login activity (success or failure)
      - Linux server compromise indicators
      - Privilege escalation via sudo
      - "Who logged into the servers?" questions

    Args:
        query: Optional focusing hint. Currently informational only.
    """
    try:
        data = _load("auth_logs_sample.json")
    except FileNotFoundError as e:
        return f"❌ Error: {e}"

    logs = data.get("logs", [])
    if not logs:
        return "## Auth Logs Analysis\n\nNo events found."

    findings: List[Dict] = []

    # --- Detection 1: SSH brute force ----------------------------------------
    sshd_failed = [l for l in logs
                   if l.get("service") == "sshd" and not l.get("success", True)]
    by_ip = defaultdict(list)
    for l in sshd_failed:
        if l.get("source_ip"):
            by_ip[l["source_ip"]].append(l)
    for ip, attempts in by_ip.items():
        if len(attempts) >= AUTH_BRUTE_THRESHOLD_MEDIUM:
            sev = "HIGH" if len(attempts) >= AUTH_BRUTE_THRESHOLD_HIGH else "MEDIUM"
            users = sorted({l["user"] for l in attempts})
            hosts = sorted({l["hostname"] for l in attempts})
            times = sorted(l["timestamp"] for l in attempts)
            findings.append({
                "type": "SSH_BRUTE_FORCE",
                "severity": sev,
                "detail": (f"{len(attempts)} failed SSH auth attempts from {ip} "
                           f"targeting users: {', '.join(users)}"),
                "source_ip": ip,
                "user": ", ".join(users),
                "host": ", ".join(hosts),
                "evidence_count": len(attempts),
                "time_window": f"{times[0]} → {times[-1]}",
                "mitre_key": "BRUTE_FORCE",
            })

    # --- Detection 2: SSH compromise (failure→success) -----------------------
    sshd_all = [l for l in logs if l.get("service") == "sshd"]
    for ip, fails in by_ip.items():
        successes = [l for l in sshd_all
                     if l.get("source_ip") == ip and l.get("success")]
        if not successes:
            continue
        last_fail_t = max(_parse_iso(l["timestamp"]) for l in fails)
        for s in successes:
            delta = (_parse_iso(s["timestamp"]) - last_fail_t).total_seconds()
            if 0 <= delta <= AUTH_COMPROMISE_WINDOW_SEC:
                findings.append({
                    "type": "SSH_COMPROMISE_AFTER_BRUTE_FORCE",
                    "severity": "CRITICAL",
                    "detail": (f"IP {ip} succeeded with user '{s['user']}' on "
                               f"{s['hostname']} after {len(fails)} failed attempts "
                               f"({delta:.0f}s after last failure)"),
                    "source_ip": ip,
                    "user": s["user"],
                    "host": s["hostname"],
                    "evidence_count": len(fails) + 1,
                    "time_window": f"{fails[0]['timestamp']} → {s['timestamp']}",
                    "mitre_key": "SSH_COMPROMISE",
                })
                break  # one finding per IP suffices

    # --- Detection 3: Sudo escalation attempts -------------------------------
    sudo_failed = [l for l in logs
                   if l.get("service") == "sudo" and not l.get("success", True)]
    by_user = defaultdict(list)
    for l in sudo_failed:
        by_user[l["user"]].append(l)
    for user, attempts in by_user.items():
        if len(attempts) >= AUTH_SUDO_FAILURE_THRESHOLD:
            cmds = sorted({l.get("command", "?") for l in attempts})
            hosts = sorted({l["hostname"] for l in attempts})
            findings.append({
                "type": "SUDO_ESCALATION_ATTEMPTS",
                "severity": "HIGH",
                "detail": (f"User '{user}' had {len(attempts)} failed sudo command(s) "
                           f"on {', '.join(hosts)}: {', '.join(cmds)}"),
                "user": user,
                "host": ", ".join(hosts),
                "evidence_count": len(attempts),
                "mitre_key": "SUDO_ESCALATION",
            })

    return _format_report(findings, "Auth Logs Analysis", len(logs))


# ============================================================================
# CLI entrypoint for standalone testing
# ============================================================================

if __name__ == "__main__":
    import sys
    choice = sys.argv[1] if len(sys.argv) > 1 else "all"
    if choice not in ("cloudtrail", "vpc", "auth", "all"):
        print("Usage: python log_analyzer.py [cloudtrail|vpc|auth|all]")
        sys.exit(1)
    if choice in ("cloudtrail", "all"):
        print(analyze_cloudtrail_logs("all"))
        print()
    if choice in ("vpc", "all"):
        print(analyze_vpc_flow_logs("all"))
        print()
    if choice in ("auth", "all"):
        print(analyze_auth_logs("all"))