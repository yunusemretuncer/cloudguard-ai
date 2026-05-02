"""
ip_reputation.py — IP threat-intelligence lookup for the CloudGuard AI agent.

This module exposes one @tool function: `check_ip_reputation(ip_address)`.

Data sources:
  • AbuseIPDB  — abuse confidence score (0-100), TOR flag, ISP, country
  • VirusTotal — last_analysis_stats (malicious / suspicious / harmless),
                 AS owner, country, reputation score

Operating modes:

  LIVE MODE — when both API keys are configured (ABUSEIPDB_API_KEY and/or
              VIRUSTOTAL_API_KEY env vars). Queries both APIs, combines
              results into a single threat level, returns a Markdown report
              with full provenance.

  DEMO MODE — when neither key is set. Falls back to a local lookup table
              built from our sample data: known attacker IPs (used in
              cloudtrail/vpc/auth scenarios) return HIGH; office benchmark
              range (198.18.x.x) returns LOW. Internal RFC 1918 IPs always
              return "no external reputation data" since they aren't routable.

Demo mode exists so the agent can be demonstrated end-to-end without
distributing API keys, and so unit tests don't depend on network access.

Threat classification logic (LIVE MODE):

  CRITICAL  AbuseIPDB score ≥ 75   OR  VirusTotal malicious ≥ 6
  HIGH      AbuseIPDB score ≥ 50   OR  VirusTotal malicious ≥ 1   OR  TOR node
  MEDIUM    AbuseIPDB score ≥ 25
  LOW       Below all thresholds

Thresholds rationale:
  - 75: AbuseIPDB itself flags 75+ as "malicious" in their UI
  - 50: corresponds to "highly likely malicious" per their docs
  - 25: edge of "potentially suspicious"
  - VT malicious ≥ 1: at least one reputable vendor flagged it
  - TOR: exit nodes are favored by attackers; treated as elevated even
    if no specific abuse reports yet
"""

import ipaddress
import os
from typing import Any, Dict

import httpx

try:
    from langchain_core.tools import tool
except ImportError:  # pragma: no cover
    def tool(func):
        return func


# ============================================================================
# Configuration
# ============================================================================

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

HTTP_TIMEOUT = 10  # seconds — APIs are usually fast; longer = stuck agent

# AbuseIPDB score thresholds
ABUSE_CRITICAL = 75
ABUSE_HIGH     = 50
ABUSE_MEDIUM   = 25

# VirusTotal: malicious vendor counts
VT_CRITICAL = 6
VT_HIGH     = 1

# ----------------------------------------------------------------------------
# Demo mode: known IPs from our sample data
# ----------------------------------------------------------------------------
# When no API keys are configured, the tool can still return meaningful
# answers for IPs that appear in our sample logs. This lets the demo be
# fully self-contained.

DEMO_KNOWN_BAD = {
    "203.0.113.45":   ("Documentation range (RFC 5737). In our incident this IP "
                       "drove the AWS console brute force, privilege escalation, "
                       "and S3 data exfiltration chain (S1+S2+S3)."),
    "198.51.100.77":  ("Documentation range (RFC 5737). In our incident this IP "
                       "used a leaked aws-deploy-bot access key to probe IAM and "
                       "EC2 endpoints (S4 — leaked-key probing)."),
    "198.51.100.200": ("Documentation range (RFC 5737). In our incident this IP "
                       "performed a 12-port vertical port scan on web-server-01 "
                       "(V1 — network reconnaissance)."),
    "45.142.213.50":  ("Hosting/abuse range. In our incident this IP brute-forced "
                       "SSH on web-server-01 and compromised the 'ubuntu' user "
                       "(VPC V2 + auth A1 cross-correlation)."),
    "45.155.205.99":  ("Hosting/abuse range. In our incident this IP received "
                       "~3 GB of exfiltrated data from the compromised "
                       "web-server-01 (V3 — data exfiltration)."),
}

# Office / trusted ranges in our sample data (RFC 2544 benchmark range)
DEMO_KNOWN_GOOD_PREFIXES = ("198.18.",)


# ============================================================================
# Validation helpers
# ============================================================================

def _validate_ip(ip: str) -> bool:
    """True if `ip` is a syntactically valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


# RFC 1918 private + RFC 6598 (CGN). Used to distinguish internal hosts.
# We deliberately use prefix matching rather than ipaddress.is_private,
# because is_private also flags RFC 5737 documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as private — which is
# correct per RFC 6890 but wrong for our purpose: those ranges represent
# external attackers in our sample data and must be treated as public.
INTERNAL_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "100.64.", "100.65.", "100.66.", "100.67.", "100.68.", "100.69.",
    "100.70.", "100.71.", "100.72.", "100.73.", "100.74.", "100.75.",
    "100.76.", "100.77.", "100.78.", "100.79.", "100.80.", "100.81.",
    "100.82.", "100.83.", "100.84.", "100.85.", "100.86.", "100.87.",
    "100.88.", "100.89.", "100.90.", "100.91.", "100.92.", "100.93.",
    "100.94.", "100.95.", "100.96.", "100.97.", "100.98.", "100.99.",
    "100.100.", "100.101.", "100.102.", "100.103.", "100.104.",
    "100.105.", "100.106.", "100.107.", "100.108.", "100.109.",
    "100.110.", "100.111.", "100.112.", "100.113.", "100.114.",
    "100.115.", "100.116.", "100.117.", "100.118.", "100.119.",
    "100.120.", "100.121.", "100.122.", "100.123.", "100.124.",
    "100.125.", "100.126.", "100.127.",
)


def _is_internal(ip: str) -> bool:
    """True if `ip` is in an RFC 1918 / 6598 private range.

    Uses prefix matching rather than ipaddress.is_private (see
    INTERNAL_PREFIXES comment for rationale).
    """
    return ip.startswith(INTERNAL_PREFIXES)


# ============================================================================
# API integrations
# ============================================================================

def _check_abuseipdb(ip: str) -> Dict[str, Any]:
    """Query AbuseIPDB. Returns parsed result dict, or {"error": <reason>}."""
    if not ABUSEIPDB_KEY:
        return {"error": "no_api_key"}
    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 401:
            return {"error": "invalid_api_key"}
        if resp.status_code == 429:
            return {"error": "rate_limited"}
        if resp.status_code != 200:
            return {"error": f"http_{resp.status_code}"}
        d = resp.json().get("data", {})
        return {
            "score":          d.get("abuseConfidenceScore", 0),
            "country":        d.get("countryCode"),
            "isp":            d.get("isp"),
            "domain":         d.get("domain"),
            "usage_type":     d.get("usageType"),
            "total_reports":  d.get("totalReports", 0),
            "last_reported":  d.get("lastReportedAt"),
            "is_tor":         d.get("isTor", False),
            "is_whitelisted": d.get("isWhitelisted", False),
        }
    except httpx.TimeoutException:
        return {"error": "timeout"}
    except (httpx.NetworkError, httpx.RequestError) as e:
        return {"error": f"network:{e.__class__.__name__}"}


def _check_virustotal(ip: str) -> Dict[str, Any]:
    """Query VirusTotal v3. Returns parsed result dict, or {"error": <reason>}."""
    if not VIRUSTOTAL_KEY:
        return {"error": "no_api_key"}
    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 401:
            return {"error": "invalid_api_key"}
        if resp.status_code == 404:
            return {"error": "not_found"}
        if resp.status_code == 429:
            return {"error": "rate_limited"}
        if resp.status_code != 200:
            return {"error": f"http_{resp.status_code}"}
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "country":     attrs.get("country"),
            "as_owner":    attrs.get("as_owner"),
            "reputation":  attrs.get("reputation", 0),
        }
    except httpx.TimeoutException:
        return {"error": "timeout"}
    except (httpx.NetworkError, httpx.RequestError) as e:
        return {"error": f"network:{e.__class__.__name__}"}


# ============================================================================
# Threat classification & formatting
# ============================================================================

def _classify_threat(abuse: Dict[str, Any], vt: Dict[str, Any]) -> str:
    """Combine the two sources into a single threat level.

    A finding from EITHER source can elevate severity. We never downgrade —
    if AbuseIPDB says CRITICAL, VirusTotal saying "harmless" doesn't help.
    """
    level = "LOW"

    if "error" not in abuse:
        score = abuse.get("score", 0)
        if score >= ABUSE_CRITICAL:
            return "CRITICAL"  # definitive — short-circuit
        if score >= ABUSE_HIGH:
            level = "HIGH"
        elif score >= ABUSE_MEDIUM:
            level = "MEDIUM"
        # TOR exit node bumps to at least HIGH
        if abuse.get("is_tor") and level in ("LOW", "MEDIUM"):
            level = "HIGH"

    if "error" not in vt:
        mal = vt.get("malicious", 0)
        if mal >= VT_CRITICAL:
            return "CRITICAL"
        if mal >= VT_HIGH and level in ("LOW", "MEDIUM"):
            level = "HIGH"

    return level


def _emoji_for(level: str) -> str:
    return {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "✅"}.get(level, "ℹ️")


def _format_section_abuseipdb(abuse: Dict[str, Any]) -> str:
    if "error" in abuse:
        return f"### AbuseIPDB\n_unavailable: {abuse['error']}_\n"
    out = "### AbuseIPDB\n"
    out += f"- **Abuse score:** {abuse['score']}/100\n"
    out += f"- **Total reports:** {abuse['total_reports']}\n"
    if abuse.get("country"):
        out += f"- **Country:** {abuse['country']}\n"
    if abuse.get("isp"):
        out += f"- **ISP:** {abuse['isp']}\n"
    if abuse.get("usage_type"):
        out += f"- **Usage type:** {abuse['usage_type']}\n"
    if abuse.get("last_reported"):
        out += f"- **Last reported:** {abuse['last_reported']}\n"
    if abuse.get("is_tor"):
        out += "- **TOR exit node:** ⚠️ Yes\n"
    if abuse.get("is_whitelisted"):
        out += "- **Whitelisted:** ✅ Yes\n"
    return out


def _format_section_virustotal(vt: Dict[str, Any]) -> str:
    if "error" in vt:
        return f"### VirusTotal\n_unavailable: {vt['error']}_\n"
    out = "### VirusTotal\n"
    out += f"- **Malicious vendors:** {vt['malicious']}\n"
    out += f"- **Suspicious vendors:** {vt['suspicious']}\n"
    out += f"- **Harmless vendors:** {vt['harmless']}\n"
    if vt.get("as_owner"):
        out += f"- **AS owner:** {vt['as_owner']}\n"
    if vt.get("country"):
        out += f"- **Country:** {vt['country']}\n"
    if vt.get("reputation") is not None:
        out += f"- **Reputation:** {vt['reputation']}\n"
    return out


def _format_recommendation(level: str) -> str:
    return {
        "CRITICAL": ("Block this IP immediately at the WAF/firewall. "
                     "Audit all logs for prior activity from this address. "
                     "Treat any sessions involving it as compromised."),
        "HIGH":     ("Block at the network perimeter. Investigate any logs "
                     "matching this IP in the past 7 days. Consider "
                     "rotating credentials of any users this IP authenticated as."),
        "MEDIUM":   ("Place under heightened monitoring. If recurring activity "
                     "is observed, escalate to HIGH and block."),
        "LOW":      ("Routine monitoring is sufficient. No immediate action needed."),
    }.get(level, "Insufficient data — manual review recommended.")


def _format_live_report(ip: str, abuse: Dict, vt: Dict, level: str) -> str:
    """Render the full report when at least one API responded."""
    out = f"## IP Reputation Report: {ip}\n\n"
    out += f"**Threat level:** {_emoji_for(level)} **{level}**\n\n"
    out += _format_section_abuseipdb(abuse) + "\n"
    out += _format_section_virustotal(vt) + "\n"
    out += "### Recommendation\n"
    out += _format_recommendation(level) + "\n"
    return out


def _format_demo_report(ip: str) -> str:
    """Fallback report when no API keys are configured."""
    header = f"## IP Reputation: {ip}\n\n"
    header += "_Demo mode — no live threat-intel API keys configured._\n"
    header += "_Set `ABUSEIPDB_API_KEY` and/or `VIRUSTOTAL_API_KEY` for live data._\n\n"

    if _is_internal(ip):
        return header + (
            "ℹ️ **Internal IP** (RFC 1918 / 6598 private range)\n"
            "- Private addresses are not routable on the public internet, so "
            "they have no external threat-intel data.\n"
            "- Reputation lookups should be performed against the *external* "
            "endpoints this IP communicates with."
        )

    if ip.startswith(DEMO_KNOWN_GOOD_PREFIXES):
        return header + (
            "✅ **Threat level:** LOW — recognized internal benchmark range\n\n"
            "This IP is in the RFC 2544 benchmark range (198.18.0.0/15) used "
            "in our sample data as the office/trusted egress range. In a "
            "production environment, this would be your corporate VPN or "
            "office network. No threat indicators."
        )

    if ip in DEMO_KNOWN_BAD:
        return header + (
            f"🚨 **Threat level:** HIGH — known attack-signal IP\n\n"
            f"**Context:** {DEMO_KNOWN_BAD[ip]}\n\n"
            f"This IP appears in our internal incident attack-signal list. In "
            f"a live environment, AbuseIPDB and VirusTotal would likely return "
            f"high abuse scores and multiple vendor flags. **Recommendation:** "
            f"Block at the perimeter and audit any logs that mention this IP."
        )

    return header + (
        "❓ **Threat level:** UNKNOWN — no data without API keys\n\n"
        "This is a public IP address but it is not in our local lookup table. "
        "To assess its reputation, configure `ABUSEIPDB_API_KEY` and "
        "`VIRUSTOTAL_API_KEY` in `.env`."
    )


# ============================================================================
# The @tool function
# ============================================================================

@tool
def check_ip_reputation(ip_address: str) -> str:
    """Looks up an IP address against threat-intelligence sources and returns
    a security assessment.

    Combines AbuseIPDB (abuse confidence score, TOR flag, ISP) with
    VirusTotal (malicious-vendor counts, AS owner, reputation) into a
    single threat level (CRITICAL / HIGH / MEDIUM / LOW) and a
    remediation recommendation.

    Use this tool when the user asks about:
      - Whether a specific IP is malicious or suspicious
      - The geographic origin or ownership of an IP
      - Whether an IP found in logs has been seen attacking others
      - The reputation, abuse score, or risk level of an IP address

    Args:
        ip_address: The IPv4 or IPv6 address to look up (e.g., "203.0.113.45").
                    Must be a syntactically valid IP — passing a hostname
                    or partial address returns an error.
    """
    if not _validate_ip(ip_address):
        return f"❌ Error: '{ip_address}' is not a valid IP address."

    if _is_internal(ip_address):
        # Internal IPs have no external reputation. Same answer in live or demo.
        return _format_demo_report(ip_address)

    # If neither key is set, fall back to demo lookup
    if not ABUSEIPDB_KEY and not VIRUSTOTAL_KEY:
        return _format_demo_report(ip_address)

    # Live mode: query whichever APIs are available
    abuse = _check_abuseipdb(ip_address)
    vt    = _check_virustotal(ip_address)
    level = _classify_threat(abuse, vt)
    return _format_live_report(ip_address, abuse, vt, level)


# ============================================================================
# CLI for standalone testing
# ============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        # Default: demo a few sample IPs
        demo_ips = [
            "203.0.113.45",     # known attacker (S1+S2+S3)
            "45.142.213.50",    # known attacker (SSH brute)
            "198.18.0.10",      # office IP
            "10.0.1.50",        # internal compromised host
            "8.8.8.8",          # public, unknown to us
            "not-an-ip",        # invalid
        ]
        for ip in demo_ips:
            print(check_ip_reputation.invoke({"ip_address": ip})
                  if hasattr(check_ip_reputation, "invoke")
                  else check_ip_reputation(ip))
            print("\n" + "="*70 + "\n")
    else:
        ip = sys.argv[1]
        print(check_ip_reputation.invoke({"ip_address": ip})
              if hasattr(check_ip_reputation, "invoke")
              else check_ip_reputation(ip))