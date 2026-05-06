"""
============================================================
SOC Triage & Threat Intelligence Automator
============================================================
Author  : Senior Cybersecurity Engineer / Python Developer
Purpose : Ingests Apache/Nginx access logs, detects SQLi,
          XSS, and Path Traversal attacks, enriches suspicious
          IPs via AbuseIPDB, and renders a Streamlit dashboard.

HOW TO RUN
----------
1. pip install -r requirements.txt
2. Create a .env file in the same directory:
       ABUSEIPDB_API_KEY=your_key_here
3. streamlit run app.py
4. Upload the mock_access.log (or paste its path) in the sidebar.
   API key from .env is pre-loaded; override it in the sidebar.
============================================================
"""

import re
import os
import json
import time
import logging
import io
from urllib.parse import unquote

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Load .env so ABUSEIPDB_API_KEY is available without typing it every run
load_dotenv()


# ══════════════════════════════════════════════════════════════════════════════
# A.  INGESTION MODULE
# ══════════════════════════════════════════════════════════════════════════════

# Combined Log Format (Apache/Nginx default):
#   IP - user [timestamp] "METHOD /path HTTP/x.x" status bytes "referer" "ua"
_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'           # client IP
    r'\s+\S+\s+\S+'          # ident, auth user (usually -)
    r'\s+\[(?P<ts>[^\]]+)\]' # [timestamp]
    r'\s+"(?P<req>[^"]*)"'   # "METHOD /path HTTP/x.x"
    r'\s+(?P<status>\d{3})'  # HTTP status code
    r'\s+(?P<bytes>\S+)'     # response bytes (can be -)
    r'(?:\s+"(?P<ref>[^"]*)")?' # optional referer
    r'(?:\s+"(?P<ua>[^"]*)")?'  # optional user-agent
)


def parse_log(raw_log_path: str) -> pd.DataFrame:
    """
    Parse Apache/Nginx combined access log into a DataFrame.

    Parameters
    ----------
    raw_log_path : str  Path to the access log file.

    Returns
    -------
    pd.DataFrame  Columns: ip, timestamp, request, status, bytes, referer, ua
    """
    records = []
    skipped = 0

    try:
        with open(raw_log_path, "r", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                m = _LOG_PATTERN.match(line)
                if not m:
                    logger.warning("Skipping malformed line %d: %.120s", lineno, line)
                    skipped += 1
                    continue
                records.append({
                    "ip":        m.group("ip"),
                    "timestamp": m.group("ts"),
                    "request":   m.group("req"),
                    "status":    int(m.group("status")),
                    "bytes":     m.group("bytes"),
                    "referer":   m.group("ref") or "",
                    "ua":        m.group("ua") or "",
                })
    except FileNotFoundError:
        logger.error("Log file not found: %s", raw_log_path)
        return pd.DataFrame()

    logger.info("Parsed %d records; skipped %d malformed lines.", len(records), skipped)
    return pd.DataFrame(records)


def parse_log_bytes(raw_bytes: bytes) -> pd.DataFrame:
    """Same as parse_log but accepts raw bytes (for Streamlit file upload)."""
    records = []
    skipped = 0
    lines = raw_bytes.decode("utf-8", errors="replace").splitlines()

    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        m = _LOG_PATTERN.match(line)
        if not m:
            logger.warning("Skipping malformed line %d: %.120s", lineno, line)
            skipped += 1
            continue
        records.append({
            "ip":        m.group("ip"),
            "timestamp": m.group("ts"),
            "request":   m.group("req"),
            "status":    int(m.group("status")),
            "bytes":     m.group("bytes"),
            "referer":   m.group("ref") or "",
            "ua":        m.group("ua") or "",
        })

    logger.info("Parsed %d records; skipped %d malformed lines.", len(records), skipped)
    return pd.DataFrame(records)


# ══════════════════════════════════════════════════════════════════════════════
# B.  DETECTION MODULE
# ══════════════════════════════════════════════════════════════════════════════

# ── SQL Injection ──────────────────────────────────────────────────────────────
# Catches keywords used in SQLi payloads (case-insensitive).
# Also matches hex-encoded variants via URL-decoding before checking.
_SQLI_PATTERNS = [
    re.compile(r"(?i)(select\s.+from|union\s+select|insert\s+into|drop\s+table)"),
    re.compile(r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s+or\s+'1'\s*=\s*'1)"),
    re.compile(r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)"),  # time-based blind
    re.compile(r"(?i)(0x[0-9a-f]{4,})"),                              # hex payloads
    re.compile(r"(?i)(--\s*$|;\s*drop|xp_cmdshell)"),                 # comment/stacked
]

# ── Cross-Site Scripting ───────────────────────────────────────────────────────
# Matches inline script tags, event handlers, and javascript: URIs.
_XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script[\s>]"),
    re.compile(r"(?i)<\/\s*script\s*>"),
    re.compile(r"(?i)javascript\s*:"),
    re.compile(r"(?i)on(error|load|click|mouseover|focus|blur)\s*="),
    re.compile(r"(?i)(<\s*img[^>]+src\s*=|<\s*iframe|<\s*svg)"),     # tag-based vectors
    re.compile(r"(?i)(expression\s*\(|vbscript\s*:)"),                # IE-era XSS
]

# ── Path Traversal ────────────────────────────────────────────────────────────
# Matches ../ or ..\ sequences and URL-encoded equivalents (%2e%2e / %2f).
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\)"),                # literal ../
    re.compile(r"(?i)(%2e%2e[%2f%5c])"),          # %2e%2e%2f or %2e%2e%5c
    re.compile(r"(?i)(\.\.%2f|\.\.%5c)"),          # ..%2f
    re.compile(r"(?i)(%252e%252e)"),               # double-encoded
    re.compile(r"(?i)(etc/passwd|etc/shadow|win\.ini|boot\.ini)"),  # target files
]

_DETECTORS = {
    "SQLi":           _SQLI_PATTERNS,
    "XSS":            _XSS_PATTERNS,
    "Path Traversal": _PATH_TRAVERSAL_PATTERNS,
}


def _check_patterns(text: str, patterns: list) -> int:
    """Return the count of patterns that match *text*."""
    return sum(1 for p in patterns if p.search(text))


def detect_attacks(df: pd.DataFrame) -> pd.DataFrame:
    """
    Scan each log record for known attack signatures.

    Strategy
    --------
    1. URL-decode the request string (handles %XX evasion).
    2. Run each detector's regex list against the decoded string.
    3. A record is flagged if ≥1 pattern matches.
    4. If multiple patterns match, confidence is "High"; otherwise "Medium".

    Returns a filtered DataFrame with extra columns:
        attack_type, confidence, evidence
    """
    if df.empty:
        return df

    hits = []
    for _, row in df.iterrows():
        # Decode URL-encoded characters to catch evasion like %3Cscript%3E
        decoded_req = unquote(row["request"])

        matched_types = []
        match_counts  = {}

        for attack_type, patterns in _DETECTORS.items():
            count = _check_patterns(decoded_req, patterns)
            if count:
                matched_types.append(attack_type)
                match_counts[attack_type] = count

        if not matched_types:
            continue  # benign request — skip

        # If more than one pattern category fires, pick the one with most hits
        primary = max(match_counts, key=match_counts.get)
        total_hits = sum(match_counts.values())
        confidence = "High" if total_hits > 1 else "Medium"

        # Evidence: first 120 chars of the (decoded) request to avoid storing full bodies
        evidence = decoded_req[:120]

        hits.append({**row.to_dict(),
                     "attack_type": primary,
                     "confidence":  confidence,
                     "evidence":    evidence})

    if not hits:
        return pd.DataFrame()

    return pd.DataFrame(hits)


# ══════════════════════════════════════════════════════════════════════════════
# C.  ENRICHMENT MODULE  (AbuseIPDB)
# ══════════════════════════════════════════════════════════════════════════════

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_REQUEST_TIMEOUT = 10   # seconds
_RATE_LIMIT_PAUSE = 1.2 # seconds between API calls (AbuseIPDB free: 1 000/day)
_MAX_RETRIES = 2


def _map_score_to_threat_level(score: int) -> str:
    """
    Map AbuseIPDB 0–100 Abuse Confidence Score to a human-readable threat level.

        0–10  → Low
        11–40 → Medium
        41–75 → High
        76–100→ Critical
    """
    if score < 0:
        return "unavailable"
    if score <= 10:
        return "Low"
    if score <= 40:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


def enrich_ip_abuseipdb(ip: str, api_key: str, cache: dict) -> dict:
    """
    Query AbuseIPDB for a single IP and return enrichment data.

    Parameters
    ----------
    ip      : str   IPv4/IPv6 address to check.
    api_key : str   AbuseIPDB v2 API key.
    cache   : dict  In-memory cache {ip -> result} to avoid duplicate calls.

    Returns
    -------
    dict with keys: usage_type, abuse_score, threat_level
    """
    # ── Cache hit ──────────────────────────────────────────────────────────────
    if ip in cache:
        return cache[ip]

    fallback = {"usage_type": "unknown", "abuse_score": -1, "threat_level": "unavailable"}

    if not api_key:
        logger.warning("No AbuseIPDB API key — skipping enrichment for %s", ip)
        cache[ip] = fallback
        return fallback

    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": False}

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = requests.get(
                _ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=_REQUEST_TIMEOUT,
            )

            # Rate limit
            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limit hit for %s; backing off.", ip)
                time.sleep(5)
                continue

            # Other non-200
            if resp.status_code != 200:
                logger.warning("AbuseIPDB returned HTTP %d for %s.", resp.status_code, ip)
                break

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            result = {
                "usage_type":  data.get("usageType", "unknown") or "unknown",
                "abuse_score": score,
                "threat_level": _map_score_to_threat_level(score),
            }
            cache[ip] = result
            time.sleep(_RATE_LIMIT_PAUSE)   # be a good API citizen
            return result

        except requests.exceptions.Timeout:
            logger.warning("AbuseIPDB timeout for %s (attempt %d).", ip, attempt)
        except requests.exceptions.ConnectionError:
            logger.warning("AbuseIPDB connection error for %s (attempt %d).", ip, attempt)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("AbuseIPDB bad response for %s: %s", ip, exc)
            break

    cache[ip] = fallback
    return fallback


def enrich_dataframe(df: pd.DataFrame, api_key: str) -> pd.DataFrame:
    """
    Enrich all unique IPs in *df* using AbuseIPDB and merge results back.
    """
    if df.empty:
        return df

    cache: dict = {}
    unique_ips = df["ip"].unique()

    rows = []
    for ip in unique_ips:
        result = enrich_ip_abuseipdb(ip, api_key, cache)
        rows.append({"ip": ip, **result})

    enrich_df = pd.DataFrame(rows)
    return df.merge(enrich_df, on="ip", how="left")


# ══════════════════════════════════════════════════════════════════════════════
# D.  REPORT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_report(enriched_df: pd.DataFrame) -> pd.DataFrame:
    """
    Select and rename columns for the final triage report.

    Output columns:
        Timestamp | Attacker IP | Attack Type | Confidence |
        Evidence  | Usage Type  | Abuse Score | Threat Intel Score
    """
    if enriched_df.empty:
        return pd.DataFrame()

    report = enriched_df[[
        "timestamp", "ip", "attack_type", "confidence",
        "evidence", "usage_type", "abuse_score", "threat_level",
    ]].copy()

    report.columns = [
        "Timestamp", "Attacker IP", "Attack Type", "Confidence",
        "Evidence", "Usage Type", "Abuse Score", "Threat Intel Score",
    ]
    return report.reset_index(drop=True)


# ══════════════════════════════════════════════════════════════════════════════
# E.  STREAMLIT APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

def run_streamlit_app() -> None:
    """Entry point for the Streamlit dashboard."""

    st.set_page_config(
        page_title="SOC Triage Automator",
        page_icon="🛡️",
        layout="wide",
    )

    # ── Custom CSS for a dark SOC aesthetic ───────────────────────────────────
    st.markdown("""
    <style>
    body { background: #0d1117; }
    .stApp { background: #0d1117; color: #c9d1d9; }
    .stTable { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }
    .metric-card {
        background: #161b22; border: 1px solid #30363d;
        border-radius: 8px; padding: 16px; text-align: center;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Header ────────────────────────────────────────────────────────────────
    st.title("🛡️ SOC Triage & Threat Intelligence Automator")
    st.caption("Ingest → Detect → Enrich → Report  |  Supports Apache / Nginx combined log format")
    st.divider()

    # ── Sidebar: configuration ────────────────────────────────────────────────
    st.sidebar.header("⚙️ Configuration")

    # Pre-load from .env; user can override at runtime (never shown in code)
    default_key = os.getenv("ABUSEIPDB_API_KEY", "")
    api_key = st.sidebar.text_input(
        "AbuseIPDB API Key",
        value=default_key,
        type="password",
        help="Get a free key at https://www.abuseipdb.com/register",
    )

    st.sidebar.markdown("---")
    st.sidebar.subheader("📂 Log Source")
    upload_mode = st.sidebar.radio("Input method", ["Upload file", "Enter file path"])

    log_df = pd.DataFrame()

    if upload_mode == "Upload file":
        uploaded = st.sidebar.file_uploader("Upload access.log", type=["log", "txt", ""])
        if uploaded:
            raw = uploaded.read()
            log_df = parse_log_bytes(raw)
            st.sidebar.success(f"Loaded {len(log_df):,} log lines.")
    else:
        log_path = st.sidebar.text_input("Log file path", placeholder="/var/log/nginx/access.log")
        if log_path and st.sidebar.button("Load"):
            log_df = parse_log(log_path)
            if not log_df.empty:
                st.sidebar.success(f"Loaded {len(log_df):,} log lines.")
            else:
                st.sidebar.error("Could not load file — check path.")

    # ── Main panel ────────────────────────────────────────────────────────────
    if log_df.empty:
        st.info("👈  Upload a log file or enter a path in the sidebar to begin.")
        _show_sample_format()
        return

    # Show raw log summary
    col1, col2 = st.columns(2)
    col1.metric("Total log lines", f"{len(log_df):,}")

    # ── Detection ─────────────────────────────────────────────────────────────
    with st.spinner("🔍 Scanning for attack signatures…"):
        attacks_df = detect_attacks(log_df)

    if attacks_df.empty:
        st.success("✅ No attack signatures detected in this log.")
        col2.metric("Suspicious requests", "0")
        return

    col2.metric("🚨 Suspicious requests", f"{len(attacks_df):,}")

    # ── Enrichment ────────────────────────────────────────────────────────────
    with st.spinner("🌐 Enriching IPs via AbuseIPDB…"):
        enriched_df = enrich_dataframe(attacks_df, api_key)

    # ── Report ────────────────────────────────────────────────────────────────
    report_df = build_report(enriched_df)

    # Metrics row
    unique_ips    = report_df["Attacker IP"].nunique()
    critical_hits = (report_df["Threat Intel Score"] == "Critical").sum()
    c1, c2, c3 = st.columns(3)
    c1.metric("Unique Attacker IPs",  unique_ips)
    c2.metric("Attack Types Found",   report_df["Attack Type"].nunique())
    c3.metric("🔴 Critical Threats",  critical_hits)

    st.divider()
    st.subheader("📋 Triage Report")
    st.table(report_df)

    # ── CSV Download ──────────────────────────────────────────────────────────
    csv_buf = io.StringIO()
    report_df.to_csv(csv_buf, index=False)
    st.download_button(
        label="⬇️ Download CSV Report",
        data=csv_buf.getvalue().encode("utf-8"),
        file_name="soc_triage_report.csv",
        mime="text/csv",
    )

    # ── Attack distribution ───────────────────────────────────────────────────
    st.divider()
    st.subheader("📊 Attack Distribution")
    dist = report_df["Attack Type"].value_counts().rename_axis("Attack Type").reset_index(name="Count")
    st.bar_chart(dist.set_index("Attack Type"))


def _show_sample_format() -> None:
    """Display an example log line so users know what format is expected."""
    st.subheader("Expected log format (Apache/Nginx combined)")
    st.code(
        '203.0.113.45 - - [05/May/2026:12:34:56 +0000] '
        '"GET /index.php?id=1 HTTP/1.1" 200 512 '
        '"-" "Mozilla/5.0"',
        language="text",
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    run_streamlit_app()
