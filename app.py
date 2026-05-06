"""
============================================================
SOC Triage & Threat Intelligence Automator (ENHANCED)
============================================================
Author  : Senior Cybersecurity Engineer / Python Developer
Purpose : Ingests Apache/Nginx access logs, detects SQLi,
          XSS, and Path Traversal attacks, enriches suspicious
          IPs via AbuseIPDB, and renders a Streamlit dashboard.

ENHANCEMENTS v2.0:
- Fixed threat score display formatting
- Added attack distribution charts
- Improved evidence truncation
- Enhanced cache with TTL (1 hour)
- Added progress indicators for API calls
- Better error recovery for rate limits

HOW TO RUN
----------
1. pip install -r requirements.txt
2. Create a .env file in the same directory:
       ABUSEIPDB_API_KEY=your_key_here
3. streamlit run app.py
============================================================
"""

import re
import os
import json
import time
import logging
import io
from urllib.parse import unquote
from datetime import datetime
from typing import Dict, Optional, Tuple
from functools import lru_cache

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
# A.  INGESTION MODULE (Enhanced with better error recovery)
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
    except Exception as e:
        logger.error(f"Unexpected error parsing log: {e}")
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
# B.  DETECTION MODULE (Enhanced with better evidence extraction)
# ══════════════════════════════════════════════════════════════════════════════

# ── SQL Injection ──────────────────────────────────────────────────────────────
_SQLI_PATTERNS = [
    re.compile(r"(?i)(select\s.+from|union\s+select|insert\s+into|drop\s+table)"),
    re.compile(r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s+or\s+'1'\s*=\s*'1)"),
    re.compile(r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)"),
    re.compile(r"(?i)(0x[0-9a-f]{4,})"),
    re.compile(r"(?i)(--\s*$|;\s*drop|xp_cmdshell)"),
]

# ── Cross-Site Scripting ───────────────────────────────────────────────────────
_XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script[\s>]"),
    re.compile(r"(?i)<\/\s*script\s*>"),
    re.compile(r"(?i)javascript\s*:"),
    re.compile(r"(?i)on(error|load|click|mouseover|focus|blur)\s*="),
    re.compile(r"(?i)(<\s*img[^>]+src\s*=|<\s*iframe|<\s*svg)"),
    re.compile(r"(?i)(expression\s*\(|vbscript\s*:)"),
]

# ── Path Traversal ────────────────────────────────────────────────────────────
_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\)"),
    re.compile(r"(?i)(%2e%2e[%2f%5c])"),
    re.compile(r"(?i)(\.\.%2f|\.\.%5c)"),
    re.compile(r"(?i)(%252e%252e)"),
    re.compile(r"(?i)(etc/passwd|etc/shadow|win\.ini|boot\.ini)"),
]

_DETECTORS = {
    "SQLi":           _SQLI_PATTERNS,
    "XSS":            _XSS_PATTERNS,
    "Path Traversal": _PATH_TRAVERSAL_PATTERNS,
}


def _check_patterns(text: str, patterns: list) -> Tuple[int, str]:
    """
    Return the count of patterns that match *text* and the first matched pattern.
    """
    matches = []
    for p in patterns:
        if p.search(text):
            matches.append(p.pattern[:50])  # Store pattern snippet
    return len(matches), ', '.join(matches[:2]) if matches else ""


def detect_attacks(df: pd.DataFrame) -> pd.DataFrame:
    """
    Scan each log record for known attack signatures.

    Enhanced: Returns confidence level and matched pattern evidence.
    """
    if df.empty:
        return df

    hits = []
    for _, row in df.iterrows():
        # Decode URL-encoded characters to catch evasion
        decoded_req = unquote(row["request"])

        matched_types = []
        match_counts = {}
        match_evidence = {}

        for attack_type, patterns in _DETECTORS.items():
            count, evidence = _check_patterns(decoded_req, patterns)
            if count:
                matched_types.append(attack_type)
                match_counts[attack_type] = count
                match_evidence[attack_type] = evidence

        if not matched_types:
            continue  # benign request — skip

        # If more than one pattern category fires, pick the one with most hits
        primary = max(match_counts, key=match_counts.get)
        total_hits = sum(match_counts.values())
        
        # Confidence: High if multiple patterns or multiple attack types
        if total_hits > 1 or len(matched_types) > 1:
            confidence = "High"
        else:
            confidence = "Medium"

        # Evidence: show matched patterns + request snippet
        evidence_snippet = match_evidence.get(primary, "")
        if evidence_snippet and len(evidence_snippet) < 80:
            evidence = f"{evidence_snippet} | {decoded_req[:100]}"
        else:
            evidence = decoded_req[:120]

        hits.append({
            **row.to_dict(),
            "attack_type": primary,
            "confidence": confidence,
            "evidence": evidence
        })

    if not hits:
        return pd.DataFrame()

    return pd.DataFrame(hits)


# ══════════════════════════════════════════════════════════════════════════════
# C.  ENRICHMENT MODULE (Enhanced with TTL cache and better error handling)
# ══════════════════════════════════════════════════════════════════════════════

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_REQUEST_TIMEOUT = 10
_RATE_LIMIT_PAUSE = 1.2
_MAX_RETRIES = 2
_CACHE_TTL = 3600  # 1 hour cache


class ThreatIntelligenceCache:
    """In-memory cache with TTL for AbuseIPDB queries"""
    
    def __init__(self):
        self.cache = {}
        self.timestamps = {}
    
    def get(self, ip: str) -> Optional[Dict]:
        """Get cached data if still valid"""
        if ip in self.cache:
            age = time.time() - self.timestamps.get(ip, 0)
            if age < _CACHE_TTL:
                return self.cache[ip]
            else:
                # Expired, remove from cache
                del self.cache[ip]
                del self.timestamps[ip]
        return None
    
    def set(self, ip: str, data: Dict):
        """Store data in cache"""
        self.cache[ip] = data
        self.timestamps[ip] = time.time()


# Global cache instance
_threat_cache = ThreatIntelligenceCache()


def _map_score_to_threat_level(score: int) -> str:
    """
    Map AbuseIPDB 0–100 Abuse Confidence Score to threat level.
    Enhanced: Better formatting for display
    """
    if score < 0:
        return "Unknown"
    elif score == 0:
        return "Low (Clean)"
    elif score <= 10:
        return "Low"
    elif score <= 40:
        return "Medium"
    elif score <= 75:
        return "High"
    else:
        return "Critical"


def enrich_ip_abuseipdb(ip: str, api_key: str, progress_callback=None) -> dict:
    """
    Query AbuseIPDB for a single IP and return enrichment data.
    Enhanced with progress callback for UI updates.
    """
    # ── Cache check ──────────────────────────────────────────────────────────
    cached = _threat_cache.get(ip)
    if cached:
        logger.debug(f"Cache hit for IP: {ip}")
        return cached

    fallback = {"usage_type": "Unknown", "abuse_score": -1, "threat_level": "Unknown"}

    if not api_key or api_key == "demo_key":
        logger.warning(f"No valid API key — using mock data for {ip}")
        # Generate mock score based on IP for demo
        mock_score = (hash(ip) % 100) if ip else 0
        mock_result = {
            "usage_type": "Mock Data (Demo Mode)",
            "abuse_score": mock_score,
            "threat_level": _map_score_to_threat_level(mock_score),
        }
        _threat_cache.set(ip, mock_result)
        return mock_result

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": False}

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            if progress_callback:
                progress_callback(f"Querying {ip} (attempt {attempt})")
            
            resp = requests.get(
                _ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=_REQUEST_TIMEOUT,
            )

            # Rate limit handling with exponential backoff
            if resp.status_code == 429:
                wait_time = 2 ** attempt
                logger.warning(f"Rate limit hit for {ip}, waiting {wait_time}s")
                time.sleep(wait_time)
                continue

            if resp.status_code != 200:
                logger.warning(f"AbuseIPDB returned HTTP {resp.status_code} for {ip}")
                if attempt == _MAX_RETRIES:
                    break
                continue

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            result = {
                "usage_type": data.get("usageType", "Unknown") or "Unknown",
                "abuse_score": score,
                "threat_level": _map_score_to_threat_level(score),
            }
            
            # Cache the result
            _threat_cache.set(ip, result)
            time.sleep(_RATE_LIMIT_PAUSE)
            return result

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout for {ip} (attempt {attempt})")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for {ip} (attempt {attempt})")
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(f"Bad response for {ip}: {exc}")
            break

    # Fallback on all failures
    logger.warning(f"All retries failed for {ip}, using fallback")
    _threat_cache.set(ip, fallback)
    return fallback


def enrich_dataframe(df: pd.DataFrame, api_key: str) -> pd.DataFrame:
    """
    Enrich all unique IPs using AbuseIPDB with progress indicators.
    """
    if df.empty:
        return df

    unique_ips = df["ip"].unique()
    
    # Create progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    enrichment_results = []
    for idx, ip in enumerate(unique_ips):
        status_text.text(f"🌐 Enriching IP {idx+1}/{len(unique_ips)}: {ip}")
        
        def update_status(msg):
            status_text.text(msg)
        
        result = enrich_ip_abuseipdb(ip, api_key, update_status)
        enrichment_results.append({"ip": ip, **result})
        
        progress_bar.progress((idx + 1) / len(unique_ips))
        
        # Rate limiting protection
        if (idx + 1) % 20 == 0:
            time.sleep(2)
    
    progress_bar.empty()
    status_text.empty()
    
    enrich_df = pd.DataFrame(enrichment_results)
    return df.merge(enrich_df, on="ip", how="left")


# ══════════════════════════════════════════════════════════════════════════════
# D.  REPORT BUILDER (Enhanced with better formatting)
# ══════════════════════════════════════════════════════════════════════════════

def build_report(enriched_df: pd.DataFrame) -> pd.DataFrame:
    """
    Select and rename columns for the final triage report.
    Enhanced: Better column formatting and sorting.
    """
    if enriched_df.empty:
        return pd.DataFrame()

    # Ensure all required columns exist
    required_cols = ["timestamp", "ip", "attack_type", "confidence", 
                     "evidence", "usage_type", "abuse_score", "threat_level"]
    
    for col in required_cols:
        if col not in enriched_df.columns:
            enriched_df[col] = "N/A"
    
    report = enriched_df[required_cols].copy()

    report.columns = [
        "Timestamp", "Attacker IP", "Attack Type", "Confidence",
        "Evidence", "Usage Type", "Abuse Score", "Threat Intel Score",
    ]
    
    # Sort by threat severity (Critical > High > Medium > Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, 
                     "Low": 3, "Low (Clean)": 4, "Unknown": 5}
    report["_severity"] = report["Threat Intel Score"].map(
        lambda x: severity_order.get(x, 99)
    )
    report = report.sort_values("_severity").drop("_severity", axis=1)
    
    # Truncate evidence for cleaner display
    report["Evidence"] = report["Evidence"].apply(
        lambda x: x[:150] + "..." if len(str(x)) > 150 else x
    )
    
    return report.reset_index(drop=True)


# ══════════════════════════════════════════════════════════════════════════════
# E.  STREAMLIT APPLICATION (Enhanced UI)
# ══════════════════════════════════════════════════════════════════════════════

def run_streamlit_app() -> None:
    """Entry point for the Streamlit dashboard with enhanced UI."""
    
    st.set_page_config(
        page_title="HanSec SOC Triage Automator",
        page_icon="🛡️",
        layout="wide",
    )

    # ── Custom CSS for SOC aesthetic ─────────────────────────────────────────
    st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    }
    .stTable {
        font-family: 'Courier New', monospace;
        font-size: 0.8rem;
    }
    .attack-critical {
        color: #ff4444;
        font-weight: bold;
    }
    .attack-high {
        color: #ff8844;
    }
    .attack-medium {
        color: #ffcc44;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── Header ────────────────────────────────────────────────────────────────
    st.title("🛡️ HanSec SOC Triage & Threat Intelligence Automator")
    st.caption("*Enterprise-grade security orchestration with real-time threat intelligence*")
    st.divider()

    # ── Sidebar: configuration ────────────────────────────────────────────────
    st.sidebar.header("⚙️ Configuration")
    
    default_key = os.getenv("ABUSEIPDB_API_KEY", "")
    api_key = st.sidebar.text_input(
        "AbuseIPDB API Key",
        value=default_key,
        type="password",
        help="Get a free key at https://www.abuseipdb.com/register"
    )
    
    if not api_key:
        st.sidebar.info("ℹ️ No API key provided. Using demo mode with mock data.")

    st.sidebar.markdown("---")
    st.sidebar.subheader("📂 Log Source")
    upload_mode = st.sidebar.radio("Input method", ["Upload file", "Enter file path"])

    log_df = pd.DataFrame()

    if upload_mode == "Upload file":
        uploaded = st.sidebar.file_uploader(
            "Upload access.log", 
            type=["log", "txt"],
            help="Apache/Nginx combined log format"
        )
        if uploaded:
            with st.spinner("Parsing log file..."):
                raw = uploaded.read()
                log_df = parse_log_bytes(raw)
                if not log_df.empty:
                    st.sidebar.success(f"✅ Loaded {len(log_df):,} log lines")
                else:
                    st.sidebar.error("No valid log entries found")
    else:
        log_path = st.sidebar.text_input(
            "Log file path", 
            placeholder="/var/log/nginx/access.log"
        )
        if log_path and st.sidebar.button("📂 Load File", type="primary"):
            with st.spinner("Parsing log file..."):
                log_df = parse_log(log_path)
                if not log_df.empty:
                    st.sidebar.success(f"✅ Loaded {len(log_df):,} log lines")
                else:
                    st.sidebar.error("Could not load file — check path")

    # ── Main panel ────────────────────────────────────────────────────────────
    if log_df.empty:
        st.info("👈 **Get Started** — Upload a log file or enter a file path in the sidebar")
        _show_sample_format()
        return

    # Statistics row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📊 Total Log Lines", f"{len(log_df):,}")
    
    # ── Detection ─────────────────────────────────────────────────────────────
    with st.spinner("🔍 Analyzing for attack patterns..."):
        attacks_df = detect_attacks(log_df)

    if attacks_df.empty:
        st.success("✅ **No attack signatures detected** — The log appears clean")
        col2.metric("🚨 Suspicious", "0")
        _show_benign_summary(log_df)
        return

    suspicious_count = len(attacks_df)
    col2.metric("🚨 Suspicious Requests", f"{suspicious_count:,}")
    
    # ── Enrichment ────────────────────────────────────────────────────────────
    with st.spinner("🌐 Enriching IPs with threat intelligence..."):
        enriched_df = enrich_dataframe(attacks_df, api_key)

    # ── Report ────────────────────────────────────────────────────────────────
    report_df = build_report(enriched_df)

    # Enhanced metrics
    unique_ips = report_df["Attacker IP"].nunique()
    attack_types = report_df["Attack Type"].nunique()
    critical_hits = (report_df["Threat Intel Score"] == "Critical").sum()
    high_hits = (report_df["Threat Intel Score"] == "High").sum()
    
    col3.metric("🎯 Attack Types", attack_types)
    col4.metric("⚠️ Critical Threats", critical_hits, 
                delta=f"+{high_hits} High" if high_hits > 0 else None)

    st.divider()
    
    # ── Triage Report Table ────────────────────────────────────────────────────
    st.subheader("📋 SOC Triage Report")
    
    # Color-code threat levels in the table
    def color_threat(val):
        if val == "Critical":
            return 'background-color: #ff4444; color: white'
        elif val == "High":
            return 'background-color: #ff8844'
        elif val == "Medium":
            return 'background-color: #ffcc44'
        return ''
    
    styled_df = report_df.style.applymap(color_threat, subset=["Threat Intel Score"])
    st.dataframe(styled_df, use_container_width=True, height=400)

    # ── CSV Download ──────────────────────────────────────────────────────────
    csv_buf = io.StringIO()
    report_df.to_csv(csv_buf, index=False)
    st.download_button(
        label="📥 Download CSV Report",
        data=csv_buf.getvalue().encode("utf-8"),
        file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        type="primary"
    )

    # ── Attack Distribution Charts ────────────────────────────────────────────
    st.divider()
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Attack Types Distribution")
        dist = report_df["Attack Type"].value_counts()
        if not dist.empty:
            st.bar_chart(dist)
    
    with col2:
        st.subheader("📊 Threat Severity Breakdown")
        severity = report_df["Threat Intel Score"].value_counts()
        if not severity.empty:
            st.bar_chart(severity)
    
    # ── Attack Details (Expandable) ───────────────────────────────────────────
    st.divider()
    with st.expander("🔍 **View Detailed Attack Analysis**"):
        for idx, row in report_df.iterrows():
            st.markdown(f"""
            **{row['Attack Type']}** from `{row['Attacker IP']}` | Confidence: {row['Confidence']} | Threat: {row['Threat Intel Score']}
            - **Evidence:** `{row['Evidence'][:200]}`
            - **Timestamp:** {row['Timestamp']}
            - **Usage Type:** {row['Usage Type']} | **Abuse Score:** {row['Abuse Score']}
            ---
            """)


def _show_sample_format() -> None:
    """Display an example log line so users know what format is expected."""
    st.subheader("📖 Expected Log Format (Apache/Nginx Combined)")
    st.code(
        '203.0.113.45 - - [05/May/2026:12:34:56 +0000] '
        '"GET /index.php?id=1 HTTP/1.1" 200 512 '
        '"-" "Mozilla/5.0"',
        language="text",
    )
    st.caption("Your log must follow this exact format for proper parsing.")


def _show_benign_summary(df: pd.DataFrame) -> None:
    """Show summary when no attacks are detected."""
    st.subheader("📊 Log Summary")
    
    # Show top IPs
    top_ips = df["ip"].value_counts().head(5)
    if not top_ips.empty:
        st.write("**Top IPs by request count:**")
        st.dataframe(top_ips.reset_index().rename(
            columns={"index": "IP", "ip": "Requests"}
        ), use_container_width=True)
    
    # Show status code distribution
    status_codes = df["status"].value_counts().sort_index()
    if not status_codes.empty:
        st.write("**HTTP Status Code Distribution:**")
        st.bar_chart(status_codes)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    run_streamlit_app()
