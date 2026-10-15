"""
=============================================================================
MODULE: detection.py
PURPOSE: Rule-Based & Anomaly-Based Botnet Detection Engine
DESCRIPTION:
  Analyzes network/firewall logs on a per-host basis. Applies 5 core heuristic
  rules to identify infected machines, command & control (C&C) beaconing,
  port scanning sweeps, and volumetric DDoS spikes.
  
  Designed for educational purposes and viva demonstrations in B.Tech Cyber Security.
=============================================================================
"""

import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple, List


# ---------------------------------------------------------------------------
# DEFAULT DETECTION THRESHOLDS & RULE WEIGHTS
# ---------------------------------------------------------------------------
DEFAULT_THRESHOLDS = {
    # Rule 1: High Connection Count (Session Flood / High Activity)
    "conn_count_threshold": 40,
    # Rule 2: High Destination Port Diversity (Port Scanning / Reconnaissance)
    "dst_ports_threshold": 6,
    # Rule 3: High Traffic Volume in Bytes (Data Exfiltration / Volumetric Flood)
    "byte_volume_threshold": 150000,
    # Rule 4: Repeated External Destination (C&C Beaconing / Target Focus)
    "repeated_dest_threshold": 25,
    # Rule 5: Burst Traffic Spike in short time window (Sudden Surge)
    "burst_spike_threshold": 3.0,  # Peak count is >= 3x host average per minute
}

DEFAULT_WEIGHTS = {
    "rule1_weight": 30,  # High Connection Count
    "rule2_weight": 25,  # High Port Diversity
    "rule3_weight": 25,  # High Volume (Bytes)
    "rule4_weight": 20,  # Repeated C&C Beaconing
    "rule5_weight": 20,  # Traffic Spike Ratio
}


def classify_risk(score: float) -> Tuple[str, str, str]:
    """
    Classifies a normalized risk score (0-100) into standard cybersecurity threat levels.
    
    Returns:
        (level_name, color_hex, badge_css_class)
    """
    if score >= 80:
        return "Critical", "#ff1744", "risk-critical"
    elif score >= 60:
        return "High", "#ff9100", "risk-high"
    elif score >= 30:
        return "Medium", "#ffd600", "risk-medium"
    else:
        return "Low", "#00e676", "risk-low"


def evaluate_host_rules(
    host_stats: Dict[str, Any],
    thresholds: Dict[str, Any],
    weights: Dict[str, int]
) -> Dict[str, Any]:
    """
    Evaluates cybersecurity detection rules for an individual source host IP.
    
    Cybersecurity Concepts Explained:
    --------------------------------
    1. Connection Flooding (Rule 1):
       Infected bot nodes often send rapid SYN or UDP connection attempts when
       instructed to participate in a DDoS attack or brute-force scanning.
       
    2. Horizontal Port Scanning (Rule 2):
       Worms and botnet propagators (e.g. Mirai) sweep multiple destination ports
       (Telnet 23, SSH 22, HTTP 8080) on remote systems to find vulnerable services.
       
    3. Volumetric Anomaly (Rule 3):
       Unusually high total bytes transferred indicates heavy payload distribution,
       DDoS amplification, or unauthorized data exfiltration.
       
    4. C&C Beaconing & Target Hammering (Rule 4):
       Bot clients periodically contact a fixed Command and Control server IP
       to check in, report status, and receive updated attack payloads.
       
    5. Burst Rate Spike (Rule 5):
       Sudden spikes where a single minute's traffic vastly outpaces baseline
       traffic indicate botnet synchronization (the botmaster issued an attack signal).
    """
    raw_score = 0
    max_possible_score = sum(weights.values())
    triggered_rules = []
    rule_details = []

    # -----------------------------------------------------------------------
    # RULE 1: High Connection Count
    # -----------------------------------------------------------------------
    conn_count = host_stats.get("total_connections", 0)
    conn_thresh = thresholds.get("conn_count_threshold", DEFAULT_THRESHOLDS["conn_count_threshold"])
    r1_wt = weights.get("rule1_weight", DEFAULT_WEIGHTS["rule1_weight"])
    
    if conn_count >= conn_thresh:
        raw_score += r1_wt
        triggered_rules.append("RULE 1: High Connection Count")
        rule_details.append({
            "rule": "RULE 1: High Connection Count",
            "points": r1_wt,
            "evidence": f"Total connections ({conn_count}) exceeds threshold ({conn_thresh}). Indicates possible session flood or botnet activity.",
            "severity": "High" if conn_count > conn_thresh * 2 else "Medium"
        })

    # -----------------------------------------------------------------------
    # RULE 2: High Destination Port Diversity (Port Scanning)
    # -----------------------------------------------------------------------
    unique_ports = host_stats.get("unique_dst_ports", 0)
    port_thresh = thresholds.get("dst_ports_threshold", DEFAULT_THRESHOLDS["dst_ports_threshold"])
    r2_wt = weights.get("rule2_weight", DEFAULT_WEIGHTS["rule2_weight"])
    
    if unique_ports >= port_thresh:
        raw_score += r2_wt
        triggered_rules.append("RULE 2: Port Scanning / Reconnaissance")
        rule_details.append({
            "rule": "RULE 2: Port Scanning / Reconnaissance",
            "points": r2_wt,
            "evidence": f"Contacted {unique_ports} unique destination ports (threshold: {port_thresh}). Suggests port scanning or vulnerability sweep.",
            "severity": "High" if unique_ports > port_thresh * 2 else "Medium"
        })

    # -----------------------------------------------------------------------
    # RULE 3: High Traffic Volume (Bytes)
    # -----------------------------------------------------------------------
    total_bytes = host_stats.get("total_bytes", 0)
    byte_thresh = thresholds.get("byte_volume_threshold", DEFAULT_THRESHOLDS["byte_volume_threshold"])
    r3_wt = weights.get("rule3_weight", DEFAULT_WEIGHTS["rule3_weight"])
    
    if total_bytes >= byte_thresh:
        raw_score += r3_wt
        triggered_rules.append("RULE 3: High Traffic Volume")
        rule_details.append({
            "rule": "RULE 3: High Traffic Volume",
            "points": r3_wt,
            "evidence": f"Transferred {total_bytes:,} bytes (threshold: {byte_thresh:,} bytes). Potential volumetric flood or data exfiltration.",
            "severity": "Medium"
        })

    # -----------------------------------------------------------------------
    # RULE 4: Repeated Single Destination Contacts (C&C Beaconing)
    # -----------------------------------------------------------------------
    max_dest_count = host_stats.get("max_connections_to_single_dst", 0)
    top_dest_ip = host_stats.get("top_dest_ip", "N/A")
    rep_thresh = thresholds.get("repeated_dest_threshold", DEFAULT_THRESHOLDS["repeated_dest_threshold"])
    r4_wt = weights.get("rule4_weight", DEFAULT_WEIGHTS["rule4_weight"])
    
    if max_dest_count >= rep_thresh:
        raw_score += r4_wt
        triggered_rules.append("RULE 4: Repeated Target Focus / C&C Beaconing")
        rule_details.append({
            "rule": "RULE 4: Repeated Target Focus / C&C Beaconing",
            "points": r4_wt,
            "evidence": f"{max_dest_count} repeated connections to single destination '{top_dest_ip}' (threshold: {rep_thresh}). Resembles C&C heartbeat polling.",
            "severity": "High" if max_dest_count > rep_thresh * 2 else "Medium"
        })

    # -----------------------------------------------------------------------
    # RULE 5: Burst Traffic Spike
    # -----------------------------------------------------------------------
    burst_ratio = host_stats.get("burst_ratio", 1.0)
    spike_thresh = thresholds.get("burst_spike_threshold", DEFAULT_THRESHOLDS["burst_spike_threshold"])
    r5_wt = weights.get("rule5_weight", DEFAULT_WEIGHTS["rule5_weight"])
    
    if burst_ratio >= spike_thresh and conn_count >= 10:
        raw_score += r5_wt
        triggered_rules.append("RULE 5: Burst Traffic Spike")
        rule_details.append({
            "rule": "RULE 5: Burst Traffic Spike",
            "points": r5_wt,
            "evidence": f"Peak activity is {burst_ratio:.1f}x higher than baseline average (threshold: {spike_thresh:.1f}x). Indicates synchronized bot surge.",
            "severity": "High"
        })

    # -----------------------------------------------------------------------
    # NORMALIZE SCORE TO 0 - 100
    # -----------------------------------------------------------------------
    if max_possible_score > 0:
        normalized_score = min(100.0, round((raw_score / max_possible_score) * 100.0, 1))
    else:
        normalized_score = 0.0

    risk_level, color, badge = classify_risk(normalized_score)

    primary_reason = triggered_rules[0] if triggered_rules else "Normal Baseline Activity"

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "risk_color": color,
        "risk_badge": badge,
        "primary_reason": primary_reason,
        "triggered_rules_count": len(triggered_rules),
        "triggered_rules": triggered_rules,
        "rule_details": rule_details
    }


def analyze_network_traffic(
    df: pd.DataFrame,
    thresholds: Dict[str, Any] = None,
    weights: Dict[str, int] = None
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Main detection entrypoint.
    Takes a normalized logs DataFrame and returns:
    1. suspicious_hosts_df: Summarized host profile with risk scores and classifications
    2. enriched_logs_df: Original logs enriched with host risk levels and triggered rules
    3. summary_stats: High level executive summary statistics
    """
    if df is None or df.empty:
        return pd.DataFrame(), pd.DataFrame(), {}

    t = DEFAULT_THRESHOLDS.copy()
    if thresholds:
        t.update(thresholds)

    w = DEFAULT_WEIGHTS.copy()
    if weights:
        w.update(weights)

    # Ensure required columns exist
    df_clean = df.copy()
    if "bytes" not in df_clean.columns:
        df_clean["bytes"] = 0
    df_clean["bytes"] = pd.to_numeric(df_clean["bytes"], errors="coerce").fillna(0).astype(int)

    # Convert timestamps to datetime for temporal analysis
    if "timestamp" in df_clean.columns:
        df_clean["dt"] = pd.to_datetime(df_clean["timestamp"], errors="coerce")
    else:
        df_clean["dt"] = pd.date_range(start="2026-10-05 12:00:00", periods=len(df_clean), freq="1s")

    # Group by Source IP to extract host profiles
    host_profiles = []
    grouped = df_clean.groupby("src_ip")

    for src_ip, group in grouped:
        total_connections = len(group)
        unique_dst_ips = group["dst_ip"].nunique() if "dst_ip" in group.columns else 1
        unique_dst_ports = group["dst_port"].nunique() if "dst_port" in group.columns else 1
        total_bytes = group["bytes"].sum()
        
        # Top destination and max frequency
        if "dst_ip" in group.columns and not group["dst_ip"].empty:
            dst_counts = group["dst_ip"].value_counts()
            top_dest_ip = dst_counts.index[0]
            max_connections_to_single_dst = dst_counts.iloc[0]
        else:
            top_dest_ip = "N/A"
            max_connections_to_single_dst = 0

        # Burst calculation (group into 1-minute bins or 30-sec bins)
        if "dt" in group.columns and not group["dt"].isna().all():
            try:
                time_bins = group.set_index("dt").resample("1min").size()
                if len(time_bins) > 1 and time_bins.mean() > 0:
                    burst_ratio = time_bins.max() / time_bins.mean()
                else:
                    burst_ratio = 1.0
            except Exception:
                burst_ratio = 1.0
        else:
            burst_ratio = 1.0

        stats = {
            "src_ip": src_ip,
            "total_connections": total_connections,
            "unique_dst_ips": unique_dst_ips,
            "unique_dst_ports": unique_dst_ports,
            "total_bytes": total_bytes,
            "avg_bytes_per_conn": round(total_bytes / total_connections, 1) if total_connections > 0 else 0,
            "top_dest_ip": top_dest_ip,
            "max_connections_to_single_dst": max_connections_to_single_dst,
            "burst_ratio": burst_ratio
        }

        eval_result = evaluate_host_rules(stats, t, w)
        combined = {**stats, **eval_result}
        host_profiles.append(combined)

    hosts_df = pd.DataFrame(host_profiles)

    if not hosts_df.empty:
        # Sort by risk score descending, then connections descending
        hosts_df = hosts_df.sort_values(by=["risk_score", "total_connections"], ascending=[False, False]).reset_index(drop=True)

    # Enrich logs dataframe with host-level risk scoring
    risk_lookup = {}
    level_lookup = {}
    reason_lookup = {}
    if not hosts_df.empty:
        risk_lookup = hosts_df.set_index("src_ip")["risk_score"].to_dict()
        level_lookup = hosts_df.set_index("src_ip")["risk_level"].to_dict()
        reason_lookup = hosts_df.set_index("src_ip")["primary_reason"].to_dict()

    enriched_logs_df = df_clean.copy()
    enriched_logs_df["risk_score"] = enriched_logs_df["src_ip"].map(risk_lookup).fillna(0.0)
    enriched_logs_df["risk_level"] = enriched_logs_df["src_ip"].map(level_lookup).fillna("Low")
    enriched_logs_df["primary_reason"] = enriched_logs_df["src_ip"].map(reason_lookup).fillna("Normal Traffic")

    # High-level summary metrics
    total_logs = len(enriched_logs_df)
    total_src_ips = enriched_logs_df["src_ip"].nunique() if "src_ip" in enriched_logs_df else 0
    total_dst_ips = enriched_logs_df["dst_ip"].nunique() if "dst_ip" in enriched_logs_df else 0
    
    suspicious_hosts_mask = hosts_df["risk_score"] >= 30 if not hosts_df.empty else pd.Series([], dtype=bool)
    suspicious_hosts_count = int(suspicious_hosts_mask.sum()) if not hosts_df.empty else 0
    
    suspicious_logs_count = int((enriched_logs_df["risk_score"] >= 30).sum()) if not enriched_logs_df.empty else 0
    total_traffic_volume = int(enriched_logs_df["bytes"].sum()) if not enriched_logs_df.empty else 0
    avg_traffic_volume = round(total_traffic_volume / total_logs, 1) if total_logs > 0 else 0

    critical_hosts = int((hosts_df["risk_level"] == "Critical").sum()) if not hosts_df.empty else 0
    high_hosts = int((hosts_df["risk_level"] == "High").sum()) if not hosts_df.empty else 0
    medium_hosts = int((hosts_df["risk_level"] == "Medium").sum()) if not hosts_df.empty else 0
    low_hosts = int((hosts_df["risk_level"] == "Low").sum()) if not hosts_df.empty else 0

    summary_stats = {
        "total_logs": total_logs,
        "total_src_ips": total_src_ips,
        "total_dst_ips": total_dst_ips,
        "suspicious_hosts_count": suspicious_hosts_count,
        "suspicious_logs_count": suspicious_logs_count,
        "total_traffic_volume": total_traffic_volume,
        "avg_traffic_volume": avg_traffic_volume,
        "risk_breakdown": {
            "Critical": critical_hosts,
            "High": high_hosts,
            "Medium": medium_hosts,
            "Low": low_hosts,
        },
        "highest_risk_host": hosts_df.iloc[0]["src_ip"] if not hosts_df.empty and hosts_df.iloc[0]["risk_score"] > 0 else "None",
        "highest_risk_score": hosts_df.iloc[0]["risk_score"] if not hosts_df.empty else 0.0
    }

    return hosts_df, enriched_logs_df, summary_stats
