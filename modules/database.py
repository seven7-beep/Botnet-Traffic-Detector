"""
=============================================================================
MODULE: database.py
PURPOSE: SQLite Database Storage & Safe SQL Query Engine
DESCRIPTION:
  Manages persistent storage for network traffic logs, suspicious host profiles,
  and analytical run summaries in SQLite (`botnet_detector.db`).
  Provides a safe, read-only SQL querying interface with pre-built queries
  tailored for B.Tech cybersecurity lab demonstrations.
=============================================================================
"""

import os
import sqlite3
import datetime
import time
import pandas as pd
from typing import Tuple, Optional, Dict, Any, List

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "botnet_detector.db")


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Creates directory if needed and returns SQLite connection."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH):
    """
    Initializes database schema with indexes for fast querying.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Table 1: Network Logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            bytes INTEGER,
            action TEXT,
            risk_score REAL DEFAULT 0.0,
            risk_level TEXT DEFAULT 'Low',
            primary_reason TEXT DEFAULT 'Normal Traffic',
            session_id TEXT
        )
    """)

    # Table 2: Suspicious Hosts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspicious_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            risk_score REAL,
            risk_level TEXT,
            total_connections INTEGER,
            unique_dst_ips INTEGER,
            unique_dst_ports INTEGER,
            total_bytes INTEGER,
            top_dest_ip TEXT,
            primary_reason TEXT,
            detected_at TEXT
        )
    """)

    # Table 3: Analysis Runs History
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_timestamp TEXT NOT NULL,
            total_logs INTEGER,
            total_hosts INTEGER,
            suspicious_hosts_count INTEGER,
            highest_risk_host TEXT,
            highest_risk_score REAL,
            avg_traffic_volume REAL
        )
    """)

    # Create Indexes for fast searching
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON network_logs(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_dst_ip ON network_logs(dst_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_protocol ON network_logs(protocol)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_risk_level ON network_logs(risk_level)")

    conn.commit()
    conn.close()


def save_analysis_session(
    enriched_logs_df: pd.DataFrame,
    hosts_df: pd.DataFrame,
    summary_stats: Dict[str, Any],
    db_path: str = DEFAULT_DB_PATH
) -> bool:
    """
    Persists an analyzed dataset and its summary into SQLite database.
    """
    if enriched_logs_df is None or enriched_logs_df.empty:
        return False

    try:
        init_db(db_path)
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        run_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session_id = f"RUN_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # 1. Clear older logs if needed or append with session_id
        # For clean educational demos, we replace active network_logs with latest session
        # but keep analysis_runs for history.
        cursor.execute("DELETE FROM network_logs")
        cursor.execute("DELETE FROM suspicious_hosts")

        # 2. Insert Enriched Logs
        logs_to_insert = enriched_logs_df.copy()
        logs_to_insert["session_id"] = session_id
        
        # Keep only matching DB columns
        db_cols = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "action", "risk_score", "risk_level", "primary_reason", "session_id"]
        for col in db_cols:
            if col not in logs_to_insert.columns:
                logs_to_insert[col] = None

        logs_to_insert[db_cols].to_sql("network_logs", conn, if_exists="append", index=False)

        # 3. Insert Suspicious Hosts
        if hosts_df is not None and not hosts_df.empty:
            hosts_to_insert = hosts_df.copy()
            hosts_to_insert["detected_at"] = run_time
            host_db_cols = ["src_ip", "risk_score", "risk_level", "total_connections", "unique_dst_ips", "unique_dst_ports", "total_bytes", "top_dest_ip", "primary_reason", "detected_at"]
            for col in host_db_cols:
                if col not in hosts_to_insert.columns:
                    hosts_to_insert[col] = None
            hosts_to_insert[host_db_cols].to_sql("suspicious_hosts", conn, if_exists="append", index=False)

        # 4. Record Run History
        cursor.execute("""
            INSERT INTO analysis_runs (
                run_timestamp, total_logs, total_hosts, suspicious_hosts_count,
                highest_risk_host, highest_risk_score, avg_traffic_volume
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            run_time,
            summary_stats.get("total_logs", 0),
            summary_stats.get("total_src_ips", 0),
            summary_stats.get("suspicious_hosts_count", 0),
            summary_stats.get("highest_risk_host", "N/A"),
            summary_stats.get("highest_risk_score", 0.0),
            summary_stats.get("avg_traffic_volume", 0.0)
        ))

        conn.commit()
        conn.close()
        return True

    except Exception as e:
        print(f"Database save error: {e}")
        return False


def execute_safe_query(
    sql_query: str,
    db_path: str = DEFAULT_DB_PATH
) -> Tuple[Optional[pd.DataFrame], Optional[str], float]:
    """
    Executes a read-only SELECT query against the SQLite database.
    Guards against destructive queries (DROP, DELETE, UPDATE, INSERT, ALTER).
    
    Returns:
        (DataFrame or None, error_message or None, execution_time_ms)
    """
    start_time = time.time()
    cleaned_query = sql_query.strip()

    # Security check for read-only educational query interface
    forbidden_keywords = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "TRUNCATE", "REPLACE", "CREATE", "ATTACH", "DETACH"]
    upper_query = cleaned_query.upper()

    # Check if query starts with SELECT or WITH
    if not (upper_query.startswith("SELECT") or upper_query.startswith("WITH") or upper_query.startswith("EXPLAIN")):
        return None, "Security Restriction: Only read-only SELECT queries are permitted in this console.", 0.0

    for keyword in forbidden_keywords:
        # Check whole word token
        words = upper_query.replace(";", " ").split()
        if keyword in words:
            return None, f"Security Restriction: Prohibited keyword '{keyword}' detected. Only read-only SELECT queries are allowed.", 0.0

    try:
        init_db(db_path)
        conn = get_db_connection(db_path)
        df_result = pd.read_sql_query(cleaned_query, conn)
        conn.close()
        
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return df_result, None, elapsed_ms

    except Exception as e:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return None, f"SQL Execution Error: {str(e)}", elapsed_ms


# ---------------------------------------------------------------------------
# PRESET EDUCATIONAL SQL QUERIES (FOR LAB & VIVA PRESENTATIONS)
# ---------------------------------------------------------------------------
PRESET_QUERIES = {
    "Top 10 Source IPs by Traffic Volume (Bytes)": """
-- Query 1: Identify High-Volume Talkers (Potential Data Exfiltration / Flooding)
SELECT 
    src_ip AS [Source IP],
    COUNT(*) AS [Total Connections],
    SUM(bytes) AS [Total Bytes Transferred],
    ROUND(AVG(bytes), 1) AS [Avg Bytes/Conn],
    risk_level AS [Threat Level]
FROM network_logs
GROUP BY src_ip
ORDER BY [Total Bytes Transferred] DESC
LIMIT 10;
""",

    "Most Contacted Destination IPs (Potential C&C Servers)": """
-- Query 2: Identify Repeated Destination Targets (C&C Beaconing Candidates)
SELECT 
    dst_ip AS [Destination IP / C&C Candidate],
    COUNT(DISTINCT src_ip) AS [Unique Source Hosts],
    COUNT(*) AS [Total Connection Attempts],
    SUM(bytes) AS [Total Bytes Received],
    GROUP_CONCAT(DISTINCT protocol) AS [Protocols Used]
FROM network_logs
GROUP BY dst_ip
ORDER BY [Total Connection Attempts] DESC
LIMIT 10;
""",

    "Port Scanning & Reconnaissance Sweep Detection": """
-- Query 3: Find Hosts Contacting High Variety of Destination Ports
SELECT 
    src_ip AS [Scanning Host IP],
    COUNT(DISTINCT dst_port) AS [Unique Target Ports],
    COUNT(DISTINCT dst_ip) AS [Unique Target IPs],
    COUNT(*) AS [Probe Count],
    risk_level AS [Risk Level],
    primary_reason AS [Detection Reason]
FROM network_logs
GROUP BY src_ip
HAVING COUNT(DISTINCT dst_port) >= 4
ORDER BY [Unique Target Ports] DESC;
""",

    "Protocol Breakdown & Transmission Statistics": """
-- Query 4: Network Protocol Distribution & Bandwidth Consumption
SELECT 
    protocol AS [Protocol],
    COUNT(*) AS [Total Packets / Sessions],
    ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM network_logs)), 2) AS [Traffic Share (%)],
    SUM(bytes) AS [Total Volume (Bytes)],
    ROUND(AVG(bytes), 1) AS [Average Packet Size]
FROM network_logs
GROUP BY protocol
ORDER BY [Total Packets / Sessions] DESC;
""",

    "Suspicious & Critical Risk Hosts Summary": """
-- Query 5: Filter Analyzed Hosts Classified as High or Critical Risk
SELECT 
    src_ip AS [Host IP],
    risk_score AS [Risk Score (0-100)],
    risk_level AS [Threat Level],
    total_connections AS [Connections],
    unique_dst_ips AS [Target IPs],
    unique_dst_ports AS [Target Ports],
    total_bytes AS [Bytes Transferred],
    top_dest_ip AS [Primary Target],
    primary_reason AS [Triggered Anomaly Rule]
FROM suspicious_hosts
WHERE risk_score >= 30
ORDER BY risk_score DESC;
""",

    "Firewall Rule Action Breakdown (ALLOW vs DROP vs BLOCK)": """
-- Query 6: Disposition Breakdown of Firewall Traffic
SELECT 
    action AS [Firewall Action],
    COUNT(*) AS [Log Count],
    ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM network_logs)), 2) AS [Percentage (%)],
    SUM(bytes) AS [Total Bytes]
FROM network_logs
GROUP BY action
ORDER BY [Log Count] DESC;
"""
}
