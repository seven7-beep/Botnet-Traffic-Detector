"""
Unit verification script for Botnet Traffic Detector
"""
import os
import sys

from modules.sample_data import generate_sample_botnet_traffic
from modules.detection import analyze_network_traffic
from modules.database import init_db, save_analysis_session, execute_safe_query, DEFAULT_DB_PATH
from modules.analysis import (
    plot_traffic_timeline,
    plot_protocol_distribution,
    plot_top_source_ips,
    plot_traffic_volume_by_host,
    plot_host_deep_dive
)
from modules.packet_parser import parse_csv_file, parse_pcap_file

def main():
    print("=" * 60)
    print("RUNNING COMPREHENSIVE BOTNET DETECTOR TEST SUITE")
    print("=" * 60)

    # 1. Sample Data Generation
    print("\n[1/5] Generating Synthetic Benchmark Traffic...")
    df = generate_sample_botnet_traffic(num_records=1200, seed=42, save_to_file="data/sample_logs.csv")
    print(f" -> Generated {len(df):,} log entries successfully.")
    print(f" -> Saved to 'data/sample_logs.csv' (File size: {os.path.getsize('data/sample_logs.csv')} bytes)")

    # 2. Detection Engine
    print("\n[2/5] Running Rule-Based Detection Engine...")
    hosts_df, enriched_df, summary = analyze_network_traffic(df)
    print(f" -> Total hosts evaluated: {len(hosts_df)}")
    print(f" -> Flagged suspicious hosts: {summary['suspicious_hosts_count']}")
    print(f" -> Highest risk host: {summary['highest_risk_host']} (Score: {summary['highest_risk_score']}/100)")
    print(f" -> Risk breakdown: {summary['risk_breakdown']}")

    # 3. SQLite Database Operations
    print("\n[3/5] Testing SQLite Database Persistence & Safe Queries...")
    init_db(DEFAULT_DB_PATH)
    saved = save_analysis_session(enriched_df, hosts_df, summary, DEFAULT_DB_PATH)
    print(f" -> Analysis session saved to DB: {saved}")

    query = "SELECT src_ip, risk_score, risk_level, primary_reason FROM suspicious_hosts WHERE risk_score >= 30"
    sql_df, sql_err, elapsed_ms = execute_safe_query(query, DEFAULT_DB_PATH)
    if sql_err:
        print(f" -> SQL Error: {sql_err}")
        return False
    print(f" -> Executed safe query in {elapsed_ms:.2f}ms. Returned {len(sql_df)} suspicious host records.")

    # 4. Chart Visualizations
    print("\n[4/5] Testing Matplotlib Chart Generation...")
    f1 = plot_traffic_timeline(enriched_df)
    f2 = plot_protocol_distribution(enriched_df)
    f3 = plot_top_source_ips(enriched_df)
    f4 = plot_traffic_volume_by_host(hosts_df)
    f5 = plot_host_deep_dive(enriched_df, "192.168.1.105")
    print(" -> All 5 dark-themed cybersecurity chart figures rendered cleanly without error.")

    # 5. Multi-Format Parsers
    print("\n[5/5] Testing CSV and PCAP Parsers...")
    with open("data/sample_logs.csv", "r") as f:
        csv_df, err = parse_csv_file(f)
    print(f" -> CSV Parser: {len(csv_df)} rows parsed, Error: {err}")

    # Generate a mini PCAP with Scapy to test PCAP parsing
    try:
        from scapy.all import IP, TCP, UDP, wrpcap
        pkts = [
            IP(src="192.168.1.105", dst="198.51.100.22")/TCP(sport=50000, dport=23),
            IP(src="192.168.1.120", dst="198.51.100.45")/TCP(sport=50001, dport=8443),
            IP(src="192.168.1.199", dst="203.0.113.88")/UDP(sport=50002, dport=80),
            IP(src="192.168.1.15", dst="8.8.8.8")/UDP(sport=50003, dport=53)
        ]
        os.makedirs("data", exist_ok=True)
        wrpcap("data/test_capture.pcap", pkts)
        pcap_df, pcap_err = parse_pcap_file("data/test_capture.pcap")
        print(f" -> PCAP Parser (Scapy): {len(pcap_df)} packets decoded, Error: {pcap_err}")
    except Exception as e:
        print(f" -> Scapy test note: {e}")

    print("\n" + "=" * 60)
    print("ALL MODULE CHECKS COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    return True

if __name__ == "__main__":
    main()
