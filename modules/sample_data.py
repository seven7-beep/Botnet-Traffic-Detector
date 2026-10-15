"""
=============================================================================
MODULE: sample_data.py
PURPOSE: Deterministic Synthetic Network & Botnet Traffic Generator
DESCRIPTION:
  Generates reproducible, realistic network firewall logs containing both
  benign baseline traffic and distinct botnet threat profiles:
    1. Mirai-style horizontal port scanner (High destination port diversity)
    2. C&C beaconing node (Repeated periodic target hammering)
    3. Volumetric DDoS flooder (Session flooding & sudden traffic spikes)
    4. Data exfiltration node (High byte volume anomaly)
    5. Benign office hosts (Standard web browsing, DNS, NTP, TLS)
  
  Ideal for college viva presentations and defensive rule demonstrations.
=============================================================================
"""

import os
import random
import datetime
import pandas as pd
from typing import Optional


def generate_sample_botnet_traffic(
    num_records: int = 1500,
    seed: int = 42,
    save_to_file: Optional[str] = "data/sample_logs.csv"
) -> pd.DataFrame:
    """
    Generates a realistic synthetic firewall log dataset with controlled botnet behaviors.
    
    Parameters:
        num_records: Approximate number of log lines to generate (default 1500)
        seed: Fixed random seed for deterministic viva demos (default 42)
        save_to_file: Optional path to save CSV file
        
    Returns:
        pd.DataFrame containing standardized firewall logs
    """
    random.seed(seed)
    
    records = []
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
    
    # -----------------------------------------------------------------------
    # 1. BENIGN (NORMAL) HOSTS: 192.168.1.10 through 192.168.1.30
    # -----------------------------------------------------------------------
    benign_hosts = [f"192.168.1.{i}" for i in range(10, 31)]
    legit_external_servers = [
        "142.250.190.46",  # Google Search / Services
        "151.101.1.140",   # Fastly CDN / Reddit / GitHub
        "104.244.42.1",    # Cloudflare CDN
        "13.107.42.14",    # Microsoft Azure / Teams
        "172.217.16.206",  # YouTube / Google Video
        "8.8.8.8",         # Google Public DNS
        "1.1.1.1",         # Cloudflare DNS
        "192.168.1.1"      # Local Gateway / Router
    ]
    
    # Generate ~60% benign traffic
    benign_count = int(num_records * 0.60)
    for i in range(benign_count):
        src_ip = random.choice(benign_hosts)
        dst_ip = random.choice(legit_external_servers)
        
        # Choose standard service
        service_type = random.choices(
            ["HTTPS", "HTTP", "DNS", "NTP", "SSH_INTERNAL"],
            weights=[60, 20, 15, 3, 2]
        )[0]
        
        if service_type == "HTTPS":
            dst_port = 443
            protocol = "TCP"
            byte_size = random.randint(400, 4500)
            action = "ALLOW"
        elif service_type == "HTTP":
            dst_port = 80
            protocol = "TCP"
            byte_size = random.randint(300, 2500)
            action = "ALLOW"
        elif service_type == "DNS":
            dst_port = 53
            protocol = "UDP"
            dst_ip = random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"])
            byte_size = random.randint(64, 256)
            action = "ALLOW"
        elif service_type == "NTP":
            dst_port = 123
            protocol = "UDP"
            byte_size = 76
            action = "ALLOW"
        else:
            dst_port = 22
            protocol = "TCP"
            dst_ip = "192.168.1.5"
            byte_size = random.randint(120, 800)
            action = "ALLOW"

        # Evenly spread timestamps
        sec_offset = int((i / benign_count) * 7200) + random.randint(0, 5)
        log_time = base_time + datetime.timedelta(seconds=sec_offset)
        
        records.append({
            "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": dst_port,
            "protocol": protocol,
            "bytes": byte_size,
            "action": action
        })

    # -----------------------------------------------------------------------
    # 2. BOTNET HOST #1: 192.168.1.105 ("Mirai / Reaper Port Scanner")
    # Behavior: Sweeps numerous distinct destination ports across targets (Rule 2 + Rule 1)
    # -----------------------------------------------------------------------
    scan_ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5555, 8080, 8443, 8888, 9000, 27017]
    scanner_ip = "192.168.1.105"
    scan_count = int(num_records * 0.12)
    
    for i in range(scan_count):
        # Sweeping random external IP blocks
        target_ip = f"{random.randint(180, 220)}.{random.randint(10, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        target_port = random.choice(scan_ports)
        sec_offset = int((i / scan_count) * 7200) + random.randint(0, 3)
        log_time = base_time + datetime.timedelta(seconds=sec_offset)
        
        action = random.choices(["BLOCK", "DROP", "ALLOW"], weights=[50, 40, 10])[0]
        
        records.append({
            "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": target_port,
            "protocol": "TCP",
            "bytes": random.randint(44, 74),  # Small SYN probes
            "action": action
        })

    # -----------------------------------------------------------------------
    # 3. BOTNET HOST #2: 192.168.1.120 ("C&C Beaconing Bot")
    # Behavior: High-frequency periodic requests to specific C&C server (Rule 4 + Rule 1)
    # -----------------------------------------------------------------------
    beacon_host = "192.168.1.120"
    cnc_server_ip = "198.51.100.45"  # External Command & Control server
    beacon_count = int(num_records * 0.10)
    
    for i in range(beacon_count):
        sec_offset = int((i / beacon_count) * 7200) + random.randint(0, 2)
        log_time = base_time + datetime.timedelta(seconds=sec_offset)
        
        records.append({
            "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": beacon_host,
            "dst_ip": cnc_server_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 8443,  # Encrypted C&C communication channel
            "protocol": "TCP",
            "bytes": random.randint(64, 128),  # Heartbeat ping
            "action": "ALLOW"
        })

    # -----------------------------------------------------------------------
    # 4. BOTNET HOST #3: 192.168.1.199 ("DDoS Volumetric Flooder")
    # Behavior: Rapid burst flood targeting victim IP (Rule 1 + Rule 5 + Rule 3)
    # -----------------------------------------------------------------------
    flooder_host = "192.168.1.199"
    victim_ip = "203.0.113.88"  # Target server under DDoS attack
    flood_count = int(num_records * 0.12)
    
    # Concentrate traffic into a tight 10-minute burst window (minute 40 to 50)
    burst_start_sec = 2400
    for i in range(flood_count):
        sec_offset = burst_start_sec + random.randint(0, 600)
        log_time = base_time + datetime.timedelta(seconds=sec_offset)
        
        protocol = random.choice(["UDP", "TCP"])
        target_port = random.choice([80, 443, 53, 3074])
        action = random.choices(["ALLOW", "DROP"], weights=[30, 70])[0]
        
        records.append({
            "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": flooder_host,
            "dst_ip": victim_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": target_port,
            "protocol": protocol,
            "bytes": random.randint(512, 1400),  # Heavy packet payloads
            "action": action
        })

    # -----------------------------------------------------------------------
    # 5. SUSPICIOUS HOST #4: 192.168.1.150 ("Data Exfiltration Agent")
    # Behavior: High outbound byte transfers to suspicious external IP (Rule 3)
    # -----------------------------------------------------------------------
    exfil_host = "192.168.1.150"
    exfil_server = "198.51.100.99"
    exfil_count = int(num_records * 0.06)
    
    for i in range(exfil_count):
        sec_offset = int((i / exfil_count) * 7200) + random.randint(0, 10)
        log_time = base_time + datetime.timedelta(seconds=sec_offset)
        
        records.append({
            "timestamp": log_time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": exfil_host,
            "dst_ip": exfil_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": random.randint(25000, 65000),  # Jumbo file uploads / exfil
            "action": "ALLOW"
        })

    # Convert to DataFrame
    df = pd.DataFrame(records)
    
    # Sort chronologically
    df["dt_sort"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="dt_sort").drop(columns=["dt_sort"]).reset_index(drop=True)

    # Save to disk if requested
    if save_to_file:
        try:
            os.makedirs(os.path.dirname(save_to_file), exist_ok=True)
            df.to_csv(save_to_file, index=False)
        except Exception:
            pass

    return df
