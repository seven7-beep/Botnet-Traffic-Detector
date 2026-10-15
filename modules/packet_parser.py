"""
=============================================================================
MODULE: packet_parser.py
PURPOSE: Multi-format Network Log & Packet Capture (PCAP) Parser
DESCRIPTION:
  Parses CSV firewall logs and PCAP capture files using Scapy and Pandas.
  Standardizes disparate network log formats into a unified schema for detection.
  Defensive, robust error handling with automatic column alias resolution.
=============================================================================
"""

import io
import datetime
import pandas as pd
from typing import Tuple, Optional, Dict, Any

# Column alias dictionary for flexible CSV mapping
COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "log_time", "packet_time", "created_at"],
    "src_ip": ["src_ip", "source_ip", "source", "src", "srcip", "ip_src", "client_ip", "source_address"],
    "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "destination", "dst", "dstip", "ip_dst", "server_ip", "target_ip", "target"],
    "src_port": ["src_port", "source_port", "sport", "srcport", "client_port"],
    "dst_port": ["dst_port", "dest_port", "dport", "dstport", "server_port", "target_port", "port"],
    "protocol": ["protocol", "proto", "transport_protocol", "layer4", "type"],
    "bytes": ["bytes", "length", "packet_size", "size", "packet_length", "len", "byte_count", "octets"],
    "action": ["action", "status", "verdict", "disposition", "rule_action", "decision"]
}


def normalize_dataframe_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Intelligently maps varying CSV column names to standardized canonical schema:
    [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, action]
    """
    df_clean = df.copy()
    col_map = {}
    
    # Lowercase all existing columns for case-insensitive matching
    existing_cols = {str(c).strip().lower(): c for c in df_clean.columns}

    for canonical_name, aliases in COLUMN_ALIASES.items():
        matched = False
        for alias in aliases:
            if alias.lower() in existing_cols:
                original_col = existing_cols[alias.lower()]
                col_map[original_col] = canonical_name
                matched = True
                break
    
    # Rename mapped columns
    df_clean = df_clean.rename(columns=col_map)

    # Impute missing canonical fields with sensible fallbacks
    row_count = len(df_clean)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if "timestamp" not in df_clean.columns:
        # Generate synthetic chronological timestamps
        base_time = datetime.datetime.now() - datetime.timedelta(minutes=row_count)
        df_clean["timestamp"] = [
            (base_time + datetime.timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S")
            for i in range(row_count)
        ]
    else:
        # Try parsing timestamp to standardized string
        df_clean["timestamp"] = pd.to_datetime(df_clean["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d %H:%M:%S").fillna(now_str)

    if "src_ip" not in df_clean.columns:
        df_clean["src_ip"] = "192.168.1.100"
    else:
        df_clean["src_ip"] = df_clean["src_ip"].astype(str).str.strip().fillna("192.168.1.100")

    if "dst_ip" not in df_clean.columns:
        df_clean["dst_ip"] = "8.8.8.8"
    else:
        df_clean["dst_ip"] = df_clean["dst_ip"].astype(str).str.strip().fillna("8.8.8.8")

    if "src_port" not in df_clean.columns:
        df_clean["src_port"] = 49152
    else:
        df_clean["src_port"] = pd.to_numeric(df_clean["src_port"], errors="coerce").fillna(49152).astype(int)

    if "dst_port" not in df_clean.columns:
        df_clean["dst_port"] = 80
    else:
        df_clean["dst_port"] = pd.to_numeric(df_clean["dst_port"], errors="coerce").fillna(80).astype(int)

    if "protocol" not in df_clean.columns:
        df_clean["protocol"] = "TCP"
    else:
        df_clean["protocol"] = df_clean["protocol"].astype(str).str.upper().str.strip().fillna("TCP")

    if "bytes" not in df_clean.columns:
        df_clean["bytes"] = 64
    else:
        df_clean["bytes"] = pd.to_numeric(df_clean["bytes"], errors="coerce").fillna(64).astype(int)

    if "action" not in df_clean.columns:
        df_clean["action"] = "ALLOW"
    else:
        df_clean["action"] = df_clean["action"].astype(str).str.upper().str.strip().fillna("ALLOW")

    # Order standard columns
    standard_cols = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "action"]
    # Retain any extra columns at the end
    remaining_cols = [c for c in df_clean.columns if c not in standard_cols]
    final_cols = standard_cols + remaining_cols
    
    return df_clean[final_cols]


def parse_csv_file(file_obj) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """
    Parses an uploaded CSV file into a normalized pandas DataFrame.
    Returns: (DataFrame or None, error_message or None)
    """
    try:
        # Handle string path or uploaded file buffer
        if isinstance(file_obj, (str, io.StringIO, io.BytesIO)):
            df = pd.read_csv(file_obj)
        elif hasattr(file_obj, "read"):
            # Streamlit UploadedFile
            df = pd.read_csv(file_obj)
        else:
            return None, "Invalid file format provided."

        if df.empty:
            return None, "The uploaded CSV file is empty. Please upload a file containing network logs."

        normalized_df = normalize_dataframe_columns(df)
        return normalized_df, None

    except Exception as e:
        return None, f"Failed to parse CSV file: {str(e)}"


def parse_pcap_file(file_bytes_or_path, max_packets: int = 5000) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
    """
    Parses a PCAP/PCAPNG packet capture file using Scapy.
    Extracts Layer 3 (IP) and Layer 4 (TCP/UDP/ICMP) metadata safely.
    
    Returns:
        (DataFrame or None, error_message or None)
    """
    try:
        # Import Scapy inside function so module still loads if Scapy is installing
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, ARP
        from scapy.utils import PcapReader
    except ImportError:
        return None, "Scapy library is not installed. Run 'pip install scapy' to enable PCAP analysis."

    records = []
    
    try:
        # If file is a Streamlit UploadedFile or BytesIO, save temporarily or parse buffer
        if hasattr(file_bytes_or_path, "getvalue"):
            raw_bytes = file_bytes_or_path.getvalue()
            pcap_stream = io.BytesIO(raw_bytes)
            # Scapy PcapReader can read from stream
            pcap_reader = PcapReader(pcap_stream)
        elif isinstance(file_bytes_or_path, bytes):
            pcap_reader = PcapReader(io.BytesIO(file_bytes_or_path))
        elif isinstance(file_bytes_or_path, str):
            pcap_reader = PcapReader(file_bytes_or_path)
        else:
            return None, "Unsupported PCAP input type."

        count = 0
        for pkt in pcap_reader:
            count += 1
            if count > max_packets:
                break

            # Packet time
            try:
                pkt_time = datetime.datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pkt_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            pkt_len = len(pkt)
            
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port = 0
            dst_port = 0
            protocol = "OTHER"
            action = "ALLOW"

            # Parse Layer 3
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif pkt.haslayer(IPv6):
                ip_layer = pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                protocol = "ARP"
            else:
                # Non-IP packet (e.g. Ethernet broadcast, STP)
                src_ip = "Layer2-Broadcast"
                dst_ip = "Layer2-Broadcast"

            # Parse Layer 4
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                # Check for DNS over TCP or HTTP
                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                elif dst_port in [80, 8080] or src_port in [80, 8080]:
                    protocol = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    protocol = "HTTPS"
            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
                if pkt.haslayer(DNS) or dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                elif dst_port in [67, 68] or src_port in [67, 68]:
                    protocol = "DHCP"
                elif dst_port == 123 or src_port == 123:
                    protocol = "NTP"
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"

            records.append({
                "timestamp": pkt_time,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "bytes": pkt_len,
                "action": action
            })

        pcap_reader.close()

        if not records:
            return None, "No IP or network packets found in the uploaded PCAP file."

        df = pd.DataFrame(records)
        normalized_df = normalize_dataframe_columns(df)
        return normalized_df, None

    except Exception as e:
        return None, f"Scapy PCAP parsing error: {str(e)}"
