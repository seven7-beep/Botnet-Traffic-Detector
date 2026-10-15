"""
=============================================================================
PROJECT: Botnet Traffic Detector
AUTHOR: B.Tech Cyber Security Project Team
DESCRIPTION:
  A college-level educational cybersecurity web application built with Streamlit.
  Analyzes firewall and network traffic logs to detect botnet-infected hosts,
  C&C beaconing channels, horizontal port scans, and volumetric DDoS spikes.
=============================================================================
"""

import os
import sys
import datetime
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

# Add current directory to path for clean imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from modules.detection import (
    analyze_network_traffic,
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    classify_risk
)
from modules.packet_parser import parse_csv_file, parse_pcap_file
from modules.sample_data import generate_sample_botnet_traffic
from modules.database import (
    init_db,
    save_analysis_session,
    execute_safe_query,
    PRESET_QUERIES,
    DEFAULT_DB_PATH
)
from modules.analysis import (
    plot_traffic_timeline,
    plot_protocol_distribution,
    plot_top_source_ips,
    plot_traffic_volume_by_host,
    plot_host_deep_dive
)

# ---------------------------------------------------------------------------
# STREAMLIT PAGE CONFIGURATION
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Botnet Traffic Detector | Cyber Defense Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------------------------
# LOAD CUSTOM CSS
# ---------------------------------------------------------------------------
def load_css():
    css_path = os.path.join(BASE_DIR, "assets", "style.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()

# ---------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# ---------------------------------------------------------------------------
if "logs_df" not in st.session_state:
    # Preload default sample data so app works immediately out-of-the-box
    sample_df = generate_sample_botnet_traffic(num_records=1200, seed=42)
    st.session_state.logs_df = sample_df
    st.session_state.data_source = "Simulated Benchmark Data (Deterministic Seed 42)"
    st.session_state.is_sample = True

if "thresholds" not in st.session_state:
    st.session_state.thresholds = DEFAULT_THRESHOLDS.copy()

if "weights" not in st.session_state:
    st.session_state.weights = DEFAULT_WEIGHTS.copy()

# Initialize DB on first run
init_db(DEFAULT_DB_PATH)


# ---------------------------------------------------------------------------
# SIDEBAR NAVIGATION & DETECTION CONTROLS
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
        <div style="text-align: center; padding: 10px 0 20px 0;">
            <div style="font-size: 32px; margin-bottom: 4px;">🛡️⚡</div>
            <div style="font-size: 18px; font-weight: 800; color: #00E5FF; letter-spacing: -0.5px;">BOTNET DETECTOR</div>
            <div style="font-size: 11px; color: #94A3B8; font-weight: 500;">B.Tech Cyber Security Project</div>
        </div>
    """, unsafe_allow_html=True)

    # Navigation menu
    selected_page = st.radio(
        "Navigation",
        [
            "📊 Dashboard",
            "📥 Upload & Ingest Data",
            "🚨 Suspicious Hosts",
            "📈 Traffic Timeline",
            "🔍 Log Analysis",
            "💾 SQL Analysis & Studio",
            "📑 Reports & Export",
            "📚 Educational Hub / About"
        ],
        index=0
    )

    st.markdown("---")
    st.markdown("### ⚙️ Detection Thresholds")
    st.caption("Heuristic parameters evaluated by detection rules.")

    with st.expander("🔧 Configure Rule Thresholds", expanded=False):
        conn_thresh = st.slider(
            "Rule 1: Connection Count Threshold",
            min_value=10, max_value=200,
            value=st.session_state.thresholds.get("conn_count_threshold", 40),
            step=5,
            help="Flag hosts with connection counts exceeding this number."
        )
        port_thresh = st.slider(
            "Rule 2: Unique Target Ports (Scanning)",
            min_value=2, max_value=30,
            value=st.session_state.thresholds.get("dst_ports_threshold", 6),
            step=1,
            help="Flag hosts contacting multiple unique destination ports (recon/sweeps)."
        )
        byte_thresh = st.number_input(
            "Rule 3: High Traffic Volume (Bytes)",
            min_value=10000, max_value=2000000,
            value=st.session_state.thresholds.get("byte_volume_threshold", 150000),
            step=10000,
            help="Flag hosts transferring high cumulative byte volume (exfiltration / DDoS)."
        )
        rep_thresh = st.slider(
            "Rule 4: Repeated C&C Destination Count",
            min_value=5, max_value=100,
            value=st.session_state.thresholds.get("repeated_dest_threshold", 25),
            step=5,
            help="Flag hosts repeatedly querying the same external IP (C&C beaconing)."
        )
        spike_thresh = st.slider(
            "Rule 5: Burst Spike Multiplier (x Baseline)",
            min_value=1.5, max_value=10.0,
            value=float(st.session_state.thresholds.get("burst_spike_threshold", 3.0)),
            step=0.5,
            help="Flag hosts whose peak 1-minute traffic is Nx higher than average."
        )

        st.session_state.thresholds = {
            "conn_count_threshold": conn_thresh,
            "dst_ports_threshold": port_thresh,
            "byte_volume_threshold": byte_thresh,
            "repeated_dest_threshold": rep_thresh,
            "burst_spike_threshold": spike_thresh
        }

        if st.button("🔄 Reset Defaults", use_container_width=True):
            st.session_state.thresholds = DEFAULT_THRESHOLDS.copy()
            st.session_state.weights = DEFAULT_WEIGHTS.copy()
            st.rerun()

    st.markdown("---")
    st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 12px; font-size: 11.5px;">
            <div style="color: #94A3B8; margin-bottom: 4px;">ACTIVE DATASET</div>
            <div style="color: #00E5FF; font-weight: 600; word-break: break-all;">{st.session_state.data_source}</div>
            <div style="color: #94A3B8; margin-top: 6px;">Total Records: <span style="color: #FFF; font-weight: 600;">{len(st.session_state.logs_df):,}</span></div>
        </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# RUN DETECTION ENGINE ON CURRENT DATASET
# ---------------------------------------------------------------------------
hosts_df, enriched_logs_df, summary_stats = analyze_network_traffic(
    st.session_state.logs_df,
    st.session_state.thresholds,
    st.session_state.weights
)

# Automatically persist analysis session to SQLite
save_analysis_session(enriched_logs_df, hosts_df, summary_stats, DEFAULT_DB_PATH)


# ===========================================================================
# PAGE 1: DASHBOARD
# ===========================================================================
if selected_page == "📊 Dashboard":
    # Header Banner
    st.markdown(f"""
        <div class="cyber-header">
            <div class="cyber-title">🛡️ Botnet Traffic Anomaly Dashboard</div>
            <div class="cyber-subtitle">
                Real-time rule-based network traffic analysis and anomaly detection engine for educational threat hunting.
                <br><span style="color: #00E5FF;">Active Dataset:</span> {st.session_state.data_source}
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Top Row Metrics Cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Total Network Logs</div>
                <div class="metric-value">{summary_stats.get('total_logs', 0):,}</div>
                <div class="metric-sub">Analyzed firewall & packet events</div>
            </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Unique Source Hosts</div>
                <div class="metric-value">{summary_stats.get('total_src_ips', 0):,}</div>
                <div class="metric-sub">{summary_stats.get('total_dst_ips', 0):,} distinct destinations</div>
            </div>
        """, unsafe_allow_html=True)

    with col3:
        susp_count = summary_stats.get('suspicious_hosts_count', 0)
        card_border = "rgba(239, 68, 68, 0.4)" if susp_count > 0 else "#1E293B"
        st.markdown(f"""
            <div class="metric-card" style="border-color: {card_border};">
                <div class="metric-label">Suspicious Hosts Flagged</div>
                <div class="metric-value" style="color: {'#EF4444' if susp_count > 0 else '#10B981'};">{susp_count}</div>
                <div class="metric-sub">{summary_stats.get('suspicious_logs_count', 0):,} associated traffic logs</div>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        total_kb = summary_stats.get('total_traffic_volume', 0) / 1024.0
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Total Traffic Volume</div>
                <div class="metric-value">{total_kb:,.1f} KB</div>
                <div class="metric-sub">Avg {summary_stats.get('avg_traffic_volume', 0):,.1f} bytes / connection</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Threat Breakdown & Quick Status Banner
    risk_breakdown = summary_stats.get("risk_breakdown", {})
    crit_n = risk_breakdown.get("Critical", 0)
    high_n = risk_breakdown.get("High", 0)
    med_n = risk_breakdown.get("Medium", 0)
    low_n = risk_breakdown.get("Low", 0)

    st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1E293B; border-radius: 10px; padding: 14px 20px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 15px; margin-bottom: 20px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-weight: 700; color: #FFF; font-size: 14px;">THREAT PROFILE:</span>
                <span class="risk-badge risk-critical">Critical: {crit_n}</span>
                <span class="risk-badge risk-high">High: {high_n}</span>
                <span class="risk-badge risk-medium">Medium: {med_n}</span>
                <span class="risk-badge risk-low">Low: {low_n}</span>
            </div>
            <div style="font-size: 13px; color: #94A3B8;">
                Highest Risk Host: <strong style="color: #00E5FF;">{summary_stats.get('highest_risk_host', 'None')}</strong> 
                (Score: <span style="color: #EF4444; font-weight: 700;">{summary_stats.get('highest_risk_score', 0):.0f}/100</span>)
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Charts Section - Row 1
    chart_col1, chart_col2 = st.columns([1.5, 1.0])
    with chart_col1:
        st.markdown("##### 📈 Network Traffic Activity Timeline")
        timeline_fig = plot_traffic_timeline(enriched_logs_df, resample_freq="1min", highlight_spikes=True)
        st.pyplot(timeline_fig)
        plt.close(timeline_fig)

    with chart_col2:
        st.markdown("##### 🍩 Protocol Distribution")
        proto_fig = plot_protocol_distribution(enriched_logs_df)
        st.pyplot(proto_fig)
        plt.close(proto_fig)

    # Charts Section - Row 2
    chart_col3, chart_col4 = st.columns(2)
    with chart_col3:
        st.markdown("##### 🔝 Top Source IPs by Connection Count")
        talkers_fig = plot_top_source_ips(enriched_logs_df, top_n=8)
        st.pyplot(talkers_fig)
        plt.close(talkers_fig)

    with chart_col4:
        st.markdown("##### 📊 Data Volume (KB) by Host")
        volume_fig = plot_traffic_volume_by_host(hosts_df, top_n=8)
        st.pyplot(volume_fig)
        plt.close(volume_fig)


# ===========================================================================
# PAGE 2: UPLOAD & INGEST DATA
# ===========================================================================
elif selected_page == "📥 Upload & Ingest Data":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">📥 Data Ingestion & Packet Capture Engine</div>
            <div class="cyber-subtitle">
                Import firewall log CSVs, upload Scapy-parsed PCAP captures, or generate realistic synthetic botnet traffic for testing.
            </div>
        </div>
    """, unsafe_allow_html=True)

    tab_csv, tab_pcap, tab_sample = st.tabs(["📄 Upload Firewall Log CSV", "📦 Upload PCAP Capture", "🧪 Generate Simulated Botnet Traffic"])

    # 1. CSV Upload Tab
    with tab_csv:
        st.markdown("#### Upload Firewall / Network Log CSV")
        st.caption("Accepts standard network logs with columns: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes`, `action`.")
        
        uploaded_csv = st.file_uploader("Choose a CSV file", type=["csv"], key="csv_uploader")
        if uploaded_csv is not None:
            parsed_df, err = parse_csv_file(uploaded_csv)
            if err:
                st.error(f"❌ Error parsing CSV: {err}")
            else:
                st.success(f"✅ Successfully parsed {len(parsed_df):,} records from '{uploaded_csv.name}'!")
                st.dataframe(parsed_df.head(10), use_container_width=True)
                
                if st.button("🚀 Load & Analyze This CSV Dataset", type="primary"):
                    st.session_state.logs_df = parsed_df
                    st.session_state.data_source = f"Uploaded CSV: {uploaded_csv.name}"
                    st.session_state.is_sample = False
                    st.toast("Dataset loaded into active memory!", icon="✅")
                    st.rerun()

    # 2. PCAP Upload Tab
    with tab_pcap:
        st.markdown("#### Upload Packet Capture (.pcap / .pcapng)")
        st.caption("Parses Ethernet/IP packet frames using Scapy defensively. Extracts IP addresses, ports, transport protocols, and byte sizes.")
        
        max_pcap_pkts = st.slider("Max Packets to Read (prevents browser lag)", 500, 10000, 3000, 500)
        uploaded_pcap = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng", "cap"], key="pcap_uploader")
        
        if uploaded_pcap is not None:
            with st.spinner("Decoding packets with Scapy..."):
                parsed_pcap_df, pcap_err = parse_pcap_file(uploaded_pcap, max_packets=max_pcap_pkts)
                
            if pcap_err:
                st.error(f"❌ Error parsing PCAP: {pcap_err}")
            else:
                st.success(f"✅ Scapy successfully extracted {len(parsed_pcap_df):,} IP packets from '{uploaded_pcap.name}'!")
                st.dataframe(parsed_pcap_df.head(10), use_container_width=True)
                
                if st.button("🚀 Load & Analyze This PCAP Dataset", type="primary"):
                    st.session_state.logs_df = parsed_pcap_df
                    st.session_state.data_source = f"Uploaded PCAP: {uploaded_pcap.name}"
                    st.session_state.is_sample = False
                    st.toast("PCAP dataset loaded into active memory!", icon="✅")
                    st.rerun()

    # 3. Synthetic Generator Tab
    with tab_sample:
        st.markdown("#### 🧪 Deterministic Synthetic Botnet Traffic Generator")
        st.info("Generates reproducible firewall logs containing normal hosts + 4 distinct botnet threat vectors (Mirai Port Scanner, C&C Beaconing, DDoS Flooder, and Data Exfiltration).")

        gen_col1, gen_col2, gen_col3 = st.columns(3)
        with gen_col1:
            gen_count = st.slider("Number of Log Records", 500, 5000, 1500, 100)
        with gen_col2:
            gen_seed = st.number_input("Random Seed (for reproducible viva demo)", min_value=1, max_value=99999, value=42)
        with gen_col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("✨ Generate Sample Botnet Traffic", type="primary", use_container_width=True):
                with st.spinner("Generating synthetic network traffic logs..."):
                    new_sample_df = generate_sample_botnet_traffic(num_records=gen_count, seed=gen_seed)
                    st.session_state.logs_df = new_sample_df
                    st.session_state.data_source = f"Simulated Benchmark Data (Seed: {gen_seed}, {len(new_sample_df)} logs)"
                    st.session_state.is_sample = True
                    st.toast(f"Generated {len(new_sample_df)} simulated logs!", icon="🎉")
                    st.rerun()

        st.markdown("##### Threat Profiles Included in Generated Sample:")
        st.markdown("""
        - 🤖 **Host `192.168.1.105` (Mirai Scanner)**: Sweeps 15 distinct ports (`21, 22, 23, 80, 443, 3389, 5555, 8080...`) across external subnets.
        - 📡 **Host `192.168.1.120` (C&C Beaconing Bot)**: Sends regular periodic heartbeats to external C&C Server `198.51.100.45:8443`.
        - 🌊 **Host `192.168.1.199` (DDoS Flooder)**: High-rate burst UDP/TCP flood against target `203.0.113.88` triggering sudden traffic spikes.
        - 💾 **Host `192.168.1.150` (Data Exfiltration)**: High outbound byte transfers to untrusted external server `198.51.100.99`.
        - 🏢 **Hosts `192.168.1.10 - 192.168.1.30` (Normal Users)**: Regular HTTPS, DNS, NTP benign browsing.
        """)


# ===========================================================================
# PAGE 3: SUSPICIOUS HOSTS
# ===========================================================================
elif selected_page == "🚨 Suspicious Hosts":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">🚨 Suspicious Hosts & Threat Assessment</div>
            <div class="cyber-subtitle">
                Ranks all source hosts by normalized risk score (0-100). Filter, inspect diagnostic rule triggers, and examine individual host behavioral profiles.
            </div>
        </div>
    """, unsafe_allow_html=True)

    if hosts_df.empty:
        st.warning("No host data available to evaluate.")
    else:
        # Filter and Search Controls
        filter_col1, filter_col2, filter_col3 = st.columns([1.5, 1.5, 2.0])
        with filter_col1:
            risk_filter = st.multiselect(
                "Filter by Threat Level",
                ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"]
            )
        with filter_col2:
            min_score = st.slider("Minimum Risk Score", 0, 100, 0)
        with filter_col3:
            search_ip = st.text_input("🔍 Search Host IP", placeholder="e.g. 192.168.1.105")

        # Apply filtering
        filtered_hosts = hosts_df[hosts_df["risk_level"].isin(risk_filter)]
        filtered_hosts = filtered_hosts[filtered_hosts["risk_score"] >= min_score]
        if search_ip:
            filtered_hosts = filtered_hosts[filtered_hosts["src_ip"].str.contains(search_ip, case=False, na=False)]

        st.markdown(f"**Showing {len(filtered_hosts)} of {len(hosts_df)} evaluated hosts**")

        # Display Clean Host Table
        display_df = filtered_hosts[[
            "src_ip", "risk_score", "risk_level", "total_connections",
            "unique_dst_ips", "unique_dst_ports", "total_bytes", "primary_reason"
        ]].copy()
        
        display_df.columns = [
            "Source IP", "Risk Score (0-100)", "Threat Level", "Connections",
            "Unique Target IPs", "Unique Target Ports", "Total Bytes", "Primary Detection Reason"
        ]
        
        st.dataframe(
            display_df.style.format({
                "Risk Score (0-100)": "{:.1f}",
                "Connections": "{:,}",
                "Unique Target IPs": "{:,}",
                "Unique Target Ports": "{:,}",
                "Total Bytes": "{:,}"
            }),
            use_container_width=True,
            height=300
        )

        st.markdown("---")
        st.markdown("### 🔬 Host Deep-Dive Inspector")
        st.caption("Select an individual host IP below to view triggered diagnostic rules, evidence, target distribution, and recommended mitigation actions.")

        host_list = hosts_df["src_ip"].tolist()
        selected_host_ip = st.selectbox("Select Host to Inspect", options=host_list, index=0)

        if selected_host_ip:
            host_row = hosts_df[hosts_df["src_ip"] == selected_host_ip].iloc[0]
            
            # Host Summary Header Box
            level_name, color_hex, badge_css = classify_risk(host_row["risk_score"])
            
            st.markdown(f"""
                <div style="background: #111827; border: 1px solid {color_hex}; border-radius: 10px; padding: 18px 24px; margin-bottom: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                        <div>
                            <div style="font-size: 20px; font-weight: 800; color: #FFF;">HOST PROFILE: <span style="color: #00E5FF;">{host_row['src_ip']}</span></div>
                            <div style="color: #94A3B8; font-size: 13px; margin-top: 4px;">Primary Target: <code style="color: #38BDF8;">{host_row.get('top_dest_ip', 'N/A')}</code> ({host_row.get('max_connections_to_single_dst', 0)} sessions)</div>
                        </div>
                        <div style="text-align: right;">
                            <span class="risk-badge {badge_css}" style="font-size: 14px; padding: 6px 16px;">{level_name} Threat</span>
                            <div style="color: {color_hex}; font-size: 22px; font-weight: 800; margin-top: 4px;">Score: {host_row['risk_score']:.0f}/100</div>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            # Triggered Rule Diagnostics Breakdown
            st.markdown("##### 🛡️ Triggered Detection Rules & Evidence")
            rule_details = host_row.get("rule_details", [])

            if rule_details:
                for idx, r in enumerate(rule_details, 1):
                    st.markdown(f"""
                        <div class="edu-card">
                            <div class="edu-title">📌 {r.get('rule')} (+{r.get('points')} pts) — Severity: <span style="color: #EF4444;">{r.get('severity')}</span></div>
                            <div class="edu-text">{r.get('evidence')}</div>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("✅ No suspicious anomaly rules were triggered for this host. Baseline traffic appears benign.")

            # Diagnostic Charts for this Host
            st.markdown("##### 📊 Target Destination & Port Distribution")
            dive_fig = plot_host_deep_dive(enriched_logs_df, selected_host_ip)
            st.pyplot(dive_fig)
            plt.close(dive_fig)

            # Recommended Incident Response Actions
            st.markdown("##### 🛠️ Recommended Defense & Incident Response Actions")
            if host_row["risk_score"] >= 60:
                st.error("""
                **Critical / High Severity Remediation Checklist:**
                1. 🔒 **Host Isolation**: Immediately isolate host `{}` from the local subnet (quarantine VLAN or 802.1X disconnect).
                2. 🚫 **Firewall Rule**: Block outbound traffic from `{}` to external IP `{}` on perimeter firewalls.
                3. 🔍 **Endpoint Investigation**: Perform memory dump and scan for unauthorized processes, rootkits, or persistence keys (e.g. cron jobs, registry run keys).
                4. 📡 **C&C Sinkholing**: If beaconing to `{}` is confirmed, add domain/IP to DNS sinkhole blocklist.
                """.format(host_row['src_ip'], host_row['src_ip'], host_row.get('top_dest_ip', 'N/A'), host_row.get('top_dest_ip', 'N/A')))
            elif host_row["risk_score"] >= 30:
                st.warning("""
                **Medium Severity Monitoring Checklist:**
                1. 👁️ **Increased Logging**: Enable verbose packet capture on switch port connected to `{}`.
                2. 🛡️ **Scan Host**: Run antivirus and vulnerability audit on host `{}`.
                3. ⏱️ **Monitor Thresholds**: Verify if connection count decreases during off-peak hours.
                """.format(host_row['src_ip'], host_row['src_ip']))
            else:
                st.info("Host is operating within normal baseline limits. No defensive action required.")


# ===========================================================================
# PAGE 4: TRAFFIC TIMELINE
# ===========================================================================
elif selected_page == "📈 Traffic Timeline":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">📈 Network Traffic Timeline & Spike Analysis</div>
            <div class="cyber-subtitle">
                Visualizes packet and connection rates over time. Identifies sudden traffic surges characteristic of coordinated botnet attacks.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Filter Controls
    t_col1, t_col2, t_col3, t_col4 = st.columns(4)
    with t_col1:
        all_hosts = ["All Hosts"] + sorted(enriched_logs_df["src_ip"].unique().tolist())
        sel_src = st.selectbox("Filter Source IP", options=all_hosts, index=0)
    with t_col2:
        resample_option = st.selectbox("Time Interval Resolution", ["10s", "30s", "1min", "5min"], index=2)
    with t_col3:
        all_protocols = ["All"] + sorted(enriched_logs_df["protocol"].unique().tolist())
        sel_proto = st.selectbox("Protocol Filter", options=all_protocols, index=0)
    with t_col4:
        show_spikes = st.checkbox("Highlight Traffic Spikes", value=True)

    # Filter data
    timeline_df = enriched_logs_df.copy()
    if sel_proto != "All":
        timeline_df = timeline_df[timeline_df["protocol"] == sel_proto]

    st.markdown("<br>", unsafe_allow_html=True)
    t_fig = plot_traffic_timeline(timeline_df, resample_freq=resample_option, highlight_spikes=show_spikes, src_ip_filter=sel_src)
    st.pyplot(t_fig)
    plt.close(t_fig)

    # Temporal Anomaly Educational Box
    st.markdown("""
        <div class="edu-card">
            <div class="edu-title">💡 Why Do Traffic Spikes Indicate Botnet Activity?</div>
            <div class="edu-text">
                Botnets typically operate in a dormant state until a command is broadcasted by the botmaster via C&C channels.
                When an attack command (e.g. <code>!udp 203.0.113.88 80 600</code>) is received, hundreds or thousands of zombie nodes simultaneously begin transmitting high-frequency packet floods. This creates abrupt, anomalous spikes in firewall log volume.
            </div>
        </div>
    """, unsafe_allow_html=True)


# ===========================================================================
# PAGE 5: LOG ANALYSIS
# ===========================================================================
elif selected_page == "🔍 Log Analysis":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">🔍 Comprehensive Log Analysis & Inspection</div>
            <div class="cyber-subtitle">
                Search, filter, and inspect individual firewall log records enriched with threat scores and detection reasons.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Filters Row
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        log_src = st.text_input("Filter Source IP", placeholder="e.g. 192.168.1.105")
    with f_col2:
        log_dst = st.text_input("Filter Dest IP", placeholder="e.g. 198.51.100.45")
    with f_col3:
        all_actions = ["All"] + sorted(enriched_logs_df["action"].unique().tolist()) if "action" in enriched_logs_df else ["All"]
        log_action = st.selectbox("Firewall Action", options=all_actions, index=0)
    with f_col4:
        all_levels = ["All", "Critical", "High", "Medium", "Low"]
        log_threat = st.selectbox("Threat Classification", options=all_levels, index=0)

    # Apply Filters
    logs_view = enriched_logs_df.copy()
    if log_src:
        logs_view = logs_view[logs_view["src_ip"].str.contains(log_src, case=False, na=False)]
    if log_dst:
        logs_view = logs_view[logs_view["dst_ip"].str.contains(log_dst, case=False, na=False)]
    if log_action != "All":
        logs_view = logs_view[logs_view["action"] == log_action]
    if log_threat != "All":
        logs_view = logs_view[logs_view["risk_level"] == log_threat]

    st.markdown(f"**Showing {min(len(logs_view), 2000):,} of {len(logs_view):,} matching logs**")

    # Clean display dataframe
    show_cols = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes", "action", "risk_score", "risk_level", "primary_reason"]
    avail_cols = [c for c in show_cols if c in logs_view.columns]
    
    st.dataframe(
        logs_view[avail_cols].head(2000),
        use_container_width=True,
        height=450
    )


# ===========================================================================
# PAGE 6: SQL ANALYSIS & STUDIO
# ===========================================================================
elif selected_page == "💾 SQL Analysis & Studio":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">💾 SQLite Database Studio & Query Engine</div>
            <div class="cyber-subtitle">
                Query analyzed network logs and suspicious host records stored in SQLite (<code>botnet_detector.db</code>). Includes safe read-only query execution and pre-built viva queries.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Database Schema Info
    with st.expander("📋 SQLite Schema Reference (`botnet_detector.db`)", expanded=False):
        st.code("""
-- Table 1: network_logs
CREATE TABLE network_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    bytes INTEGER,
    action TEXT,
    risk_score REAL,
    risk_level TEXT,
    primary_reason TEXT,
    session_id TEXT
);

-- Table 2: suspicious_hosts
CREATE TABLE suspicious_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    risk_score REAL,
    risk_level TEXT,
    total_connections INTEGER,
    unique_dst_ips INTEGER,
    unique_dst_ports INTEGER,
    total_bytes INTEGER,
    top_dest_ip TEXT,
    primary_reason TEXT,
    detected_at TEXT
);
        """, language="sql")

    st.markdown("#### 🎯 Pre-Built Cybersecurity SQL Queries")
    st.caption("Select a query below to quickly demonstrate database queries during your viva presentation:")

    preset_name = st.selectbox("Choose Preset Query", options=list(PRESET_QUERIES.keys()))
    preset_sql = PRESET_QUERIES[preset_name]

    # SQL Editor area
    custom_sql = st.text_area("SQL Query Editor (Read-Only SELECT)", value=preset_sql.strip(), height=150)

    if st.button("▶️ Execute Query", type="primary"):
        df_sql, sql_err, exec_time = execute_safe_query(custom_sql, DEFAULT_DB_PATH)
        if sql_err:
            st.error(f"❌ {sql_err}")
        else:
            st.success(f"✅ Query executed successfully in {exec_time:.2f} ms ({len(df_sql)} rows returned)")
            st.dataframe(df_sql, use_container_width=True)


# ===========================================================================
# PAGE 7: REPORTS & EXPORT
# ===========================================================================
elif selected_page == "📑 Reports & Export":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">📑 Threat Assessment Reports & Data Export</div>
            <div class="cyber-subtitle">
                Generate executive incident reports and export analyzed telemetry and risk scores in CSV format.
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Executive Summary Card
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown("#### 📄 Executive Threat Assessment Summary")
    
    st.markdown(f"""
        <div style="background: #111827; border: 1px solid #1E293B; border-radius: 10px; padding: 24px; margin-bottom: 24px;">
            <div style="font-size: 18px; font-weight: 800; color: #00E5FF; margin-bottom: 12px; border-bottom: 1px solid #1E293B; padding-bottom: 8px;">
                SECURITY INCIDENT SUMMARY REPORT
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; font-size: 13.5px;">
                <div><span style="color: #94A3B8;">Analysis Timestamp:</span><br><strong>{now_str}</strong></div>
                <div><span style="color: #94A3B8;">Dataset Source:</span><br><strong>{st.session_state.data_source}</strong></div>
                <div><span style="color: #94A3B8;">Total Records Analyzed:</span><br><strong>{summary_stats.get('total_logs', 0):,} logs</strong></div>
                <div><span style="color: #94A3B8;">Hosts Evaluated:</span><br><strong>{summary_stats.get('total_src_ips', 0):,} hosts</strong></div>
                <div><span style="color: #94A3B8;">Suspicious Hosts Flagged:</span><br><strong style="color: #EF4444;">{summary_stats.get('suspicious_hosts_count', 0)} ({((summary_stats.get('suspicious_hosts_count', 0)/max(summary_stats.get('total_src_ips', 1), 1))*100):.1f}%)</strong></div>
                <div><span style="color: #94A3B8;">Highest-Risk Host:</span><br><strong style="color: #F97316;">{summary_stats.get('highest_risk_host', 'None')} ({summary_stats.get('highest_risk_score', 0):.0f}/100)</strong></div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # CSV Export Section
    st.markdown("#### 💾 Export Telemetry & Analysis Data")
    st.caption("Download structured CSV reports for documentation and offline review.")

    col_exp1, col_exp2, col_exp3 = st.columns(3)

    with col_exp1:
        if not hosts_df.empty:
            csv_hosts = hosts_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Suspicious Hosts (CSV)",
                data=csv_hosts,
                file_name=f"suspicious_hosts_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

    with col_exp2:
        if not enriched_logs_df.empty:
            csv_logs = enriched_logs_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Enriched Logs (CSV)",
                data=csv_logs,
                file_name=f"enriched_network_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

    with col_exp3:
        if not hosts_df.empty:
            # Generate markdown/text report
            report_text = f"""=============================================================================
BOTNET TRAFFIC DETECTOR - EXECUTIVE INCIDENT REPORT
=============================================================================
Generated At: {now_str}
Active Data: {st.session_state.data_source}
Total Analyzed Logs: {summary_stats.get('total_logs', 0)}
Total Source Hosts: {summary_stats.get('total_src_ips', 0)}
Suspicious Hosts Count: {summary_stats.get('suspicious_hosts_count', 0)}

CRITICAL / HIGH THREAT HOSTS:
{hosts_df[hosts_df['risk_score'] >= 60][['src_ip', 'risk_score', 'risk_level', 'primary_reason']].to_string(index=False) if not hosts_df.empty else 'None'}

=============================================================================
"""
            st.download_button(
                label="📥 Download Summary Text Report",
                data=report_text.encode('utf-8'),
                file_name=f"executive_threat_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True
            )


# ===========================================================================
# PAGE 8: EDUCATIONAL HUB / ABOUT
# ===========================================================================
elif selected_page == "📚 Educational Hub / About":
    st.markdown("""
        <div class="cyber-header">
            <div class="cyber-title">📚 Educational Hub & Viva Reference Guide</div>
            <div class="cyber-subtitle">
                Foundational cybersecurity concepts, architecture explanations, and viva interview questions for B.Tech Cyber Security students.
            </div>
        </div>
    """, unsafe_allow_html=True)

    edu_tab1, edu_tab2, edu_tab3, edu_tab4 = st.tabs([
        "🧠 Core Cybersecurity Concepts",
        "⚙️ Detection Rules Methodology",
        "🎯 Viva FAQ & Answers",
        "⚠️ Project Scope & Limitations"
    ])

    with edu_tab1:
        st.markdown("""
        <div class="edu-card">
            <div class="edu-title">🤖 1. What is a Botnet?</div>
            <div class="edu-text">
                A <strong>botnet</strong> (robot network) is a collection of internet-connected compromised devices (computers, IoT cameras, routers, servers) that are infected with malware and controlled remotely by a threat actor called the <strong>botmaster</strong> or bot herder.
            </div>
        </div>

        <div class="edu-card">
            <div class="edu-title">📡 2. What is a Command and Control (C&C / C2) Server?</div>
            <div class="edu-text">
                The <strong>Command and Control (C&C)</strong> server is the centralized or peer-to-peer infrastructure used by the botmaster to transmit instructions (such as launching a DDoS attack, mining cryptocurrency, or scanning subnets) to infected bot nodes, and to receive stolen data.
            </div>
        </div>

        <div class="edu-card">
            <div class="edu-title">🛡️ 3. What is a Firewall Log?</div>
            <div class="edu-text">
                A <strong>firewall log</strong> is a chronological audit record generated by a network security device documenting session initiation, source/destination IP addresses, port numbers, transport protocol, packet/byte counts, and firewall dispositions (<code>ALLOW</code>, <code>DROP</code>, <code>BLOCK</code>).
            </div>
        </div>

        <div class="edu-card">
            <div class="edu-title">📊 4. Rule-Based vs Anomaly-Based vs Machine Learning Detection</div>
            <div class="edu-text">
                <ul>
                    <li><strong>Rule-Based Detection (Heuristics):</strong> Flags traffic matching predefined deterministic rules (e.g. &gt;40 connections or &gt;6 ports). Fast, transparent, and easy to explain.</li>
                    <li><strong>Anomaly-Based Detection:</strong> Establishes a normal behavioral baseline and alerts on deviations (e.g., sudden 3x traffic spikes).</li>
                    <li><strong>Machine Learning:</strong> Uses trained models (Random Forest, SVM, Isolation Forest) to recognize complex multi-dimensional patterns.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with edu_tab2:
        st.markdown("#### 🔍 The 5 Heuristic Detection Rules in this Application")
        st.markdown("""
        | Rule # | Anomaly Pattern | Weight | Cybersecurity Rationale |
        | :--- | :--- | :--- | :--- |
        | **Rule 1** | **High Connection Count** | **+30 pts** | Infected bots initiate excessive session counts during DDoS floods or brute force attacks. |
        | **Rule 2** | **High Destination Port Diversity** | **+25 pts** | Horizontal port sweeps across Telnet (23), SSH (22), HTTP (8080) indicate worm propagation (e.g. Mirai). |
        | **Rule 3** | **High Cumulative Volume (Bytes)** | **+25 pts** | Abnormal byte transfer volume indicates volumetric amplification or unauthorized data exfiltration. |
        | **Rule 4** | **Repeated Single Target (Beaconing)** | **+20 pts** | High proportion of connections to a single external IP indicates periodic C&C heartbeat polling. |
        | **Rule 5** | **Burst Traffic Surge (Spike Ratio)** | **+20 pts** | Sharp surge in a 1-minute window indicates simultaneous attack trigger activation. |
        """)

    with edu_tab3:
        st.markdown("#### 🎤 Common Viva Questions & Model Answers")
        with st.expander("Q1: How does your tool differentiate benign web browsing from a botnet port scanner?", expanded=True):
            st.markdown("""
            **Answer:**
            Normal web browsing contacts standard web ports (80 HTTP, 443 HTTPS, 53 DNS) on a small set of well-known CDNs/servers. A botnet scanner (Rule 2) attempts connections to a broad variety of unusual destination ports (21, 23, 445, 3389, 5555, 8080) across random external IPs in rapid succession, resulting in high port diversity and dropped connection packets.
            """)

        with st.expander("Q2: What is C&C beaconing and how does Rule 4 detect it?"):
            st.markdown("""
            **Answer:**
            Beaconing is regular, periodic network communication between an infected host and the botmaster's C&C server to report heartbeat status and query for pending tasks. Rule 4 monitors target concentration: if a host repeatedly directs connections to a single external destination above the configurable threshold, it accumulates risk points.
            """)

        with st.expander("Q3: Why normalize the risk score to a 0–100 scale?"):
            st.markdown("""
            **Answer:**
            Normalization provides a standard, intuitive risk metric across heterogeneous network sizes. Scores are mapped to industry-standard severity tiers: Low (0-29), Medium (30-59), High (60-79), and Critical (80-100), enabling security analysts to prioritize triage workflows.
            """)

        with st.expander("Q4: Why did your team use SQLite instead of a heavy database server?"):
            st.markdown("""
            **Answer:**
            SQLite is a serverless, self-contained, transactional SQL database engine ideal for embedded analytical tools, local lab testing, and self-contained academic demonstrations without external service dependencies.
            """)

    with edu_tab4:
        st.markdown("""
        <div class="edu-card">
            <div class="edu-title">⚠️ Project Scope & Academic Disclaimer</div>
            <div class="edu-text">
                This software is designed strictly for <strong>educational and laboratory demonstration purposes</strong> as part of a B.Tech Cyber Security project.
                <br><br>
                <strong>Key Limitations:</strong>
                <ul>
                    <li><strong>Heuristic Evasion:</strong> Sophisticated botnets use low-and-slow beaconing with randomized jitter to evade threshold-based heuristics.</li>
                    <li><strong>Encrypted Payload Inspection:</strong> Analyzes transport Layer 3/4 headers and metadata; does not perform Deep Packet Inspection (DPI) on encrypted TLS payloads.</li>
                    <li><strong>Defensive Only:</strong> Contains no offensive or malware code; only parses and analyzes uploaded or synthetic telemetry.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
