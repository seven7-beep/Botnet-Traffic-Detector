"""
=============================================================================
MODULE: analysis.py
PURPOSE: Cybersecurity Analytics & Matplotlib Chart Generation
DESCRIPTION:
  Produces sleek, dark-themed cyber analytics charts for:
  - Network Traffic Timeline & Spike Detection
  - Protocol Breakdown (TCP, UDP, ICMP, DNS, HTTP, HTTPS)
  - Top Source Talkers & Connection Frequency
  - Suspicious Host Threat Scoring Breakdown
  - Individual Host Deep-Dive Profiling (Port Sweeps, Destination Hammering)
=============================================================================
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from typing import Optional, Dict, Any

# Cybersecurity Dark Theme Color Palette
CYBER_BG = "#0B0F19"         # Deep slate/black
CYBER_PANEL = "#111827"      # Dark navy panel
CYBER_GRID = "#1F2937"       # Subtle grid lines
CYBER_TEXT = "#E2E8F0"       # Crisp light slate
CYBER_MUTED = "#94A3B8"      # Muted slate
CYBER_CYAN = "#00E5FF"       # Primary accent
CYBER_PURPLE = "#8B5CF6"     # Secondary accent
CYBER_GREEN = "#10B981"      # Low risk / Benign
CYBER_YELLOW = "#FBBF24"     # Medium risk
CYBER_ORANGE = "#F97316"     # High risk
CYBER_RED = "#EF4444"        # Critical risk


def apply_cyber_theme(fig, ax):
    """Applies a high-contrast dark cybersecurity aesthetic to Matplotlib axes."""
    fig.patch.set_facecolor(CYBER_PANEL)
    ax.set_facecolor(CYBER_BG)
    ax.tick_params(colors=CYBER_TEXT, labelsize=9)
    ax.xaxis.label.set_color(CYBER_TEXT)
    ax.yaxis.label.set_color(CYBER_TEXT)
    ax.title.set_color(CYBER_TEXT)
    
    # Spine styling
    for spine in ax.spines.values():
        spine.set_edgecolor(CYBER_GRID)
        spine.set_linewidth(1.0)
        
    ax.grid(True, linestyle="--", alpha=0.35, color=CYBER_GRID)


def plot_traffic_timeline(
    df: pd.DataFrame,
    resample_freq: str = "1min",
    highlight_spikes: bool = True,
    src_ip_filter: Optional[str] = None
) -> plt.Figure:
    """
    Renders network traffic activity over time with optional spike highlighting.
    """
    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=100)
    apply_cyber_theme(fig, ax)

    if df is None or df.empty:
        ax.text(0.5, 0.5, "No traffic log data available", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    df_work = df.copy()
    if src_ip_filter and src_ip_filter != "All Hosts":
        df_work = df_work[df_work["src_ip"] == src_ip_filter]

    if df_work.empty:
        ax.text(0.5, 0.5, f"No logs found for host: {src_ip_filter}", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    if "dt" not in df_work.columns:
        df_work["dt"] = pd.to_datetime(df_work["timestamp"], errors="coerce")

    df_valid = df_work.dropna(subset=["dt"]).sort_values("dt")
    if df_valid.empty:
        ax.text(0.5, 0.5, "Invalid timestamp formatting", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    # Resample time series
    try:
        ts = df_valid.set_index("dt").resample(resample_freq).size()
    except Exception:
        ts = df_valid.set_index("dt").resample("1min").size()

    if len(ts) == 0:
        ax.text(0.5, 0.5, "Insufficient time intervals", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    # Plot line & gradient fill
    x_vals = ts.index
    y_vals = ts.values
    
    line_color = CYBER_CYAN if (not src_ip_filter or src_ip_filter == "All Hosts") else CYBER_PURPLE
    ax.plot(x_vals, y_vals, color=line_color, linewidth=2.2, label="Packet / Session Count", zorder=3)
    ax.fill_between(x_vals, 0, y_vals, color=line_color, alpha=0.2, zorder=2)

    # Highlight traffic spikes
    if highlight_spikes and len(y_vals) > 3:
        mean_val = float(np.mean(y_vals))
        std_val = float(np.std(y_vals))
        spike_threshold = mean_val + 2.0 * std_val
        
        spike_mask = y_vals >= max(spike_threshold, 15)
        if np.any(spike_mask):
            spike_x = x_vals[spike_mask]
            spike_y = y_vals[spike_mask]
            ax.scatter(spike_x, spike_y, color=CYBER_RED, s=60, edgecolors="#FFFFFF", linewidth=1.2, zorder=5, label="Detected Traffic Spike")
            ax.axhline(spike_threshold, color=CYBER_ORANGE, linestyle=":", alpha=0.7, label=f"Anomaly Baseline ({spike_threshold:.1f})")

    ax.set_title(f"Network Traffic Rate Over Time ({resample_freq} intervals)" if not src_ip_filter or src_ip_filter == "All Hosts" else f"Traffic Timeline for {src_ip_filter}", fontsize=11, fontweight="bold", pad=12)
    ax.set_xlabel("Time (HH:MM:SS)", fontsize=9, labelpad=8)
    ax.set_ylabel("Logs / Packets Count", fontsize=9, labelpad=8)
    
    # Format x-axis dates
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    fig.autofmt_xdate(rotation=30)
    
    ax.legend(facecolor=CYBER_PANEL, edgecolor=CYBER_GRID, labelcolor=CYBER_TEXT, fontsize=8, loc="upper right")
    fig.tight_layout()
    return fig


def plot_protocol_distribution(df: pd.DataFrame) -> plt.Figure:
    """
    Renders high-contrast donut chart of network protocols.
    """
    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=100)
    fig.patch.set_facecolor(CYBER_PANEL)
    ax.set_facecolor(CYBER_BG)

    if df is None or df.empty or "protocol" not in df.columns:
        ax.text(0.5, 0.5, "No protocol data", color=CYBER_MUTED, ha="center", va="center")
        return fig

    proto_counts = df["protocol"].value_counts()
    if len(proto_counts) == 0:
        ax.text(0.5, 0.5, "No protocol data", color=CYBER_MUTED, ha="center", va="center")
        return fig

    # Colors palette
    colors = [CYBER_CYAN, CYBER_PURPLE, CYBER_GREEN, CYBER_YELLOW, CYBER_ORANGE, CYBER_RED, "#38BDF8"]
    
    wedges, texts, autotexts = ax.pie(
        proto_counts.values,
        labels=proto_counts.index,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors[:len(proto_counts)],
        wedgeprops=dict(width=0.45, edgecolor=CYBER_PANEL, linewidth=2),
        pctdistance=0.75
    )

    for text in texts:
        text.set_color(CYBER_TEXT)
        text.set_fontsize(9)
        text.set_fontweight("bold")
    for autotext in autotexts:
        autotext.set_color("#0B0F19")
        autotext.set_fontsize(8)
        autotext.set_fontweight("bold")

    ax.set_title("Protocol Share Breakdown", color=CYBER_TEXT, fontsize=11, fontweight="bold", pad=12)
    fig.tight_layout()
    return fig


def plot_top_source_ips(df: pd.DataFrame, top_n: int = 8) -> plt.Figure:
    """
    Renders horizontal bar chart of top talking source IPs with risk-aware colors.
    """
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=100)
    apply_cyber_theme(fig, ax)

    if df is None or df.empty or "src_ip" not in df.columns:
        ax.text(0.5, 0.5, "No source IP data", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    top_talkers = df["src_ip"].value_counts().head(top_n).sort_values(ascending=True)
    if top_talkers.empty:
        ax.text(0.5, 0.5, "No talker data", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    y_pos = range(len(top_talkers))
    bars = ax.barh(y_pos, top_talkers.values, color=CYBER_CYAN, edgecolor=CYBER_PANEL, height=0.65, alpha=0.9)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(top_talkers.index, fontsize=9)
    ax.set_xlabel("Total Connection Count", fontsize=9, labelpad=8)
    ax.set_title(f"Top {len(top_talkers)} Source IPs by Connections", fontsize=11, fontweight="bold", pad=12)

    # Add numeric labels to bars
    for bar in bars:
        width = bar.get_width()
        ax.text(width + (max(top_talkers.values) * 0.015), bar.get_y() + bar.get_height()/2, f"{int(width):,}",
                ha="left", va="center", color=CYBER_TEXT, fontsize=8, fontweight="bold")

    fig.tight_layout()
    return fig


def plot_traffic_volume_by_host(hosts_df: pd.DataFrame, top_n: int = 8) -> plt.Figure:
    """
    Renders horizontal bar chart of total bytes transferred per host.
    """
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=100)
    apply_cyber_theme(fig, ax)

    if hosts_df is None or hosts_df.empty or "total_bytes" not in hosts_df.columns:
        ax.text(0.5, 0.5, "No volume data", color=CYBER_MUTED, ha="center", va="center", transform=ax.transAxes)
        return fig

    sorted_df = hosts_df.sort_values(by="total_bytes", ascending=False).head(top_n).sort_values(by="total_bytes", ascending=True)
    
    y_pos = range(len(sorted_df))
    # Convert bytes to KB for clean scale
    kb_values = sorted_df["total_bytes"] / 1024.0
    
    # Dynamic bar color based on risk level
    color_map = {
        "Critical": CYBER_RED,
        "High": CYBER_ORANGE,
        "Medium": CYBER_YELLOW,
        "Low": CYBER_GREEN
    }
    bar_colors = [color_map.get(lvl, CYBER_CYAN) for lvl in sorted_df.get("risk_level", ["Low"]*len(sorted_df))]

    bars = ax.barh(y_pos, kb_values, color=bar_colors, edgecolor=CYBER_PANEL, height=0.65, alpha=0.9)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(sorted_df["src_ip"], fontsize=9)
    ax.set_xlabel("Data Volume (Kilobytes)", fontsize=9, labelpad=8)
    ax.set_title("Traffic Volume (KB) by Host", fontsize=11, fontweight="bold", pad=12)

    # Add numeric labels
    for bar in bars:
        width = bar.get_width()
        ax.text(width + (max(kb_values) * 0.015), bar.get_y() + bar.get_height()/2, f"{width:.1f} KB",
                ha="left", va="center", color=CYBER_TEXT, fontsize=8, fontweight="bold")

    fig.tight_layout()
    return fig


def plot_host_deep_dive(df: pd.DataFrame, src_ip: str) -> plt.Figure:
    """
    Renders a side-by-side diagnostic visualization for a single host:
    Left: Destination Port Distribution (Port Sweeping Analysis)
    Right: Destination IP Distribution (Target Concentration Analysis)
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.0), dpi=100)
    apply_cyber_theme(fig, ax1)
    apply_cyber_theme(fig, ax2)

    host_logs = df[df["src_ip"] == src_ip] if df is not None and not df.empty else pd.DataFrame()

    if host_logs.empty:
        ax1.text(0.5, 0.5, f"No logs for {src_ip}", color=CYBER_MUTED, ha="center", va="center", transform=ax1.transAxes)
        ax2.text(0.5, 0.5, f"No logs for {src_ip}", color=CYBER_MUTED, ha="center", va="center", transform=ax2.transAxes)
        return fig

    # Port Breakdown
    top_ports = host_logs["dst_port"].value_counts().head(7).sort_values(ascending=True)
    y_pos1 = range(len(top_ports))
    ax1.barh(y_pos1, top_ports.values, color=CYBER_PURPLE, height=0.6)
    ax1.set_yticks(y_pos1)
    ax1.set_yticklabels([f"Port {p}" for p in top_ports.index], fontsize=8)
    ax1.set_xlabel("Connections Count", fontsize=8)
    ax1.set_title(f"Target Ports ({len(host_logs['dst_port'].unique())} total)", fontsize=10, fontweight="bold")

    # Destination IP Breakdown
    top_dsts = host_logs["dst_ip"].value_counts().head(7).sort_values(ascending=True)
    y_pos2 = range(len(top_dsts))
    ax2.barh(y_pos2, top_dsts.values, color=CYBER_CYAN, height=0.6)
    ax2.set_yticks(y_pos2)
    ax2.set_yticklabels(top_dsts.index, fontsize=8)
    ax2.set_xlabel("Connections Count", fontsize=8)
    ax2.set_title(f"Target IPs ({len(host_logs['dst_ip'].unique())} total)", fontsize=10, fontweight="bold")

    fig.suptitle(f"Target Breakdown for Host: {src_ip}", color=CYBER_TEXT, fontsize=11, fontweight="bold", y=1.02)
    fig.tight_layout()
    return fig
