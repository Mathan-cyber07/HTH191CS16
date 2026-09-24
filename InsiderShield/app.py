"""InsiderShield — Explainable, Capacity-Aware SOC Analyst Command Center.

A 4-page Streamlit application providing decision-support intelligence for SOC investigators:
- Page 1: Executive Overview Dashboard
- Page 2: Capacity-Aware Investigation Queue
- Page 3: Incident Deep-Dive & Explanation Checklist
- Page 4: Side-by-Side Baseline Comparison & Drift Visualization
"""

import json
import os
from datetime import datetime
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.baseline import UserBaselineProfiler
from src.correlator import IncidentCorrelator
from src.pipeline import run_pipeline
from src.queue import CapacityQueueManager

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
LOGS_PATH = os.path.join(DATA_DIR, "activity_logs.csv")
USERS_PATH = os.path.join(DATA_DIR, "users.csv")
BASELINES_PATH = os.path.join(DATA_DIR, "user_baselines.json")
INCIDENTS_PATH = os.path.join(DATA_DIR, "incidents.json")

st.set_page_config(
    page_title="InsiderShield | SOC Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Custom Styling & CSS
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    .metric-card {
        background-color: #1a1e29;
        border: 1px solid #2d3748;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .badge-critical {
        background-color: #dc2626;
        color: white;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 13px;
    }
    .badge-high {
        background-color: #ea580c;
        color: white;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 13px;
    }
    .badge-medium {
        background-color: #d97706;
        color: white;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 13px;
    }
    .badge-low {
        background-color: #16a34a;
        color: white;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 13px;
    }
    .badge-active {
        background-color: #2563eb;
        color: white;
        padding: 3px 8px;
        border-radius: 3px;
        font-size: 12px;
    }
    .badge-backlog {
        background-color: #4b5563;
        color: #e5e7eb;
        padding: 3px 8px;
        border-radius: 3px;
        font-size: 12px;
    }
    .reason-box {
        background-color: #131924;
        border-left: 4px solid #3b82f6;
        padding: 10px 14px;
        margin: 6px 0;
        border-radius: 0 6px 6px 0;
        font-family: monospace;
        font-size: 13px;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Data Loading & Session State Management
# -----------------------------------------------------------------------------
@st.cache_data
def load_base_data():
    users_df = pd.read_csv(USERS_PATH) if os.path.exists(USERS_PATH) else pd.DataFrame()
    logs_df = pd.read_csv(LOGS_PATH) if os.path.exists(LOGS_PATH) else pd.DataFrame()
    with open(BASELINES_PATH, "r", encoding="utf-8") as f:
        baselines = json.load(f)
    return users_df, logs_df, baselines


def init_state():
    if "incidents" not in st.session_state or not st.session_state.incidents:
        if os.path.exists(INCIDENTS_PATH):
            st.session_state.incidents = IncidentCorrelator.load_incidents(INCIDENTS_PATH)
        else:
            res = run_pipeline()
            st.session_state.incidents = res["incidents"]

    if "incident_status_override" not in st.session_state:
        st.session_state.incident_status_override = {}

    if "capacity" not in st.session_state:
        st.session_state.capacity = 3


init_state()
users_df, logs_df, baselines_dict = load_base_data()


# -----------------------------------------------------------------------------
# Global Navigation Sidebar
# -----------------------------------------------------------------------------
st.sidebar.markdown("## 🛡️ **InsiderShield**")
st.sidebar.caption("Explainable Insider Risk Decision-Support System")
st.sidebar.markdown("---")

st.sidebar.markdown("### ⚙️ **SOC Configuration**")
capacity = st.sidebar.slider(
    "Active Investigator Slots (N)",
    min_value=1,
    max_value=10,
    value=st.session_state.capacity,
    help="Limits the number of incidents routed simultaneously to human investigators.",
)
st.session_state.capacity = capacity

st.sidebar.markdown("---")
st.sidebar.markdown("### 🧪 **Demo Scenario Injector**")
st.sidebar.caption("Filter live telemetry to inspect specific scenarios:")

col_s1, col_s2 = st.sidebar.columns(2)
if col_s1.button("Scenario A", help="Compromised Finance Account"):
    st.session_state.scenario_filter = "scenario_a_compromised_finance"
    st.rerun()
if col_s2.button("Scenario B", help="Malicious Developer"):
    st.session_state.scenario_filter = "scenario_b_malicious_dev"
    st.rerun()

col_s3, col_s4 = st.sidebar.columns(2)
if col_s3.button("Scenario C", help="Privilege Misuse"):
    st.session_state.scenario_filter = "scenario_c_privilege_misuse"
    st.rerun()
if col_s4.button("Scenario D", help="Password Brute Force"):
    st.session_state.scenario_filter = "scenario_d_password_attack"
    st.rerun()

col_s5, col_s6 = st.sidebar.columns(2)
if col_s5.button("Scenario E", help="Benign Anomaly"):
    st.session_state.scenario_filter = "scenario_e_benign_anomaly"
    st.rerun()
if col_s6.button("Full Scan", help="Scan All Today's Events"):
    st.session_state.scenario_filter = None
    st.rerun()

st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigation Views",
    [
        "📊 1. Executive Overview",
        "🎯 2. Capacity Investigation Queue",
        "🔍 3. Incident Deep-Dive & Explanations",
        "⚖️ 4. Baseline vs. Anomaly Comparison",
    ],
)

# Apply runtime status overrides to incidents in session state
incidents = []
for inc in st.session_state.incidents:
    inc_copy = dict(inc)
    if inc_copy["incident_id"] in st.session_state.incident_status_override:
        inc_copy["status"] = st.session_state.incident_status_override[inc_copy["incident_id"]]
    incidents.append(inc_copy)

# Filter if scenario button clicked
if getattr(st.session_state, "scenario_filter", None):
    filtered_inc = [i for i in incidents if i.get("scenario_tag") == st.session_state.scenario_filter]
    if filtered_inc:
        display_incidents = filtered_inc
        st.sidebar.info(f"Filtered: `{st.session_state.scenario_filter}`")
    else:
        display_incidents = incidents
else:
    display_incidents = incidents

# Rank queue with Capacity Manager
queue_mgr = CapacityQueueManager(capacity=st.session_state.capacity)
ranked = queue_mgr.rank_incidents(display_incidents, capacity=st.session_state.capacity)
rec_queue = ranked["recommended_queue"]
def_queue = ranked["deferred_queue"]
queue_metrics = ranked["metrics"]


# =============================================================================
# PAGE 1: EXECUTIVE OVERVIEW
# =============================================================================
if page.startswith("📊"):
    st.title("Executive Overview — SOC Command Center")
    st.markdown("Real-time behavioral telemetry, anomaly distribution, and investigator capacity metrics.")

    # High-level KPIs
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Events Logged", f"{len(logs_df):,}")
    with col2:
        today_events = len(logs_df[logs_df["timestamp"].str.startswith("2026-09-24")])
        st.metric("Today's Events Scanned", f"{today_events}")
    with col3:
        st.metric("Correlated Incidents", f"{len(display_incidents)}")
    with col4:
        crit_count = sum(1 for i in display_incidents if i.get("severity") == "Critical")
        st.metric("Critical Incidents", f"{crit_count}", delta=f"{crit_count} Urgent", delta_color="inverse")
    with col5:
        util = queue_metrics["capacity_utilization_pct"]
        st.metric("Analyst Capacity Util.", f"{util}%", delta=f"{queue_metrics['active_investigations']}/{capacity} Slots")

    st.markdown("---")

    # Visuals Row
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Incidents by Severity Bracket")
        sev_counts = pd.Series([i["severity"] for i in display_incidents]).value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        color_map = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#16a34a",
        }
        fig_sev = px.bar(
            sev_counts,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map=color_map,
            text="Count",
        )
        fig_sev.update_layout(height=320, showlegend=False, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig_sev, use_container_width=True)

    with chart_col2:
        st.subheader("Incidents by Department")
        dept_counts = pd.Series([i["department"] for i in display_incidents]).value_counts().reset_index()
        dept_counts.columns = ["Department", "Count"]
        fig_dept = px.pie(
            dept_counts,
            names="Department",
            values="Count",
            color_discrete_sequence=px.colors.qualitative.Plotly,
            hole=0.45,
        )
        fig_dept.update_layout(height=320, margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig_dept, use_container_width=True)

    # Incident Activity Timeline
    st.subheader("Temporal Anomaly Distribution (2026-09-24)")
    time_records = []
    for inc in display_incidents:
        for evt in inc.get("events", []):
            time_records.append({
                "timestamp": evt.get("timestamp"),
                "user_name": inc["user_name"],
                "incident_id": inc["incident_id"],
                "severity": inc["severity"],
                "risk_score": inc["risk_score"],
                "event_type": evt.get("event_type"),
                "resource": evt.get("resource"),
            })

    if time_records:
        tdf = pd.DataFrame(time_records)
        tdf["time"] = pd.to_datetime(tdf["timestamp"])
        fig_time = px.scatter(
            tdf,
            x="time",
            y="risk_score",
            color="severity",
            color_discrete_map=color_map,
            hover_data=["incident_id", "user_name", "resource"],
            size=[14] * len(tdf),
            title="Flagged Telemetry Events Along Timeline",
        )
        fig_time.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig_time, use_container_width=True)


# =============================================================================
# PAGE 2: CAPACITY-AWARE INVESTIGATION QUEUE
# =============================================================================
elif page.startswith("🎯"):
    st.title("Capacity-Aware Prioritized Investigation Queue")
    st.markdown(
        f"Prioritizes alerts strictly under **{capacity} Available Human Investigator Slots** "
        "to prevent cognitive fatigue and ensure high-confidence response."
    )

    st.info(
        f"**Queue Allocation Status:** {len(rec_queue)} Active Investigations assigned to analysts. "
        f"{len(def_queue)} Incidents deferred in triage backlog."
    )

    st.subheader(f"🛡️ Top-{capacity} Priority Queue (Active Slots)")
    if rec_queue:
        table_rows = []
        for item in rec_queue:
            flags_str = ", ".join(item["primary_flags"][:3])
            if len(item["primary_flags"]) > 3:
                flags_str += f" (+{len(item['primary_flags']) - 3} more)"

            table_rows.append({
                "Rank": f"#{item['queue_rank']}",
                "Assigned Analyst": item["assigned_investigator"],
                "Incident ID": item["incident_id"],
                "Employee": f"{item['user_name']} ({item['user_id']})",
                "Department": item["department"],
                "Severity": item["severity"],
                "Risk Score": f"{item['risk_score']} / 100",
                "Priority Score": item["priority_score"],
                "Primary Triggered Flags": flags_str,
                "Status": item["status"],
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)
    else:
        st.write("No active incidents in queue.")

    if def_queue:
        with st.expander(f"⏳ Triage Backlog ({len(def_queue)} Incidents Pending Capacity)", expanded=True):
            st.warning("⚠️ These incidents exceed current investigator bandwidth and await slot release.")
            def_rows = []
            for item in def_queue:
                def_rows.append({
                    "Rank": f"#{item['queue_rank']}",
                    "Incident ID": item["incident_id"],
                    "Employee": f"{item['user_name']} ({item['user_id']})",
                    "Department": item["department"],
                    "Severity": item["severity"],
                    "Risk Score": item["risk_score"],
                    "Priority Score": item["priority_score"],
                    "Status": "Deferred (Backlog)",
                })
            st.dataframe(pd.DataFrame(def_rows), use_container_width=True, hide_index=True)


# =============================================================================
# PAGE 3: INCIDENT DEEP-DIVE & EXPLANATION CHECKLIST
# =============================================================================
elif page.startswith("🔍"):
    st.title("Incident Deep-Dive & Explanation Checklist")
    st.markdown("Inspect exact contributing factors, transparent rule scores, and raw forensic event logs.")

    if not incidents:
        st.warning("No incidents available to inspect.")
    else:
        inc_options = {
            f"{i['incident_id']} - {i['user_name']} ({i['department']}) [{i['severity']} - Score: {i['risk_score']}]": i
            for i in incidents
        }
        selected_label = st.selectbox("Select Incident to Investigate:", list(inc_options.keys()))
        selected_inc = inc_options[selected_label]

        st.markdown("---")

        # Incident Summary Header
        h_col1, h_col2, h_col3, h_col4 = st.columns(4)
        with h_col1:
            st.markdown(f"**Employee:** {selected_inc['user_name']} (`{selected_inc['user_id']}`)")
            st.markdown(f"**Role:** {selected_inc['role']} — {selected_inc['department']}")
        with h_col2:
            sev = selected_inc["severity"]
            sev_class = f"badge-{sev.lower()}"
            st.markdown(f"**Severity:** <span class='{sev_class}'>{sev.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"**Triage Status:** `{selected_inc.get('status', 'Open')}`")
        with h_col3:
            st.markdown(f"**Window:** `{selected_inc['start_time']}`")
            st.markdown(f"**Events in Incident:** `{selected_inc['event_count']}`")
        with h_col4:
            st.markdown(f"**Max Asset Sensitivity:** `{selected_inc.get('max_resource_sensitivity', 'N/A').upper()}`")
            st.markdown(f"**Total Exfiltration:** `{selected_inc.get('total_download_mb', 0.0)} MB`")

        # Risk Score Breakdown Gauge
        gauge_col, exp_col = st.columns([1, 2])
        with gauge_col:
            score = selected_inc["risk_score"]
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={"text": "Transparent Risk Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "#3b82f6"},
                    "steps": [
                        {"range": [0, 24], "color": "#16a34a"},
                        {"range": [25, 49], "color": "#d97706"},
                        {"range": [50, 74], "color": "#ea580c"},
                        {"range": [75, 100], "color": "#dc2626"},
                    ],
                }
            ))
            fig_gauge.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_gauge, use_container_width=True)

        with exp_col:
            st.subheader("📋 Explainable Contributing Factors")
            st.caption("Discrete rules violated with human-readable rationale (No black-box math):")
            for r_text in selected_inc.get("reasons", []):
                st.markdown(f"<div class='reason-box'>⚠️ <b>FLAG:</b> {r_text}</div>", unsafe_allow_html=True)

            score_bd = selected_inc.get("score_breakdown", {})
            if score_bd:
                st.caption(
                    f"**Score Math:** Base Rule Points ({score_bd.get('base_score', 0)}) + "
                    f"Multi-Signal Pattern Bonus ({score_bd.get('pattern_bonus', 0)}) = "
                    f"**{score_bd.get('total_score', score)} pts**"
                )

        st.markdown("---")

        # Chronological Events Table
        st.subheader("🕒 Chronological Event Timeline")
        raw_events = selected_inc.get("events", [])
        if raw_events:
            ev_df = pd.DataFrame(raw_events)[[
                "event_id", "timestamp", "event_type", "login_status",
                "country", "city", "device_id", "resource", "download_mb"
            ]]
            st.dataframe(ev_df, use_container_width=True, hide_index=True)

        st.markdown("---")

        # Analyst Action Buttons
        st.subheader("⚡ Human Analyst Disposition Actions")
        st.caption("Empower analysts with decision support; record review outcome:")
        act_col1, act_col2, act_col3, act_col4 = st.columns(4)

        inc_id = selected_inc["incident_id"]

        with act_col1:
            if st.button("🔎 Mark Investigating", key=f"inv_{inc_id}"):
                st.session_state.incident_status_override[inc_id] = "Investigating"
                st.success(f"{inc_id} status updated to: Investigating")
                st.rerun()

        with act_col2:
            if st.button("✅ Flag as Benign / Expected", key=f"ben_{inc_id}"):
                st.session_state.incident_status_override[inc_id] = "Resolved (Benign Anomaly)"
                st.info(f"{inc_id} resolved as Benign.")
                st.rerun()

        with act_col3:
            if st.button("🚨 Escalate to Tier 2 IR", key=f"esc_{inc_id}"):
                st.session_state.incident_status_override[inc_id] = "Escalated (Tier 2 Incident Response)"
                st.error(f"{inc_id} escalated to Tier 2 Incident Response!")
                st.rerun()

        with act_col4:
            if st.button("📁 Close Incident", key=f"cls_{inc_id}"):
                st.session_state.incident_status_override[inc_id] = "Closed"
                st.warning(f"{inc_id} marked as Closed.")
                st.rerun()


# =============================================================================
# PAGE 4: SIDE-BY-SIDE BASELINE COMPARISON & DRIFT
# =============================================================================
elif page.startswith("⚖️"):
    st.title("Side-by-Side Baseline Comparison & Drift Visualization")
    st.markdown("Compare an employee's historical 14-day baseline against today's anomalous activity.")

    all_users = list(baselines_dict.keys())
    # Highlight scenario users first
    scenario_users = ["EMP_014", "EMP_022", "EMP_008", "EMP_031", "EMP_005"]
    user_choices = scenario_users + [u for u in all_users if u not in scenario_users]

    selected_u = st.selectbox(
        "Select User Profile to Compare:",
        user_choices,
        format_func=lambda x: f"{x} - {baselines_dict[x]['user_name']} ({baselines_dict[x]['department']})",
    )

    base = baselines_dict[selected_u]

    # Find today's activity for this user
    user_today_logs = logs_df[
        (logs_df["user_id"] == selected_u) & (logs_df["timestamp"].str.startswith("2026-09-24"))
    ]

    # Compute observed stats for today
    if not user_today_logs.empty:
        obs_times = pd.to_datetime(user_today_logs["timestamp"])
        obs_start_str = obs_times.min().strftime("%H:%M:%S")
        obs_countries = ", ".join(user_today_logs["country"].unique())
        obs_devices = ", ".join(user_today_logs["device_id"].unique())
        obs_dl = user_today_logs["download_mb"].sum()
        obs_resources = ", ".join(user_today_logs["resource"].unique()[:3])
    else:
        obs_start_str = "No events today"
        obs_countries = "N/A"
        obs_devices = "N/A"
        obs_dl = 0.0
        obs_resources = "N/A"

    st.subheader(f"Profile: {base['user_name']} ({base['user_id']}) — {base['department']}")

    # Precalculate deviation statuses cleanly
    if not user_today_logs.empty:
        hours_anom = any(h < base["normal_work_start"] or h > base["normal_work_end"] for h in obs_times.dt.hour)
        hours_status = "⚠️ Off-Hours Activity" if hours_anom else "✅ Normal"

        country_anom = any(c not in base["known_countries"] for c in user_today_logs["country"].unique())
        country_status = "⚠️ Foreign Country" if country_anom else "✅ Normal"

        dev_anom = any(d not in base["known_devices"] for d in user_today_logs["device_id"].unique())
        dev_status = "⚠️ Unregistered Device" if dev_anom else "✅ Normal"

        dl_ratio = round(obs_dl / max(base["avg_download_mb"], 1.0), 1)
        dl_status = f"⚠️ {dl_ratio}x Baseline Surge" if obs_dl > base["avg_download_mb"] * 5 else "✅ Normal"

        sens_anom = any(s in ["high", "critical"] for s in user_today_logs["resource_sensitivity"])
        res_status = "⚠️ Sensitive / Critical Access" if sens_anom else "✅ Normal"
    else:
        hours_status = "Normal (No Logs)"
        country_status = "Normal (No Logs)"
        dev_status = "Normal (No Logs)"
        dl_status = "Normal (No Logs)"
        res_status = "Normal (No Logs)"

    # Comparison Grid Table
    comp_data = [
        {
            "Behavioral Metric": "Work Schedule / Login Hours",
            "Historical 14-Day Baseline": f"{base['normal_work_start']:02d}:00 – {base['normal_work_end']:02d}:00",
            "Today's Observed Activity": obs_start_str,
            "Deviation Status": hours_status,
        },
        {
            "Behavioral Metric": "Recognized Countries",
            "Historical 14-Day Baseline": ", ".join(base["known_countries"]),
            "Today's Observed Activity": obs_countries,
            "Deviation Status": country_status,
        },
        {
            "Behavioral Metric": "Authorized Hardware Devices",
            "Historical 14-Day Baseline": ", ".join(base["known_devices"]),
            "Today's Observed Activity": obs_devices,
            "Deviation Status": dev_status,
        },
        {
            "Behavioral Metric": "Daily Download Volume",
            "Historical 14-Day Baseline": f"Mean: {base['avg_download_mb']} MB (Max: {base['max_normal_download_mb']} MB)",
            "Today's Observed Activity": f"{obs_dl:.1f} MB",
            "Deviation Status": dl_status,
        },
        {
            "Behavioral Metric": "Accessed Resources",
            "Historical 14-Day Baseline": f"{base['department']} Resources ({', '.join(base['normal_sensitivity'])})",
            "Today's Observed Activity": obs_resources,
            "Deviation Status": res_status,
        },
    ]

    st.table(pd.DataFrame(comp_data))

    st.markdown("---")

    # BONUS FEATURE: Baseline Drift Over Time
    st.subheader("📈 Bonus Feature: Behavioral Baseline Drift Over Time")
    st.caption("14-day historical daily download volume versus today's observed surge:")

    user_all_logs = logs_df[logs_df["user_id"] == selected_u].copy()
    user_all_logs["date"] = pd.to_datetime(user_all_logs["timestamp"]).dt.date
    daily_dl = user_all_logs.groupby("date")["download_mb"].sum().reset_index()

    fig_drift = go.Figure()
    # Baseline normal period
    normal_dl = daily_dl[daily_dl["date"] < datetime(2026, 9, 24).date()]
    today_dl = daily_dl[daily_dl["date"] == datetime(2026, 9, 24).date()]

    fig_drift.add_trace(go.Bar(
        x=normal_dl["date"].astype(str),
        y=normal_dl["download_mb"],
        name="Historical Daily Download (MB)",
        marker_color="#3b82f6",
    ))

    # Add baseline average line
    fig_drift.add_hline(
        y=base["avg_download_mb"],
        line_dash="dash",
        line_color="#22c55e",
        annotation_text=f"Baseline Avg: {base['avg_download_mb']} MB",
    )

    if not today_dl.empty:
        fig_drift.add_trace(go.Bar(
            x=today_dl["date"].astype(str),
            y=today_dl["download_mb"],
            name="Today's Anomaly (2026-09-24)",
            marker_color="#dc2626",
        ))

    fig_drift.update_layout(
        height=340,
        xaxis_title="Date",
        yaxis_title="Total Download Volume (MB)",
        margin=dict(l=20, r=20, t=30, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig_drift, use_container_width=True)
