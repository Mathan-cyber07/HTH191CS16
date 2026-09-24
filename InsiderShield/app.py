"""InsiderShield — Insider Threat Attack Simulator & Analyst Console.

An intuitive, visually striking 3-view command center designed for judges & SOC analysts:
- VIEW 1: 🎮 Attack Simulator & Live Ingestion (Interactive scenario cards & step-by-step log stream)
- VIEW 2: 🎯 Capacity-Aware Triage Queue (Strict N=3 analyst workload slots + deferred backlog)
- VIEW 3: 🔍 Explainable Incident Investigator (8-rule checklist, behavioral shift matrix, & decision console)
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, Any, List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.baseline import UserBaselineProfiler
from src.detector import ExplainableDetector
from src.scorer import RiskScorer
from src.correlator import IncidentCorrelator
from src.queue import CapacityQueueManager

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
LOGS_PATH = os.path.join(DATA_DIR, "activity_logs.csv")
USERS_PATH = os.path.join(DATA_DIR, "users.csv")
BASELINES_PATH = os.path.join(DATA_DIR, "user_baselines.json")
INCIDENTS_PATH = os.path.join(DATA_DIR, "incidents.json")

st.set_page_config(
    page_title="InsiderShield | Attack Simulator & SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Sleek Cybersecurity UI Styles
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    .main-header {
        font-size: 26px;
        font-weight: 700;
        color: #f8fafc;
        margin-bottom: 2px;
    }
    .sub-header {
        font-size: 14px;
        color: #94a3b8;
        margin-bottom: 18px;
    }
    .scenario-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .scenario-title {
        font-size: 16px;
        font-weight: 700;
        color: #38bdf8;
        margin-bottom: 6px;
    }
    .scenario-desc {
        font-size: 13px;
        color: #cbd5e1;
        line-height: 1.4;
        margin-bottom: 12px;
    }
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
    }
    .badge-high {
        background-color: #f97316;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
    }
    .badge-medium {
        background-color: #eab308;
        color: #0f172a;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
    }
    .badge-low {
        background-color: #22c55e;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
    }
    .rule-violation {
        background-color: #450a0a;
        border-left: 4px solid #ef4444;
        padding: 10px 14px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 8px;
        font-size: 13px;
    }
    .rule-passed {
        background-color: #064e3b;
        border-left: 4px solid #10b981;
        padding: 8px 14px;
        border-radius: 0 6px 6px 0;
        margin-bottom: 6px;
        font-size: 13px;
        color: #a7f3d0;
    }
    .workload-slot-active {
        background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
        border: 1px solid #3b82f6;
        border-radius: 8px;
        padding: 14px;
        color: white;
    }
    .workload-slot-empty {
        background-color: #0f172a;
        border: 1px dashed #475569;
        border-radius: 8px;
        padding: 14px;
        color: #94a3b8;
    }
</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Data Ingestion & State Management
# -----------------------------------------------------------------------------
@st.cache_data
def get_static_data():
    users_df = pd.read_csv(USERS_PATH) if os.path.exists(USERS_PATH) else pd.DataFrame()
    logs_df = pd.read_csv(LOGS_PATH) if os.path.exists(LOGS_PATH) else pd.DataFrame()
    with open(BASELINES_PATH, "r", encoding="utf-8") as f:
        baselines = json.load(f)
    return users_df, logs_df, baselines


users_df, logs_df, baselines_dict = get_static_data()
detector = ExplainableDetector(baselines_dict=baselines_dict)
correlator = IncidentCorrelator(window_minutes=30)

SCENARIOS = {
    "scenario_a_compromised_finance": {
        "letter": "A",
        "title": "Stolen Credentials (Finance)",
        "target": "Rajesh Sharma (EMP_014)",
        "department": "Finance",
        "icon": "💸",
        "description": "Attacker logs in from Moscow, Russia via unknown device at 02:15 AM, accesses confidential payroll, and downloads 2,048 MB.",
        "expected_severity": "Critical",
        "risk_tag": "CRITICAL RISK",
        "is_attack": True,
    },
    "scenario_b_malicious_dev": {
        "letter": "B",
        "title": "Disgruntled Developer (Engineering)",
        "target": "Vikram Iyer (EMP_022)",
        "department": "Engineering",
        "icon": "💻",
        "description": "Employee logs in late at night (01:30 AM) on authorized laptop, accesses proprietary source code zip, and exfiltrates 3,500 MB.",
        "expected_severity": "Critical",
        "risk_tag": "CRITICAL RISK",
        "is_attack": True,
    },
    "scenario_c_privilege_misuse": {
        "letter": "C",
        "title": "Privilege Misuse (Sales)",
        "target": "Priya Patel (EMP_008)",
        "department": "Sales",
        "icon": "📑",
        "description": "Sales Rep snoops outside department bounds during business hours, accessing executive salaries and bonus records in HR.",
        "expected_severity": "High",
        "risk_tag": "HIGH RISK",
        "is_attack": True,
    },
    "scenario_d_password_attack": {
        "letter": "D",
        "title": "Password Brute-Force (HR)",
        "target": "Sneha Reddy (EMP_031)",
        "department": "HR",
        "icon": "🔓",
        "description": "6 rapid failed logins from Netherlands attacker IP within 3 mins, followed by 1 successful login and immediate SSN theft.",
        "expected_severity": "Critical",
        "risk_tag": "CRITICAL RISK",
        "is_attack": True,
    },
    "scenario_e_benign_anomaly": {
        "letter": "E",
        "title": "False Positive Test (IT Support)",
        "target": "Karthik Menon (EMP_005)",
        "department": "IT",
        "icon": "🔧",
        "description": "Systems admin working late at 11:20 PM from known laptop, downloading 5 MB of low-sensitivity patch logs. SHOULD NOT ALERT heavily.",
        "expected_severity": "Low / Benign",
        "risk_tag": "BENIGN / EXPECTED",
        "is_attack": False,
    },
}


def process_simulation(selected_tag: str = "ALL"):
    """Evaluate logs and generate correlated incidents based on simulation target."""
    today_logs = logs_df[logs_df["timestamp"].str.startswith("2026-09-24")].copy()
    if selected_tag != "ALL":
        today_logs = today_logs[today_logs["scenario_tag"] == selected_tag]

    events = today_logs.to_dict(orient="records")
    flagged_events = []
    user_history = {}

    for evt in events:
        u_id = evt.get("user_id", "")
        if u_id not in user_history:
            user_history[u_id] = []
        hist = user_history[u_id]
        triggered = detector.evaluate_event(evt, recent_user_events=hist)
        hist.append(evt)

        if triggered:
            evt_copy = dict(evt)
            evt_copy["triggered_rules"] = triggered
            flagged_events.append(evt_copy)

    incidents = correlator.correlate_events(flagged_events)
    return events, flagged_events, incidents


# Initialize Session State
if "active_scenario" not in st.session_state:
    st.session_state.active_scenario = "ALL"
    ev, fl, inc = process_simulation("ALL")
    st.session_state.sim_events = ev
    st.session_state.sim_flagged = fl
    st.session_state.incidents = inc

if "capacity" not in st.session_state:
    st.session_state.capacity = 3

if "incident_status_override" not in st.session_state:
    st.session_state.incident_status_override = {}

if "live_stream_active" not in st.session_state:
    st.session_state.live_stream_active = False


# -----------------------------------------------------------------------------
# Global Navigation Sidebar
# -----------------------------------------------------------------------------
st.sidebar.markdown("## 🛡️ **InsiderShield**")
st.sidebar.caption("Explainable Insider Risk Simulator & SOC Console")
st.sidebar.markdown("---")

st.sidebar.markdown("### 🎛️ **Investigator Capacity**")
cap_val = st.sidebar.slider(
    "Active Human Investigator Slots",
    min_value=1,
    max_value=5,
    value=st.session_state.capacity,
    help="Limits the maximum number of threats routed simultaneously to prevent SOC analyst cognitive fatigue.",
)
st.session_state.capacity = cap_val

st.sidebar.markdown("---")
view_selection = st.sidebar.radio(
    "Console Views",
    [
        "🎮 1. Attack Simulator & Live Stream",
        "🎯 2. Capacity-Aware Triage Queue",
        "🔍 3. Explainable Incident Investigator",
    ],
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🚀 **Quick Scenario Launcher**")
if st.sidebar.button("⚡ Simulate All 5 Scenarios", use_container_width=True):
    st.session_state.active_scenario = "ALL"
    ev, fl, inc = process_simulation("ALL")
    st.session_state.sim_events = ev
    st.session_state.sim_flagged = fl
    st.session_state.incidents = inc
    st.session_state.live_stream_active = True
    st.rerun()

st.sidebar.caption("InsiderShield decision-support system. Never automatically punishes employees.")


# =============================================================================
# VIEW 1: ATTACK SIMULATOR & LIVE INGESTION
# =============================================================================
if view_selection.startswith("🎮"):
    st.markdown("<div class='main-header'>🎮 Insider Threat Attack Simulator</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sub-header'>Test and demonstrate how InsiderShield detects stealthy insider behaviors in real time across 5 diverse threat archetypes.</div>",
        unsafe_allow_html=True,
    )

    # 5 Scenario Cards Side-by-Side
    cols = st.columns(5)
    for idx, (tag, s_info) in enumerate(SCENARIOS.items()):
        with cols[idx]:
            card_border = "#ef4444" if s_info["is_attack"] else "#10b981"
            st.markdown(
                f"""
                <div style='background-color:#1e293b; border-top: 4px solid {card_border}; border-radius:8px; padding:12px; min-height: 250px;'>
                    <div style='font-size:24px;'>{s_info['icon']}</div>
                    <div style='font-weight:700; font-size:14px; color:#f8fafc; margin-top:4px;'>Scenario {s_info['letter']}</div>
                    <div style='font-size:13px; font-weight:600; color:#38bdf8;'>{s_info['title']}</div>
                    <div style='font-size:12px; color:#94a3b8; margin:6px 0;'><b>Target:</b> {s_info['target']}</div>
                    <div style='font-size:11px; color:#cbd5e1; line-height:1.3;'>{s_info['description']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
            if st.button(f"LAUNCH {s_info['letter']}", key=f"btn_launch_{tag}", use_container_width=True):
                st.session_state.active_scenario = tag
                ev, fl, inc = process_simulation(tag)
                st.session_state.sim_events = ev
                st.session_state.sim_flagged = fl
                st.session_state.incidents = inc
                st.session_state.live_stream_active = True
                st.rerun()

    st.markdown("---")

    # Live Log Ingestion Stream
    active_tag = st.session_state.active_scenario
    active_name = (
        "All 5 Scenarios (Full Telemetry Scan)"
        if active_tag == "ALL"
        else f"Scenario {SCENARIOS[active_tag]['letter']}: {SCENARIOS[active_tag]['title']}"
    )

    st.subheader(f"📡 Live Telemetry Ingestion Stream — [{active_name}]")
    st.caption("Incoming synthetic events evaluated instantaneously against 8 explainable behavioral baseline rules.")

    events_to_show = st.session_state.sim_events

    if not events_to_show:
        st.info("No events in current simulation buffer. Click 'Simulate All 5 Scenarios' above.")
    else:
        # Ingestion KPI metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Live Events Ingested", len(events_to_show))
        m2.metric("Violations Flagged", len(st.session_state.sim_flagged))
        m3.metric("Correlated Incidents", len(st.session_state.incidents))
        crit_count = sum(1 for i in st.session_state.incidents if i["severity"] == "Critical")
        m4.metric("Critical Threats", crit_count)

        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

        # Real-time event review container
        with st.container():
            st.markdown("#### Real-Time Log Evaluation Stream")
            for e_idx, evt in enumerate(events_to_show, start=1):
                triggered_list = detector.evaluate_event(evt)
                is_violation = len(triggered_list) > 0

                evt_time = evt.get("timestamp", "").split()[-1]
                evt_user = f"{evt.get('user_name')} ({evt.get('user_id')})"
                evt_type = evt.get("event_type", "").upper()
                evt_res = evt.get("resource", "portal")
                evt_dl = f"{evt.get('download_mb', 0)} MB"
                evt_country = evt.get("country", "")

                with st.expander(
                    f"{'🚨 VIOLATION' if is_violation else '✅ NORMAL'} | {evt_time} | {evt_user} | {evt_type} | {evt_res} ({evt_dl})",
                    expanded=is_violation,
                ):
                    c1, c2, c3, c4 = st.columns(4)
                    c1.markdown(f"**IP Address:** `{evt.get('source_ip')}`")
                    c2.markdown(f"**Location:** `{evt_country} ({evt.get('city')})`")
                    c3.markdown(f"**Device ID:** `{evt.get('device_id')}`")
                    c4.markdown(f"**Sensitivity:** `{evt.get('resource_sensitivity', 'low').upper()}`")

                    if is_violation:
                        st.markdown("**Triggered Rule Violations:**")
                        for r in triggered_list:
                            st.markdown(
                                f"<div class='rule-violation'>⚠️ <b>+{r['score']} pts — {r['rule_name']}:</b> {r['reason']}</div>",
                                unsafe_allow_html=True,
                            )
                    else:
                        st.markdown("<div class='rule-passed'>✅ Activity matches user's historical 14-day baseline.</div>", unsafe_allow_html=True)


# =============================================================================
# VIEW 2: CAPACITY-AWARE TRIAGE QUEUE (N=3 SLOTS)
# =============================================================================
elif view_selection.startswith("🎯"):
    st.markdown("<div class='main-header'>🎯 Capacity-Aware Triage Queue</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div class='sub-header'>Human security investigators have limited bandwidth. InsiderShield routes only the <b>Top-{st.session_state.capacity}</b> highest-priority incidents to active investigators to prevent cognitive fatigue and missed signals.</div>",
        unsafe_allow_html=True,
    )

    # Rank current incidents
    queue_mgr = CapacityQueueManager(capacity=st.session_state.capacity)
    ranked_data = queue_mgr.rank_incidents(st.session_state.incidents, capacity=st.session_state.capacity)
    rec_queue = ranked_data["recommended_queue"]
    def_queue = ranked_data["deferred_queue"]

    # Analyst Workload Slots Visual Display
    st.subheader(f"👥 Active Analyst Workload Slots (Capacity = {st.session_state.capacity})")
    slot_cols = st.columns(st.session_state.capacity)

    for s_idx in range(st.session_state.capacity):
        with slot_cols[s_idx]:
            if s_idx < len(rec_queue):
                item = rec_queue[s_idx]
                sev_badge = f"badge-{item['severity'].lower()}"
                st.markdown(
                    f"""
                    <div class='workload-slot-active'>
                        <div style='font-size:12px; color:#93c5fd; font-weight:700;'>SLOT #{s_idx + 1} — {item['assigned_investigator']}</div>
                        <div style='font-size:18px; font-weight:700; margin:6px 0;'>{item['user_name']}</div>
                        <div style='font-size:13px; color:#e2e8f0;'>Dept: <b>{item['department']}</b></div>
                        <div style='margin-top:8px;'>
                            <span class='{sev_badge}'>{item['severity'].upper()}</span>
                            <span style='font-size:14px; font-weight:700; margin-left:8px;'>Score: {item['risk_score']}/100</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div class='workload-slot-empty'>
                        <div style='font-weight:700;'>SLOT #{s_idx + 1}</div>
                        <div style='margin-top:10px; font-size:14px;'>🟢 Available Slot</div>
                        <div style='font-size:12px; margin-top:4px;'>No active alert assigned.</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    st.markdown("---")

    # Main Priority Queue Table
    st.subheader("📋 Active Investigation Queue (Priority Ranked)")
    st.caption("Priority Formula: `(Risk Score × 0.6) + (Violations × 10) + (Asset Sensitivity × 20)`")

    if rec_queue:
        for r_idx, item in enumerate(rec_queue, start=1):
            with st.container():
                c_rank, c_info, c_meter, c_flags, c_action = st.columns([1, 4, 3, 4, 2])
                with c_rank:
                    st.markdown(f"### #{r_idx}")
                    st.caption(f"{item['assigned_investigator'].split()[0]}")

                with c_info:
                    st.markdown(f"**{item['user_name']}** (`{item['user_id']}`)")
                    st.markdown(f"*{item['role']}* — **{item['department']}**")

                with c_meter:
                    st.markdown(f"**Risk Score: {item['risk_score']} / 100**")
                    sev_color = (
                        "red"
                        if item["severity"] == "Critical"
                        else "orange"
                        if item["severity"] == "High"
                        else "yellow"
                    )
                    st.progress(item["risk_score"] / 100)
                    st.caption(f"Severity: **{item['severity']}** | Priority Pts: **{item['priority_score']}**")

                with c_flags:
                    st.markdown("**Key Explainable Flags:**")
                    for flg in item["primary_flags"][:2]:
                        st.markdown(f"• `{flg}`")
                    if len(item["primary_flags"]) > 2:
                        st.caption(f"+ {len(item['primary_flags']) - 2} more violations")

                with c_action:
                    st.markdown(f"**Status:** `{item.get('status', 'Open')}`")
                    if st.button("Inspect 🔍", key=f"insp_btn_{item['incident_id']}"):
                        st.session_state.selected_incident_id = item["incident_id"]
                        st.info(f"Navigate to 'Explainable Incident Investigator' to deep dive on {item['user_name']}.")

                st.markdown("<hr style='margin: 8px 0; border-color: #334155;'/>", unsafe_allow_html=True)
    else:
        st.write("No incidents currently in active queue.")

    # Expandable Deferred Backlog
    if def_queue:
        with st.expander(
            f"⏳ Deferred Triage Backlog ({len(def_queue)} alerts held back due to capacity limit)",
            expanded=True,
        ):
            st.warning(
                f"⚠️ These {len(def_queue)} incidents have lower priority scores and are queued to protect investigator focus. Increase capacity in the sidebar to allocate more slots."
            )
            b_rows = []
            for b_idx, b_item in enumerate(def_queue, start=len(rec_queue) + 1):
                b_rows.append({
                    "Queue Rank": f"#{b_idx}",
                    "Employee": f"{b_item['user_name']} ({b_item['user_id']})",
                    "Department": b_item["department"],
                    "Severity": b_item["severity"],
                    "Risk Score": f"{b_item['risk_score']} / 100",
                    "Priority Score": b_item["priority_score"],
                    "Violations": ", ".join(b_item["primary_flags"]),
                    "Status": "Deferred in Backlog",
                })
            st.dataframe(pd.DataFrame(b_rows), use_container_width=True, hide_index=True)


# =============================================================================
# VIEW 3: EXPLAINABLE INCIDENT INVESTIGATOR
# =============================================================================
elif view_selection.startswith("🔍"):
    st.markdown("<div class='main-header'>🔍 Explainable Incident Investigator</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sub-header'>Zero black-box ambiguity. Inspect exact rule violations, historical behavioral shifts, and take human decision-support actions.</div>",
        unsafe_allow_html=True,
    )

    incidents = st.session_state.incidents
    if not incidents:
        st.warning("No incidents available. Please run a simulation in View 1.")
    else:
        # Build dropdown options
        inc_map = {f"{i['incident_id']} — {i['user_name']} ({i['department']}) [{i['severity']} - Score: {i['risk_score']}]": i for i in incidents}
        default_index = 0

        # Check if pre-selected from Queue view
        if "selected_incident_id" in st.session_state:
            for idx, k in enumerate(inc_map.keys()):
                if inc_map[k]["incident_id"] == st.session_state.selected_incident_id:
                    default_index = idx
                    break

        selected_label = st.selectbox("Select Incident to Investigate:", list(inc_map.keys()), index=default_index)
        sel_inc = inc_map[selected_label]
        u_id = sel_inc["user_id"]
        base = baselines_dict.get(u_id, {})

        # Apply runtime status override if analyst took action
        current_status = st.session_state.incident_status_override.get(sel_inc["incident_id"], sel_inc.get("status", "Open"))

        st.markdown("---")

        # Top Incident Summary Card
        top_c1, top_c2, top_c3, top_c4 = st.columns(4)
        with top_c1:
            st.markdown(f"### {sel_inc['user_name']}")
            st.markdown(f"**ID:** `{u_id}` | **Dept:** {sel_inc['department']}")
        with top_c2:
            sev = sel_inc["severity"]
            sev_badge = f"badge-{sev.lower()}"
            st.markdown(f"**Severity:** <span class='{sev_badge}'>{sev.upper()}</span>", unsafe_allow_html=True)
            st.markdown(f"**Status:** `{current_status}`")
        with top_c3:
            st.markdown(f"**Total Downloaded:** `{sel_inc.get('total_download_mb', 0)} MB`")
            st.markdown(f"**Highest Asset Class:** `{sel_inc.get('max_resource_sensitivity', 'low').upper()}`")
        with top_c4:
            st.markdown(f"**Score:** `{sel_inc['risk_score']} / 100`")
            st.progress(sel_inc["risk_score"] / 100)

        st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

        col_rules, col_matrix = st.columns([1, 1])

        # ---------------------------------------------------------------------
        # Part A: The 8-Rule Explainability Checklist
        # ---------------------------------------------------------------------
        with col_rules:
            st.subheader("📋 8-Rule Explainability Checklist")
            st.caption("Full audit trail showing exactly which rules triggered and which passed:")

            all_rules = [
                ("Off-Hours Activity", 15),
                ("Anomalous Country/Location", 20),
                ("Unregistered Device", 15),
                ("Critical Asset Access", 20),
                ("Abnormal Download Volume", 20),
                ("Cross-Department Privilege Anomaly", 25),
                ("Failed Login Burst", 15),
                ("Impossible Travel", 25),
            ]

            triggered_names = sel_inc.get("primary_flags", [])
            reasons_list = sel_inc.get("reasons", [])

            for r_name, r_pts in all_rules:
                if r_name in triggered_names:
                    # Find matching reason string
                    matched_r = next((r for r in reasons_list if r_name.split()[0].lower() in r.lower()), f"Violation of {r_name}")
                    st.markdown(
                        f"""
                        <div class='rule-violation'>
                            <div style='font-weight:700; color:#fca5a5;'>❌ VIOLATION (+{r_pts} pts) — {r_name}</div>
                            <div style='font-size:12px; color:#fecaca; margin-top:2px;'>{matched_r}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"""
                        <div class='rule-passed'>
                            🟢 <b>PASSED (0 pts)</b> — {r_name}: Activity within baseline norms.
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

            # Score computation box
            bd = sel_inc.get("score_breakdown", {})
            st.markdown(
                f"""
                <div style='background-color:#1e293b; border:1px solid #475569; border-radius:6px; padding:10px; margin-top:10px; font-size:13px;'>
                    <b>Deterministic Scoring Formula:</b><br/>
                    Base Points ({bd.get('base_score', sel_inc['risk_score'])}) + Multi-Signal Bonus ({bd.get('pattern_bonus', 0)}) = <b>{sel_inc['risk_score']} / 100 ({sel_inc['severity']})</b>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # ---------------------------------------------------------------------
        # Part B: Behavioral Shift Matrix (Normal vs Suspicious)
        # ---------------------------------------------------------------------
        with col_matrix:
            st.subheader("⚖️ Behavioral Shift Matrix")
            st.caption("Visual contrast of 14-day learned baseline vs. observed telemetry:")

            # Extract observed attributes
            inc_events = sel_inc.get("events", [])
            if inc_events:
                e_df = pd.DataFrame(inc_events)
                obs_hour = pd.to_datetime(e_df["timestamp"]).dt.strftime("%H:%M:%S").iloc[0]
                obs_country = ", ".join(e_df["country"].unique())
                obs_device = ", ".join(e_df["device_id"].unique())
                obs_dl = f"{sel_inc.get('total_download_mb', 0)} MB"
                obs_res = ", ".join(e_df["resource"].unique()[:2])
            else:
                obs_hour, obs_country, obs_device, obs_dl, obs_res = "N/A", "N/A", "N/A", "N/A", "N/A"

            shift_table = [
                {
                    "Metric": "🕒 Activity Hours",
                    "Normal Baseline (14 Days)": f"{base.get('normal_work_start', 9):02d}:00 – {base.get('normal_work_end', 18):02d}:00",
                    "Current Observed Behavior": obs_hour,
                    "Shift": "⚠️ Off-Hours" if any("Off-Hours" in f for f in triggered_names) else "✅ Normal",
                },
                {
                    "Metric": "🌍 Country / Location",
                    "Normal Baseline (14 Days)": ", ".join(base.get("known_countries", ["India"])),
                    "Current Observed Behavior": obs_country,
                    "Shift": "⚠️ New Country" if any("Country" in f for f in triggered_names) else "✅ Normal",
                },
                {
                    "Metric": "💻 Authorized Device",
                    "Normal Baseline (14 Days)": ", ".join(base.get("known_devices", ["LAPTOP"])),
                    "Current Observed Behavior": obs_device,
                    "Shift": "⚠️ Unknown Device" if any("Device" in f for f in triggered_names) else "✅ Normal",
                },
                {
                    "Metric": "📦 Download Volume",
                    "Normal Baseline (14 Days)": f"Mean: {base.get('avg_download_mb', 20)} MB (Max: {base.get('max_normal_download_mb', 40)} MB)",
                    "Current Observed Behavior": obs_dl,
                    "Shift": "⚠️ Exfiltration Spike" if any("Download" in f for f in triggered_names) else "✅ Normal",
                },
                {
                    "Metric": "🔒 Resource Access",
                    "Normal Baseline (14 Days)": f"{base.get('department')} low/medium assets",
                    "Current Observed Behavior": obs_res,
                    "Shift": "⚠️ Unauthorized Asset" if any("Asset" in f or "Privilege" in f for f in triggered_names) else "✅ Normal",
                },
            ]
            st.table(pd.DataFrame(shift_table))

            # Raw Event Log for forensic confirmation
            with st.expander("🔍 Forensic Event Trail"):
                st.dataframe(pd.DataFrame(inc_events)[["event_id", "timestamp", "event_type", "resource", "download_mb", "country", "device_id"]], use_container_width=True, hide_index=True)

        st.markdown("---")

        # ---------------------------------------------------------------------
        # Part C: Interactive Decision Console
        # ---------------------------------------------------------------------
        st.subheader("⚡ Human Decision-Support Console")
        st.caption("Record official analyst triage disposition for this incident:")

        a1, a2, a3 = st.columns(3)
        inc_id = sel_inc["incident_id"]

        with a1:
            if st.button("🔒 Lock Employee Account", key=f"btn_lock_{inc_id}", use_container_width=True):
                st.session_state.incident_status_override[inc_id] = "Account Locked & Contained"
                st.error(f"🚨 Action Recorded: {sel_inc['user_name']}'s Active Directory account has been LOCKED.")
                st.rerun()

        with a2:
            if st.button("✅ Dismiss as Benign", key=f"btn_benign_{inc_id}", use_container_width=True):
                st.session_state.incident_status_override[inc_id] = "Dismissed (Benign Overtime)"
                st.success(f"✅ Action Recorded: Incident {inc_id} marked as Expected / Benign.")
                st.rerun()

        with a3:
            if st.button("🚨 Escalate to SOC Tier 2", key=f"btn_esc_{inc_id}", use_container_width=True):
                st.session_state.incident_status_override[inc_id] = "Escalated to Tier 2 IR Team"
                st.warning(f"⚠️ Action Recorded: Incident {inc_id} escalated for forensic disk acquisition.")
                st.rerun()
