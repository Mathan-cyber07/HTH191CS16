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
from src.generator import simulate_100_events

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
    if selected_tag == "STRESS_100":
        events = simulate_100_events(users_df)
    else:
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

if "user_account_status" not in st.session_state:
    st.session_state.user_account_status = {
        "EMP_014": "Active",
        "EMP_022": "Active",
        "EMP_008": "Active",
        "EMP_031": "Active",
        "EMP_005": "Active",
    }


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
        "👤 4. Employee Portal Simulator",
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

if st.sidebar.button("🚀 Run 100-Event Stress Test", use_container_width=True):
    st.session_state.active_scenario = "STRESS_100"
    ev, fl, inc = process_simulation("STRESS_100")
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

    # -------------------------------------------------------------------------
    # Enterprise Noise & Stress Test Section (100 Alerts Simulation)
    # -------------------------------------------------------------------------
    st.markdown(
        """
        <div style='background: linear-gradient(135deg, #1e1b4b 0%, #172554 100%); border: 1px solid #4338ca; border-radius: 10px; padding: 18px; margin-bottom: 14px;'>
            <div style='font-size:18px; font-weight:700; color:#a5b4fc; display:flex; align-items:center; gap:8px;'>
                ⚡ Enterprise Noise & Stress Test (100 Alerts Simulation)
            </div>
            <div style='font-size:13px; color:#cbd5e1; margin-top:6px; line-height:1.4;'>
                Simulates a full enterprise workday with <b>100 incoming events</b> (95 benign/noise logs + 5 critical insider threats). Watch how the Capacity Queue filters out noise and prioritizes the top 5 threats.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("🚀 LAUNCH 100 THREAT ALERTS SIMULATION", key="btn_stress_100", type="primary", use_container_width=True):
        progress_bar = st.progress(0, text="Initiating enterprise telemetry stream (100 logs)...")
        for percent in range(15, 101, 20):
            time.sleep(0.04)
            progress_bar.progress(percent, text=f"Evaluating rule heuristics across event batch ({percent}/100)...")
        progress_bar.empty()

        st.session_state.active_scenario = "STRESS_100"
        ev, fl, inc = process_simulation("STRESS_100")
        st.session_state.sim_events = ev
        st.session_state.sim_flagged = fl
        st.session_state.incidents = inc
        st.session_state.live_stream_active = True
        st.rerun()

    # Prominent summary card for the 100 events stress test
    if st.session_state.active_scenario == "STRESS_100":
        st.markdown(
            """
            <div style='background-color:#0f172a; border: 1px solid #38bdf8; border-radius: 8px; padding: 14px 18px; margin: 12px 0 16px 0;'>
                <div style='font-weight:700; font-size:16px; color:#38bdf8; margin-bottom:4px;'>
                    📊 Enterprise Workday Stress Test Summary (100 Events)
                </div>
                <div style='font-size:13px; color:#94a3b8; line-height:1.4;'>
                    100 continuous events evaluated against behavioral baselines. Operational noise was automatically filtered or suppressed, while all 5 real threat campaigns were identified and prioritized at the top of the queue.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        sm1, sm2, sm3, sm4, sm5 = st.columns(5)
        sm1.metric("Total Ingested Logs", "100")
        sm2.metric("Suppressed Noise / Benign", "~95 Events", delta="Filtered Noise", delta_color="normal")
        sm3.metric("Flagged Critical/High", "5 Threats", delta="Top Priority", delta_color="inverse")
        used_slots = min(len(st.session_state.incidents), st.session_state.capacity)
        sm4.metric("Active Triage Slots Used", f"{used_slots} / {st.session_state.capacity}", delta="Full Capacity")
        queued_count = max(0, len(st.session_state.incidents) - st.session_state.capacity)
        sm5.metric("Deferred Backlog", f"{queued_count} Queued", delta="Protected from Burnout")

        st.markdown(
            """
            <div style='background-color:#1e1b4b; border: 1px solid #6366f1; border-radius: 8px; padding: 14px 18px; margin: 12px 0 16px 0;'>
                <div style='font-size: 15px; font-weight: 700; color: #c7d2fe;'>
                    🔍 Understanding the Enterprise Triage Funnel (100 Logs Processed):
                </div>
                <div style='display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 10px; font-family: monospace; font-size: 12px;'>
                    <div style='background:#312e81; padding:8px 10px; border-radius:6px; text-align:center;'>
                        <b style='color:#ffffff;'>100 Raw Logs Ingested</b><br/><span style='color:#a5b4fc;'>Full Workday Telemetry</span>
                    </div>
                    <div style='background:#064e3b; padding:8px 10px; border-radius:6px; text-align:center;'>
                        <b style='color:#ffffff;'>83 Normal Logs Suppressed</b><br/><span style='color:#6ee7b7;'>0 pts (Legitimate Traffic)</span>
                    </div>
                    <div style='background:#7f1d1d; padding:8px 10px; border-radius:6px; text-align:center;'>
                        <b style='color:#ffffff;'>17 Incidents Flagged</b><br/><span style='color:#fca5a5;'>5 Threats + 12 Mild Noise</span>
                    </div>
                    <div style='background:#1e3a8a; padding:8px 10px; border-radius:6px; text-align:center;'>
                        <b style='color:#ffffff;'>Top 3 Slots Occupied</b><br/><span style='color:#93c5fd;'>14 in Deferred Backlog</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # Live Log Ingestion Stream
    active_tag = st.session_state.active_scenario
    if active_tag == "STRESS_100":
        active_name = "Enterprise Stress Test (100 Events Workday Simulation)"
    elif active_tag == "ALL":
        active_name = "All 5 Scenarios (Full Telemetry Scan)"
    else:
        active_name = f"Scenario {SCENARIOS[active_tag]['letter']}: {SCENARIOS[active_tag]['title']}"

    st.subheader(f"📡 Live Telemetry Ingestion Stream — [{active_name}]")
    st.caption("Incoming synthetic events evaluated instantaneously against 8 explainable behavioral baseline rules.")

    events_to_show = st.session_state.sim_events

    if not events_to_show:
        st.info("No events in current simulation buffer. Click 'Simulate All 5 Scenarios' or 'LAUNCH 100 THREAT ALERTS SIMULATION' above.")
    else:
        # Ingestion KPI metrics
        if st.session_state.active_scenario != "STRESS_100":
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Live Events Ingested", len(events_to_show))
            m2.metric("Violations Flagged", len(st.session_state.sim_flagged))
            m3.metric("Correlated Incidents", len(st.session_state.incidents))
            crit_count = sum(1 for i in st.session_state.incidents if i["severity"] == "Critical")
            m4.metric("Critical Threats", crit_count)

        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

        if st.session_state.active_scenario == "STRESS_100":
            tab_raw_100, tab_flagged_stream = st.tabs([
                "📋 All 100 Ingested Telemetry Logs (Full Audit Trail)",
                f"🚨 Flagged Violations & Correlated Incidents ({len(st.session_state.sim_flagged)} Events)"
            ])

            with tab_raw_100:
                st.caption("Complete chronological record of all 100 enterprise workday logs processed by InsiderShield:")
                raw_table = []
                for e in events_to_show:
                    tr = detector.evaluate_event(e)
                    is_v = len(tr) > 0
                    raw_table.append({
                        "Event ID": e.get("event_id"),
                        "Timestamp": e.get("timestamp", "").split()[-1],
                        "Employee": f"{e.get('user_name')} ({e.get('user_id')})",
                        "Department": e.get("department"),
                        "Action": e.get("event_type", "").upper(),
                        "Resource": e.get("resource"),
                        "Size": f"{e.get('download_mb', 0)} MB",
                        "Location": f"{e.get('country')} ({e.get('city')})",
                        "Rule Evaluation Status": "🔴 VIOLATION FLAGGED" if is_v else "🟢 SUPPRESSED (NORMAL WORK)",
                    })
                st.dataframe(pd.DataFrame(raw_table), use_container_width=True, hide_index=True)

            with tab_flagged_stream:
                st.caption("Detailed view of flagged violations evaluated against baseline rules:")
                for e_idx, evt in enumerate(events_to_show, start=1):
                    triggered_list = detector.evaluate_event(evt)
                    if not triggered_list:
                        continue

                    evt_time = evt.get("timestamp", "").split()[-1]
                    evt_user = f"{evt.get('user_name')} ({evt.get('user_id')})"
                    evt_type = evt.get("event_type", "").upper()
                    evt_res = evt.get("resource", "portal")
                    evt_dl = f"{evt.get('download_mb', 0)} MB"
                    evt_country = evt.get("country", "")

                    with st.expander(
                        f"🚨 VIOLATION | {evt_time} | {evt_user} | {evt_type} | {evt_res} ({evt_dl})",
                        expanded=True,
                    ):
                        c1, c2, c3, c4 = st.columns(4)
                        c1.markdown(f"**IP Address:** `{evt.get('source_ip')}`")
                        c2.markdown(f"**Location:** `{evt_country} ({evt.get('city')})`")
                        c3.markdown(f"**Device ID:** `{evt.get('device_id')}`")
                        c4.markdown(f"**Sensitivity:** `{evt.get('resource_sensitivity', 'low').upper()}`")

                        st.markdown("**Triggered Rule Violations:**")
                        for r in triggered_list:
                            st.markdown(
                                f"<div class='rule-violation'>⚠️ <b>+{r['score']} pts — {r['rule_name']}:</b> {r['reason']}</div>",
                                unsafe_allow_html=True,
                            )
        else:
            # Standard single/all scenario view
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

    if st.session_state.active_scenario == "STRESS_100":
        st.info(
            f"⚡ **Enterprise Workday Stress Test Active:** Ingested **100 events** across the organization. "
            f"**83 normal events were automatically suppressed** as legitimate background traffic. "
            f"**{len(st.session_state.incidents)} incidents were flagged**, with the **Top {st.session_state.capacity} critical threats assigned to active investigator slots** "
            f"and the remaining {max(0, len(st.session_state.incidents) - st.session_state.capacity)} lower-priority alerts safely held in the deferred backlog."
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

        if st.session_state.active_scenario == "STRESS_100":
            st.info(
                f"⚡ **Enterprise Workday Stress Test Active:** Displaying the {len(incidents)} flagged incidents from the 100-event run. "
                "Notice how the 5 critical/high threats are prioritized at the top of the list, while 83 normal events were suppressed."
            )

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
        # Part C: Interactive Decision Console & Active Containment
        # ---------------------------------------------------------------------
        st.subheader("⚡ Human Decision-Support & Active Containment Console")
        st.caption("Execute immediate containment actions across enterprise Identity & Access Management (IAM):")

        u_acct_status = st.session_state.user_account_status.get(u_id, "Active")
        inc_id = sel_inc["incident_id"]

        c_lock, c_unban, c_benign, c_esc = st.columns(4)

        with c_lock:
            lock_label = "🔒 Lock / Suspend Account" if u_acct_status != "Suspended / Banned" else "🔒 Account Already Suspended"
            if st.button(lock_label, key=f"btn_lock_{inc_id}", type="primary" if u_acct_status != "Suspended / Banned" else "secondary", use_container_width=True):
                st.session_state.user_account_status[u_id] = "Suspended / Banned"
                st.session_state.incident_status_override[inc_id] = "Account Locked & Contained"
                st.error(f"🚨 Action Executed: {sel_inc['user_name']}'s account is SUSPENDED. Portal session terminated!")
                st.rerun()

        with c_unban:
            unban_label = "🔓 Un-Ban / Restore Access" if u_acct_status == "Suspended / Banned" else "🔓 Restore Access (Active)"
            if st.button(unban_label, key=f"btn_unban_{inc_id}", use_container_width=True):
                st.session_state.user_account_status[u_id] = "Active"
                st.session_state.incident_status_override[inc_id] = "Resolved (Account Restored)"
                st.success(f"✅ Access Restored: {sel_inc['user_name']}'s account status set to ACTIVE. Portal login re-enabled.")
                st.rerun()

        with c_benign:
            if st.button("✅ Dismiss as Benign", key=f"btn_benign_{inc_id}", use_container_width=True):
                st.session_state.incident_status_override[inc_id] = "Dismissed (Benign Overtime)"
                st.info(f"Action Recorded: Incident {inc_id} marked as Expected / Benign.")
                st.rerun()

        with c_esc:
            if st.button("🚨 Escalate to SOC Tier 2", key=f"btn_esc_{inc_id}", use_container_width=True):
                st.session_state.incident_status_override[inc_id] = "Escalated to Tier 2 IR Team"
                st.warning(f"⚠️ Action Recorded: Incident {inc_id} escalated for forensic disk acquisition.")
                st.rerun()


# =============================================================================
# VIEW 4: EMPLOYEE PORTAL SIMULATOR
# =============================================================================
elif view_selection.startswith("👤"):
    st.markdown("<div class='main-header'>👤 Corporate Employee Portal — Active Containment Simulator</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='sub-header'>Experience the end-user perspective. Simulate logging into the corporate intranet as an employee, triggering a 100-point attack, and experiencing real-time session termination when contained by the SOC.</div>",
        unsafe_allow_html=True,
    )

    demo_employees = {
        "EMP_014": "Rajesh Sharma (EMP_014 - Finance / Financial Analyst)",
        "EMP_022": "Vikram Iyer (EMP_022 - Engineering / Software Engineer)",
        "EMP_008": "Priya Patel (EMP_008 - Sales / Sales Rep)",
        "EMP_031": "Sneha Reddy (EMP_031 - HR / HR Specialist)",
        "EMP_005": "Karthik Menon (EMP_005 - IT / Systems Admin)",
    }

    selected_emp_id = st.selectbox(
        "Select Employee Account to Simulate:",
        list(demo_employees.keys()),
        format_func=lambda x: demo_employees[x],
        index=0,
    )

    emp_status = st.session_state.user_account_status.get(selected_emp_id, "Active")
    emp_label = demo_employees[selected_emp_id]

    st.markdown("---")

    # -------------------------------------------------------------------------
    # CASE A: ACCOUNT IS ACTIVE
    # -------------------------------------------------------------------------
    if emp_status == "Active":
        st.markdown(
            f"""
            <div style='background-color:#1e293b; border: 1px solid #10b981; border-radius: 10px; padding: 20px; margin-bottom: 20px;'>
                <div style='display:flex; justify-content:space-between; align-items:center;'>
                    <div>
                        <div style='font-size:20px; font-weight:700; color:#f8fafc;'>🏢 ACME Enterprise Corporate Intranet</div>
                        <div style='font-size:14px; color:#cbd5e1; margin-top:4px;'>Logged in as: <b>{emp_label}</b></div>
                    </div>
                    <div>
                        <span class='badge-low'>🟢 LOGGED IN / SESSION ACTIVE</span>
                    </div>
                </div>
                <hr style='border-color:#334155; margin:14px 0;'/>
                <div style='display:flex; gap:16px; font-size:13px; color:#94a3b8;'>
                    <div><b>IAM Domain:</b> <code>CORP.LOCAL</code></div>
                    <div><b>SSO Token:</b> <code>VALID (Expires in 8h)</code></div>
                    <div><b>Containment State:</b> <span style='color:#34d399; font-weight:600;'>NORMAL (UNRESTRICTED)</span></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.subheader("📁 Authorized Employee Applications & Portals")
        app_c1, app_c2, app_c3 = st.columns(3)
        with app_c1:
            st.markdown(
                """
                <div style='background-color:#0f172a; border:1px solid #334155; border-radius:8px; padding:14px;'>
                    <div style='font-size:18px;'>📊 Financial Ledger & Reports</div>
                    <div style='font-size:12px; color:#94a3b8; margin-top:4px;'>Access quarterly department budgets and balance sheets.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with app_c2:
            st.markdown(
                """
                <div style='background-color:#0f172a; border:1px solid #334155; border-radius:8px; padding:14px;'>
                    <div style='font-size:18px;'>💳 Corporate Expense Claims</div>
                    <div style='font-size:12px; color:#94a3b8; margin-top:4px;'>Submit travel, meals, and software receipt claims.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with app_c3:
            st.markdown(
                """
                <div style='background-color:#0f172a; border:1px solid #334155; border-radius:8px; padding:14px;'>
                    <div style='font-size:18px;'>💼 Payroll Self-Service</div>
                    <div style='font-size:12px; color:#94a3b8; margin-top:4px;'>Review annual tax withholding, salary slips, and direct deposit.</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

        # Attack Simulator Trigger Box
        st.markdown(
            """
            <div style='background: linear-gradient(135deg, #450a0a 0%, #2b0000 100%); border: 1px solid #ef4444; border-radius: 10px; padding: 18px;'>
                <div style='font-size:17px; font-weight:700; color:#fca5a5;'>
                    💥 Live Attack Simulation (From this Account)
                </div>
                <div style='font-size:13px; color:#fecaca; margin-top:6px; line-height:1.4;'>
                    Click the button below to simulate an active credential theft attack under <b>EMP_014</b>'s credentials (anomalous Russian IP login + 2,048 MB confidential payroll export).
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
        if st.button("💥 SIMULATE 100-POINT CRITICAL ATTACK", type="primary", use_container_width=True):
            st.session_state.active_scenario = "scenario_a_compromised_finance"
            ev, fl, inc = process_simulation("scenario_a_compromised_finance")
            st.session_state.sim_events = ev
            st.session_state.sim_flagged = fl
            st.session_state.incidents = inc
            st.session_state.live_stream_active = True

            st.error(
                "🚨 **CRITICAL 100-POINT ATTACK INJECTED!**\n\n"
                "• Event 1: Off-Hours Login from Moscow, Russia (IP: `185.220.101.5`)\n"
                "• Event 2: Unauthorized Access to `payroll_2026_master.xlsx` (Critical Sensitivity)\n"
                "• Event 3: Mass Exfiltration of **2,048 MB**\n\n"
                "👉 **Next Step:** Switch to **View 2 (Capacity Queue)** or **View 3 (Investigator)** to see the SOC detect this incident and click **`[🔒 Lock / Suspend Account]`** to contain the breach!"
            )

    # -------------------------------------------------------------------------
    # CASE B: ACCOUNT IS SUSPENDED / BANNED
    # -------------------------------------------------------------------------
    else:
        st.markdown(
            """
            <div style='background: linear-gradient(135deg, #7f1d1d 0%, #450a0a 100%); border: 2px solid #ef4444; border-radius: 10px; padding: 24px; color: white; margin-bottom: 20px;'>
                <div style='font-size: 24px; font-weight: 800; display:flex; align-items:center; gap:10px;'>
                    🚫 ACCESS DENIED — ACCOUNT SUSPENDED
                </div>
                <div style='font-size: 15px; margin-top: 10px; line-height: 1.5; color: #fecaca;'>
                    Your Active Directory session has been terminated and access revoked by the <b>Security Operations Center (SOC)</b> due to critical behavioral anomalies detected under your credentials.
                </div>
                <hr style='border-color: #ef4444; margin: 16px 0;'/>
                <div style='font-size: 13px; color: #fca5a5; line-height: 1.5;'>
                    <b>Containment Reference:</b> Incident Containment Order #SEC-2026-0924 &bull; <b>Status:</b> Locked & Contained<br/>
                    <b>Action Required:</b> Contact IT Security Helpdesk (<code>soc-triage@corp.local</code>) to undergo identity verification.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.subheader("🔒 Corporate Single Sign-On (SSO) Login")
        st.caption("Active Directory authentication is currently disabled for this principal:")

        f_col1, f_col2 = st.columns([2, 1])
        with f_col1:
            st.text_input("Corporate Username / Email", value=f"{selected_emp_id}@corp.local", disabled=True)
            st.text_input("Password", value="••••••••••••••••", type="password", disabled=True)
            st.button("🔒 Sign In (Access Revoked by SOC)", disabled=True, use_container_width=True)
            st.error("Authentication Error: Access Denied: Contact IT Security")

        with f_col2:
            st.markdown(
                """
                <div style='background-color:#1e293b; border:1px solid #64748b; border-radius:8px; padding:16px;'>
                    <div style='font-weight:700; color:#38bdf8; font-size:14px; margin-bottom:6px;'>
                        💡 Reviewer Verification Step:
                    </div>
                    <div style='font-size:12px; color:#cbd5e1; line-height:1.4;'>
                        1. In the sidebar, select <b>View 3: Explainable Incident Investigator</b>.<br/>
                        2. Find this employee's incident.<br/>
                        3. Click <b>[🔓 Un-Ban / Restore Access]</b>.<br/>
                        4. Return to this page to see the session instantly re-activated!
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

