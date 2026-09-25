# 🛡️ InsiderShield
### Explainable, Capacity-Aware Insider Threat Detection System

> **HTH-CS-07** · Hackathon Project · Python + Streamlit · Production-Ready

InsiderShield is an **interactive SOC (Security Operations Center) simulator** that detects, explains, and contains insider threats in real time. It combines behavioral anomaly detection, a capacity-aware triage queue, and a full employee portal — all in one dashboard built for both security analysts and non-technical judges.

---

## 📋 Table of Contents

1. [What Does It Do?](#-what-does-it-do)
2. [Quick Start](#-quick-start)
3. [Project Structure](#-project-structure)
4. [The 4 Dashboard Views](#-the-4-dashboard-views)
5. [Demo Walkthrough (Step-by-Step)](#-demo-walkthrough-step-by-step)
6. [Architecture & Data Pipeline](#-architecture--data-pipeline)
7. [Running Tests](#-running-tests)
8. [Configuration & Customization](#-configuration--customization)
9. [Troubleshooting](#-troubleshooting)

---

## 🔍 What Does It Do?

InsiderShield monitors employee activity logs and flags **insider threats** using 8 explainable behavioral rules — no black-box AI. When a threat is detected, it:

- **Scores** it with a deterministic risk formula (0–100)
- **Correlates** related events into a single incident
- **Queues** it within a configurable analyst capacity limit (prevents SOC burnout)
- **Explains** exactly which rules triggered and why
- **Automates containment** via a configurable SOAR policy
- **Simulates** the employee's perspective when their account gets locked

---

## ⚡ Quick Start

### Prerequisites

- Python **3.10+** (tested on 3.14)
- pip

### 1 · Clone the Repository

```bash
git clone <your-repo-url>
cd InsiderShield
```

### 2 · Install Dependencies

```bash
pip install -r requirements.txt
```

### 3 · Run the Dashboard

```bash
streamlit run app.py
```

Your browser will open automatically at **`http://localhost:8501`**.

> **VS Code users:** Press `F5` or use the pre-configured `Run InsiderShield App` launch task.

---

## 📁 Project Structure

```
InsiderShield/
│
├── app.py                  # ← Main Streamlit dashboard (run this)
├── requirements.txt        # Python dependencies
│
├── src/                    # Backend engine modules
│   ├── generator.py        # Synthetic data generator & attack scenario injector
│   ├── baseline.py         # 14-day behavioral profiler per employee
│   ├── detector.py         # 8-rule explainable anomaly detector
│   ├── scorer.py           # Deterministic risk scorer (0–100)
│   ├── correlator.py       # 30-min sliding window incident correlator
│   ├── queue.py            # Capacity-aware priority triage queue
│   └── pipeline.py         # End-to-end CLI pipeline runner
│
├── data/                   # Generated data files (auto-created)
│   ├── users.csv           # 50 synthetic employees
│   ├── activity_logs.csv   # 14 days normal + 5 attack scenarios
│   ├── user_baselines.json # Per-employee behavioral baselines
│   └── incidents.json      # Correlated incident records
│
├── tests/                  # pytest test suite (34 tests)
│   ├── test_generator.py
│   ├── test_baseline.py
│   ├── test_detector.py
│   ├── test_scorer.py
│   ├── test_correlator.py
│   └── test_queue.py
│
└── docs/
    └── demo_script.md      # Guided demo script for presentations
```

---

## 🖥️ The 4 Dashboard Views

Navigate between views using the **sidebar radio buttons**.

---

### 🎮 View 1 — Attack Simulator & Live Stream

The entry point. Choose from **5 pre-built attack scenarios** or run a 100-event enterprise stress test.

| Scenario | Employee | Threat Type | Expected Severity |
|---|---|---|---|
| **A** | Rajesh Sharma (EMP_014) | Stolen Credentials — Russian IP + 2 GB payroll exfiltration | 🔴 Critical |
| **B** | Vikram Iyer (EMP_022) | Disgruntled Developer — midnight 3.5 GB source code download | 🔴 Critical |
| **C** | Priya Patel (EMP_008) | Privilege Misuse — Sales rep accessing HR salary files | 🟠 High |
| **D** | Sneha Reddy (EMP_031) | Brute-Force Attack — 6 failed logins + SSN theft | 🔴 Critical |
| **E** | Karthik Menon (EMP_005) | False Positive Test — IT admin working late (benign) | 🟢 Low |

**Click any `LAUNCH X` button** → the system ingests the scenario and shows a live log stream with rule-by-rule evaluations.

**100-Event Enterprise Stress Test** → simulates a full corporate workday (85–90 benign + 5–10 noise + 5 real threats) to demonstrate noise filtering and queue capacity management.

---

### 🎯 View 2 — Capacity-Aware Triage Queue

Shows how InsiderShield **prevents SOC analyst burnout** by limiting active slots.

- **Analyst Slots (N):** Configurable 1–5 via the sidebar slider (default: 3)
- The **Top-N highest-priority incidents** are assigned to investigators
- All remaining incidents are held in a **Deferred Backlog** — visible but not overloading analysts

**Priority Formula:**
```
Priority Score = (Risk Score × 0.6) + (Rule Violations × 10) + (Asset Sensitivity × 20)
```

---

### 🔍 View 3 — Explainable Incident Investigator

The analyst's deep-dive console. Select any incident to see:

**📋 8-Rule Explainability Checklist** — Every rule is shown as PASSED (green) or VIOLATED (red):
1. Off-Hours Activity (+15 pts)
2. Anomalous Country/Location (+20 pts)
3. Unregistered Device (+15 pts)
4. Critical Asset Access (+20 pts)
5. Abnormal Download Volume (+20 pts)
6. Cross-Department Privilege Anomaly (+25 pts)
7. Failed Login Burst (+15 pts)
8. Impossible Travel (+25 pts)

**⚖️ Behavioral Shift Matrix** — Side-by-side table of the employee's 14-day learned baseline vs. what was actually observed.

**⚡ SOAR Automated Policy Controls:**
- Toggle: `Enable Automated Containment Policy`
- Slider: `Automated Ban Threshold (0–100, default 80)`
- When enabled: any incident scoring ≥ threshold is **automatically suspended** — no analyst click required
- Status badge shows `⚡ AUTO-CONTAINMENT ACTIVE` (green) or `🟡 MANUAL MODE` (amber)

**Analyst Action Buttons:**
| Button | Effect |
|---|---|
| 🔒 Lock / Suspend Account | Manually suspends the employee |
| 🔓 Un-Ban / Restore Access | Restores access; protects user from immediate re-ban |
| ✅ Dismiss as Benign | Marks incident as a false positive |
| 🚨 Escalate to SOC Tier 2 | Routes to forensic investigation team |

---

### 👤 View 4 — Employee Portal Simulator

Experience the **end-user perspective**. Log in as any of the 5 demo employees.

**If account is Active (`🟢 LOGGED IN`):**
- See the corporate intranet with authorized app tiles
- Click **`💥 SIMULATE 100-POINT CRITICAL ATTACK`** to inject a live credential-theft scenario (Russian IP + 2 GB payroll export) under that account

**If account is Suspended (`🚫 ACCESS DENIED`):**
- The session is immediately terminated
- The lockout banner shows **exactly why** the account was suspended:
  - `⚡ AUTOMATED SOAR POLICY` — suspended by the auto-containment rule
  - `🔒 MANUAL ANALYST ACTION` — suspended manually by an analyst
- The login form is disabled with `"Access Denied: Contact IT Security"`

> **Reviewer tip:** Go to View 3 and click `[🔓 Un-Ban / Restore Access]` → return to View 4 to see the session instantly re-activate!

---

## 🎬 Demo Walkthrough (Step-by-Step)

Perfect for a live hackathon presentation:

### Act 1 — Baseline Simulation
1. Open the app → you're in **View 1**
2. Click **`LAUNCH A`** (Stolen Credentials) → watch the live log stream flag off-hours login, foreign IP, and mass download
3. Navigate to **View 2** → observe Rajesh Sharma occupying Slot #1 with Score 100/100

### Act 2 — Investigator Explainability
4. Navigate to **View 3** → select Rajesh Sharma's incident
5. Walk through the **8-Rule Checklist** — show exactly which rules fired and why
6. Point to the **Behavioral Shift Matrix** — show "Normal: India" vs "Observed: Russia"

### Act 3 — SOAR Automated Policy
7. Still in View 3, **toggle ON** "Enable Automated Containment Policy" (threshold = 80)
8. The system **instantly auto-suspends** Rajesh Sharma — badge turns `🔴 AUTO-SUSPENDED BY POLICY`

### Act 4 — Employee Portal Impact
9. Navigate to **View 4** → select EMP_014 (Rajesh Sharma)
10. Show the red **`🚫 ACCESS DENIED`** screen with `⚡ AUTOMATED SOAR POLICY` trigger label
11. Go back to View 3 → click **`🔓 Un-Ban / Restore Access`**
12. Return to View 4 → session is instantly active again (`🟢 LOGGED IN`)

### Act 5 — Enterprise Stress Test
13. Go to **View 1** → click **`🚀 LAUNCH 100 THREAT ALERTS SIMULATION`**
14. Navigate to **View 2** → show 83 suppressed, 17 flagged, Top-3 slots occupied, 14 in backlog

---

## 🏗️ Architecture & Data Pipeline

```
Raw Activity Logs (activity_logs.csv)
          │
          ▼
  [Detector] — 8-Rule Heuristic Engine
  Evaluates each event against user's behavioral baseline
          │
          ▼
  [Scorer] — Deterministic Risk Scorer
  Composite score (0–100) + severity bracket
          │
          ▼
  [Correlator] — 30-min Sliding Window
  Groups related events into a single Incident
          │
          ▼
  [Queue Manager] — Capacity-Aware Triage
  Routes Top-N to analysts, defers the rest
          │
          ▼
  [Streamlit Dashboard] — 4-View SOC Console
  Visualize · Explain · Contain · Simulate
```

### Detection Rules Engine (`src/detector.py`)

Each rule is deterministic and auditable:

| Rule | Points | Trigger Condition |
|---|---|---|
| Off-Hours Activity | +15 | Login outside `09:00–18:00` baseline window |
| Anomalous Country | +20 | Country not in employee's 14-day known locations |
| Unregistered Device | +15 | Device ID not in employee's known device list |
| Critical Asset Access | +20 | Resource sensitivity = `critical` |
| Abnormal Download | +20 | Download > 2× the employee's historical max |
| Cross-Dept Privilege | +25 | Access to another department's resources |
| Failed Login Burst | +15 | ≥3 failed logins within a 5-minute window |
| Impossible Travel | +25 | Country change faster than physically possible |

---

## 🧪 Running Tests

```bash
# Run full test suite
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_detector.py -v

# Run with coverage (if pytest-cov installed)
python -m pytest tests/ --cov=src --cov-report=term-missing
```

**Current status: 34/34 tests passing ✅**

| Test File | Tests | Coverage Area |
|---|---|---|
| `test_generator.py` | 10 | Data generation, scenario injection |
| `test_baseline.py` | 3 | Baseline profiling and serialization |
| `test_detector.py` | 9 | All 8 detection rules |
| `test_scorer.py` | 6 | Risk scoring, caps, severity brackets |
| `test_correlator.py` | 3 | Event correlation, time windows |
| `test_queue.py` | 3 | Capacity limits, priority ranking |

---

## ⚙️ Configuration & Customization

### Analyst Capacity
Adjust the **"Active Human Investigator Slots"** slider in the sidebar (1–5). This controls how many incidents are actively worked at once.

### SOAR Policy Threshold
In **View 3**, use the **"Automated Ban Threshold"** slider (0–100, default 80). Set lower (e.g., 60) to be more aggressive; set higher (e.g., 95) to be more conservative.

### Adding New Scenarios
Edit `src/generator.py` — add a new scenario function following the pattern of `inject_scenario_a()` through `inject_scenario_e()`.

### Changing Baseline Days
In `src/baseline.py`, modify the `window_days` parameter (default: 14) to change how many days of history the profiler uses.

---

## 🔧 Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | Run `pip install -r requirements.txt` |
| App shows "No incidents" | Click any **LAUNCH** button in View 1 first |
| `data/user_baselines.json` not found | Run `python src/pipeline.py` once to generate all data files |
| Port 8501 already in use | Run `streamlit run app.py --server.port 8502` |
| Tests fail | Ensure you're in the `InsiderShield/` root directory when running `pytest` |

---

## 📄 License

This project was built for **HTH-CS-07 Hackathon**. For educational and demonstration purposes.

---

<div align="center">
  <b>Built with Python · Streamlit · Plotly · pandas</b><br/>
  <i>InsiderShield — Because every breach starts from within.</i>
</div>
