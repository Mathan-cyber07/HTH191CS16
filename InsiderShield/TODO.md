# TODO.md — InsiderShield Development Roadmap

## Phase 1 — Project Initialization & Planning [COMPLETED]
- [x] Inspect workspace and environment (Python 3.14.6, Pandas 3.0.5, NumPy 2.5.3).
- [x] Initialize Git repository and `.gitignore`.
- [x] Create project layout (`src/`, `data/`, `tests/`, `docs/`).
- [x] Establish documentation (`PROJECT_SPEC.md`, `DEVELOPMENT_STATUS.md`, `DECISIONS.md`, `TODO.md`, `requirements.txt`).

## Phase 2 — Synthetic Data Generator [COMPLETED]
- [x] Implement user profile generator (50 users across Eng, Finance, HR, Sales, IT, Legal, Marketing).
- [x] Implement baseline activity log generator (normal hours, usual IPs/locations, normal download sizes).
- [x] Implement injection hooks for 5 demo threat scenarios (Compromised Finance, Malicious Dev, Privilege Misuse, Password Attack, Benign Anomaly).
- [x] Export baseline data to CSV (`data/users.csv`, `data/activity_logs.csv`).
- [x] Unit tests for data generation validity and determinism (`tests/test_generator.py`).

## Phase 3 — User Baseline Profiler [COMPLETED]
- [x] Implement `UserBaselineProfiler` in `src/baseline.py`.
- [x] Calculate working hours, known devices, known geolocations, download statistics, allowed depts.
- [x] Export baseline JSON to `data/user_baselines.json`.
- [x] Unit tests for baseline calculation (`tests/test_baseline.py`).

## Phase 4 — Explainable Detection Rules Engine [COMPLETED]
- [x] Implement discrete rule checks in `src/detector.py` (8 rules: Off-hours, New location, Unknown device, Sensitive resource, Abnormal download, Role mismatch, Failed login burst, Impossible travel).
- [x] Implement structured explanation generation for each trigger.
- [x] Unit tests for each detection rule (`tests/test_detector.py`).

## Phase 5 — Risk Scoring & Severity [COMPLETED]
- [x] Implement `RiskScorer` in `src/scorer.py` (base weights + pattern bonus, capped at 100).
- [x] Implement severity classification (Low, Medium, High, Critical).
- [x] Unit tests for risk scoring math and edge cases (`tests/test_scorer.py`).

## Phase 6 — Incident Correlation [COMPLETED]
- [x] Implement sliding-window incident aggregation in `src/correlator.py`.
- [x] Group events by user into incidents with aggregated reason trails and output `data/incidents.json`.
- [x] Unit tests for incident correlation (`tests/test_correlator.py`).

## Phase 7 — Investigator Prioritization Queue [COMPLETED]
- [x] Implement capacity-aware queue in `src/queue.py` (N investigator slots).
- [x] Rank incidents by multi-signal priority formula with active vs. deferred backlog split.
- [x] Unit tests for prioritization logic (`tests/test_queue.py`).

## Phase 8 — SOC Streamlit Dashboard [COMPLETED]
- [x] Implement `app.py` with 4-view layout:
  - Page 1: Executive Overview Dashboard with KPIs, severity bar chart, dept pie chart, and anomaly timeline.
  - Page 2: Capacity-Aware Investigation Queue table with active vs. deferred backlog expander.
  - Page 3: Incident Deep-Dive with risk score gauge, explainable factors checklist, raw event table, and analyst action buttons.
  - Page 4: Side-by-Side Baseline vs Anomaly Comparison table + Bonus baseline drift chart over time.

## Phase 9 — Demo Scenarios & Interactive Controls [COMPLETED]
- [x] Add interactive scenario injector buttons directly in Streamlit sidebar.
- [x] Dynamic capacity adjustment slider with real-time slot re-allocation.
- [x] In-app analyst status update triggers (Mark Investigating, Benign, Escalate, Close).

## Phase 10 — Testing, Polish, Documentation & Pitch Prep [COMPLETED]
- [x] Run full end-to-end test suite (33/33 passing tests).
- [x] Prepare `docs/demo_script.md` with step-by-step 3-minute hackathon pitch narrative.
- [x] Syntax verification and clean packaging.
