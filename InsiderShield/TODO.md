# TODO.md — InsiderShield Development Roadmap

## Phase 1 — Project Initialization & Planning [COMPLETED]
- [x] Inspect workspace and environment (Python 3.14.6, Pandas 3.0.5, NumPy 2.5.3).
- [x] Initialize Git repository and `.gitignore`.
- [x] Create project layout (`src/`, `data/`, `tests/`, `docs/`).
- [x] Establish documentation (`PROJECT_SPEC.md`, `DEVELOPMENT_STATUS.md`, `DECISIONS.md`, `TODO.md`, `requirements.txt`).

## Phase 2 — Synthetic Data Generator
- [ ] Implement user profile generator (20–50 users across Eng, Finance, HR, Sales, IT).
- [ ] Implement baseline activity log generator (normal hours, usual IPs/locations, normal download sizes).
- [ ] Implement injection hooks for 5 demo threat scenarios (Compromised Finance, Malicious Dev, Privilege Misuse, Password Attack, Benign Anomaly).
- [ ] Export baseline data to CSV (`data/users.csv`, `data/activity_logs.csv`).
- [ ] Unit tests for data generation validity and determinism (`tests/test_generator.py`).

## Phase 3 — User Baseline Profiler
- [ ] Implement `BaselineProfiler` in `src/baseline.py`.
- [ ] Calculate working hours/days, known devices, known geolocations, download volume statistics (mean, std, max).
- [ ] Unit tests for baseline calculation (`tests/test_baseline.py`).

## Phase 4 — Explainable Detection Rules Engine
- [ ] Implement discrete rule checks in `src/detector.py` (Off-hours, New location, Unknown device, Sensitive resource, Abnormal download, Role mismatch, Failed login burst, Impossible travel).
- [ ] Implement structured explanation generation for each trigger.
- [ ] Unit tests for each detection rule (`tests/test_detector.py`).

## Phase 5 — Risk Scoring & Severity
- [ ] Implement `RiskScorer` in `src/scorer.py` (base weights + asset sensitivity + sequence bonus, capped at 100).
- [ ] Implement severity classification (Low, Medium, High, Critical).
- [ ] Unit tests for risk scoring math and edge cases (`tests/test_scorer.py`).

## Phase 6 — Incident Correlation
- [ ] Implement sliding-window incident aggregation in `src/correlation.py`.
- [ ] Group events by user/entity into incidents with aggregated reason trails.
- [ ] Unit tests for incident correlation (`tests/test_correlation.py`).

## Phase 7 — Investigator Prioritization Queue
- [ ] Implement capacity-aware queue in `src/queue.py` (e.g. 3 active investigator slots).
- [ ] Rank incidents by severity, risk score, and recency with transparent justification.
- [ ] Unit tests for prioritization logic (`tests/test_queue.py`).

## Phase 8 — SOC Streamlit Dashboard
- [ ] Implement `app.py` with multi-view layout:
  - Executive/SOC overview (total events, open incidents, investigator capacity gauge).
  - Ranked incident triage queue with explanation cards.
  - Incident deep dive (timeline of events, triggered rules breakdown).
  - User profile & baseline inspection view.
- [ ] Interactive filtering (by department, severity, time range).

## Phase 9 — Demo Scenarios & Interactive Controls
- [ ] Add interactive scenario injector buttons directly in Streamlit sidebar/controls.
- [ ] Verify that all 5 target scenarios trigger accurately and explain themselves clearly.

## Phase 10 — Testing, Polish, Documentation & Pitch Prep
- [ ] Run full end-to-end test suite.
- [ ] Prepare `docs/demo_script.md` with step-by-step 3-minute hackathon pitch narrative.
- [ ] Final UI styling and bug fixes.
