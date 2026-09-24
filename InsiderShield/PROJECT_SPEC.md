# PROJECT_SPEC.md — InsiderShield (HTH-CS-07)

## 1. Project Overview
* **Project Name**: InsiderShield
* **Problem**: Insider threats are notoriously subtle, hard to detect with perimeter security, and often handled by black-box ML models that analysts cannot easily trust or verify.
* **Goal**: Build an explainable, decision-support behavioral anomaly detector for SOC analysts that monitors synthetic user activity, computes normal individual baselines, flags and explains deviations transparently, correlates events into prioritized incidents, and respects human investigator capacity.
* **Philosophy**: Decision-support only; strictly no automated punitive/adverse actions against employees.

---

## 2. Core Components & Architecture
1. **Synthetic Data Generation (`src/generator.py`)**:
   * Generates realistic baseline activity logs (20–50 users across multiple departments).
   * Injects 4–6 specific insider threat demo scenarios (compromised accounts, malicious dev data exfiltration, privilege misuse, password brute-force, benign anomalies).
2. **User Baseline Profiler (`src/baseline.py`)**:
   * Tracks normal login hours, active days, usual countries/cities, known devices, typical download volumes, typical systems/sensitivity, failed login rates per user.
3. **Explainable Rule Engine (`src/detector.py`)**:
   * Evaluates logs against baselines with discrete, explainable detection rules (e.g. off-hours login +15, new country +20, unknown device +15, abnormal download +20, impossible travel +25, etc.).
   * Generates explicit human-readable reasons for every point awarded.
4. **Risk & Severity Scorer (`src/scorer.py`)**:
   * Computes deterministic composite score: `Base Rule Points + Asset Sensitivity Bonus + Correlation Bonus` (capped at 100).
   * Maps to severity bands: Low (0–24), Medium (25–49), High (50–74), Critical (75–100).
5. **Incident Correlator (`src/correlation.py`)**:
   * Clusters related anomaly events by user, device, and temporal proximity (e.g. 30–60 min window) into unified security incidents.
6. **Capacity-Aware Investigator Queue (`src/queue.py`)**:
   * Ranks incidents based on severity, score, and confidence, allocating them across finite analyst slots (e.g. 3 investigators) with clear workload indicators.
7. **SOC Dashboard (`app.py`)**:
   * Streamlit-based analyst console featuring summary metrics, ranked incident queue, incident deep dive, user profile baseline view, and demo scenario triggers.

---

## 3. Data Schema
* **User Profile**: `user_id`, `user_name`, `department`, `role`, `work_hours`, `work_days`, `known_devices`, `known_locations`, `avg_download_mb`, `max_download_mb`, `allowed_resources`.
* **Activity Event**: `timestamp`, `user_id`, `user_name`, `department`, `role`, `event_type`, `source_ip`, `country`, `city`, `device_id`, `known_device`, `resource`, `resource_sensitivity`, `download_mb`, `login_status`.
* **Anomaly Flag**: `event_id`, `rule_id`, `rule_name`, `points`, `explanation`.
* **Incident**: `incident_id`, `user_id`, `severity`, `total_score`, `event_count`, `time_window`, `explanation_summary`, `investigator_assigned`, `status`.

---

## 4. Boundaries & Exclusions
* No external cloud infrastructure, Docker, Kubernetes, or microservices.
* No Node.js / React frontend (Pure Python + Streamlit).
* No real-world user surveillance or invasive agents.
* No opaque uninterpretable ML models for MVP.
