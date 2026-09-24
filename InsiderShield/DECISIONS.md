# DECISIONS.md — Architecture & Technical Decision Record

## Decision 1: Rule-First Explainability over Black-Box ML
* **Context**: Insider threats require high explainability for SOC analysts and compliance. ML models like Isolation Forest can output anomaly scores without intuitive justification.
* **Decision**: Implement a deterministic, points-based rule engine with structured text explanations for each flag. Keep ML (Isolation Forest) as a secondary/stretch enhancement only after the rule-based MVP is proven.
* **Impact**: Judges and analysts can immediately verify *why* an alert fired. Zero hallucinations or unexplained score jumps.

## Decision 2: Pure Python + Streamlit Stack
* **Context**: 24-hour hackathon timeline requires rapid iteration without frontend/backend protocol synchronization bottlenecks.
* **Decision**: Use Streamlit with Plotly for interactive dashboards and Pandas/SQLite for in-memory & file-based data processing.
* **Impact**: No Node/npm builds, zero CORS/proxy issues, fast execution, easy live demo.

## Decision 3: Deterministic Data Model & Synthetic Scenarios
* **Context**: Need reproducible demo data for 20–50 users that clearly exhibits distinct insider threat archetypes and benign edge cases.
* **Decision**: Build a seeded synthetic data generator (`src/generator.py`) capable of generating standard operational noise plus 5 distinct, predictable scenario archetypes (Compromised Finance, Malicious Dev, Privilege Misuse, Password Brute-Force, Benign Anomaly).
* **Impact**: Demos are 100% reliable and repeatable in front of hackathon judges.

## Decision 4: Lightweight In-Process Incident Correlation
* **Context**: Individual alerts can flood analysts. We need alert aggregation without heavy enterprise SIEM components.
* **Decision**: Implement a sliding-window time and entity correlator in Python (`src/correlation.py`) grouping alerts by `(user_id, time_window)` into structured incidents with composite scoring.
* **Impact**: Low complexity, instant execution, transparent scoring.
