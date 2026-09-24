# InsiderShield — 3-Minute Hackathon Pitch & Demo Script (HTH-CS-07)

> **Theme**: Explainable, Capacity-Aware Insider Threat Detection  
> **Target Audience**: Hackathon Judges, SOC Managers, Cybersecurity Evaluators  
> **Key Differentiator**: Zero black-box opacity; exact regulatory attribution; respects human analyst fatigue.

---

## 1. The 30-Second Hook

> *"Perimeter firewalls and antivirus don't stop authorized employees who turn rogue or get compromised. Traditional ML anomaly detectors output mysterious numbers like 'Risk: 0.89', leaving SOC analysts confused, fatigued, and distrustful.*  
>  
> *Meet **InsiderShield**: an explainable, decision-support behavioral anomaly detector. Instead of an unexplained score, InsiderShield breaks down every single contributing violation—from off-hours logins to 50x exfiltration surges—and prioritizes them under realistic human investigator capacity."*

---

## 2. 3-Minute Live Demo Walkthrough

### Step 1: Open the SOC Command Center (`app.py`)
* Run: `streamlit run app.py`
* **Highlight on Page 1 (Executive Overview)**:
  * "Notice our live HUD: 2,759 events ingested across 50 employees and 7 departments."
  * "Today's activity immediately flagged correlated incidents across Finance, Engineering, Sales, and IT."
  * Point to the **Analyst Workload Gauge**: *"Our SOC has a strict capacity limit of 3 active investigators. We do not bury our team in 500 alerts."*

---

### Step 2: The Capacity-Aware Priority Queue (Page 2)
* Switch to **Page 2: Capacity-Aware Investigation Queue**.
* Explain the triage algorithm:
  * *Formula*: `Priority = (Risk Score × 0.6) + (Signals × 10) + (Asset Sensitivity × 20)`
* Show the allocation:
  * **Slot 1 (Lead Analyst Sarah)**: Assigned to `INC_003` (Rajesh Sharma - Finance Compromise).
  * **Slot 2 (Forensics Analyst David)**: Assigned to `INC_005` (Sneha Reddy - Password Brute Force to SSN theft).
  * **Slot 3 (Triage Analyst Priya)**: Assigned to `INC_004` (Vikram Iyer - Malicious Developer exfiltrating proprietary code).
  * Expand the **Deferred Backlog**: *"Notice how lower-priority alerts and benign anomalies are gracefully held in backlog rather than overwhelming analysts."*
* **Live Interactive Demo**: Move the sidebar slider from `3` to `5`. Watch the backlog dynamically promote incidents in real-time!

---

### Step 3: Explainable Incident Deep-Dive (Page 3)
* Switch to **Page 3: Incident Deep-Dive & Explanation Checklist**.
* Select `INC_003 (Rajesh Sharma - Finance)`:
  * Point to the **Transparent Risk Score Gauge (100 / 100 - Critical)**.
  * Show the **Explainable Contributing Factors Checklist**:
    * `⚠️ Off-Hours Activity: Activity at 02:15:12 is outside normal work hours (09:00–18:00)`
    * `⚠️ Anomalous Country/Location: Access from 'Russia' is outside user's recognized countries (India)`
    * `⚠️ Unregistered Device: Device 'UNKNOWN_DEV_X9' is not in authorized hardware baseline`
    * `⚠️ Critical Asset Access: Accessed resource 'payroll_2026_master.xlsx' with 'CRITICAL' sensitivity`
    * `⚠️ Abnormal Download Volume: Download volume of 2048.0 MB is 71.9x higher than user's normal average`
  * Show the math: `Base Rule Points (90) + Multi-Signal Pattern Bonus (15) = 100 pts (Capped)`.
* Demonstrate **Analyst Decision Support Actions**:
  * Click **[🚨 Escalate to Tier 2 IR]**.
  * The status instantly updates across the SOC console.

---

### Step 4: The Crucial "Benign Anomaly" Test
* Now select `INC_001 (Karthik Menon - IT Systems Admin)`:
  * Off-hours patch logs download.
  * Point out that risk score is low, resource is low-sensitivity, and device was verified.
  * Click **[✅ Flag as Benign / Expected]**.
  * Explain: *"InsiderShield is designed to distinguish true threats from benign operational overtime without false-positive panic."*

---

### Step 5: Bonus Feature — Baseline Drift Over Time (Page 4)
* Switch to **Page 4: Baseline vs. Anomaly Comparison**.
* Select `EMP_014 (Rajesh Sharma)`:
  * Show the side-by-side comparison matrix comparing 14-day history vs. today's event.
  * Point to the **Baseline Drift Time-Series Chart**:
    * Clean green baseline bar chart across the past 14 days ($~28\text{ MB/day}$).
    * Red explosive spike today at $2,048\text{ MB}$.
  * *"Judges, this visual proof empowers non-technical executives and legal counsel to immediately understand the threat."*

---

## 3. Answers to Likely Judge Questions

| Question | Winning Answer |
| :--- | :--- |
| **"Why rules instead of unsupervised neural networks or Isolation Forest?"** | In insider risk, every alert must be legally defendable, transparent, and auditable under regulatory frameworks (NIST, CISA). Black-box embeddings cannot articulate *why* someone is flagged. Our rules are deterministic, calibrated to historical statistical baselines, and offer 100% signal explainability. |
| **"How does capacity awareness scale?"** | Enterprise SOCs suffer 70%+ alert fatigue. Our queue computes multi-factor triage priority scores and dynamically routes to available analyst headcount while tracking deferred backlog SLAs. |
| **"Can you add new threat rules?"** | Yes! `ExplainableDetector` is completely modular. Adding a new rule is simply defining a python method with a discrete weight and reason string. |
