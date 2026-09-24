"""End-to-end processing pipeline for InsiderShield.

Orchestrates:
1. Ingesting raw activity logs (data/activity_logs.csv)
2. Computing or loading behavioral baselines (src/baseline.py)
3. Evaluating live events with explainable rules (src/detector.py)
4. Correlating flags into incidents (src/correlator.py)
5. Exporting data/incidents.json and ranking via capacity queue (src/queue.py)
"""

import json
import os
from typing import List, Dict, Any, Optional
import pandas as pd

from src.baseline import UserBaselineProfiler
from src.detector import ExplainableDetector
from src.correlator import IncidentCorrelator
from src.queue import CapacityQueueManager

DEFAULT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))


def run_pipeline(
    logs_path: Optional[str] = None,
    baselines_path: Optional[str] = None,
    output_incidents_path: Optional[str] = None,
    scan_date: Optional[str] = "2026-09-24",
    capacity: int = 3,
) -> Dict[str, Any]:
    """Execute end-to-end InsiderShield pipeline."""
    if logs_path is None:
        logs_path = os.path.join(DEFAULT_DATA_DIR, "activity_logs.csv")
    if baselines_path is None:
        baselines_path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")
    if output_incidents_path is None:
        output_incidents_path = os.path.join(DEFAULT_DATA_DIR, "incidents.json")

    print(f"Loading activity logs from {logs_path}...")
    df = pd.read_csv(logs_path)

    # Step 1: Ensure baselines exist or fit from baseline normal records
    if not os.path.exists(baselines_path):
        print(f"Baselines file not found. Fitting baselines from normal records...")
        profiler = UserBaselineProfiler()
        profiler.fit(df)
        profiler.save_baselines(baselines_path)
    else:
        profiler = UserBaselineProfiler()
        profiler.load_baselines(baselines_path)

    detector = ExplainableDetector(baselines_dict=profiler.baselines)

    # Step 2: Select live telemetry events to scan
    df_scan = df.copy()
    if scan_date:
        df_scan = df_scan[df_scan["timestamp"].str.startswith(scan_date)]
        print(f"Filtered for scan date '{scan_date}': {len(df_scan)} events found.")
    else:
        print(f"Scanning all {len(df_scan)} events in dataset.")

    # Convert to list of dicts sorted chronologically
    events = df_scan.to_dict(orient="records")
    flagged_events = []

    # Map user history to feed sliding checks (bursts, impossible travel)
    user_event_history: Dict[str, List[Dict[str, Any]]] = {}

    print(f"Evaluating {len(events)} events against 8 explainable rules...")
    for evt in events:
        u_id = evt.get("user_id", "")
        if u_id not in user_event_history:
            user_event_history[u_id] = []

        history = user_event_history[u_id]
        triggered = detector.evaluate_event(evt, recent_user_events=history)
        
        # Append to history
        history.append(evt)

        if triggered:
            evt_copy = dict(evt)
            evt_copy["triggered_rules"] = triggered
            flagged_events.append(evt_copy)

    print(f"Flagged {len(flagged_events)} anomalous events.")

    # Step 3: Correlate into incidents
    correlator = IncidentCorrelator(window_minutes=30)
    incidents = correlator.correlate_events(flagged_events)
    print(f"Formed {len(incidents)} correlated security incidents.")

    # Step 4: Save incidents to JSON
    IncidentCorrelator.save_incidents(incidents, output_incidents_path)
    print(f"Saved incidents to {output_incidents_path}")

    # Step 5: Rank with capacity queue
    queue_mgr = CapacityQueueManager(capacity=capacity)
    queue_result = queue_mgr.rank_incidents(incidents, capacity=capacity)

    print("\n--- Capacity-Aware Prioritized Queue ---")
    for idx, inc in enumerate(queue_result["recommended_queue"], start=1):
        print(f"Slot {idx} [{inc['assigned_investigator']}]: {inc['incident_id']} - {inc['user_name']} ({inc['department']}) | Severity: {inc['severity']} | Risk: {inc['risk_score']} | Signals: {len(inc['primary_flags'])}")

    if queue_result["deferred_queue"]:
        print(f"\nDeferred Backlog: {len(queue_result['deferred_queue'])} incidents pending capacity.")

    return {
        "total_scanned": len(events),
        "total_flagged": len(flagged_events),
        "incidents": incidents,
        "queue_result": queue_result,
    }


if __name__ == "__main__":
    run_pipeline()
