"""Incident Correlator for InsiderShield.

Clusters individual atomic anomaly flags occurring within a 30-minute sliding window
per user into unified, actionable security incidents.
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from src.scorer import RiskScorer

DEFAULT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))

SENSITIVITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class IncidentCorrelator:
    """Aggregates flagged anomalous events into correlated security incidents."""

    def __init__(self, window_minutes: int = 30):
        self.window_minutes = window_minutes

    def correlate_events(self, flagged_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Cluster flagged events into incidents using a sliding time window per user.
        
        Args:
            flagged_events: List of event dicts that each contain 'triggered_rules'.
            
        Returns:
            List of correlated incident dictionaries.
        """
        if not flagged_events:
            return []

        # Sort events by user_id and timestamp
        def parse_ts(item):
            ts = item.get("timestamp")
            if isinstance(ts, str):
                return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            elif isinstance(ts, datetime):
                return ts
            return datetime.min

        sorted_events = sorted(flagged_events, key=lambda e: (e.get("user_id", ""), parse_ts(e)))

        clusters: List[List[Dict[str, Any]]] = []
        current_cluster: List[Dict[str, Any]] = []

        for evt in sorted_events:
            if not current_cluster:
                current_cluster.append(evt)
                continue

            prev_evt = current_cluster[-1]
            same_user = evt.get("user_id") == prev_evt.get("user_id")
            delta = parse_ts(evt) - parse_ts(prev_evt)

            if same_user and delta <= timedelta(minutes=self.window_minutes):
                current_cluster.append(evt)
            else:
                clusters.append(current_cluster)
                current_cluster = [evt]

        if current_cluster:
            clusters.append(current_cluster)

        # Convert clusters to Incident objects
        incidents = []
        for idx, cluster in enumerate(clusters, start=1):
            incident_id = f"INC_{idx:03d}"
            u_id = cluster[0].get("user_id", "UNKNOWN")
            u_name = cluster[0].get("user_name", "Unknown User")
            dept = cluster[0].get("department", "Unknown Dept")
            role = cluster[0].get("role", "Unknown Role")

            start_time = min(e.get("timestamp") for e in cluster)
            end_time = max(e.get("timestamp") for e in cluster)

            # Collect unique triggered rules and reasons across all events in cluster
            unique_rules_map = {}
            reasons = []
            max_sens = "low"
            total_dl = 0.0
            scenario_tags = set()

            for e in cluster:
                total_dl += float(e.get("download_mb", 0.0) or 0.0)
                sens = str(e.get("resource_sensitivity", "low")).lower()
                if SENSITIVITY_WEIGHTS.get(sens, 0) > SENSITIVITY_WEIGHTS.get(max_sens, 0):
                    max_sens = sens

                tag = e.get("scenario_tag")
                if tag and tag != "normal":
                    scenario_tags.add(tag)

                for rule in e.get("triggered_rules", []):
                    r_name = rule.get("rule_name")
                    if r_name not in unique_rules_map:
                        unique_rules_map[r_name] = rule
                    r_reason = rule.get("reason")
                    if r_reason and r_reason not in reasons:
                        reasons.append(r_reason)

            unique_rules = list(unique_rules_map.values())
            risk_score, score_breakdown = RiskScorer.calculate_risk_score(unique_rules)
            severity = RiskScorer.map_severity(risk_score)

            incidents.append({
                "incident_id": incident_id,
                "user_id": u_id,
                "user_name": u_name,
                "department": dept,
                "role": role,
                "severity": severity,
                "risk_score": risk_score,
                "score_breakdown": score_breakdown,
                "event_count": len(cluster),
                "start_time": str(start_time),
                "end_time": str(end_time),
                "reasons": reasons,
                "primary_flags": list(unique_rules_map.keys()),
                "max_resource_sensitivity": max_sens,
                "total_download_mb": round(total_dl, 2),
                "scenario_tag": list(scenario_tags)[0] if scenario_tags else "anomaly",
                "status": "Open",
                "assigned_investigator": None,
                "events": cluster,
            })

        return incidents

    @staticmethod
    def save_incidents(incidents: List[Dict[str, Any]], path: Optional[str] = None) -> str:
        """Export incidents list to JSON file."""
        if path is None:
            path = os.path.join(DEFAULT_DATA_DIR, "incidents.json")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(incidents, f, indent=2)
        return path

    @staticmethod
    def load_incidents(path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load incidents list from JSON file."""
        if path is None:
            path = os.path.join(DEFAULT_DATA_DIR, "incidents.json")
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
