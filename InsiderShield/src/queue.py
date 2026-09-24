"""Capacity-Aware Prioritization Queue for InsiderShield.

Ranks security incidents under limited human investigator headcount (e.g., 3 analysts).
Calculates priority scores:
  Priority = (Risk Score * 0.6) + (Number of Triggered Signals * 10) + (Resource Sensitivity Weight * 20)
"""

from typing import List, Dict, Any, Optional

SENSITIVITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

DEFAULT_INVESTIGATORS = [
    "Analyst Sarah (Lead)",
    "Analyst David (Forensics)",
    "Analyst Priya (Triage)",
]


class CapacityQueueManager:
    """Manages triage ranking and capacity constraint allocation for SOC investigators."""

    def __init__(self, capacity: int = 3, investigators: Optional[List[str]] = None):
        self.capacity = max(1, capacity)
        self.investigators = investigators or DEFAULT_INVESTIGATORS

    @staticmethod
    def calculate_priority_score(incident: Dict[str, Any]) -> float:
        """Compute transparent priority score for incident triage ranking.
        
        Formula:
          Priority = (Risk Score * 0.6) + (Signals * 10) + (Sensitivity Weight * 20)
        """
        risk_score = float(incident.get("risk_score", 0))
        num_signals = float(len(incident.get("primary_flags", [])))
        
        sens_str = str(incident.get("max_resource_sensitivity", "low")).lower()
        sens_weight = float(SENSITIVITY_WEIGHTS.get(sens_str, 1))

        priority = (risk_score * 0.6) + (num_signals * 10.0) + (sens_weight * 20.0)
        return round(priority, 2)

    def rank_incidents(
        self,
        incidents: List[Dict[str, Any]],
        capacity: Optional[int] = None
    ) -> Dict[str, Any]:
        """Rank incidents and split into active recommended queue vs deferred backlog."""
        active_capacity = capacity if capacity is not None else self.capacity
        if not incidents:
            return {
                "recommended_queue": [],
                "deferred_queue": [],
                "metrics": {
                    "total_incidents": 0,
                    "capacity": active_capacity,
                    "active_investigations": 0,
                    "deferred_backlog": 0,
                    "capacity_utilization_pct": 0.0,
                    "critical_in_backlog": 0,
                }
            }

        # Calculate priority scores and attach
        scored_incidents = []
        for inc in incidents:
            inc_copy = dict(inc)
            inc_copy["priority_score"] = self.calculate_priority_score(inc_copy)
            scored_incidents.append(inc_copy)

        # Sort descending by priority score, secondary by risk score
        scored_incidents.sort(
            key=lambda x: (x["priority_score"], x.get("risk_score", 0)),
            reverse=True
        )

        recommended_queue = []
        deferred_queue = []

        for idx, inc in enumerate(scored_incidents):
            inc_data = dict(inc)
            inc_data["queue_rank"] = idx + 1

            if idx < active_capacity:
                investigator_name = (
                    self.investigators[idx]
                    if idx < len(self.investigators)
                    else f"Investigator #{idx + 1}"
                )
                inc_data["triage_status"] = "ACTIVE_INVESTIGATION"
                inc_data["assigned_investigator"] = investigator_name
                recommended_queue.append(inc_data)
            else:
                inc_data["triage_status"] = "DEFERRED_BACKLOG"
                inc_data["assigned_investigator"] = "Unassigned (Pending Capacity)"
                deferred_queue.append(inc_data)

        utilization = min(100.0, round((len(recommended_queue) / max(active_capacity, 1)) * 100, 1))
        critical_backlog = sum(1 for i in deferred_queue if i.get("severity") == "Critical")

        metrics = {
            "total_incidents": len(incidents),
            "capacity": active_capacity,
            "active_investigations": len(recommended_queue),
            "deferred_backlog": len(deferred_queue),
            "capacity_utilization_pct": utilization,
            "critical_in_backlog": critical_backlog,
        }

        return {
            "recommended_queue": recommended_queue,
            "deferred_queue": deferred_queue,
            "metrics": metrics,
        }
