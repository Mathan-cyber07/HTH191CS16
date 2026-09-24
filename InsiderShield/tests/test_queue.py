"""Unit tests for Phase 7: Capacity-Aware Prioritization Queue."""

import pytest
from src.queue import CapacityQueueManager


def test_empty_incidents_queue():
    manager = CapacityQueueManager(capacity=3)
    result = manager.rank_incidents([])
    assert result["recommended_queue"] == []
    assert result["deferred_queue"] == []
    assert result["metrics"]["total_incidents"] == 0
    assert result["metrics"]["active_investigations"] == 0


def test_capacity_truncation_and_ranking():
    """Given 5 incidents and capacity 3, top 3 should be recommended and 2 deferred."""
    manager = CapacityQueueManager(capacity=3)
    sample_incidents = [
        # Low priority
        {
            "incident_id": "INC_001",
            "risk_score": 25,
            "primary_flags": ["Off-Hours Activity"],
            "max_resource_sensitivity": "low",
        },
        # Critical priority (high score, multiple signals, critical resource)
        {
            "incident_id": "INC_002",
            "risk_score": 95,
            "primary_flags": ["Off-Hours", "New Country", "Unknown Device", "Download"],
            "max_resource_sensitivity": "critical",
        },
        # High priority
        {
            "incident_id": "INC_003",
            "risk_score": 75,
            "primary_flags": ["Privilege Misuse", "Sensitive Asset"],
            "max_resource_sensitivity": "high",
        },
        # Medium priority
        {
            "incident_id": "INC_004",
            "risk_score": 40,
            "primary_flags": ["Sensitive Asset"],
            "max_resource_sensitivity": "medium",
        },
        # Critical priority #2
        {
            "incident_id": "INC_005",
            "risk_score": 90,
            "primary_flags": ["Off-Hours", "Exfiltration"],
            "max_resource_sensitivity": "critical",
        },
    ]

    result = manager.rank_incidents(sample_incidents, capacity=3)
    rec = result["recommended_queue"]
    def_q = result["deferred_queue"]
    metrics = result["metrics"]

    assert len(rec) == 3
    assert len(def_q) == 2
    assert metrics["total_incidents"] == 5
    assert metrics["active_investigations"] == 3
    assert metrics["deferred_backlog"] == 2
    assert metrics["capacity_utilization_pct"] == 100.0

    # Ensure ranking is sorted descending by priority score
    rec_priorities = [i["priority_score"] for i in rec]
    assert rec_priorities == sorted(rec_priorities, reverse=True)

    # Top incident must be INC_002
    assert rec[0]["incident_id"] == "INC_002"
    assert rec[0]["triage_status"] == "ACTIVE_INVESTIGATION"
    assert "Analyst" in rec[0]["assigned_investigator"]

    # Deferred items should be marked accordingly
    assert def_q[0]["triage_status"] == "DEFERRED_BACKLOG"
    assert "Pending" in def_q[0]["assigned_investigator"]


def test_dynamic_capacity_override():
    """Testing that passing capacity=1 allocates only 1 slot."""
    manager = CapacityQueueManager(capacity=3)
    incidents = [
        {"incident_id": f"INC_{i}", "risk_score": 50, "primary_flags": ["Flag"], "max_resource_sensitivity": "medium"}
        for i in range(4)
    ]
    result = manager.rank_incidents(incidents, capacity=1)
    assert len(result["recommended_queue"]) == 1
    assert len(result["deferred_queue"]) == 3
    assert result["metrics"]["active_investigations"] == 1
