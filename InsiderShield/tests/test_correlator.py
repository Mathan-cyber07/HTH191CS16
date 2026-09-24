"""Unit tests for Phase 6: Incident Correlation Engine."""

from datetime import datetime
import pytest
from src.correlator import IncidentCorrelator


def test_correlate_empty_events():
    correlator = IncidentCorrelator(window_minutes=30)
    incidents = correlator.correlate_events([])
    assert incidents == []


def test_correlate_single_user_within_window():
    """Events for same user within 15 minutes should form a single incident."""
    correlator = IncidentCorrelator(window_minutes=30)
    events = [
        {
            "event_id": "EVT_1",
            "user_id": "EMP_014",
            "user_name": "Rajesh Sharma",
            "department": "Finance",
            "role": "Financial Analyst",
            "timestamp": "2026-09-24 02:15:00",
            "resource": "payroll_2026_master.xlsx",
            "resource_sensitivity": "critical",
            "download_mb": 0.0,
            "triggered_rules": [
                {"rule_name": "Off-Hours Activity", "score": 15, "reason": "Logged in at 02:15 AM"},
                {"rule_name": "Anomalous Country/Location", "score": 20, "reason": "Access from Russia"},
            ],
        },
        {
            "event_id": "EVT_2",
            "user_id": "EMP_014",
            "user_name": "Rajesh Sharma",
            "department": "Finance",
            "role": "Financial Analyst",
            "timestamp": "2026-09-24 02:22:00",
            "resource": "payroll_2026_master.xlsx",
            "resource_sensitivity": "critical",
            "download_mb": 2048.0,
            "triggered_rules": [
                {"rule_name": "Critical Asset Access", "score": 20, "reason": "Accessed critical payroll"},
                {"rule_name": "Abnormal Download Volume", "score": 20, "reason": "Downloaded 2048 MB"},
            ],
        },
    ]

    incidents = correlator.correlate_events(events)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["incident_id"] == "INC_001"
    assert inc["user_id"] == "EMP_014"
    assert inc["event_count"] == 2
    assert inc["max_resource_sensitivity"] == "critical"
    assert inc["total_download_mb"] == 2048.0
    # 4 rules -> base 75 + bonus 15 = 90 (Critical)
    assert inc["risk_score"] == 90
    assert inc["severity"] == "Critical"
    assert len(inc["reasons"]) == 4


def test_correlate_multiple_users_and_time_gaps():
    """Events >30 mins apart or different users should produce distinct incidents."""
    correlator = IncidentCorrelator(window_minutes=30)
    events = [
        # User 1, Event 1
        {
            "event_id": "EVT_1",
            "user_id": "EMP_001",
            "user_name": "Alice",
            "timestamp": "2026-09-24 09:00:00",
            "triggered_rules": [{"rule_name": "Off-Hours Activity", "score": 15, "reason": "Off-hours"}],
        },
        # User 1, Event 2 (45 min later -> new incident)
        {
            "event_id": "EVT_2",
            "user_id": "EMP_001",
            "user_name": "Alice",
            "timestamp": "2026-09-24 09:45:00",
            "triggered_rules": [{"rule_name": "Critical Asset Access", "score": 20, "reason": "Critical asset"}],
        },
        # User 2
        {
            "event_id": "EVT_3",
            "user_id": "EMP_002",
            "user_name": "Bob",
            "timestamp": "2026-09-24 10:00:00",
            "triggered_rules": [{"rule_name": "Unregistered Device", "score": 15, "reason": "Unknown device"}],
        },
    ]

    incidents = correlator.correlate_events(events)
    assert len(incidents) == 3
