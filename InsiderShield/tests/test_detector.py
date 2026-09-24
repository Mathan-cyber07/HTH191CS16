"""Unit tests for Phase 4: Explainable Detection Rules Engine."""

from datetime import datetime
import pytest
from src.detector import ExplainableDetector


@pytest.fixture
def sample_baseline():
    return {
        "EMP_TEST": {
            "user_id": "EMP_TEST",
            "normal_work_start": 9,
            "normal_work_end": 18,
            "known_countries": ["India"],
            "known_devices": ["DEV_TEST_LAPTOP"],
            "avg_download_mb": 20.0,
            "max_normal_download_mb": 40.0,
            "department": "Engineering",
            "allowed_departments": ["Engineering"],
            "normal_sensitivity": ["low", "medium"],
        }
    }


@pytest.fixture
def detector(sample_baseline):
    return ExplainableDetector(baselines_dict=sample_baseline)


def test_normal_event_does_not_trigger(detector):
    """Normal daytime activity should trigger 0 rules."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 11:30:00",
        "country": "India",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "repo_frontend_main.git",
        "resource_sensitivity": "medium",
        "download_mb": 15.0,
        "department": "Engineering",
        "event_type": "file_download",
        "login_status": "success",
    }
    flags = detector.evaluate_event(event)
    assert len(flags) == 0


def test_rule1_off_hours(detector):
    """Off-hours event (02:00 AM) triggers Rule 1."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 02:00:00",
        "country": "India",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "repo_frontend_main.git",
        "resource_sensitivity": "medium",
        "download_mb": 5.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(event)
    rule_names = [f["rule_name"] for f in flags]
    assert "Off-Hours Activity" in rule_names
    assert flags[0]["score"] == 15


def test_rule2_new_country(detector):
    """Access from Russia triggers Rule 2."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 14:00:00",
        "country": "Russia",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "repo_frontend_main.git",
        "resource_sensitivity": "medium",
        "download_mb": 5.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(event)
    rule_names = [f["rule_name"] for f in flags]
    assert "Anomalous Country/Location" in rule_names


def test_rule3_unknown_device(detector):
    """Access from unregistered device triggers Rule 3."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 14:00:00",
        "country": "India",
        "device_id": "DEV_UNKNOWN_99",
        "known_device": False,
        "resource": "repo_frontend_main.git",
        "resource_sensitivity": "medium",
        "download_mb": 5.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(event)
    rule_names = [f["rule_name"] for f in flags]
    assert "Unregistered Device" in rule_names


def test_rule4_sensitive_file(detector):
    """Access to critical payroll triggers Rule 4."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 14:00:00",
        "country": "India",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "payroll_2026_master.xlsx",
        "resource_sensitivity": "critical",
        "download_mb": 5.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(event)
    rule_names = [f["rule_name"] for f in flags]
    assert "Critical Asset Access" in rule_names


def test_rule5_unusual_download(detector):
    """Download of 2000MB (>5x avg) triggers Rule 5."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 14:00:00",
        "country": "India",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "repo_frontend_main.git",
        "resource_sensitivity": "medium",
        "download_mb": 2048.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(event)
    rule_names = [f["rule_name"] for f in flags]
    assert "Abnormal Download Volume" in rule_names


def test_rule6_department_mismatch(detector):
    """Engineering user accessing HR salaries triggers Rule 6."""
    event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 14:00:00",
        "country": "India",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "executive_salaries_and_bonuses.xlsx",
        "resource_sensitivity": "high",
        "download_mb": 5.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(event)
    rule_names = [f["rule_name"] for f in flags]
    assert "Cross-Department Privilege Anomaly" in rule_names


def test_rule7_failed_login_burst(detector):
    """5 failed logins in 5 minutes triggers Rule 7."""
    recent_events = [
        {"timestamp": f"2026-09-24 08:0{i}:00", "event_type": "failed_login", "login_status": "failed"}
        for i in range(5)
    ]
    curr_event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 08:06:00",
        "country": "India",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "sso_auth_portal",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(curr_event, recent_user_events=recent_events)
    rule_names = [f["rule_name"] for f in flags]
    assert "Failed Login Burst" in rule_names


def test_rule8_impossible_travel(detector):
    """Login from US within 1 hour of login from India triggers Rule 8."""
    recent_events = [
        {"timestamp": "2026-09-24 10:00:00", "country": "India", "event_type": "login"}
    ]
    curr_event = {
        "user_id": "EMP_TEST",
        "timestamp": "2026-09-24 11:00:00",
        "country": "United States",
        "device_id": "DEV_TEST_LAPTOP",
        "known_device": True,
        "resource": "sso_auth_portal",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "department": "Engineering",
    }
    flags = detector.evaluate_event(curr_event, recent_user_events=recent_events)
    rule_names = [f["rule_name"] for f in flags]
    assert "Impossible Travel" in rule_names
