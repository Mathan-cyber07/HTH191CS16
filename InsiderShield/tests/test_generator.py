"""Tests for Phase 2: Synthetic Data Generator and Scenario Injector."""

import os
import pandas as pd
import pytest
from src.generator import DATA_DIR, build_and_save_dataset


def test_users_csv_exists_and_valid():
    """Verify that users.csv exists, has 50 rows, and conforms to required schema."""
    users_path = os.path.join(DATA_DIR, "users.csv")
    assert os.path.exists(users_path), f"users.csv not found at {users_path}"

    df = pd.read_csv(users_path)
    assert len(df) == 50, f"Expected 50 users, got {len(df)}"

    required_cols = [
        "user_id", "user_name", "department", "role",
        "normal_country", "normal_city", "known_device_id",
        "normal_start_hour", "normal_end_hour", "avg_daily_download_mb"
    ]
    for col in required_cols:
        assert col in df.columns, f"Missing column: {col}"

    # Verify country distribution: 45 India, 3 United States, 2 UK
    country_counts = df["normal_country"].value_counts().to_dict()
    assert country_counts.get("India", 0) == 45
    assert country_counts.get("United States", 0) == 3
    assert country_counts.get("UK", 0) == 2


def test_scenario_designated_users():
    """Ensure pinned scenario users exist with exact designated departments."""
    users_path = os.path.join(DATA_DIR, "users.csv")
    df = pd.read_csv(users_path).set_index("user_id")

    assert df.loc["EMP_014", "department"] == "Finance"
    assert df.loc["EMP_022", "department"] == "Engineering"
    assert df.loc["EMP_008", "department"] == "Sales"
    assert df.loc["EMP_031", "department"] == "HR"
    assert df.loc["EMP_005", "department"] == "IT"


def test_activity_logs_csv_exists_and_schema():
    """Verify activity_logs.csv exists, is non-empty, and contains all required event fields."""
    logs_path = os.path.join(DATA_DIR, "activity_logs.csv")
    assert os.path.exists(logs_path), f"activity_logs.csv not found at {logs_path}"

    df = pd.read_csv(logs_path)
    assert len(df) > 1000, f"Expected >1000 activity logs, found {len(df)}"

    required_cols = [
        "event_id", "timestamp", "user_id", "user_name", "department", "role",
        "event_type", "login_status", "source_ip", "country", "city",
        "device_id", "known_device", "resource", "resource_type",
        "resource_sensitivity", "download_mb", "scenario_tag"
    ]
    for col in required_cols:
        assert col in df.columns, f"Missing column in activity_logs.csv: {col}"


def test_all_five_attack_scenarios_present():
    """Verify that all 5 scenario tags are present and have expected event counts."""
    logs_path = os.path.join(DATA_DIR, "activity_logs.csv")
    df = pd.read_csv(logs_path)

    expected_scenarios = [
        "scenario_a_compromised_finance",
        "scenario_b_malicious_dev",
        "scenario_c_privilege_misuse",
        "scenario_d_password_attack",
        "scenario_e_benign_anomaly",
    ]

    for tag in expected_scenarios:
        subset = df[df["scenario_tag"] == tag]
        assert len(subset) > 0, f"Scenario tag {tag} has no events"


def test_scenario_a_details():
    """Scenario A: Compromised Finance Account should have unknown device, Russia, 2048MB download."""
    df = pd.read_csv(os.path.join(DATA_DIR, "activity_logs.csv"))
    scen_a = df[df["scenario_tag"] == "scenario_a_compromised_finance"]

    assert "EMP_014" in scen_a["user_id"].values
    assert (scen_a["country"] == "Russia").all()
    assert (scen_a["known_device"] == False).all()  # noqa: E712
    assert (scen_a["download_mb"] == 2048.0).any()
    assert (scen_a["resource"] == "payroll_2026_master.xlsx").any()


def test_scenario_b_details():
    """Scenario B: Malicious Developer exfiltrating 3500MB source code."""
    df = pd.read_csv(os.path.join(DATA_DIR, "activity_logs.csv"))
    scen_b = df[df["scenario_tag"] == "scenario_b_malicious_dev"]

    assert "EMP_022" in scen_b["user_id"].values
    assert (scen_b["download_mb"] == 3500.0).any()
    assert (scen_b["resource"] == "core_proprietary_source_code.zip").any()
    assert (scen_b["known_device"] == True).all()  # noqa: E712


def test_scenario_c_details():
    """Scenario C: Sales user accessing HR salary records."""
    df = pd.read_csv(os.path.join(DATA_DIR, "activity_logs.csv"))
    scen_c = df[df["scenario_tag"] == "scenario_c_privilege_misuse"]

    assert "EMP_008" in scen_c["user_id"].values
    assert (scen_c["department"] == "Sales").all()
    assert (scen_c["resource"] == "executive_salaries_and_bonuses.xlsx").any()


def test_scenario_d_details():
    """Scenario D: 6 failed logins + 1 success + SSN records access."""
    df = pd.read_csv(os.path.join(DATA_DIR, "activity_logs.csv"))
    scen_d = df[df["scenario_tag"] == "scenario_d_password_attack"]

    assert "EMP_031" in scen_d["user_id"].values
    failed = scen_d[scen_d["login_status"] == "failed"]
    success_logins = scen_d[(scen_d["event_type"] == "login") & (scen_d["login_status"] == "success")]

    assert len(failed) == 6
    assert len(success_logins) == 1
    assert (scen_d["resource"] == "employee_ssn_records.csv").any()


def test_scenario_e_details():
    """Scenario E: Benign Anomaly with low sensitivity patch logs download."""
    df = pd.read_csv(os.path.join(DATA_DIR, "activity_logs.csv"))
    scen_e = df[df["scenario_tag"] == "scenario_e_benign_anomaly"]

    assert "EMP_005" in scen_e["user_id"].values
    assert (scen_e["resource_sensitivity"] == "low").all()
    assert (scen_e["download_mb"] == 5.0).any()
