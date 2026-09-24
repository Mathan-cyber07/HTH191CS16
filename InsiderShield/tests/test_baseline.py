"""Unit tests for Phase 3: Per-User Behavioral Baseline Profiler."""

import os
import json
import pandas as pd
import pytest
from src.baseline import UserBaselineProfiler, DEFAULT_DATA_DIR


def test_baseline_json_exists_and_valid():
    """Verify that user_baselines.json exists, contains 50 users, and valid schema."""
    path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")
    assert os.path.exists(path), f"Baselines JSON not found at {path}"

    with open(path, "r", encoding="utf-8") as f:
        baselines = json.load(f)

    assert len(baselines) == 50, f"Expected 50 user baselines, got {len(baselines)}"

    required_fields = [
        "user_id", "user_name", "department", "role",
        "normal_work_start", "normal_work_end",
        "known_countries", "known_devices",
        "avg_download_mb", "max_normal_download_mb",
        "allowed_departments", "normal_sensitivity"
    ]

    for user_id, profile in baselines.items():
        assert user_id.startswith("EMP_")
        for fld in required_fields:
            assert fld in profile, f"User {user_id} missing field: {fld}"

        assert 0 <= profile["normal_work_start"] <= 23
        assert 0 <= profile["normal_work_end"] <= 23
        assert profile["normal_work_start"] <= profile["normal_work_end"]
        assert len(profile["known_countries"]) > 0
        assert len(profile["known_devices"]) > 0
        assert profile["avg_download_mb"] > 0
        assert profile["max_normal_download_mb"] >= profile["avg_download_mb"]
        assert profile["department"] in profile["allowed_departments"]


def test_scenario_user_baselines():
    """Verify pinned scenario users have appropriate baseline parameters."""
    path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")
    with open(path, "r", encoding="utf-8") as f:
        baselines = json.load(f)

    # EMP_014 Finance baseline
    u14 = baselines["EMP_014"]
    assert u14["department"] == "Finance"
    assert "India" in u14["known_countries"]
    assert "Russia" not in u14["known_countries"]
    assert "UNKNOWN_DEV_X9" not in u14["known_devices"]
    assert u14["max_normal_download_mb"] < 100.0

    # EMP_022 Engineering baseline
    u22 = baselines["EMP_022"]
    assert u22["department"] == "Engineering"
    assert u22["max_normal_download_mb"] < 100.0

    # EMP_008 Sales baseline
    u08 = baselines["EMP_008"]
    assert u08["department"] == "Sales"
    assert "HR" not in u08["allowed_departments"]


def test_save_and_load_roundtrip(tmp_path):
    """Verify save_baselines and load_baselines serialize and deserialize accurately."""
    sample_data = {
        "EMP_999": {
            "user_id": "EMP_999",
            "user_name": "Test User",
            "department": "Engineering",
            "role": "QA Engineer",
            "normal_work_start": 9,
            "normal_work_end": 18,
            "known_countries": ["India"],
            "known_devices": ["DEV_TEST_LAPTOP"],
            "avg_download_mb": 20.0,
            "max_normal_download_mb": 40.0,
            "allowed_departments": ["Engineering"],
            "normal_sensitivity": ["low", "medium"],
        }
    }
    profiler = UserBaselineProfiler(sample_data)
    test_file = str(tmp_path / "test_baselines.json")
    profiler.save_baselines(test_file)

    loaded_profiler = UserBaselineProfiler()
    loaded_data = loaded_profiler.load_baselines(test_file)
    assert loaded_data == sample_data
