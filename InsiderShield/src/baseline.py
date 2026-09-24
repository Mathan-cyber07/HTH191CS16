"""Per-User Behavioral Baseline Profiler for InsiderShield.

Learns normal behavioral profiles from historical activity logs:
- Work start and end hours
- Known countries, cities, and hardware devices
- Download statistics (mean and max volume)
- Departmental boundaries and resource sensitivities
"""

import json
import os
from typing import Dict, Any, Optional
import pandas as pd

DEFAULT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))


class UserBaselineProfiler:
    """Computes and manages per-user behavioral baselines from normal activity logs."""

    def __init__(self, baselines: Optional[Dict[str, Any]] = None):
        self.baselines: Dict[str, Any] = baselines or {}

    def fit(self, df: pd.DataFrame) -> "UserBaselineProfiler":
        """Compute normal behavioral profile for every user in the baseline logs.
        
        Filters records where scenario_tag == 'normal'.
        """
        # Ensure timestamp is datetime
        logs = df.copy()
        if not pd.api.types.is_datetime64_any_dtype(logs["timestamp"]):
            logs["timestamp"] = pd.to_datetime(logs["timestamp"])

        normal_logs = logs[logs["scenario_tag"] == "normal"]
        if normal_logs.empty:
            raise ValueError("No records with scenario_tag == 'normal' found to build baselines.")

        normal_logs = normal_logs.copy()
        normal_logs["hour"] = normal_logs["timestamp"].dt.hour

        baselines = {}
        grouped = normal_logs.groupby("user_id")

        for user_id, user_df in grouped:
            user_name = str(user_df["user_name"].iloc[0])
            dept = str(user_df["department"].iloc[0])
            role = str(user_df["role"].iloc[0])

            # Hours
            min_hour = int(user_df["hour"].min())
            max_hour = int(user_df["hour"].max())

            # Devices and Locations
            known_countries = sorted(list(user_df["country"].dropna().unique()))
            known_devices = sorted(list(user_df["device_id"].dropna().unique()))
            known_cities = sorted(list(user_df["city"].dropna().unique()))

            # Download metrics
            dl_records = user_df[user_df["download_mb"] > 0]
            if not dl_records.empty:
                avg_download = round(float(dl_records["download_mb"].mean()), 2)
                max_download = round(float(user_df["download_mb"].max()), 2)
            else:
                avg_download = 15.0
                max_download = 25.0

            # Department and sensitivity
            allowed_departments = sorted(list(user_df["department"].dropna().unique()))
            normal_sensitivities = sorted(list(user_df["resource_sensitivity"].dropna().unique()))
            # Baseline normal sensitivities typically do not include critical
            normal_sensitivities = [s for s in normal_sensitivities if s in ["low", "medium"]]
            if not normal_sensitivities:
                normal_sensitivities = ["low", "medium"]

            baselines[user_id] = {
                "user_id": user_id,
                "user_name": user_name,
                "department": dept,
                "role": role,
                "normal_work_start": min_hour,
                "normal_work_end": max_hour,
                "known_countries": known_countries,
                "known_cities": known_cities,
                "known_devices": known_devices,
                "avg_download_mb": avg_download,
                "max_normal_download_mb": max_download,
                "allowed_departments": allowed_departments,
                "normal_sensitivity": normal_sensitivities,
            }

        self.baselines = baselines
        return self

    def save_baselines(self, path: Optional[str] = None) -> str:
        """Export computed baselines to JSON file."""
        if path is None:
            path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.baselines, f, indent=2)
        return path

    def load_baselines(self, path: Optional[str] = None) -> Dict[str, Any]:
        """Load baselines from JSON file."""
        if path is None:
            path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Baseline file not found at {path}")
        with open(path, "r", encoding="utf-8") as f:
            self.baselines = json.load(f)
        return self.baselines

    def get_user_baseline(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get baseline profile for a specific user ID."""
        return self.baselines.get(user_id)


def generate_and_save_baselines(
    logs_csv_path: Optional[str] = None,
    output_json_path: Optional[str] = None
) -> str:
    """Helper to train on activity logs CSV and write user_baselines.json."""
    if logs_csv_path is None:
        logs_csv_path = os.path.join(DEFAULT_DATA_DIR, "activity_logs.csv")
    if output_json_path is None:
        output_json_path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")

    df = pd.read_csv(logs_csv_path)
    profiler = UserBaselineProfiler()
    profiler.fit(df)
    saved_path = profiler.save_baselines(output_json_path)
    print(f"Computed baselines for {len(profiler.baselines)} users -> {saved_path}")
    return saved_path


if __name__ == "__main__":
    generate_and_save_baselines()
