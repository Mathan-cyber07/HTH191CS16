"""Explainable Detection Rules Engine for InsiderShield.

Implements 8 discrete, transparent behavioral anomaly rules:
1. Off-Hours Activity (+15 pts)
2. Anomalous Country/Location (+20 pts)
3. Unregistered Device (+15 pts)
4. Critical Asset Access (+20 pts)
5. Abnormal Download Volume (+20 pts)
6. Cross-Department Privilege Anomaly (+25 pts)
7. Failed Login Burst (+15 pts)
8. Impossible Travel (+25 pts)

Each rule returns an explainable payload:
{"triggered": bool, "score": int, "rule_name": str, "reason": str}
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import pandas as pd

DEFAULT_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))

# Resource keyword mapping to identify department ownership
RESOURCE_DEPT_HINTS = {
    "HR": ["salary", "salaries", "hr_", "ssn", "candidate", "handbook", "performance_review", "employee_ssn"],
    "Finance": ["budget", "ledger", "invoice", "payroll", "tax", "expense"],
    "Engineering": ["repo", "source_code", "api", "git", "sql", "dev_", "proprietary"],
    "Sales": ["leads", "sales", "crm", "contract", "pricing"],
    "IT": ["patch", "network", "ad_user", "server", "helpdesk", "topology"],
    "Legal": ["nda", "compliance", "patent", "sla"],
    "Marketing": ["brand", "social_media", "campaign", "press_release"],
}


def infer_resource_department(resource_name: str) -> Optional[str]:
    """Infers the department associated with a resource name based on keywords."""
    res_lower = str(resource_name).lower()
    for dept, keywords in RESOURCE_DEPT_HINTS.items():
        for kw in keywords:
            if kw in res_lower:
                return dept
    return None


class ExplainableDetector:
    """Evaluates user telemetry against per-user baselines using explainable rules."""

    def __init__(self, baselines_path: Optional[str] = None, baselines_dict: Optional[Dict[str, Any]] = None):
        if baselines_dict is not None:
            self.baselines = baselines_dict
        else:
            if baselines_path is None:
                baselines_path = os.path.join(DEFAULT_DATA_DIR, "user_baselines.json")
            if os.path.exists(baselines_path):
                with open(baselines_path, "r", encoding="utf-8") as f:
                    self.baselines = json.load(f)
            else:
                self.baselines = {}

    def get_baseline(self, user_id: str) -> Dict[str, Any]:
        """Fetch baseline for a user, or provide safe fallback defaults."""
        return self.baselines.get(user_id, {
            "user_id": user_id,
            "normal_work_start": 9,
            "normal_work_end": 18,
            "known_countries": ["India"],
            "known_devices": [],
            "avg_download_mb": 25.0,
            "max_normal_download_mb": 50.0,
            "allowed_departments": [],
            "normal_sensitivity": ["low", "medium"],
        })

    def check_off_hours(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Rule 1: Off-Hours Activity (+15 pts)."""
        ts = event.get("timestamp")
        if isinstance(ts, str):
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        elif isinstance(ts, pd.Timestamp) or isinstance(ts, datetime):
            dt = ts
        else:
            return {"triggered": False, "score": 0, "rule_name": "Off-Hours Activity", "reason": ""}

        hour = dt.hour
        start = baseline.get("normal_work_start", 9)
        end = baseline.get("normal_work_end", 18)

        # Off hours if outside normal window (e.g. 02:00 or 23:00)
        if hour < start or hour > end:
            return {
                "triggered": True,
                "score": 15,
                "rule_name": "Off-Hours Activity",
                "reason": f"Activity at {dt.strftime('%H:%M:%S')} is outside normal work hours ({start:02d}:00–{end:02d}:00)"
            }
        return {"triggered": False, "score": 0, "rule_name": "Off-Hours Activity", "reason": ""}

    def check_new_country(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Rule 2: Anomalous Country/Location (+20 pts)."""
        country = event.get("country")
        known = baseline.get("known_countries", [])
        if country and known and country not in known:
            return {
                "triggered": True,
                "score": 20,
                "rule_name": "Anomalous Country/Location",
                "reason": f"Access from '{country}' is outside user's recognized countries ({', '.join(known)})"
            }
        return {"triggered": False, "score": 0, "rule_name": "Anomalous Country/Location", "reason": ""}

    def check_unknown_device(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Rule 3: Unregistered Device (+15 pts)."""
        dev = event.get("device_id")
        known = baseline.get("known_devices", [])
        is_known_flag = event.get("known_device")

        # Trigger if explicitly not known or device_id not in baseline known devices
        if is_known_flag is False or (dev and known and dev not in known):
            return {
                "triggered": True,
                "score": 15,
                "rule_name": "Unregistered Device",
                "reason": f"Device '{dev}' is not in user's authorized hardware baseline"
            }
        return {"triggered": False, "score": 0, "rule_name": "Unregistered Device", "reason": ""}

    def check_sensitive_file(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Rule 4: Critical Asset Access (+20 pts)."""
        sens = str(event.get("resource_sensitivity", "")).lower()
        res = event.get("resource", "Unknown Resource")
        allowed_sens = baseline.get("normal_sensitivity", ["low", "medium"])

        # Trigger if sensitivity is critical or high when user normally only touches low/medium
        if sens == "critical" or (sens == "high" and "high" not in allowed_sens):
            return {
                "triggered": True,
                "score": 20,
                "rule_name": "Critical Asset Access",
                "reason": f"Accessed resource '{res}' with '{sens.upper()}' sensitivity (baseline allows: {', '.join(allowed_sens)})"
            }
        return {"triggered": False, "score": 0, "rule_name": "Critical Asset Access", "reason": ""}

    def check_unusual_download(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Rule 5: Abnormal Download Volume (+20 pts)."""
        dl = float(event.get("download_mb", 0.0) or 0.0)
        if dl <= 0:
            return {"triggered": False, "score": 0, "rule_name": "Abnormal Download Volume", "reason": ""}

        avg_dl = baseline.get("avg_download_mb", 20.0)
        max_normal = baseline.get("max_normal_download_mb", 40.0)

        # Triggered if download > 5x avg_download_mb OR > max_normal_download_mb (with threshold floor)
        if (dl > 5.0 * avg_dl) or (dl > max(max_normal * 1.5, 100.0)):
            ratio = round(dl / max(avg_dl, 1.0), 1)
            return {
                "triggered": True,
                "score": 20,
                "rule_name": "Abnormal Download Volume",
                "reason": f"Download volume of {dl:.1f} MB is {ratio}x higher than user's normal average ({avg_dl:.1f} MB)"
            }
        return {"triggered": False, "score": 0, "rule_name": "Abnormal Download Volume", "reason": ""}

    def check_department_mismatch(self, event: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Rule 6: Cross-Department Privilege Anomaly (+25 pts)."""
        user_dept = event.get("department") or baseline.get("department")
        res_dept = event.get("resource_department") or infer_resource_department(event.get("resource", ""))

        if res_dept and user_dept and res_dept != user_dept:
            return {
                "triggered": True,
                "score": 25,
                "rule_name": "Cross-Department Privilege Anomaly",
                "reason": f"User in '{user_dept}' accessed '{event.get('resource')}' belonging to '{res_dept}'"
            }
        return {"triggered": False, "score": 0, "rule_name": "Cross-Department Privilege Anomaly", "reason": ""}

    def check_failed_login_burst(
        self,
        event: Dict[str, Any],
        recent_user_events: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Rule 7: Failed Login Burst (+15 pts).
        
        Triggered if user has >= 5 failed logins within a 10-minute sliding window.
        """
        if not recent_user_events:
            return {"triggered": False, "score": 0, "rule_name": "Failed Login Burst", "reason": ""}

        curr_ts = event.get("timestamp")
        if isinstance(curr_ts, str):
            curr_dt = datetime.strptime(curr_ts, "%Y-%m-%d %H:%M:%S")
        else:
            curr_dt = curr_ts

        window_start = curr_dt - timedelta(minutes=10)
        failed_count = 0

        for prev in recent_user_events:
            prev_ts = prev.get("timestamp")
            if isinstance(prev_ts, str):
                p_dt = datetime.strptime(prev_ts, "%Y-%m-%d %H:%M:%S")
            else:
                p_dt = prev_ts

            if window_start <= p_dt <= curr_dt:
                if prev.get("event_type") == "failed_login" or prev.get("login_status") == "failed":
                    failed_count += 1

        if failed_count >= 5:
            return {
                "triggered": True,
                "score": 15,
                "rule_name": "Failed Login Burst",
                "reason": f"Observed {failed_count} failed login attempts within 10-minute window"
            }
        return {"triggered": False, "score": 0, "rule_name": "Failed Login Burst", "reason": ""}

    def check_impossible_travel(
        self,
        event: Dict[str, Any],
        recent_user_events: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Rule 8: Impossible Travel (+25 pts).
        
        Triggered if logins occur from 2 different countries within 2 hours.
        """
        curr_country = event.get("country")
        if not curr_country or not recent_user_events:
            return {"triggered": False, "score": 0, "rule_name": "Impossible Travel", "reason": ""}

        curr_ts = event.get("timestamp")
        if isinstance(curr_ts, str):
            curr_dt = datetime.strptime(curr_ts, "%Y-%m-%d %H:%M:%S")
        else:
            curr_dt = curr_ts

        window_start = curr_dt - timedelta(hours=2)

        for prev in recent_user_events:
            prev_country = prev.get("country")
            if not prev_country or prev_country == curr_country:
                continue

            prev_ts = prev.get("timestamp")
            if isinstance(prev_ts, str):
                p_dt = datetime.strptime(prev_ts, "%Y-%m-%d %H:%M:%S")
            else:
                p_dt = prev_ts

            if window_start <= p_dt <= curr_dt:
                # Different country within 2 hours!
                return {
                    "triggered": True,
                    "score": 25,
                    "rule_name": "Impossible Travel",
                    "reason": f"Login from '{curr_country}' occurred within 2 hours of login from '{prev_country}'"
                }
        return {"triggered": False, "score": 0, "rule_name": "Impossible Travel", "reason": ""}

    def evaluate_event(
        self,
        event: Dict[str, Any],
        recent_user_events: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """Evaluate an activity event against all 8 explainable detection rules."""
        user_id = event.get("user_id", "")
        baseline = self.get_baseline(user_id)

        checks = [
            self.check_off_hours(event, baseline),
            self.check_new_country(event, baseline),
            self.check_unknown_device(event, baseline),
            self.check_sensitive_file(event, baseline),
            self.check_unusual_download(event, baseline),
            self.check_department_mismatch(event, baseline),
            self.check_failed_login_burst(event, recent_user_events),
            self.check_impossible_travel(event, recent_user_events),
        ]

        # Return only the triggered rules
        return [c for c in checks if c["triggered"]]
