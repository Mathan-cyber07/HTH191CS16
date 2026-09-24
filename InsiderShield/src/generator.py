"""Synthetic Data Generator & Attack Scenario Injector for InsiderShield.

Generates:
1. data/users.csv (50 synthetic employees with organizational & baseline attributes)
2. data/activity_logs.csv (14 days of realistic normal logs + 5 injected demo scenarios)
"""

import os
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np

# Ensure deterministic generation for demo reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))

# Preset department and role definitions
DEPT_ROLES = [
    ("Finance", "Financial Analyst"),
    ("Engineering", "Software Engineer"),
    ("HR", "HR Specialist"),
    ("Sales", "Sales Rep"),
    ("IT", "Systems Admin"),
    ("Legal", "Legal Counsel"),
    ("Marketing", "Marketing Specialist"),
]

# Realistic names catalog
FIRST_NAMES = [
    "Aarav", "Priya", "Rajesh", "Sneha", "Vikram", "Ananya", "Rohan", "Divya",
    "Karthik", "Pooja", "Arjun", "Meera", "Suresh", "Kavita", "Aditya", "Ritu",
    "Manoj", "Deepika", "Sanjay", "Neha", "Harish", "Swati", "Naveen", "Preeti",
    "Gaurav", "Sunita", "Ashok", "Shreya", "Vijay", "Aarthi", "Praveen", "Rashmi",
    "Amit", "Nandini", "Kiran", "Geeta", "Vinod", "Aparna", "Alok", "Vandana",
    "Siddharth", "Bhavna", "Manish", "Tara", "Chetan", "Varun", "Maya",
    "John", "Sarah", "Oliver"
]

LAST_NAMES = [
    "Sharma", "Patel", "Kumar", "Reddy", "Iyer", "Nair", "Verma", "Rao",
    "Gupta", "Deshmukh", "Menon", "Joshi", "Pillai", "Chopra", "Kulkarni", "Bhat",
    "Mehta", "Bose", "Saxena", "Sen", "Nambiar", "Pandey", "Chatterjee", "Mishra",
    "Agarwal", "Kapoor", "Trivedi", "Banerjee", "Ghosh", "Dutta", "Malhotra", "Shukla",
    "Gokhale", "Srivastava", "Chowdhury", "Mukherjee", "Das", "Bhattacharya", "Chauhan", "Bhardwaj",
    "Subramanian", "Ranganathan", "Sundaram", "Krishnan", "Venkat", "Raghavan", "Venkatesh",
    "Miller", "Jenkins", "Smith"
]

# Realistic resource templates by department
DEPARTMENT_RESOURCES = {
    "Finance": [
        ("quarterly_budget_2026.xlsx", "file", "high"),
        ("expense_reports_q3.csv", "file", "medium"),
        ("vendor_invoices_sep.pdf", "file", "low"),
        ("financial_ledger_db", "database", "high"),
        ("tax_filings_draft.docx", "file", "medium"),
    ],
    "Engineering": [
        ("repo_frontend_main.git", "file", "medium"),
        ("api_service_build.tar.gz", "file", "medium"),
        ("dev_environment_setup.md", "file", "low"),
        ("sprint_backlog_jira", "portal", "low"),
        ("staging_database_dump.sql", "database", "high"),
    ],
    "HR": [
        ("employee_handbook_v4.pdf", "file", "low"),
        ("interview_candidate_eval.docx", "file", "medium"),
        ("training_schedule_2026.xlsx", "file", "low"),
        ("hr_portal_selfservice", "portal", "low"),
        ("performance_reviews_q3.xlsx", "file", "high"),
    ],
    "Sales": [
        ("crm_leads_september.csv", "file", "medium"),
        ("q3_sales_deck.pptx", "file", "low"),
        ("client_contract_standard.docx", "file", "medium"),
        ("salesforce_dashboard", "portal", "low"),
        ("pricing_discount_calculator.xlsx", "file", "medium"),
    ],
    "IT": [
        ("network_topology_map.vsd", "file", "medium"),
        ("system_patch_logs.txt", "file", "low"),
        ("ad_user_directory", "portal", "medium"),
        ("server_inventory_audit.xlsx", "file", "low"),
        ("helpdesk_ticket_export.csv", "file", "low"),
    ],
    "Legal": [
        ("nda_master_template.docx", "file", "low"),
        ("compliance_audit_2026.pdf", "file", "high"),
        ("ip_patent_filings.docx", "file", "high"),
        ("vendor_sla_agreements.pdf", "file", "medium"),
    ],
    "Marketing": [
        ("brand_assets_vector.zip", "file", "low"),
        ("social_media_calendar.xlsx", "file", "low"),
        ("campaign_analytics_q3.csv", "file", "medium"),
        ("press_release_product_v2.docx", "file", "low"),
    ],
}


def generate_users() -> pd.DataFrame:
    """Generate 50 synthetic employees with strict scenario-aligned assignments."""
    users = []

    # Pin designated employees for specific demo scenarios
    pinned_assignments = {
        "EMP_014": {
            "name": "Rajesh Sharma",
            "department": "Finance",
            "role": "Financial Analyst",
            "country": "India",
            "city": "Coimbatore",
            "avg_download": 28.5,
        },
        "EMP_022": {
            "name": "Vikram Iyer",
            "department": "Engineering",
            "role": "Software Engineer",
            "country": "India",
            "city": "Bangalore",
            "avg_download": 45.0,
        },
        "EMP_008": {
            "name": "Priya Patel",
            "department": "Sales",
            "role": "Sales Rep",
            "country": "India",
            "city": "Chennai",
            "avg_download": 18.0,
        },
        "EMP_031": {
            "name": "Sneha Reddy",
            "department": "HR",
            "role": "HR Specialist",
            "country": "India",
            "city": "Bangalore",
            "avg_download": 22.0,
        },
        "EMP_005": {
            "name": "Karthik Menon",
            "department": "IT",
            "role": "Systems Admin",
            "country": "India",
            "city": "Chennai",
            "avg_download": 35.0,
        },
    }

    # Location distribution: 45 India, 3 US, 2 UK
    # We assign US to EMP_048, EMP_049 and UK to EMP_050, EMP_047
    countries = ["India"] * 45 + ["United States"] * 3 + ["UK"] * 2

    # City options by country
    cities_by_country = {
        "India": ["Coimbatore", "Chennai", "Bangalore", "Mumbai", "Hyderabad"],
        "United States": ["New York", "San Francisco", "Austin"],
        "UK": ["London", "Manchester"],
    }

    used_names = set()

    for idx in range(1, 51):
        user_id = f"EMP_{idx:03d}"

        if user_id in pinned_assignments:
            p = pinned_assignments[user_id]
            user_name = p["name"]
            dept = p["department"]
            role = p["role"]
            country = p["country"]
            city = p["city"]
            avg_download = p["avg_download"]
            used_names.add(user_name)
        else:
            # Pick a realistic unique name
            fname = FIRST_NAMES[(idx - 1) % len(FIRST_NAMES)]
            lname = LAST_NAMES[(idx - 1) % len(LAST_NAMES)]
            user_name = f"{fname} {lname}"
            if user_name in used_names:
                user_name = f"{fname} {LAST_NAMES[(idx * 3) % len(LAST_NAMES)]}"
            used_names.add(user_name)

            # Cycle department & role evenly
            dept, role = DEPT_ROLES[(idx - 1) % len(DEPT_ROLES)]
            
            # Country allocation
            country = countries[idx - 1]
            city = random.choice(cities_by_country[country])
            avg_download = round(random.uniform(15.0, 48.0), 1)

        known_device_id = f"DEV_{user_id}_LAPTOP"
        normal_start_hour = 9
        normal_end_hour = 18

        users.append({
            "user_id": user_id,
            "user_name": user_name,
            "department": dept,
            "role": role,
            "normal_country": country,
            "normal_city": city,
            "known_device_id": known_device_id,
            "normal_start_hour": normal_start_hour,
            "normal_end_hour": normal_end_hour,
            "avg_daily_download_mb": avg_download,
        })

    return pd.DataFrame(users)


def _ip_for_location(country: str, city: str, idx: int) -> str:
    """Generate consistent IP addresses for locations."""
    if country == "India":
        if city == "Coimbatore":
            return f"106.51.72.{10 + (idx % 200)}"
        elif city == "Bangalore":
            return f"122.171.18.{10 + (idx % 200)}"
        elif city == "Chennai":
            return f"117.216.45.{10 + (idx % 200)}"
        elif city == "Mumbai":
            return f"115.112.89.{10 + (idx % 200)}"
        else:
            return f"103.22.40.{10 + (idx % 200)}"
    elif country == "United States":
        return f"198.51.100.{10 + (idx % 200)}"
    elif country == "UK":
        return f"195.154.122.{10 + (idx % 200)}"
    return f"10.0.0.{10 + (idx % 200)}"


def generate_baseline_activity_logs(users_df: pd.DataFrame, days: int = 14) -> List[Dict[str, Any]]:
    """Generate realistic normal baseline activity logs over the past N days."""
    logs = []
    end_date = datetime(2026, 9, 23, 23, 59, 59)
    start_date = end_date - timedelta(days=days - 1)

    event_counter = 100000

    current_day = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    user_records = users_df.to_dict(orient="records")

    while current_day <= end_date:
        # 0 = Monday, 6 = Sunday
        weekday = current_day.weekday()
        is_weekend = weekday >= 5

        for u_idx, user in enumerate(user_records):
            # Weekend attendance is rare for baseline (5% probability)
            if is_weekend and random.random() > 0.05:
                continue

            # Rare weekday absence (e.g. sick leave / vacation: 3% probability)
            if not is_weekend and random.random() < 0.03:
                continue

            user_id = user["user_id"]
            user_name = user["user_name"]
            dept = user["department"]
            role = user["role"]
            country = user["normal_country"]
            city = user["normal_city"]
            device_id = user["known_device_id"]
            source_ip = _ip_for_location(country, city, u_idx)

            # Daily login between 08:45 and 09:30
            login_min_offset = random.randint(45, 90) # 8:45 to 9:30
            login_time = current_day + timedelta(hours=8, minutes=login_min_offset, seconds=random.randint(0, 59))

            # Occasional typo on login (1% chance single failed login followed by success)
            if random.random() < 0.01:
                event_counter += 1
                typo_time = login_time - timedelta(seconds=random.randint(20, 60))
                logs.append({
                    "event_id": f"EVT_{event_counter}",
                    "timestamp": typo_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": user_id,
                    "user_name": user_name,
                    "department": dept,
                    "role": role,
                    "event_type": "failed_login",
                    "login_status": "failed",
                    "source_ip": source_ip,
                    "country": country,
                    "city": city,
                    "device_id": device_id,
                    "known_device": True,
                    "resource": "sso_auth_portal",
                    "resource_type": "portal",
                    "resource_sensitivity": "low",
                    "download_mb": 0.0,
                    "scenario_tag": "normal",
                })

            # Successful login
            event_counter += 1
            logs.append({
                "event_id": f"EVT_{event_counter}",
                "timestamp": login_time.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": user_id,
                "user_name": user_name,
                "department": dept,
                "role": role,
                "event_type": "login",
                "login_status": "success",
                "source_ip": source_ip,
                "country": country,
                "city": city,
                "device_id": device_id,
                "known_device": True,
                "resource": "sso_auth_portal",
                "resource_type": "portal",
                "resource_sensitivity": "low",
                "download_mb": 0.0,
                "scenario_tag": "normal",
            })

            # 3 to 6 daily file actions during working hours (9 AM - 6 PM)
            num_actions = random.randint(3, 6)
            dept_res_list = DEPARTMENT_RESOURCES.get(dept, DEPARTMENT_RESOURCES["Engineering"])

            for a_idx in range(num_actions):
                action_hour = random.randint(user["normal_start_hour"], user["normal_end_hour"] - 1)
                action_min = random.randint(0, 59)
                action_sec = random.randint(0, 59)
                action_time = current_day.replace(hour=action_hour, minute=action_min, second=action_sec)

                # Ensure action_time is strictly after login
                if action_time <= login_time:
                    action_time = login_time + timedelta(minutes=random.randint(10, 45))

                res_name, res_type, res_sens = random.choice(dept_res_list)
                is_download = random.random() < 0.40

                if is_download:
                    evt_type = "file_download"
                    # Baseline download sizes conform to user's daily budget
                    download_val = round(random.uniform(0.5, 12.0), 2)
                else:
                    evt_type = "file_access"
                    download_val = 0.0

                event_counter += 1
                logs.append({
                    "event_id": f"EVT_{event_counter}",
                    "timestamp": action_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": user_id,
                    "user_name": user_name,
                    "department": dept,
                    "role": role,
                    "event_type": evt_type,
                    "login_status": "success",
                    "source_ip": source_ip,
                    "country": country,
                    "city": city,
                    "device_id": device_id,
                    "known_device": True,
                    "resource": res_name,
                    "resource_type": res_type,
                    "resource_sensitivity": res_sens,
                    "download_mb": download_val,
                    "scenario_tag": "normal",
                })

        current_day += timedelta(days=1)

    return logs


def inject_scenarios(users_df: pd.DataFrame, starting_event_id: int = 200000) -> List[Dict[str, Any]]:
    """Inject 5 specific attack/anomaly scenarios occurring on 2026-09-24."""
    scenario_logs = []
    evt_id = starting_event_id
    user_map = {row["user_id"]: row for row in users_df.to_dict(orient="records")}

    # =========================================================================
    # Scenario A (Compromised Finance Account) [EMP_014 - Finance]
    # - Off-hours login (02:15 AM), country="Russia", city="Moscow", device="UNKNOWN_DEV_X9", known_device=False.
    # - Accesses "payroll_2026_master.xlsx" (sensitivity="critical").
    # - File download of 2048.0 MB.
    # - scenario_tag="scenario_a_compromised_finance"
    # =========================================================================
    u14 = user_map["EMP_014"]
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 02:15:12",
        "user_id": u14["user_id"],
        "user_name": u14["user_name"],
        "department": u14["department"],
        "role": u14["role"],
        "event_type": "login",
        "login_status": "success",
        "source_ip": "185.220.101.5",
        "country": "Russia",
        "city": "Moscow",
        "device_id": "UNKNOWN_DEV_X9",
        "known_device": False,
        "resource": "sso_auth_portal",
        "resource_type": "portal",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "scenario_tag": "scenario_a_compromised_finance",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 02:18:30",
        "user_id": u14["user_id"],
        "user_name": u14["user_name"],
        "department": u14["department"],
        "role": u14["role"],
        "event_type": "file_access",
        "login_status": "success",
        "source_ip": "185.220.101.5",
        "country": "Russia",
        "city": "Moscow",
        "device_id": "UNKNOWN_DEV_X9",
        "known_device": False,
        "resource": "payroll_2026_master.xlsx",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 0.0,
        "scenario_tag": "scenario_a_compromised_finance",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 02:22:10",
        "user_id": u14["user_id"],
        "user_name": u14["user_name"],
        "department": u14["department"],
        "role": u14["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "185.220.101.5",
        "country": "Russia",
        "city": "Moscow",
        "device_id": "UNKNOWN_DEV_X9",
        "known_device": False,
        "resource": "payroll_2026_master.xlsx",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 2048.0,
        "scenario_tag": "scenario_a_compromised_finance",
    })

    # =========================================================================
    # Scenario B (Malicious Developer) [EMP_022 - Engineering]
    # - Off-hours session (01:30 AM), normal country, known device.
    # - Accesses "core_proprietary_source_code.zip" (sensitivity="critical").
    # - File download of 3500.0 MB.
    # - scenario_tag="scenario_b_malicious_dev"
    # =========================================================================
    u22 = user_map["EMP_022"]
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 01:30:15",
        "user_id": u22["user_id"],
        "user_name": u22["user_name"],
        "department": u22["department"],
        "role": u22["role"],
        "event_type": "login",
        "login_status": "success",
        "source_ip": _ip_for_location(u22["normal_country"], u22["normal_city"], 22),
        "country": u22["normal_country"],
        "city": u22["normal_city"],
        "device_id": u22["known_device_id"],
        "known_device": True,
        "resource": "sso_auth_portal",
        "resource_type": "portal",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "scenario_tag": "scenario_b_malicious_dev",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 01:35:40",
        "user_id": u22["user_id"],
        "user_name": u22["user_name"],
        "department": u22["department"],
        "role": u22["role"],
        "event_type": "file_access",
        "login_status": "success",
        "source_ip": _ip_for_location(u22["normal_country"], u22["normal_city"], 22),
        "country": u22["normal_country"],
        "city": u22["normal_city"],
        "device_id": u22["known_device_id"],
        "known_device": True,
        "resource": "core_proprietary_source_code.zip",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 0.0,
        "scenario_tag": "scenario_b_malicious_dev",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 01:42:00",
        "user_id": u22["user_id"],
        "user_name": u22["user_name"],
        "department": u22["department"],
        "role": u22["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": _ip_for_location(u22["normal_country"], u22["normal_city"], 22),
        "country": u22["normal_country"],
        "city": u22["normal_city"],
        "device_id": u22["known_device_id"],
        "known_device": True,
        "resource": "core_proprietary_source_code.zip",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 3500.0,
        "scenario_tag": "scenario_b_malicious_dev",
    })

    # =========================================================================
    # Scenario C (Privilege Misuse) [EMP_008 - Sales Rep]
    # - Normal working hours (11:15 AM), normal device.
    # - Accesses "executive_salaries_and_bonuses.xlsx" (department="HR", sensitivity="high").
    # - Small download 12.0 MB.
    # - scenario_tag="scenario_c_privilege_misuse"
    # =========================================================================
    u08 = user_map["EMP_008"]
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 11:15:20",
        "user_id": u08["user_id"],
        "user_name": u08["user_name"],
        "department": u08["department"],
        "role": u08["role"],
        "event_type": "file_access",
        "login_status": "success",
        "source_ip": _ip_for_location(u08["normal_country"], u08["normal_city"], 8),
        "country": u08["normal_country"],
        "city": u08["normal_city"],
        "device_id": u08["known_device_id"],
        "known_device": True,
        "resource": "executive_salaries_and_bonuses.xlsx",
        "resource_type": "file",
        "resource_sensitivity": "high",
        "download_mb": 0.0,
        "scenario_tag": "scenario_c_privilege_misuse",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 11:18:05",
        "user_id": u08["user_id"],
        "user_name": u08["user_name"],
        "department": u08["department"],
        "role": u08["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": _ip_for_location(u08["normal_country"], u08["normal_city"], 8),
        "country": u08["normal_country"],
        "city": u08["normal_city"],
        "device_id": u08["known_device_id"],
        "known_device": True,
        "resource": "executive_salaries_and_bonuses.xlsx",
        "resource_type": "file",
        "resource_sensitivity": "high",
        "download_mb": 12.0,
        "scenario_tag": "scenario_c_privilege_misuse",
    })

    # =========================================================================
    # Scenario D (Password Brute Force / Account Takeover) [EMP_031 - HR]
    # - 6 consecutive failed logins within 5 minutes from unknown IP & device.
    # - Followed by 1 successful login from unknown device.
    # - Immediately accesses "employee_ssn_records.csv" (sensitivity="critical").
    # - scenario_tag="scenario_d_password_attack"
    # =========================================================================
    u31 = user_map["EMP_031"]
    failed_times = [
        "2026-09-24 08:05:10",
        "2026-09-24 08:05:45",
        "2026-09-24 08:06:20",
        "2026-09-24 08:07:00",
        "2026-09-24 08:07:35",
        "2026-09-24 08:08:15",
    ]
    for ft in failed_times:
        evt_id += 1
        scenario_logs.append({
            "event_id": f"EVT_{evt_id}",
            "timestamp": ft,
            "user_id": u31["user_id"],
            "user_name": u31["user_name"],
            "department": u31["department"],
            "role": u31["role"],
            "event_type": "failed_login",
            "login_status": "failed",
            "source_ip": "194.26.29.112",
            "country": "Netherlands",
            "city": "Amsterdam",
            "device_id": "ATTACKER_BOX_88",
            "known_device": False,
            "resource": "sso_auth_portal",
            "resource_type": "portal",
            "resource_sensitivity": "low",
            "download_mb": 0.0,
            "scenario_tag": "scenario_d_password_attack",
        })

    # 1 successful login from unknown device
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 08:09:10",
        "user_id": u31["user_id"],
        "user_name": u31["user_name"],
        "department": u31["department"],
        "role": u31["role"],
        "event_type": "login",
        "login_status": "success",
        "source_ip": "194.26.29.112",
        "country": "Netherlands",
        "city": "Amsterdam",
        "device_id": "ATTACKER_BOX_88",
        "known_device": False,
        "resource": "sso_auth_portal",
        "resource_type": "portal",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "scenario_tag": "scenario_d_password_attack",
    })

    # Immediate sensitive file access
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 08:11:00",
        "user_id": u31["user_id"],
        "user_name": u31["user_name"],
        "department": u31["department"],
        "role": u31["role"],
        "event_type": "file_access",
        "login_status": "success",
        "source_ip": "194.26.29.112",
        "country": "Netherlands",
        "city": "Amsterdam",
        "device_id": "ATTACKER_BOX_88",
        "known_device": False,
        "resource": "employee_ssn_records.csv",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 0.0,
        "scenario_tag": "scenario_d_password_attack",
    })

    # File download
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 08:12:30",
        "user_id": u31["user_id"],
        "user_name": u31["user_name"],
        "department": u31["department"],
        "role": u31["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "194.26.29.112",
        "country": "Netherlands",
        "city": "Amsterdam",
        "device_id": "ATTACKER_BOX_88",
        "known_device": False,
        "resource": "employee_ssn_records.csv",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 45.0,
        "scenario_tag": "scenario_d_password_attack",
    })

    # =========================================================================
    # Scenario E (Benign Anomaly - Support Working Late) [EMP_005 - IT/Support]
    # - Off-hours login (11:20 PM = 23:20:00), known device, normal country.
    # - Accesses "system_patch_logs.txt" (sensitivity="low").
    # - Download 5.0 MB.
    # - scenario_tag="scenario_e_benign_anomaly"
    # =========================================================================
    u05 = user_map["EMP_005"]
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 23:20:00",
        "user_id": u05["user_id"],
        "user_name": u05["user_name"],
        "department": u05["department"],
        "role": u05["role"],
        "event_type": "login",
        "login_status": "success",
        "source_ip": _ip_for_location(u05["normal_country"], u05["normal_city"], 5),
        "country": u05["normal_country"],
        "city": u05["normal_city"],
        "device_id": u05["known_device_id"],
        "known_device": True,
        "resource": "sso_auth_portal",
        "resource_type": "portal",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "scenario_tag": "scenario_e_benign_anomaly",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 23:24:15",
        "user_id": u05["user_id"],
        "user_name": u05["user_name"],
        "department": u05["department"],
        "role": u05["role"],
        "event_type": "file_access",
        "login_status": "success",
        "source_ip": _ip_for_location(u05["normal_country"], u05["normal_city"], 5),
        "country": u05["normal_country"],
        "city": u05["normal_city"],
        "device_id": u05["known_device_id"],
        "known_device": True,
        "resource": "system_patch_logs.txt",
        "resource_type": "file",
        "resource_sensitivity": "low",
        "download_mb": 0.0,
        "scenario_tag": "scenario_e_benign_anomaly",
    })
    evt_id += 1
    scenario_logs.append({
        "event_id": f"EVT_{evt_id}",
        "timestamp": "2026-09-24 23:28:40",
        "user_id": u05["user_id"],
        "user_name": u05["user_name"],
        "department": u05["department"],
        "role": u05["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": _ip_for_location(u05["normal_country"], u05["normal_city"], 5),
        "country": u05["normal_country"],
        "city": u05["normal_city"],
        "device_id": u05["known_device_id"],
        "known_device": True,
        "resource": "system_patch_logs.txt",
        "resource_type": "file",
        "resource_sensitivity": "low",
        "download_mb": 5.0,
        "scenario_tag": "scenario_e_benign_anomaly",
    })

    return scenario_logs


def simulate_100_events(users_df: Optional[pd.DataFrame] = None) -> List[Dict[str, Any]]:
    """Generate 100 realistic corporate workday events for enterprise stress testing.
    
    Composition:
    - 87 events: Completely normal, routine business-hour activity (Risk Score: 0 pts)
    - 8 events: Mild anomalies / benign false positives (Risk Score: 15-35 pts)
    - Exactly 5 events: Critical / high real threat attacks (Risk Score: 75-100 pts)
    
    Total: exactly 100 events.
    """
    if users_df is None:
        users_path = os.path.join(DATA_DIR, "users.csv")
        if os.path.exists(users_path):
            users_df = pd.read_csv(users_path)
        else:
            users_df = generate_users()

    user_map = {row["user_id"]: row for row in users_df.to_dict(orient="records")}
    all_user_ids = sorted(list(user_map.keys()))

    events = []
    
    # -------------------------------------------------------------------------
    # 1. EXACTLY 5 CRITICAL / HIGH REAL THREAT ALERTS (Scores: 75 - 100 pts)
    # -------------------------------------------------------------------------
    # Threat 1: Stolen Credentials - Finance Exfiltration (EMP_014)
    u14 = user_map["EMP_014"]
    events.append({
        "timestamp": "2026-09-24 02:15:12",
        "user_id": u14["user_id"],
        "user_name": u14["user_name"],
        "department": u14["department"],
        "role": u14["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "185.220.101.5",
        "country": "Russia",
        "city": "Moscow",
        "device_id": "UNKNOWN_DEV_X9",
        "known_device": False,
        "resource": "payroll_2026_master.xlsx",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 2048.0,
        "scenario_tag": "stress_threat_finance_compromise",
    })

    # Threat 2: Disgruntled Developer - Source Code Exfiltration (EMP_022)
    u22 = user_map["EMP_022"]
    events.append({
        "timestamp": "2026-09-24 01:30:15",
        "user_id": u22["user_id"],
        "user_name": u22["user_name"],
        "department": u22["department"],
        "role": u22["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "122.171.18.22",
        "country": u22["normal_country"],
        "city": u22["normal_city"],
        "device_id": u22["known_device_id"],
        "known_device": True,
        "resource": "core_proprietary_source_code.zip",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 3500.0,
        "scenario_tag": "stress_threat_dev_exfiltration",
    })

    # Threat 3: Privilege Misuse - Sales Accessing HR Salaries (EMP_008)
    u08 = user_map["EMP_008"]
    events.append({
        "timestamp": "2026-09-24 11:15:20",
        "user_id": u08["user_id"],
        "user_name": u08["user_name"],
        "department": u08["department"],
        "role": u08["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "117.216.45.8",
        "country": u08["normal_country"],
        "city": u08["normal_city"],
        "device_id": u08["known_device_id"],
        "known_device": True,
        "resource": "executive_salaries_and_bonuses.xlsx",
        "resource_type": "file",
        "resource_sensitivity": "high",
        "download_mb": 12.0,
        "scenario_tag": "stress_threat_privilege_misuse",
    })

    # Threat 4: Account Takeover - Rapid Brute Force into SSN theft (EMP_031)
    u31 = user_map["EMP_031"]
    events.append({
        "timestamp": "2026-09-24 08:08:15",
        "user_id": u31["user_id"],
        "user_name": u31["user_name"],
        "department": u31["department"],
        "role": u31["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "194.26.29.112",
        "country": "Netherlands",
        "city": "Amsterdam",
        "device_id": "ATTACKER_BOX_88",
        "known_device": False,
        "resource": "employee_ssn_records.csv",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 45.0,
        "scenario_tag": "stress_threat_account_takeover",
    })

    # Threat 5: Legal Breach - Massive Confidential Merger File Theft (EMP_018)
    u18 = user_map.get("EMP_018", user_map["EMP_001"])
    events.append({
        "timestamp": "2026-09-24 23:45:00",
        "user_id": u18["user_id"],
        "user_name": u18["user_name"],
        "department": u18["department"],
        "role": u18["role"],
        "event_type": "file_download",
        "login_status": "success",
        "source_ip": "221.192.199.44",
        "country": "China",
        "city": "Beijing",
        "device_id": "DEV_COMPROMISED_99",
        "known_device": False,
        "resource": "merger_acquisition_confidential.pdf",
        "resource_type": "file",
        "resource_sensitivity": "critical",
        "download_mb": 4200.0,
        "scenario_tag": "stress_threat_legal_exfiltration",
    })

    # -------------------------------------------------------------------------
    # 2. EXACTLY 8 MILD ANOMALIES / BENIGN FALSE POSITIVES (Scores: 15 - 35 pts)
    # -------------------------------------------------------------------------
    mild_definitions = [
        ("EMP_005", "2026-09-24 23:20:00", "system_patch_logs.txt", "low", 5.0, True, None),
        ("EMP_011", "2026-09-24 19:15:00", "social_media_calendar.xlsx", "low", 2.0, True, None),
        ("EMP_025", "2026-09-24 07:45:00", "dev_environment_setup.md", "low", 1.0, True, None),
        ("EMP_033", "2026-09-24 14:10:00", "vendor_invoices_sep.pdf", "low", 3.5, False, "DEV_EMP_033_TABLET"),
        ("EMP_042", "2026-09-24 20:30:00", "crm_leads_september.csv", "medium", 4.0, True, None),
        ("EMP_003", "2026-09-24 10:15:00", "employee_handbook_v4.pdf", "low", 1.2, False, "DEV_EMP_003_HOME"),
        ("EMP_019", "2026-09-24 22:00:00", "server_inventory_audit.xlsx", "low", 2.0, True, None),
        ("EMP_027", "2026-09-24 21:10:00", "api_service_build.tar.gz", "medium", 18.0, True, None),
    ]

    for uid, ts, res, sens, dl, known_dev, alt_dev in mild_definitions:
        u = user_map.get(uid, user_map["EMP_001"])
        dev = alt_dev if alt_dev else u["known_device_id"]
        events.append({
            "timestamp": ts,
            "user_id": u["user_id"],
            "user_name": u["user_name"],
            "department": u["department"],
            "role": u["role"],
            "event_type": "file_download" if dl > 0 else "login",
            "login_status": "success",
            "source_ip": "106.51.72.50",
            "country": u["normal_country"],
            "city": u["normal_city"],
            "device_id": dev,
            "known_device": known_dev,
            "resource": res,
            "resource_type": "file",
            "resource_sensitivity": sens,
            "download_mb": dl,
            "scenario_tag": "stress_benign_noise",
        })

    # -------------------------------------------------------------------------
    # 3. EXACTLY 87 NORMAL ROUTINE LOGS (Risk Score: 0 pts)
    # -------------------------------------------------------------------------
    # Distribute 87 events across employees during regular working hours (9:00 - 17:30)
    needed_normal = 87
    normal_users = [user_map[uid] for uid in all_user_ids if uid not in ["EMP_014", "EMP_022", "EMP_031"]]
    
    for i in range(needed_normal):
        u = normal_users[i % len(normal_users)]
        dept = u["department"]
        dept_res_list = DEPARTMENT_RESOURCES.get(dept, DEPARTMENT_RESOURCES["Engineering"])
        res_name, res_type, res_sens = dept_res_list[i % len(dept_res_list)]

        # Time strictly between 09:15 and 17:45
        hour = 9 + ((i * 11) % 9)  # 9 through 17
        minute = (i * 17) % 60
        second = (i * 23) % 60
        ts = f"2026-09-24 {hour:02d}:{minute:02d}:{second:02d}"

        is_dl = (i % 3) == 0
        dl_amt = round(1.0 + ((i * 1.7) % 10.0), 2) if is_dl else 0.0

        events.append({
            "timestamp": ts,
            "user_id": u["user_id"],
            "user_name": u["user_name"],
            "department": dept,
            "role": u["role"],
            "event_type": "file_download" if is_dl else "file_access",
            "login_status": "success",
            "source_ip": "106.51.72.100",
            "country": u["normal_country"],
            "city": u["normal_city"],
            "device_id": u["known_device_id"],
            "known_device": True,
            "resource": res_name,
            "resource_type": res_type,
            "resource_sensitivity": "low" if res_sens == "low" else "medium",
            "download_mb": dl_amt,
            "scenario_tag": "stress_normal_routine",
        })

    # Sort strictly chronologically
    events.sort(key=lambda x: x["timestamp"])

    # Assign event IDs
    for idx, e in enumerate(events, start=1):
        e["event_id"] = f"EVT_STRESS_{idx:03d}"

    return events


def build_and_save_dataset() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Generate both users and activity logs, save them to data/ directory, and return DataFrames."""
    os.makedirs(DATA_DIR, exist_ok=True)

    print("Generating users...")
    users_df = generate_users()
    users_path = os.path.join(DATA_DIR, "users.csv")
    users_df.to_csv(users_path, index=False)
    print(f"Saved {len(users_df)} users to {users_path}")

    print("Generating 14-day baseline activity logs...")
    baseline_logs = generate_baseline_activity_logs(users_df, days=14)
    print(f"Generated {len(baseline_logs)} baseline activity records.")

    print("Injecting 5 attack scenarios...")
    scenario_logs = inject_scenarios(users_df, starting_event_id=len(baseline_logs) + 100000)
    print(f"Injected {len(scenario_logs)} scenario events.")

    all_logs = baseline_logs + scenario_logs
    logs_df = pd.DataFrame(all_logs)

    # Sort deterministically by timestamp
    logs_df["timestamp"] = pd.to_datetime(logs_df["timestamp"])
    logs_df = logs_df.sort_values(by="timestamp").reset_index(drop=True)
    logs_df["timestamp"] = logs_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # Format event_id cleanly
    logs_df["event_id"] = [f"EVT_{100001 + i}" for i in range(len(logs_df))]

    logs_path = os.path.join(DATA_DIR, "activity_logs.csv")
    logs_df.to_csv(logs_path, index=False)
    print(f"Saved {len(logs_df)} total activity records to {logs_path}")

    return users_df, logs_df


if __name__ == "__main__":
    build_and_save_dataset()
