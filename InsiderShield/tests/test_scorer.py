"""Unit tests for Phase 5: Risk Scoring & Severity Mapping."""

import pytest
from src.scorer import RiskScorer


def test_empty_rules_score():
    score, breakdown = RiskScorer.calculate_risk_score([])
    assert score == 0
    assert breakdown["base_score"] == 0
    assert breakdown["pattern_bonus"] == 0
    assert RiskScorer.map_severity(score) == "Low"


def test_single_rule_score():
    rules = [{"rule_name": "Off-Hours Activity", "score": 15}]
    score, breakdown = RiskScorer.calculate_risk_score(rules)
    assert score == 15
    assert breakdown["base_score"] == 15
    assert breakdown["pattern_bonus"] == 0
    assert RiskScorer.map_severity(score) == "Low"


def test_two_rules_score_medium():
    rules = [
        {"rule_name": "Off-Hours Activity", "score": 15},
        {"rule_name": "Unregistered Device", "score": 15},
    ]
    score, breakdown = RiskScorer.calculate_risk_score(rules)
    assert score == 30
    assert breakdown["pattern_bonus"] == 0
    assert RiskScorer.map_severity(score) == "Medium"


def test_three_rules_triggers_pattern_bonus():
    rules = [
        {"rule_name": "Off-Hours Activity", "score": 15},
        {"rule_name": "Anomalous Country/Location", "score": 20},
        {"rule_name": "Critical Asset Access", "score": 20},
    ]
    # base = 15 + 20 + 20 = 55, bonus = 15 -> total = 70 (High)
    score, breakdown = RiskScorer.calculate_risk_score(rules)
    assert breakdown["base_score"] == 55
    assert breakdown["pattern_bonus"] == 15
    assert score == 70
    assert RiskScorer.map_severity(score) == "High"


def test_score_caps_at_100():
    rules = [
        {"rule_name": "Off-Hours Activity", "score": 15},
        {"rule_name": "Anomalous Country/Location", "score": 20},
        {"rule_name": "Unregistered Device", "score": 15},
        {"rule_name": "Critical Asset Access", "score": 20},
        {"rule_name": "Abnormal Download Volume", "score": 20},
        {"rule_name": "Cross-Department Privilege Anomaly", "score": 25},
    ]
    # base = 115, bonus = 15 -> 130, capped at 100
    score, breakdown = RiskScorer.calculate_risk_score(rules)
    assert score == 100
    assert breakdown["total_score"] == 100
    assert RiskScorer.map_severity(score) == "Critical"


def test_severity_bracket_boundaries():
    assert RiskScorer.map_severity(0) == "Low"
    assert RiskScorer.map_severity(24) == "Low"
    assert RiskScorer.map_severity(25) == "Medium"
    assert RiskScorer.map_severity(49) == "Medium"
    assert RiskScorer.map_severity(50) == "High"
    assert RiskScorer.map_severity(74) == "High"
    assert RiskScorer.map_severity(75) == "Critical"
    assert RiskScorer.map_severity(100) == "Critical"
