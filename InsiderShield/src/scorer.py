"""Transparent Risk Scoring & Severity Mapping for InsiderShield.

Calculates composite risk score (0-100) and maps to standard SOC severity bands:
- Low (0–24)
- Medium (25–49)
- High (50–74)
- Critical (75–100)
"""

from typing import List, Dict, Any, Tuple


class RiskScorer:
    """Computes deterministic composite risk score and severity classifications."""

    @staticmethod
    def calculate_risk_score(triggered_rules: List[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """Calculate composite risk score from list of triggered rules.
        
        Formula:
          base_score = sum(rule["score"])
          pattern_bonus = +15 if len(triggered_rules) >= 3 else 0
          final_score = min(100, base_score + pattern_bonus)
        
        Returns:
          (final_score, breakdown_dict)
        """
        if not triggered_rules:
            return 0, {
                "base_score": 0,
                "pattern_bonus": 0,
                "total_score": 0,
                "rule_count": 0,
                "rule_scores": {},
            }

        base_score = sum(int(r.get("score", 0)) for r in triggered_rules)
        rule_scores = {r.get("rule_name", f"Rule_{i}"): int(r.get("score", 0)) for i, r in enumerate(triggered_rules)}

        # Composite pattern bonus for multi-signal attacks (>= 3 concurrent triggers)
        pattern_bonus = 15 if len(triggered_rules) >= 3 else 0
        total_score = min(100, base_score + pattern_bonus)

        breakdown = {
            "base_score": base_score,
            "pattern_bonus": pattern_bonus,
            "total_score": total_score,
            "rule_count": len(triggered_rules),
            "rule_scores": rule_scores,
        }
        return total_score, breakdown

    @staticmethod
    def map_severity(score: int) -> str:
        """Map numeric score (0-100) to SOC severity bracket."""
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        else:
            return "Low"
