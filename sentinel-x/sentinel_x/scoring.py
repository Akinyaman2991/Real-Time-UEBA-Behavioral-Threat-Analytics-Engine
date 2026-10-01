from typing import List, Dict
from sentinel_x.models import ThreatAlert

class RiskEngine:
    @staticmethod
    def calculate_user_risk_profile(alerts: List[ThreatAlert]) -> Dict[str, dict]:
        user_profile = {}
        
        for alert in alerts:
            user = alert.user_id
            if user not in user_profile:
                user_profile[user] = {"total_risk_score": 0, "alerts_count": 0, "highest_severity": "LOW"}
            
            user_profile[user]["total_risk_score"] += alert.risk_score
            user_profile[user]["alerts_count"] += 1
            
            if alert.severity == "CRITICAL":
                user_profile[user]["highest_severity"] = "CRITICAL"
            elif alert.severity == "HIGH" and user_profile[user]["highest_severity"] != "CRITICAL":
                user_profile[user]["highest_severity"] = "HIGH"

        return user_profile