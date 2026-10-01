import math
from typing import List
from sentinel_x.detectors.base import BaseDetector
from sentinel_x.models import LogEntry, ThreatAlert

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))

class ImpossibleTravelDetector(BaseDetector):
    def detect(self, logs: List[LogEntry]) -> List[ThreatAlert]:
        alerts = []
        user_history = {}
        max_speed = self.config.get("impossible_travel", {}).get("max_speed_kmh", 800.0)

        # Logları zamana göre sırala
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)

        for log in sorted_logs:
            if log.event_type == "LOGIN_SUCCESS" and log.latitude and log.longitude:
                user = log.user_id
                if user in user_history:
                    prev = user_history[user]
                    time_diff = (log.timestamp - prev.timestamp).total_seconds() / 3600.0

                    if time_diff > 0:
                        dist = haversine(prev.latitude, prev.longitude, log.latitude, log.longitude)
                        speed = dist / time_diff

                        if speed > max_speed:
                            alerts.append(ThreatAlert(
                                alert_id=f"ALT-TRAVEL-{log.event_id}",
                                user_id=user,
                                rule_name="Impossible Travel Speed Anomaly",
                                mitre_tactic="T1078 - Valid Accounts",
                                severity="CRITICAL",
                                risk_score=95,
                                details=f"{time_diff:.2f} saat içinde {dist:.0f} km mesafe kat edildi (Hesaplanan Hız: {speed:.0f} km/s). Nereden: {prev.location} -> Nereye: {log.location}",
                                recommended_action="Oturumu derhal sonlandırın ve MFA zorunluluğu ile şifre sıfırlama başlatın."
                            ))
                user_history[user] = log
        return alerts