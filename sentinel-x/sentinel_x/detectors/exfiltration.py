from typing import List
from sentinel_x.detectors.base import BaseDetector
from sentinel_x.models import LogEntry, ThreatAlert

class OffHoursExfiltrationDetector(BaseDetector):
    def detect(self, logs: List[LogEntry]) -> List[ThreatAlert]:
        alerts = []
        
        # YAML konfigürasyonundan parametreleri çek
        exfil_cfg = self.config.get("data_exfiltration", {})
        if not exfil_cfg.get("enabled", True):
            return alerts

        start_hour = exfil_cfg.get("off_hours_start", 0)
        end_hour = exfil_cfg.get("off_hours_end", 5)
        record_threshold = exfil_cfg.get("record_threshold", 50000)

        for log in logs:
            if log.event_type == "DATABASE_EXPORT":
                records = log.records_extracted or 0
                event_hour = log.timestamp.hour

                # Mesai dışı saat kontrolü (Örn: 00:00 - 05:00 arası)
                is_off_hours = start_hour <= event_hour <= end_hour
                is_high_volume = records >= record_threshold

                if is_off_hours and is_high_volume:
                    alerts.append(ThreatAlert(
                        alert_id=f"ALT-EXFIL-{log.event_id}",
                        user_id=log.user_id,
                        rule_name="Off-Hours Mass Data Exfiltration",
                        mitre_tactic="T1020 - Automated Exfiltration",
                        severity="HIGH",
                        risk_score=75,
                        details=f"Saat {event_hour:02d}:{log.timestamp.minute:02d}'de (Mesai Dışı) tek seferde {records:,} kayıt veritabanından dışa aktarıldı.",
                        recommended_action="Kullanıcının veritabanı oturumlarını sonlandırın ve DLP (Data Loss Prevention) incelemesi başlatın."
                    ))

        return alerts