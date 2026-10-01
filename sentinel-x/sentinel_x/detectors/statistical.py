import numpy as np
from typing import List
from collections import defaultdict
from sentinel_x.detectors.base import BaseDetector
from sentinel_x.models import LogEntry, ThreatAlert

class StatisticalBehaviorDetector(BaseDetector):
    def detect(self, logs: List[LogEntry]) -> List[ThreatAlert]:
        alerts = []
        z_threshold = self.config.get("statistical_anomaly", {}).get("z_score_threshold", 2.5)
        min_samples = self.config.get("statistical_anomaly", {}).get("min_historical_samples", 3)

        user_exports = defaultdict(list)

        for log in logs:
            if log.event_type == "DATABASE_EXPORT" and log.records_extracted > 0:
                history = user_exports[log.user_id]
                
                # Yeterli geçmiş veri varsa Z-Score hesapla
                if len(history) >= min_samples:
                    mean = np.mean(history)
                    std = np.std(history)
                    
                    if std > 0:
                        z_score = (log.records_extracted - mean) / std
                        if z_score > z_threshold:
                            alerts.append(ThreatAlert(
                                alert_id=f"ALT-STAT-{log.event_id}",
                                user_id=log.user_id,
                                rule_name="Behavioral Volume Anomaly (Z-Score)",
                                mitre_tactic="T1030 - Data Transfer Size Limits",
                                severity="HIGH",
                                risk_score=80,
                                details=f"Kullanıcının geçmiş ortalaması {mean:.0f} kayıt iken {log.records_extracted:,} kayıt çekildi (Z-Score: {z_score:.2f}).",
                                recommended_action="Kullanıcının veri erişim yetkilerini inceleyin ve DLP alarmı oluşturun."
                            ))
                
                # Kullanıcı geçmişine yeni sorguyu ekle
                history.append(log.records_extracted)

        return alerts