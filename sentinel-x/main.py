import json
from sentinel_x.config import ConfigLoader
from sentinel_x.models import LogEntry
from sentinel_x.detectors import (
    ImpossibleTravelDetector,
    StatisticalBehaviorDetector,
    OffHoursExfiltrationDetector
)
from sentinel_x.scoring import RiskEngine
from sentinel_x.reporter import SecurityReporter

def main():
    # 1. Konfigürasyonu yükle
    config = ConfigLoader.load_config("config/rules_config.yaml")

    # 2. Logları yükle ve Pydantic ile normalize et
    with open("data/system_access_logs.json", "r", encoding="utf-8") as f:
        raw_logs = json.load(f)
    logs = [LogEntry(**log) for log in raw_logs]

    # 3. Tüm tespit motorlarını çalıştır
    detectors = [
        ImpossibleTravelDetector(config),
        StatisticalBehaviorDetector(config),
        OffHoursExfiltrationDetector(config)
    ]

    all_alerts = []
    for detector in detectors:
        alerts = detector.detect(logs)
        all_alerts.extend(alerts)

    # 4. Kullanıcı birikimli risk skorlarını hesapla
    user_risks = RiskEngine.calculate_user_risk_profile(all_alerts)

    # 5. Güvenlik raporunu oluştur
    SecurityReporter.generate_markdown(all_alerts, user_risks, "docs/Threat_Detection_Report.md")
    print(f"[+] Detection execution finished successfully. Total Alerts Triggered: {len(all_alerts)}")

if __name__ == "__main__":
    main()