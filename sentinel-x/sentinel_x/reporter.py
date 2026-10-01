from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from sentinel_x.models import ThreatAlert

class SecurityReporter:
    @staticmethod
    def generate_markdown(alerts: List[ThreatAlert], user_risks: Dict[str, Dict[str, Any]], output_path: str = "docs/Threat_Detection_Report.md") -> None:
        """
        Üretilen alarmları ve hesaplanan kullanıcı risk skorlarını alarak
        profesyonel bir SOC Incident Markdown raporu oluşturur.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        markdown_lines = [
            "# 🛡️ SENTINEL-X | Security Threat & UEBA Incident Report",
            "",
            f"**Generated At:** {now_str}  ",
            "**Engine Version:** v1.0.0  ",
            "**Scope:** Real-Time Behavioral Analytics & UEBA Threat Detection  ",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            "During the execution of the **SENTINEL-X UEBA Engine**, system access logs were systematically analyzed using multi-layered threat detection algorithms including **Haversine Speed Anomalies**, **Z-Score Behavioral Profiling**, **Off-Hours Mass Exfiltration**, and **Threat Intelligence Feed Matching**.",
            "",
            f"- **Total Threat Alerts Triggered:** `{len(alerts)}`",
            f"- **High / Critical Risk Users:** `{len([u for u in user_risks.values() if u['risk_score'] >= 70])}`",
            "",
            "---",
            "",
            "## 👤 User Risk Profiles & Threat Scores",
            "",
            "| User ID | Accumulated Risk Score | Risk Level | Total Alerts |",
            "| :--- | :---: | :---: | :---: |"
        ]

        # Kullanıcı Risk Tablosunu Hazırla
        for user_id, risk_data in user_risks.items():
            score = risk_data["risk_score"]
            if score >= 90:
                level_str = "🔴 **CRITICAL**"
            elif score >= 70:
                level_str = "🟠 **HIGH**"
            elif score >= 40:
                level_str = "🟡 **MEDIUM**"
            else:
                level_str = "🟢 **LOW**"

            markdown_lines.append(f"| **`{user_id}`** | **{score}** | {level_str} | {risk_data['alert_count']} |")

        markdown_lines.extend([
            "",
            "---",
            "",
            "## 🚨 Triggered Threat Alerts",
            ""
        ])

        # Alarm Detaylarını Ekle
        if not alerts:
            markdown_lines.append("*No threat alerts triggered during this execution pass.*")
        else:
            for idx, alert in enumerate(alerts, 1):
                severity_icon = "🔴" if alert.severity in ["CRITICAL", "HIGH"] else "🟡"
                markdown_lines.extend([
                    f"### {idx}. {alert.rule_name}",
                    f"- **Alert ID:** `{alert.alert_id}`",
                    f"- **User:** `{alert.user_id}`",
                    f"- **MITRE ATT&CK Tactic:** `{alert.mitre_tactic}`",
                    f"- **Severity:** {severity_icon} **{alert.severity}** (Risk Score: **{alert.risk_score}**)",
                    f"- **Details:** {alert.details}",
                    f"- **Recommended Action:** {alert.recommended_action}",
                    ""
                ])

        # Incident Playbook Kısmı
        markdown_lines.extend([
            "---",
            "",
            "## 🛠 Recommended Incident Response Playbook",
            "",
            "1. **Critical/High Risk Accounts:** Immediately force-terminate all active OAuth / SAML sessions and enforce password reset with MFA re-enrollment.",
            "2. **Malicious IP Findings:** Automatically propagate detected C2 / Tor Exit Node IP addresses to Perimeter Firewalls and WAF blocklists.",
            "3. **Data Exfiltration Alerts:** Engage Data Loss Prevention (DLP) protocols and isolate host machines involved in massive database queries.",
            "",
            "---",
            "",
            "*This document was automatically compiled and rendered by **SENTINEL-X Core Engine**.*"
        ])

        # Dosyaya Yaz
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(markdown_lines))

        print(f"[+] Report generated successfully at: {path.resolve()}")