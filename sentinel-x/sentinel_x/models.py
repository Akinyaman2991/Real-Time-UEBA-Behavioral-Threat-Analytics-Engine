from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class LogEntry(BaseModel):
    event_id: str
    timestamp: datetime
    user_id: str
    event_type: str
    source_ip: str
    location: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    records_extracted: Optional[int] = 0
    user_role: Optional[str] = "Standard User"
    target_role: Optional[str] = None

class ThreatAlert(BaseModel):
    alert_id: str
    user_id: str
    rule_name: str
    mitre_tactic: str
    severity: str
    risk_score: int
    details: str
    recommended_action: str