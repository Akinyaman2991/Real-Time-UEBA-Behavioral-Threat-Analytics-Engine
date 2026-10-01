from abc import ABC, abstractmethod
from typing import List
from sentinel_x.models import LogEntry, ThreatAlert

class BaseDetector(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def detect(self, logs: List[LogEntry]) -> List[ThreatAlert]:
        pass