from pathlib import Path
import yaml
from typing import Dict, Any

class ConfigLoader:
    @staticmethod
    def load_config(config_path: str = "config/rules_config.yaml") -> Dict[str, Any]:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found at: {config_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            try:
                return yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise ValueError(f"Error parsing YAML config file: {e}")