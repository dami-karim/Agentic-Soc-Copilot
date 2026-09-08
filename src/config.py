"""
Week 8 — Multi-tenant configuration system.

Allows different organizations/tenants to define:
  - Custom severity scoring rules
  - ATT&CK technique whitelists / blacklists
  - Custom containment playbooks per technique
  - Integration configs (SIEM endpoints, ticketing, etc.)
  - Notification channels (Slack, Teams, email)

Configuration is loaded from YAML files with environment variable overrides,
enabling 12-factor app deployment (https://12factor.net/config).
"""
import os
import yaml
from typing import Any
from pathlib import Path

DEFAULT_CONFIG = {
    "org_name": "default",
    "severity_weights": {
        "low": 10,
        "medium": 40,
        "high": 70,
        "critical": 90,
    },
    "eventcode_boosts": {
        "4625": 20,
        "4624": 10,
        "4688": 25,
        "4698": 30,
        "4672": 15,
        "4776": 20,
    },
    "benign_threshold": 30.0,
    "borderline_margin": 5.0,
    "attack_technique_threshold": 0.3,
    "technique_blacklist": [],
    "playbooks": {
        "default": {
            "on_true_positive": ["isolate_host", "full_edr_scan", "reset_credentials"],
            "on_false_positive": ["update_detection_rules", "collect_forensics"],
            "notification_channels": ["slack#sec-ops"],
        }
    },
    "integrations": {
        "siem": {"type": "opensearch", "endpoint": "http://localhost:9200"},
        "asset_graph": {"type": "neo4j", "endpoint": "bolt://localhost:7687"},
        "vector_store": {"type": "qdrant", "endpoint": "http://localhost:6333"},
        "ticketing": None,
    },
    "model": {
        "provider": "ollama",
        "model": os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        "temperature": 0.0,
        "max_tokens": 2048,
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "docs_enabled": True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(org_id: str = "default") -> dict[str, Any]:
    """
    Load configuration for the given tenant/organization.

    Resolution order (highest priority last):
      1. defaults (DEFAULT_CONFIG)
      2. config file: config/{org_id}.yaml
      3. environment variables (SOC_{KEY})
    """
    config_path = Path("config") / f"{org_id}.yaml"
    config = DEFAULT_CONFIG.copy()

    if config_path.exists():
        with open(config_path) as f:
            file_config = yaml.safe_load(f) or {}
        config = _deep_merge(config, file_config)

    # Environment variable overrides (SOC_ prefix, e.g. SOC_BENIGN_THRESHOLD)
    for key in list(os.environ.keys()):
        if key.startswith("SOC_"):
            config_key = key[4:].lower()
            try:
                value = os.environ[key]
                if config_key == "benign_threshold":
                    config["benign_threshold"] = float(value)
                elif config_key == "borderline_margin":
                    config["borderline_margin"] = float(value)
                elif config_key == "attack_technique_threshold":
                    config["attack_technique_threshold"] = float(value)
                else:
                    config[config_key] = value
            except (ValueError, KeyError):
                config[config_key] = value

    return config


def get_severity_weights(config: dict) -> dict[str, int]:
    return config.get("severity_weights", DEFAULT_CONFIG["severity_weights"])


def get_eventcode_boosts(config: dict) -> dict[str, int]:
    return config.get("eventcode_boosts", DEFAULT_CONFIG["eventcode_boosts"])


def is_technique_allowed(config: dict, technique_id: str) -> bool:
    """Check if an ATT&CK technique is in the tenant's allowed list."""
    blacklist = config.get("technique_blacklist", [])
    return technique_id not in blacklist


def get_playbook(config: dict, technique_id: str | None = None) -> dict:
    """Get the playbook for a given technique, falling back to default."""
    playbooks = config.get("playbooks", {})
    if technique_id and technique_id in playbooks:
        return _deep_merge(playbooks.get("default", {}), playbooks[technique_id])
    return playbooks.get("default", DEFAULT_CONFIG["playbooks"]["default"])
