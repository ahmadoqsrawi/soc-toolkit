"""
config/loader.py
----------------
Loads YAML config files and exposes a typed Config object.
Falls back to defaults when no config file is provided.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib     import Path
from typing      import Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


@dataclass
class Config:
    # Detection thresholds
    brute_force_threshold:  int  = 5
    brute_force_window_sec: int  = 1800   # 30 minutes

    spray_threshold:        int  = 10     # distinct usernames from one IP
    spray_window_sec:       int  = 300

    # Allowlist
    allowed_ips:    list[str] = field(default_factory=list)
    allowed_users:  list[str] = field(default_factory=list)

    # Output
    max_events_per_finding: int = 100     # cap evidence list size

    # Performance
    stream_buffer_size: int = 10_000      # max events in correlation window


def load_config(path: Optional[Path] = None) -> Config:
    """Load config from YAML file, or return defaults if path is None."""
    if path is None:
        return Config()

    if not _YAML_AVAILABLE:
        print("[WARNING] PyYAML not installed. Using default config. "
              "Install with: pip install pyyaml")
        return Config()

    if not path.exists():
        print(f"[WARNING] Config file not found: {path}. Using defaults.")
        return Config()

    with open(path) as f:
        data = yaml.safe_load(f) or {}

    return Config(**{k: v for k, v in data.items()
                     if k in Config.__dataclass_fields__})
