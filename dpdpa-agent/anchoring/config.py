"""
Anchoring settings. Off until configured.

A YAML file (`anchoring.yaml`, in /etc/veritas on Linux and macOS, in the data folder on Windows; override with
VERITAS_ANCHOR_CONFIG) holds the settings, exactly as in docs/ANCHORING.md:

    anchoring:
      enabled: true
      interval_minutes: 5
      every_n_records: 100
      min_witnesses: 2
      sinks:
        - type: file
          path: /mnt/audit-witness/veritas/
        - type: syslog
          host: siem.internal
          port: 6514
          protocol: tcp-tls

For a quick start, VERITAS_ANCHOR_DIR=/some/folder switches anchoring on with one file witness and nothing else.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class AnchorConfig:
    enabled: bool = False
    interval_minutes: float = 5.0
    every_n_records: int = 100
    min_witnesses: int = 1
    sinks: List[dict] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)


def config_path() -> Path:
    env = os.environ.get("VERITAS_ANCHOR_CONFIG", "").strip()
    if env:
        return Path(env)
    if sys.platform == "win32":
        from runtime_paths import data_root
        return data_root() / "anchoring.yaml"
    return Path("/etc/veritas/anchoring.yaml")


def load_config(path: Optional[Path] = None) -> AnchorConfig:
    cfg = AnchorConfig()
    quick = os.environ.get("VERITAS_ANCHOR_DIR", "").strip()
    path = path or config_path()
    raw = {}
    try:
        import yaml
        if path.is_file():
            raw = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("anchoring", {}) or {}
    except Exception as e:
        cfg.problems.append(f"{path}: cannot read the anchoring settings ({e})")
    if raw:
        cfg.enabled = bool(raw.get("enabled", False))
        cfg.interval_minutes = _number(raw.get("interval_minutes", 5), 5.0, cfg, "interval_minutes", minimum=0.5)
        cfg.every_n_records = int(_number(raw.get("every_n_records", 100), 100, cfg, "every_n_records", minimum=1))
        cfg.min_witnesses = int(_number(raw.get("min_witnesses", 1), 1, cfg, "min_witnesses", minimum=1))
        cfg.sinks = list(raw.get("sinks") or [])
    elif quick:
        cfg.enabled = True
        cfg.sinks = [{"type": "file", "path": quick}]
    if cfg.enabled and not cfg.sinks:
        cfg.problems.append("anchoring is on but no witness is configured: checkpoints cannot be witnessed")
    if cfg.enabled and cfg.min_witnesses > len(cfg.sinks) > 0:
        cfg.problems.append(f"min_witnesses is {cfg.min_witnesses} but only {len(cfg.sinks)} witness(es) are configured")
    return cfg


def _number(value, default, cfg, name, minimum):
    try:
        v = float(value)
    except (TypeError, ValueError):
        cfg.problems.append(f"{name} is not a number; using {default}")
        return default
    if v < minimum:
        cfg.problems.append(f"{name} must be at least {minimum}; using {minimum}")
        return minimum
    return v
