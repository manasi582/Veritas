"""
Settings file: /etc/veritas/config.env (the same path on Linux and macOS).

One line per setting, `NAME=value`, `#` for comments. It is read when Veritas starts and when a
command line tool runs, and it survives upgrades (the package never overwrites it). A setting that is
already in the process environment wins, so the service definition (macOS plist, systemd unit) can
still override the file. Only VERITAS_* settings and the two AI keys are taken from it.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_PATH = Path("/etc/veritas/config.env")
_ALLOWED = re.compile(r"^(VERITAS_[A-Z0-9_]+|ANTHROPIC_API_KEY|OPENAI_API_KEY)$")


def parse(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()     # a trailing comment
        if _ALLOWED.match(name):
            values[name] = value
    return values


def load_into_environment(path: Optional[Path] = None) -> List[str]:
    """Put the file's settings into os.environ without replacing any that are already set."""
    if path is None:
        env_path = os.environ.get("VERITAS_CONFIG_FILE", "").strip()
        if env_path:
            path = Path(env_path)
        elif sys.platform != "win32":
            path = DEFAULT_PATH
        else:
            return []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return []                               # no file, or not readable by this account: nothing to add
    loaded = []
    for name, value in parse(text).items():
        if name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded
