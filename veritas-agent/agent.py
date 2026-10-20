"""
Veritas Agent — Deployable telemetry forwarder
=========================================================
Reads log files and Docker container logs, forwards every line to the
Veritas Server as an authenticated event.

Deliberately dumb by design — no PII detection, no compliance logic,
no authoritative storage. Its only job: read → authenticate → forward.

TLS support:
  The agent communicates with the Veritas Server over HTTPS by default
  when the server address starts with https://.

  TLS verification is controlled by:
    - VERITAS_CA_CERT       path to server's CA/self-signed cert (recommended)
    - VERITAS_TLS_VERIFY    "true" (default) | "false" (insecure, dev only)

  The server certificate can be obtained from:
    GET {veritas_address}/api/tls/cert

State (the agent's permanent identity):
  After registering, the agent saves its identity (agent id, token, endpoint)
  and the server certificate it trusts in a state directory. The directory is,
  in order of priority: $VERITAS_STATE_DIR, "state_dir" in the config, or the
  current working directory. It must be writable: it is checked BEFORE
  registering, because the registration key can only be used once.

Exit codes:
  0   clean shutdown
  1   transient failure (server unreachable); supervisors may restart the agent
  78  configuration problem that retrying cannot fix (bad/used key, unwritable
      state directory, missing config, TLS misconfiguration); the systemd unit
      lists 78 in RestartPreventExitStatus so it is reported once, not looped

Usage:
    python agent.py [--config agent-config.yaml]

Config file (agent-config.yaml):
    veritas_address: https://192.168.1.50:8000
    registration_key: <one-time-key>
    source_label: production-server-1

    tls:
      ca_cert: /etc/veritas/server.crt   # path to server cert for verification
      verify: true                        # set false only for development

    sources:
      - type: file
        path: /var/log/order-service/app.log
        source_system: order-service
      - type: docker
        container: marketing-service
        source_system: marketing-analytics

    redaction:                  # optional; see docs/AGENT_REDACTION.md
      mode: mask                # monitor (default) | mask | hash | drop, for every kind of data below
      categories:               # optional per kind: aadhaar, pan, phone, email, card
        card: drop
        email: monitor
      fail_closed: true         # if redaction fails for a line, drop the line instead of sending it raw
      max_line_chars: 65536     # longer lines are cut here (nothing past the cut is sent)
      tee_file: /var/log/veritas-agent/masked.log   # optional masked copy for a log shipper
      hash_key: ${VERITAS_HASH_KEY}                 # needed for mode: hash (16 or more characters)
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import logging
import os
import queue
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import requests
import yaml

try:   # the shared recognizer pack (next to this file); needed only when redaction is configured
    import veritas_recognizers as vr
except ImportError:    # pragma: no cover - a damaged install; load_config says so if redaction is asked for
    vr = None

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("veritas.agent")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STATE_FILE_NAME         = ".veritas_state.json"
SERVER_CERT_NAME        = ".veritas_server.crt"
CONFIG_FILE_DEFAULT     = Path("agent-config.yaml")
EXIT_CONFIG             = 78    # configuration error that retrying cannot fix
HEARTBEAT_INTERVAL      = 30    # seconds
BUFFER_MAX              = 1000  # max queued events before dropping
FORWARD_TIMEOUT         = 10    # seconds per HTTP request
REGISTRATION_RETRIES    = 5
REGISTRATION_RETRY_DELAY = 5   # seconds between registration attempts
MAX_BACKOFF             = 30    # seconds, forwarding retry cap

# ---------------------------------------------------------------------------
# TLS configuration
# ---------------------------------------------------------------------------

def _silence_insecure_request_warning() -> None:
    """
    With verification turned off, urllib3 repeats an InsecureRequestWarning on every request,
    which floods the service log. The agent has already warned once, clearly, at start-up.
    """
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass


def _tls_verify(config: Dict[str, Any]) -> Union[bool, str]:
    """
    Return the TLS verification setting for requests calls.

    Priority (highest to lowest):
      1. VERITAS_TLS_VERIFY env var ("false" → skip, "true" or missing → verify)
      2. VERITAS_CA_CERT env var → path to CA/server cert
      3. config["tls"]["ca_cert"] → path to CA/server cert
      4. config["tls"]["verify"] == False → skip (dev only)
      5. Default: True (strict verification)

    Returns:
      True      — use system CA bundle (requires cert signed by trusted CA)
      str       — path to CA cert file (for self-signed / private CA)
      False     — skip TLS verification (INSECURE — log warning)
    """
    # Environment overrides take highest priority
    env_verify = os.environ.get("VERITAS_TLS_VERIFY", "").strip().lower()
    if env_verify == "false":
        logger.warning(
            "TLS verification disabled (VERITAS_TLS_VERIFY=false). "
            "This is insecure and should not be used in production."
        )
        _silence_insecure_request_warning()
        return False

    env_ca = os.environ.get("VERITAS_CA_CERT", "").strip()
    if env_ca:
        if Path(env_ca).exists():
            return env_ca
        logger.warning("VERITAS_CA_CERT path does not exist: %s — falling back to system CA", env_ca)
        return True

    # Config file TLS section
    tls_cfg = config.get("tls", {}) or {}
    cfg_ca = tls_cfg.get("ca_cert", "")
    if cfg_ca and Path(cfg_ca).exists():
        return str(cfg_ca)

    cfg_verify = tls_cfg.get("verify", True)
    if cfg_verify is False:
        logger.warning(
            "TLS verification disabled in config (tls.verify: false). "
            "This is insecure and should not be used in production."
        )
        _silence_insecure_request_warning()
        return False

    return True  # default: strict verification


def _fetch_server_cert(base_url: str, dest: Path, verify: Union[bool, str]) -> bool:
    """
    Download the server's TLS certificate from GET {base_url}/api/tls/cert.
    Saves it to dest. Returns True on success.
    Used during enrollment to obtain the CA cert for future connections.
    """
    try:
        url = base_url.rstrip("/") + "/api/tls/cert"
        resp = requests.get(url, timeout=10, verify=verify)
        if resp.ok and resp.text.startswith("-----BEGIN CERTIFICATE"):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(resp.text, encoding="utf-8")
            logger.info("Downloaded server TLS certificate to %s", dest)
            return True
    except Exception as e:
        logger.debug("Could not fetch server cert: %s", e)
    return False


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value: Any, missing: Optional[List[str]] = None) -> Any:
    """
    Replace ${NAME} with the environment variable NAME in every string of the config
    (recursively). Unset variables are collected in `missing` instead of being left as
    literal text: a registration key of "${VERITAS_REGISTRATION_KEY}" must never be sent
    to the server as if it were a key.
    """
    if missing is None:
        missing = []
    if isinstance(value, str):
        def sub(m: "re.Match[str]") -> str:
            name = m.group(1)
            if name in os.environ:
                return os.environ[name]
            missing.append(name)
            return m.group(0)
        return _ENV_REF.sub(sub, value)
    if isinstance(value, list):
        return [expand_env(v, missing) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v, missing) for k, v in value.items()}
    return value


K8S_MATCH_KEYS = ("namespace", "pod", "container")
K8S_DEFAULT_PATH = "/var/log/containers/*.log"
LOG_FORMATS = ("raw", "cri", "docker", "auto")
MAX_FILES_DEFAULT = 500


def validate_sources(sources: Any) -> List[str]:
    """Return a list of problems with the sources section (empty list = fine)."""
    problems: List[str] = []
    if sources is None:
        return problems
    if not isinstance(sources, list):
        return ["'sources' must be a list"]
    for i, src in enumerate(sources):
        where = f"sources[{i}]"
        if not isinstance(src, dict):
            problems.append(f"{where} must be a mapping")
            continue
        kind = str(src.get("type", "")).lower()
        if kind not in ("file", "docker", "kubernetes_logs", "db_schema_log", "syslog"):
            problems.append(f"{where}: unknown type {src.get('type')!r} (use file, docker, kubernetes_logs, db_schema_log or syslog)")
            continue
        fmt = src.get("format")
        if fmt is not None and str(fmt).lower() not in LOG_FORMATS:
            problems.append(f"{where}: format must be one of {', '.join(LOG_FORMATS)}")
        max_files = src.get("max_files")
        if max_files is not None and (not isinstance(max_files, int) or isinstance(max_files, bool) or max_files < 1):
            problems.append(f"{where}: max_files must be a positive integer")
        if kind in ("file", "db_schema_log") and not src.get("path"):
            problems.append(f"{where}: {kind} source needs a path")
        if kind in ("file", "db_schema_log", "syslog") and not src.get("source_system"):
            problems.append(f"{where}: {kind} source needs a source_system")
        if kind == "syslog":
            port = src.get("port")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                problems.append(f"{where}: syslog needs a port from 1 to 65535")
            if str(src.get("protocol", "udp")).lower() not in ("udp", "tcp"):
                problems.append(f"{where}: syslog protocol must be udp or tcp")
        if kind == "docker" and not src.get("container"):
            problems.append(f"{where}: docker source needs a container")
        if kind == "kubernetes_logs":
            if src.get("unmapped", "drop") != "drop":
                problems.append(f"{where}: unmapped must be 'drop' (the only supported mode)")
            rules = src.get("rules")
            if not isinstance(rules, list) or not rules:
                problems.append(f"{where}: kubernetes_logs needs at least one rule (a mapping from "
                                f"namespace/pod/container to a source_system)")
                continue
            for j, rule in enumerate(rules):
                rwhere = f"{where}.rules[{j}]"
                if not isinstance(rule, dict):
                    problems.append(f"{rwhere} must be a mapping")
                    continue
                match = rule.get("match")
                if not isinstance(match, dict) or not match:
                    problems.append(f"{rwhere}: 'match' must list at least one of {', '.join(K8S_MATCH_KEYS)}")
                else:
                    bad = [k for k in match if k not in K8S_MATCH_KEYS]
                    if bad:
                        problems.append(f"{rwhere}: unknown match key(s) {bad}; allowed: {', '.join(K8S_MATCH_KEYS)}")
                    if any(not isinstance(v, str) or not v for v in match.values()):
                        problems.append(f"{rwhere}: match values must be non-empty text patterns")
                target = rule.get("source_system")
                if not isinstance(target, str) or not target.strip():
                    problems.append(f"{rwhere}: source_system is required")
                else:
                    try:
                        target.format(namespace="n", pod="p", container="c")
                    except (KeyError, IndexError, ValueError):
                        problems.append(f"{rwhere}: source_system may only use {{namespace}}, {{pod}} and {{container}}")
    return problems


REDACTION_MODES = ("monitor", "mask", "hash", "drop")
REDACTION_KEYS = {"mode", "categories", "fail_closed", "max_line_chars", "tee_file", "tee_max_bytes", "hash_key"}
DEFAULT_MAX_LINE_CHARS = 65536
DEFAULT_TEE_MAX_BYTES = 50 * 1024 * 1024


def validate_redaction(section: Any) -> List[str]:
    """Problems with the redaction section (empty list = fine)."""
    if section is None:
        return []
    if not isinstance(section, dict):
        return ["'redaction' must be a mapping"]
    problems: List[str] = []
    if vr is None:
        return ["redaction needs veritas_recognizers.py next to agent.py, and it is missing (reinstall the agent)"]
    unknown = sorted(set(section) - REDACTION_KEYS)
    if unknown:
        problems.append(f"redaction: unknown setting(s) {unknown}; allowed: {', '.join(sorted(REDACTION_KEYS))}")
    default = str(section.get("mode", "monitor")).lower()
    if default not in REDACTION_MODES:
        problems.append(f"redaction.mode must be one of {', '.join(REDACTION_MODES)}")
    cats = section.get("categories") or {}
    labels = sorted(l.lower() for l in vr.LABELS.values())
    if not isinstance(cats, dict):
        problems.append("redaction.categories must be a mapping of kind to mode")
        cats = {}
    for k, v in cats.items():
        if str(k).lower() not in labels:
            problems.append(f"redaction.categories: unknown kind {k!r}; use {', '.join(labels)}")
        if str(v).lower() not in REDACTION_MODES:
            problems.append(f"redaction.categories.{k} must be one of {', '.join(REDACTION_MODES)}")
    modes = {default} | {str(v).lower() for v in cats.values()}
    n = section.get("max_line_chars", DEFAULT_MAX_LINE_CHARS)
    if not isinstance(n, int) or isinstance(n, bool) or not 1024 <= n <= 1_000_000:
        problems.append("redaction.max_line_chars must be a whole number from 1024 to 1000000")
    if not isinstance(section.get("fail_closed", True), bool):
        problems.append("redaction.fail_closed must be true or false")
    if "hash" in modes and section.get("hash_key") and len(str(section.get("hash_key"))) < 16:
        problems.append("redaction.hash_key must be 16 or more characters (or leave it out to use the key the server delivers)")
    if section.get("tee_file") and not (modes - {"monitor"}):
        problems.append("redaction.tee_file needs at least one kind set to mask, hash or drop (otherwise it would copy raw lines)")
    return problems


class MaskedTee:
    """Appends the lines that are actually sent to a second file, for a log shipper that must never see raw data."""

    def __init__(self, path: str, max_bytes: int = DEFAULT_TEE_MAX_BYTES) -> None:
        self.path, self.max_bytes = Path(path), max_bytes
        self._lock = threading.Lock()
        self._fh = None

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        self._fh = os.fdopen(fd, "a", encoding="utf-8", errors="replace", newline="\n")

    def write(self, line: str) -> None:
        with self._lock:
            if self._fh is None:
                self._open()
            if self.max_bytes and self._fh.tell() > self.max_bytes:
                self._fh.close()
                self._fh = None
                os.replace(str(self.path), str(self.path) + ".1")
                self._open()
            self._fh.write(line.replace("\r", " ").replace("\n", " ") + "\n")
            self._fh.flush()


class Redactor:
    """
    Masks, hashes or drops structured personal data in a line before it leaves the host.

    Per kind of data (aadhaar, pan, phone, email, card) the mode is: monitor (send as is), mask ([PHONE_REDACTED]),
    hash (a keyed token, [PHONE#...], that lets the server find the same identifier again without holding it) or
    drop (the line is not sent at all). It cannot find names; that stays on the server. It does not change the
    application's own log files.
    """

    def __init__(self, section: Optional[Dict[str, Any]] = None, tee: Optional[MaskedTee] = None) -> None:
        section = section or {}
        self.default = str(section.get("mode", "monitor")).lower()
        self.modes: Dict[str, str] = {}
        if vr is not None:
            for label in (l.lower() for l in vr.LABELS.values()):
                self.modes[label] = str((section.get("categories") or {}).get(label, self.default)).lower()
        self.fail_closed = bool(section.get("fail_closed", True))
        # without a redaction section nothing is cut: lines go as they always did
        self.max_chars = int(section.get("max_line_chars", DEFAULT_MAX_LINE_CHARS)) if section else 10 ** 12
        configured = str(section.get("hash_key") or "")
        self.key_pinned = bool(configured)           # a key in the file wins over the one the server delivers
        self.key = configured.encode("utf-8")
        self.key_id = vr.key_id_of(self.key) if (vr and self.key) else ""
        self.tee = tee
        self.active = any(m != "monitor" for m in self.modes.values())
        self._entities = [e for e, l in (vr.LABELS.items() if vr else []) if self.modes.get(l.lower(), "monitor") != "monitor"]

    _STRICTNESS = {"monitor": 0, "mask": 1, "hash": 2, "drop": 3}

    def set_server_floor(self, kinds: Any) -> bool:
        """
        Apply the minimum modes the server asks for (an approved rule with the redact action). They can only make a kind
        stricter than the local configuration, never looser; an empty answer removes the server's part and the local
        configuration stands. Hash needs the key, so until one is held it is applied as mask. True if anything changed.
        """
        if vr is None or not isinstance(kinds, dict):
            return False
        if not hasattr(self, "_local_modes"):
            self._local_modes = dict(self.modes)
        wanted: Dict[str, str] = {}
        for kind, mode in kinds.items():
            kind, mode = str(kind).lower(), str(mode).lower()
            if kind in self._local_modes and mode in ("mask", "hash", "drop"):
                wanted[kind] = "mask" if (mode == "hash" and not self.key) else mode
        new = dict(self._local_modes)
        for kind, mode in wanted.items():
            if self._STRICTNESS[mode] > self._STRICTNESS[new[kind]]:
                new[kind] = mode
        if new == self.modes:
            return False
        self.modes = new
        self.active = any(m != "monitor" for m in self.modes.values())
        self._entities = [e for e, l in vr.LABELS.items() if self.modes.get(l.lower(), "monitor") != "monitor"]
        return True

    def set_delivered_key(self, key_id: str, key_hex: str) -> bool:
        """Use the key the server delivered (unless the configuration pins one). True if it changed."""
        if self.key_pinned or not vr:
            return False
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return False
        if len(key) < 16 or vr.key_id_of(key) != key_id or key == self.key:
            return False
        self.key, self.key_id = key, key_id
        return True

    @property
    def overall_mode(self) -> str:
        modes = set(self.modes.values()) or {"monitor"}
        return modes.pop() if len(modes) == 1 else "mixed"

    def describe(self) -> Dict[str, Any]:
        """Settings and rules version for the heartbeat (never any line text)."""
        return {
            "mode": self.overall_mode, "categories": dict(self.modes), "fail_closed": self.fail_closed,
            "tee": self.tee is not None, "max_line_chars": self.max_chars,
            "pack_version": vr.PACK_VERSION if vr else "", "pack_fingerprint": vr.pack_fingerprint() if vr else "",
            "hash_key_id": self.key_id,
        }

    def process(self, line: str):
        """
        Returns (line to send or None if it is dropped, {kind: how many values were masked or hashed}, truncated).

        A line over the limit is cut, and nothing past the cut is sent. The cut is moved back before any value that
        would be split by it, so a half of a phone number is never left behind.
        """
        truncated = len(line) > self.max_chars
        if not self.active:
            return (line[:self.max_chars] + " [TRUNCATED]" if truncated else line), {}, truncated
        window = line[:self.max_chars + 64] if truncated else line      # a little beyond the cut, to see a value that crosses it
        dets = vr.scan(window, self._entities)
        cut = len(line)
        if truncated:
            cut = self.max_chars
            for d in dets:
                if d.start < cut < d.end:
                    cut = d.start
            dets = [d for d in dets if d.end <= cut]
        text = line[:cut]
        counts: Dict[str, int] = {}
        out, pos = [], 0
        for start, end, label in vr.covered_spans(dets):
            mode = self.modes[label.lower()]
            if mode == "drop":
                return None, {label.lower(): 1}, truncated
            out.append(text[pos:start])
            if mode == "hash" and not self.key:
                raise RuntimeError("hash mode has no key yet (the server delivers it at registration)")
            out.append(vr.hash_token(label, text[start:end], self.key) if mode == "hash" else vr.placeholder(label))
            counts[label.lower()] = counts.get(label.lower(), 0) + 1
            pos = end
        out.append(text[pos:])
        result = "".join(out)
        return (result + " [TRUNCATED]" if truncated else result), counts, truncated


REDACTOR = Redactor()      # replaced in main() when the configuration asks for redaction


def apply_redaction(line: str):
    """
    The one place a line is redacted, before it is queued or copied anywhere. Returns (line, counts) or
    (None, counts) when the line must not be sent. With fail_closed (the default), an error drops the line.
    """
    r = REDACTOR
    try:
        started = time.perf_counter()
        out, counts, truncated = r.process(line)
        if truncated:
            STATS.incr("truncated_lines")
        if out is None:
            STATS.incr("dropped_redaction")
            REDACTION_DROPS.add(counts)
            return None, counts
        if counts:
            STATS.incr("lines_redacted")
            REDACTION_COUNTS.add(counts)
        slow = time.perf_counter() - started
        if slow > 0.25:
            log_limited("redaction-slow", logging.WARNING,
                        "Redacting one line took %.2f s; very long or unusual lines slow the agent.", slow)
    except Exception as e:
        STATS.incr("redaction_errors")
        log_limited("redaction-error", logging.ERROR,
                    "Redaction failed on a line (%s: %s). %s", type(e).__name__, e,
                    "The line is dropped (fail_closed)." if r.fail_closed else "The line is sent as it was (fail_closed is off).")
        if r.fail_closed:
            STATS.incr("dropped_redaction_error")
            return None, {}
        return line, {}
    if r.tee is not None:
        try:
            r.tee.write(out)
        except Exception as e:
            STATS.incr("tee_errors")
            log_limited("tee", logging.WARNING, "Could not write the masked copy: %s", e)
    return out, counts


class RedactionCounts:
    """How many values of each kind this agent has masked or hashed (counts only), for the heartbeat."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Dict[str, int] = {}

    def add(self, counts: Dict[str, int]) -> None:
        with self._lock:
            for k, v in counts.items():
                self._counts[k] = self._counts.get(k, 0) + v

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counts)


REDACTION_COUNTS = RedactionCounts()
REDACTION_DROPS = RedactionCounts()      # lines not sent because they held this kind of data (mode drop)




def validate_address(address: Any) -> Optional[str]:
    """Explain what is wrong with veritas_address, or None. Retrying cannot fix any of these."""
    from urllib.parse import urlparse
    text = str(address or "").strip()
    if "<" in text or ">" in text or "CHANGE_ME" in text.upper() or "YOUR-" in text.upper():
        return (f"veritas_address is still a placeholder ({text!r}). Replace it with the real address "
                "of the Veritas server, for example https://veritas.yourcompany.internal:8000")
    try:
        parsed = urlparse(text)
        port = parsed.port           # raises ValueError for a non-numeric port
    except ValueError:
        return f"veritas_address {text!r} is not a valid address (check the port number)."
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return (f"veritas_address {text!r} must start with http:// or https:// and name a host, "
                "for example https://192.168.1.50:8000")
    return None


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        logger.error("Config file not found: %s", path)
        sys.exit(EXIT_CONFIG)
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    missing: List[str] = []
    cfg = expand_env(cfg, missing)
    if missing:
        logger.error("Config refers to environment variable(s) that are not set: %s",
                     ", ".join(sorted(set(missing))))
        sys.exit(EXIT_CONFIG)

    if not cfg.get("veritas_address"):
        logger.error("Config missing required field: veritas_address")
        sys.exit(EXIT_CONFIG)
    address_problem = validate_address(cfg.get("veritas_address"))
    if address_problem:
        logger.error("Config problem: %s", address_problem)
        sys.exit(EXIT_CONFIG)
    key = str(cfg.get("registration_key") or "")
    if key and ("<" in key or ">" in key):
        logger.error("Config problem: registration_key is still a placeholder (%r). Paste the key "
                     "issued in the Veritas dashboard (Agents > Issue Registration Key).", key)
        sys.exit(EXIT_CONFIG)
    problems = validate_sources(cfg.get("sources")) + validate_redaction(cfg.get("redaction"))
    if problems:
        for problem in problems:
            logger.error("Config problem: %s", problem)
        sys.exit(EXIT_CONFIG)
    return cfg


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

_state_dir_override: Optional[Path] = None


def configure_state_dir(config: Dict[str, Any]) -> None:
    """Pick the state directory: $VERITAS_STATE_DIR, then config 'state_dir', else cwd."""
    global _state_dir_override
    env = os.environ.get("VERITAS_STATE_DIR", "").strip()
    cfg = str(config.get("state_dir", "") or "").strip()
    chosen = env or cfg
    _state_dir_override = Path(chosen) if chosen else None


def state_dir() -> Path:
    return _state_dir_override if _state_dir_override is not None else Path(".")


def state_file() -> Path:
    return state_dir() / STATE_FILE_NAME


def server_cert_path() -> Path:
    """Where the trusted server certificate is kept (absolute, inside the state dir)."""
    return (state_dir() / SERVER_CERT_NAME).resolve()


def ensure_state_writable() -> None:
    """
    Fail fast, BEFORE using the one-time registration key, if the identity cannot
    be saved. Exits with EXIT_CONFIG and a clear message.
    """
    d = state_dir()
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / f".veritas_write_test_{os.getpid()}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as e:
        logger.error(
            "Cannot write to the agent state directory %s: %s. The agent must be able "
            "to save its identity after registering, and the registration key can only "
            "be used once, so registration was NOT attempted. Make the directory "
            "writable for this user, or set VERITAS_STATE_DIR (or 'state_dir' in the "
            "config) to a writable path.", d.resolve(), e,
        )
        sys.exit(EXIT_CONFIG)


def load_state() -> Dict[str, Any]:
    path = state_file()
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Could not read state file %s: %s — starting fresh", path, e)
    return {}


def save_state(state: Dict[str, Any]) -> None:
    """Write the identity atomically with owner-only permissions (it holds the auth token)."""
    path = state_file()
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def state_is_valid(state: Dict[str, Any]) -> bool:
    return bool(state.get("agent_id") and state.get("auth_token") and state.get("event_endpoint"))


# ---------------------------------------------------------------------------
# Bootstrap registration
# ---------------------------------------------------------------------------

def bootstrap(config: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    if state_is_valid(state):
        logger.info("Using existing identity: %s (org: %s)", state["agent_id"], state.get("org_id"))
        return state

    if not config.get("registration_key"):
        logger.error(
            "No registration_key in config and no saved identity. "
            "Issue a key from the Veritas dashboard and add it to agent-config.yaml."
        )
        sys.exit(EXIT_CONFIG)

    # The key is single-use: make sure the identity can be saved before spending it.
    ensure_state_writable()

    base = config["veritas_address"].rstrip("/")
    url  = f"{base}/agent/register"
    payload = {
        "registration_key": config["registration_key"],
        "source_label": config.get("source_label", ""),
    }

    # Determine TLS verification for registration calls.
    # On first contact with a self-signed server, we may need to download the cert first.
    verify = _tls_verify(config)
    is_https = base.startswith("https://")

    # If HTTPS + strict verify but no CA cert configured → try to fetch server cert first
    if is_https and verify is True:
        default_ca_path = server_cert_path()
        if not default_ca_path.exists():
            logger.info(
                "HTTPS server detected but no CA cert configured. "
                "Attempting to fetch server certificate from %s/api/tls/cert ...", base
            )
            # First attempt with no verification to get the cert (bootstrap trust)
            if _fetch_server_cert(base, default_ca_path, verify=False):
                verify = str(default_ca_path)
            else:
                logger.warning(
                    "Could not fetch server cert. Proceeding with system CA bundle. "
                    "If this fails, set VERITAS_CA_CERT to the server's certificate path."
                )
        else:
            verify = str(default_ca_path)

    for attempt in range(1, REGISTRATION_RETRIES + 1):
        try:
            logger.info("Registering with server at %s (attempt %d/%d)…", base, attempt, REGISTRATION_RETRIES)
            resp = requests.post(url, json=payload, timeout=FORWARD_TIMEOUT, verify=verify)
            resp.raise_for_status()
            data = resp.json()

            state.update({
                "agent_id":       data["agent_id"],
                "auth_token":     data["auth_token"],
                "org_id":         data["org_id"],
                "event_endpoint": data["event_endpoint"],
                "tls_verify":     str(verify),   # persist for future calls
            })
            if isinstance(data.get("redaction_key"), dict):      # the organization's key for hash mode
                state["redaction_key"] = {"key_id": str(data["redaction_key"].get("key_id", "")),
                                          "key": str(data["redaction_key"].get("key", ""))}
            try:
                save_state(state)
            except OSError as e:
                logger.error(
                    "Registered as %s but could NOT save the identity to %s: %s. The "
                    "registration key is now used up. Revoke this agent in the Veritas "
                    "dashboard (Agents tab), fix the directory permissions, and issue a "
                    "new key.", state["agent_id"], state_file().resolve(), e,
                )
                sys.exit(EXIT_CONFIG)

            logger.info(
                "Registered as %s | org: %s | endpoint: %s | TLS: %s | server %s",
                state["agent_id"], state["org_id"], state["event_endpoint"],
                "HTTPS" if is_https else "HTTP", data.get("server_version") or "?",
            )
            return state

        except requests.exceptions.SSLError as e:
            logger.error(
                "TLS certificate verification failed: %s\n"
                "Solutions:\n"
                "  1. Set VERITAS_CA_CERT to the server's certificate path.\n"
                "  2. Set VERITAS_TLS_VERIFY=false (insecure, dev only).\n"
                "  3. Download cert: GET %s/api/tls/cert",
                e, base,
            )
            sys.exit(EXIT_CONFIG)

        except requests.exceptions.ConnectionError:
            logger.warning("Server unreachable. Retrying in %ds…", REGISTRATION_RETRY_DELAY)
        except requests.exceptions.HTTPError as e:
            logger.error("Registration rejected (%s): %s", e.response.status_code, e.response.text)
            # A rejected key (used, expired, unknown) cannot be fixed by retrying.
            sys.exit(EXIT_CONFIG)
        except Exception as e:
            logger.warning("Registration attempt failed: %s. Retrying…", e)

        if attempt < REGISTRATION_RETRIES:
            time.sleep(REGISTRATION_RETRY_DELAY)

    logger.error("Could not reach the server after %d attempts. Exiting.", REGISTRATION_RETRIES)
    sys.exit(1)


# ---------------------------------------------------------------------------
# TLS verify for ongoing calls (from persisted state)
# ---------------------------------------------------------------------------

def _verify_from_state(config: Dict[str, Any], state: Dict[str, Any]) -> Union[bool, str]:
    """
    Return the TLS verify setting for post-registration calls.
    Uses the persisted state value if available, falling back to config.
    """
    persisted = state.get("tls_verify", "")
    if persisted == "False" or persisted is False:
        return False
    if persisted and persisted not in ("True", "true", ""):
        p = Path(persisted)
        if p.exists():
            return str(p)
    return _tls_verify(config)


# ---------------------------------------------------------------------------
# Counters and rate-limited logging
# ---------------------------------------------------------------------------

class AgentStats:
    """Thread-safe counters. Reported in the heartbeat so operators can see health."""

    NAMES = (
        "lines_read", "forwarded", "retries",
        "dropped_buffer_full", "dropped_rejected", "dropped_auth", "dropped_other",
        "lines_redacted", "dropped_redaction", "dropped_redaction_error", "redaction_errors",
        "truncated_lines", "tee_errors",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts = {name: 0 for name in self.NAMES}

    def incr(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._counts[name] += n

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._counts)


STATS = AgentStats()

START_TIME = time.monotonic()


def get_agent_version() -> str:
    """
    The release version of this agent: $VERITAS_AGENT_VERSION, else the VERSION file
    next to this script (written by the package/image build), else "dev".
    """
    env = os.environ.get("VERITAS_AGENT_VERSION", "").strip()
    if env:
        return env[:64]
    try:
        text = (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        text = ""
    return (text or "dev")[:64]


_VERSION_WARNED = False


def note_server_versions(data: Dict[str, Any]) -> None:
    """
    Log, once, what the server says about this agent's version: the server's release and
    whether this agent is older than the oldest version it supports. Never raises.
    """
    global _VERSION_WARNED
    try:
        server_version = str(data.get("server_version") or "")
        minimum = str(data.get("min_agent_version") or "")
        if data.get("agent_outdated") is True and not _VERSION_WARNED:
            _VERSION_WARNED = True
            logger.warning(
                "This agent (%s) is older than %s, the oldest version Veritas server %s fully "
                "supports. Upgrade the agent: some features may not work.",
                get_agent_version(), minimum or "the minimum", server_version or "?",
            )
    except Exception:
        pass


class SourceBoard:
    """State of each configured log source, reported in the heartbeat."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sources: Dict[tuple, Dict[str, Any]] = {}

    def update(self, kind: str, target: str, **fields: Any) -> None:
        with self._lock:
            entry = self._sources.setdefault(
                (kind, target),
                {"type": kind, "target": target, "source_system": "", "state": "waiting",
                 "detail": "", "last_line_at": None},
            )
            entry.update(fields)

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(v) for v in self._sources.values()]


SOURCES = SourceBoard()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_last_logged: Dict[str, float] = {}


def log_limited(key: str, level: int, message: str, *args: Any, interval: float = 60.0) -> None:
    """Log at most once per `interval` seconds per key (a bad state must not flood the log)."""
    now = time.monotonic()
    if now - _last_logged.get(key, -interval) >= interval:
        _last_logged[key] = now
        logger.log(level, message, *args)


# ---------------------------------------------------------------------------
# Event forwarding
# ---------------------------------------------------------------------------

def _build_headers(state: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {state['auth_token']}",
        "Content-Type": "application/json",
    }


def forward_event(
    base_url: str,
    state: Dict[str, Any],
    raw_snippet: str,
    source_system: str,
    verify: Union[bool, str] = True,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    url     = base_url.rstrip("/") + state["event_endpoint"]
    headers = _build_headers(state)
    payload = {
        "source_type":   "log",
        "source_system": source_system,
        "raw_snippet":   raw_snippet,
        "fields":        {},
    }
    if meta:    # event schema 2: what this agent did to the line (counts only), see docs/AGENT_REDACTION.md
        payload.update(meta)
    resp = requests.post(url, json=payload, headers=headers, timeout=FORWARD_TIMEOUT, verify=verify)
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Forwarding worker (runs on main thread)
# ---------------------------------------------------------------------------

# How a failed delivery is handled. The queue is processed in order, so an event
# that can never succeed must not be retried forever: it would block every line
# behind it. Outages, on the other hand, must not lose data.
#
#   outage / overload (retry with backoff, no limit; the bounded queue absorbs it)
#       connection errors, timeouts, HTTP 408, 429, 502, 503, 504
#   server error on this event (retry a few times, then drop it and count it)
#       other HTTP 5xx
#   rejected (drop at once and count it; retrying cannot change the answer)
#       other HTTP 4xx except 401/403, for example 400, 413, 422
#   not authorised (drop and count; the agent may be revoked or the token wrong)
#       HTTP 401, 403
#   TLS errors (drop and count; a certificate problem needs an operator)
#
# Log lines never contain the event text, which may hold personal data.

INFINITE_RETRY_STATUSES = frozenset({408, 429, 502, 503, 504})
MAX_SERVER_ERROR_ATTEMPTS = 6


def deliver(
    item: tuple,
    forward,
    sleep=time.sleep,
    stats: AgentStats = STATS,
    max_backoff: float = MAX_BACKOFF,
) -> str:
    """
    Deliver one (raw_snippet, source_system) item, optionally with a third element (event schema 2 fields).
    Returns "delivered" or "dropped". `forward` is called as forward(raw_snippet, source_system), with the third
    element as an extra argument only when there is one.
    """
    raw_snippet, source_system = item[0], item[1]
    extra = (item[2],) if len(item) > 2 and item[2] else ()
    backoff = 1.0
    server_error_attempts = 0

    while True:
        try:
            forward(raw_snippet, source_system, *extra)
            stats.incr("forwarded")
            return "delivered"

        except requests.exceptions.SSLError as e:
            stats.incr("dropped_other")
            log_limited("tls", logging.ERROR,
                        "TLS error forwarding events: %s. Check VERITAS_CA_CERT / the server "
                        "certificate. Dropping events until fixed.", e)
            return "dropped"

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            stats.incr("retries")
            log_limited("unreachable", logging.WARNING,
                        "Veritas server unreachable or slow, retrying in %ds: %s", int(backoff), e)
            sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

        except requests.exceptions.HTTPError as e:
            response = e.response
            status = response.status_code if response is not None else 0

            if status in (401, 403):
                stats.incr("dropped_auth")
                log_limited("auth", logging.ERROR,
                            "Veritas rejected this agent (HTTP %s). It may be revoked. Dropping "
                            "events. Register a new agent from the dashboard if needed.", status)
                return "dropped"

            if status in INFINITE_RETRY_STATUSES:
                stats.incr("retries")
                delay = backoff
                retry_after = response.headers.get("Retry-After") if response is not None else None
                if status in (429, 503) and retry_after and str(retry_after).isdigit():   # a busy server says when
                    delay = min(float(retry_after), max_backoff)
                log_limited(f"http{status}", logging.WARNING,
                            "HTTP %s from the server, retrying in %ds", status, int(delay))
                sleep(delay)
                backoff = min(backoff * 2, max_backoff)
                continue

            if 500 <= status < 600:
                server_error_attempts += 1
                if server_error_attempts >= MAX_SERVER_ERROR_ATTEMPTS:
                    stats.incr("dropped_rejected")
                    log_limited("http5xx-drop", logging.ERROR,
                                "Server error HTTP %s on the same event %d times; dropping it so "
                                "the events behind it are not blocked.", status, server_error_attempts)
                    return "dropped"
                stats.incr("retries")
                log_limited(f"http{status}", logging.WARNING,
                            "HTTP %s from the server, retrying in %ds", status, int(backoff))
                sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
                continue

            # Other 4xx: the server understood and refused this event.
            stats.incr("dropped_rejected")
            detail = ""
            try:
                detail = (response.text or "")[:200] if response is not None else ""
            except Exception:
                pass
            log_limited("rejected", logging.WARNING,
                        "Server rejected an event (HTTP %s), dropping it: %s", status, detail)
            return "dropped"

        except Exception as e:
            stats.incr("dropped_other")
            log_limited("unexpected", logging.ERROR,
                        "Unexpected forwarding error: %s. Dropping the event.", e)
            return "dropped"


def forwarding_worker(
    config: Dict[str, Any],
    state: Dict[str, Any],
    event_queue: queue.Queue,
) -> None:
    base_url = config["veritas_address"]
    verify   = _verify_from_state(config, state)

    def forward(raw_snippet: str, source_system: str, meta: Optional[Dict[str, Any]] = None) -> None:
        forward_event(base_url, state, raw_snippet, source_system, verify=verify, meta=meta)

    logger.info("Forwarding worker started. Watching queue…")

    while True:
        try:
            item = event_queue.get(timeout=1)
        except queue.Empty:
            continue
        deliver(item, forward)


# ---------------------------------------------------------------------------
# Source: file tail
# ---------------------------------------------------------------------------

class FileFollower:
    """
    Follows one log file the way `tail -F` does, without threads or sleeping so it
    can be tested directly. poll() returns the complete new lines since the last call.

    - Only lines written after the agent starts are read (history is not replayed),
      unless the file did not exist yet: then everything in it is new.
    - A line is delivered only once it is complete (ends with a newline), so a
      writer caught mid-line cannot make one value arrive as two events and hide
      personal data from detection. A final line without a newline is delivered
      when the file is rotated away.
    - Rotation by rename (logrotate default): the rest of the old file is drained,
      then the new file is read from its start. Nothing is lost or repeated.
    - Truncation in place (logrotate copytruncate): reading restarts at the top.
    - While the file is briefly missing during rotation the old handle is kept.
    """

    def __init__(self, path: Union[str, Path], read_from_start: bool = False) -> None:
        self.path = Path(path)
        self._fh = None
        self._ident = None
        self._pending = b""
        # A file that already exists when the agent starts is read from its end (history is
        # not replayed). read_from_start is for files found later: all of it is new.
        self._seek_end_on_first_open = self.path.exists() and not read_from_start

    @staticmethod
    def _identity(st: os.stat_result):
        # (device, inode); inode is 0 on filesystems that do not report one.
        return (st.st_dev, st.st_ino)

    def _open(self, from_end: bool) -> bool:
        try:
            fh = open(self.path, "rb")
        except FileNotFoundError:
            return False
        self._fh = fh
        self._ident = self._identity(os.fstat(fh.fileno()))
        if from_end:
            fh.seek(0, os.SEEK_END)
        self._pending = b""
        return True

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None
                self._ident = None

    def _read_available(self) -> list:
        data = self._pending + self._fh.read()
        if not data:
            return []
        *complete, self._pending = data.split(b"\n")
        return self._decode(complete)

    @staticmethod
    def _decode(raw_lines) -> list:
        out = []
        for raw in raw_lines:
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                out.append(line)
        return out

    def _flush_pending(self) -> list:
        raw, self._pending = self._pending, b""
        return self._decode([raw]) if raw else []

    def poll(self) -> list:
        lines: list = []

        if self._fh is None:
            first = self._seek_end_on_first_open
            if not self._open(from_end=first):
                return lines
            self._seek_end_on_first_open = False
            if first:
                return lines  # started at the end; nothing new yet

        lines += self._read_available()

        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return lines  # mid-rotation: keep reading the old handle until the new file appears

        if self._identity(st) != self._ident and st.st_ino != 0:
            # The path now points to a different file: it was rotated.
            lines += self._read_available()
            lines += self._flush_pending()
            self.close()
            logger.info("Log file rotated, following the new file: %s", self.path)
            if self._open(from_end=False):
                lines += self._read_available()
        elif st.st_size < self._fh.tell():
            # Same file, now shorter: truncated in place (copytruncate).
            lines += self._flush_pending()
            self._fh.seek(0)
            logger.info("Log file truncated, reading from the start: %s", self.path)
            lines += self._read_available()

        return lines


def serve_syslog(host: str, port: int, protocol: str, source_system: str, event_queue: queue.Queue,
                 stop_event: Optional[threading.Event] = None, max_message: int = 8192, ready: Optional[threading.Event] = None) -> None:
    """
    Receives syslog messages (RFC 3164 or 5424) on a UDP or TCP port and queues each as a log line, as a file source would.
    TCP accepts newline-separated messages and RFC 6587 octet-counted frames. A message longer than `max_message` is cut.
    Bind it to loopback unless other machines must send to it: the agent does not authenticate senders.
    """
    import socket
    stop = stop_event or threading.Event()
    target = f"{protocol}://{host}:{port}"

    def take(raw: bytes) -> None:
        text = raw[:max_message].decode("utf-8", errors="replace").strip("\r\n\x00 ")
        if text:
            _enqueue(event_queue, text, source_system)

    if protocol == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(0.5)
        SOURCES.update("syslog", target, source_system=source_system, state="reading", detail="")
        logger.info("Receiving syslog on %s (source_system: %s)", target, source_system)
        if ready:
            ready.set()
        while not stop.is_set():
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            for line in data.split(b"\n"):
                take(line)
        sock.close()
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(16)
    server.settimeout(0.5)
    SOURCES.update("syslog", target, source_system=source_system, state="reading", detail="")
    logger.info("Receiving syslog on %s (source_system: %s)", target, source_system)
    if ready:
        ready.set()

    def connection(conn) -> None:
        conn.settimeout(1.0)
        buf = b""
        with conn:
            while not stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while buf:
                    m = re.match(rb"^(\d{1,6}) ", buf)
                    if m:                                       # RFC 6587 octet counting: "<length> <message>"
                        n = int(m.group(1))
                        if len(buf) < m.end() + n:
                            break
                        take(buf[m.end():m.end() + n])
                        buf = buf[m.end() + n:]
                    elif b"\n" in buf:
                        line, _, buf = buf.partition(b"\n")
                        take(line)
                    else:
                        if len(buf) > 4 * max_message:
                            take(buf)
                            buf = b""
                        break

    while not stop.is_set():
        try:
            conn, _addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=connection, args=(conn,), daemon=True, name="syslog-conn").start()
    server.close()


class DdlJoiner:
    """
    For a database log (PostgreSQL with log_statement=ddl or pgaudit, MySQL's audit or general log, or a migration
    file): keeps only schema statements (CREATE, ALTER or DROP TABLE) and joins a statement that is spread over several
    lines. Every other line, which may carry values (INSERT, UPDATE, SELECT), is dropped on the host and never sent.
    """
    START = re.compile(r"\b(?:CREATE|ALTER|DROP)\s+(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP|TEMPORARY)\s+|UNLOGGED\s+)?TABLE\b", re.I)
    NEW_RECORD = re.compile(r"^\s*(?:\d{4}-\d{2}-\d{2}[ T]|\d{6}\s+\d|\[\d{4}-)")
    MAX_STATEMENT = 16 * 1024

    def __init__(self) -> None:
        self._buf: List[str] = []
        self._size = 0

    def _take(self) -> str:
        text, self._buf, self._size = " ".join(self._buf), [], 0
        return text

    def feed(self, line: str) -> List[str]:
        out: List[str] = []
        starts_record = bool(self.NEW_RECORD.match(line))
        if self._buf and (starts_record or self._size > self.MAX_STATEMENT):
            out.append(self._take())                     # the previous statement is over
        if self.START.search(line):
            if self._buf:
                out.append(self._take())
            self._buf.append(line.strip())
            self._size += len(line)
        elif self._buf and not starts_record:
            self._buf.append(line.strip())               # a continuation line of a statement in progress
            self._size += len(line)
        if self._buf and self._buf[-1].rstrip().endswith(";"):
            out.append(self._take())                     # a statement that ends with a semicolon is complete
        return out

    def flush_if_complete(self) -> List[str]:
        return [self._take()] if self._buf and self._buf[-1].rstrip().endswith(";") else []


def tail_file(
    path: str,
    source_system: str,
    event_queue: queue.Queue,
    poll_interval: float = 0.5,
    stop_event: Optional[threading.Event] = None,
    kind: Optional[str] = None,
    joiner: Optional["DdlJoiner"] = None,
    src_type: str = "file",
) -> None:
    file_path = Path(path)
    logger.info("Tailing %s: %s (source_system: %s)", src_type, file_path, source_system)

    follower = FileFollower(file_path)
    last_warning = 0.0
    SOURCES.update(src_type, str(file_path), source_system=source_system, state="waiting",
                   detail="file does not exist yet" if not file_path.exists() else "")

    def warn_rate_limited(message: str, *args) -> None:
        nonlocal last_warning
        now = time.monotonic()
        if now - last_warning >= 60:
            last_warning = now
            logger.warning(message, *args)

    while not (stop_event is not None and stop_event.is_set()):
        try:
            if not file_path.exists() and follower._fh is None:
                warn_rate_limited("Waiting for log file to appear: %s", file_path)
            new_lines = follower.poll()
            for line in new_lines:
                if joiner is None:
                    _enqueue(event_queue, line, source_system, kind)
                else:
                    for statement in joiner.feed(line):      # only whole DDL statements leave; everything else is dropped here
                        _enqueue(event_queue, statement, source_system, kind)
            if joiner is not None:
                for statement in joiner.flush_if_complete():
                    _enqueue(event_queue, statement, source_system, kind)
            if follower._fh is not None:
                fields: Dict[str, Any] = {"state": "reading", "detail": ""}
                if new_lines:
                    fields["last_line_at"] = _now_iso()
                SOURCES.update(src_type, str(file_path), **fields)
            else:
                SOURCES.update(src_type, str(file_path), state="waiting", detail="file does not exist yet")
        except PermissionError as e:
            follower.close()
            SOURCES.update(src_type, str(file_path), state="error", detail="Permission denied")
            warn_rate_limited(
                "Permission denied reading %s: %s. The agent cannot read this file; grant "
                "the agent's user read access (on Linux the service user is "
                "'veritas-agent', in group 'adm'). Retrying.", file_path, e,
            )
            time.sleep(max(poll_interval, 5))
        except OSError as e:
            follower.close()
            SOURCES.update(src_type, str(file_path), state="error", detail=str(e)[:200])
            warn_rate_limited("Error reading %s: %s. Retrying.", file_path, e)
            time.sleep(max(poll_interval, 5))
        time.sleep(poll_interval)

    follower.close()


# ---------------------------------------------------------------------------
# Container logs on a node (Kubernetes DaemonSet) and wildcard file sources
# ---------------------------------------------------------------------------

# Two line formats are written by container runtimes:
#   CRI (containerd, CRI-O):  2026-10-05T10:00:00.123456789Z stdout F the message
#                             flag F = a full line, P = a partial piece to be joined
#   Docker json-file:         {"log":"the message\n","stream":"stdout","time":"..."}
_CRI_LINE = re.compile(r"^(\S+) (stdout|stderr) ([FP]) ?(.*)$")
MAX_JOINED_LINE = 64 * 1024     # stop joining partial pieces beyond this size


def parse_container_line(line: str, fmt: str = "auto") -> Optional[tuple]:
    """
    Return (message, is_partial) for one raw log line, or None if the line has no message.
    fmt: raw | cri | docker | auto (decide per line).
    """
    if fmt == "raw":
        return line, False

    if fmt in ("docker", "auto") and line.startswith("{"):
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("log"), str):
            text = obj["log"]
            partial = not text.endswith("\n")
            return text.rstrip("\r\n"), partial
        if fmt == "docker":
            return line, False

    if fmt in ("cri", "auto"):
        m = _CRI_LINE.match(line)
        if m:
            return m.group(4), m.group(3) == "P"
        if fmt == "cri":
            return line, False

    return line, False


class LineJoiner:
    """Joins the P (partial) pieces of one container log file into whole lines."""

    def __init__(self, fmt: str = "auto") -> None:
        self.fmt = fmt
        self._buffer: List[str] = []
        self._size = 0

    def feed(self, raw_line: str) -> Optional[str]:
        """Feed one raw line; returns a complete message when one is ready, else None."""
        parsed = parse_container_line(raw_line, self.fmt)
        if parsed is None:
            return None
        text, partial = parsed
        self._buffer.append(text)
        self._size += len(text)
        if partial and self._size < MAX_JOINED_LINE:
            return None
        message = "".join(self._buffer).strip()
        self._buffer, self._size = [], 0
        return message or None


# <pod>_<namespace>_<container>-<64 hex container id>.log, as named by the kubelet
_K8S_LOG_NAME = re.compile(
    r"^(?P<pod>[a-z0-9][-a-z0-9.]*)_(?P<namespace>[a-z0-9-]+)_(?P<container>.+)-(?P<cid>[0-9a-f]{64})\.log$"
)


def parse_k8s_log_name(filename: str) -> Optional[Dict[str, str]]:
    """{'pod','namespace','container'} from a /var/log/containers file name, or None."""
    m = _K8S_LOG_NAME.match(filename)
    return {k: m.group(k) for k in K8S_MATCH_KEYS} if m else None


class RuleResolver:
    """
    Maps a node log file to a source_system using the configured rules. Every key in a
    rule's `match` (namespace, pod, container) must match its pattern (shell-style
    wildcards); the first rule that matches wins. source_system may use {namespace},
    {pod} and {container}. Files that match no rule return None and are ignored.
    """

    def __init__(self, rules: List[Dict[str, Any]]) -> None:
        self.rules = rules

    def resolve(self, path: Union[str, Path]) -> Optional[str]:
        meta = parse_k8s_log_name(Path(path).name)
        if meta is None:
            return None
        for rule in self.rules:
            if all(fnmatch.fnmatchcase(meta[key], pattern) for key, pattern in rule["match"].items()):
                return rule["source_system"].format(**meta)
        return None

    def describe(self, path: Union[str, Path]) -> str:
        meta = parse_k8s_log_name(Path(path).name)
        return f"{meta['namespace']}/{meta['pod']}" if meta else Path(path).name


def has_wildcard(path: str) -> bool:
    return any(ch in path for ch in "*?[")


class GlobTailer:
    """
    Follows every file matching a wildcard pattern (for example /var/log/containers/*.log),
    picking up files that appear later and letting go of files that disappear. Testable
    without threads: poll() returns [(message, source_system), ...].

    - Files that exist when the tailer starts are read from their end; files that appear
      afterwards (new pods) are read from their start.
    - resolver(path) returns the source_system for a file, or None to ignore it.
    - fmt selects the log line format (raw, cri, docker, auto).
    """

    def __init__(
        self,
        pattern: str,
        resolver,
        fmt: str = "raw",
        max_files: int = MAX_FILES_DEFAULT,
        rescan_seconds: float = 5.0,
        describe=None,
        clock=time.monotonic,
    ) -> None:
        self.pattern = pattern
        self.resolver = resolver
        self.fmt = fmt
        self.max_files = max_files
        self.rescan_seconds = rescan_seconds
        self._describe = describe or (lambda p: Path(p).name)
        self._clock = clock
        self._tracked: Dict[str, Dict[str, Any]] = {}
        self._ignored: set = set()
        self._over_limit: set = set()
        self._first_scan = True
        self._next_scan = 0.0

    # -- bookkeeping exposed to the health report --------------------------
    @property
    def files_followed(self) -> int:
        return len(self._tracked)

    @property
    def files_ignored(self) -> int:
        return len(self._ignored)

    @property
    def files_over_limit(self) -> int:
        return len(self._over_limit)

    def ignored_names(self, limit: int = 10) -> List[str]:
        return sorted(self._describe(p) for p in self._ignored)[:limit]

    def _scan(self) -> None:
        found = set(glob.glob(self.pattern))
        for path in sorted(found):
            if path in self._tracked or path in self._ignored or path in self._over_limit:
                continue
            system = self.resolver(path)
            if system is None:
                self._ignored.add(path)
                continue
            if len(self._tracked) >= self.max_files:
                self._over_limit.add(path)
                continue
            self._tracked[path] = {
                "follower": FileFollower(path, read_from_start=not self._first_scan),
                "joiner": LineJoiner(self.fmt),
                "system": system,
                "gone_polls": 0,
            }
        # Forget ignored / over-limit files that no longer exist so the counts stay true.
        self._ignored &= found
        self._over_limit &= found
        self._first_scan = False

    def poll(self) -> List[tuple]:
        now = self._clock()
        if now >= self._next_scan:
            self._scan()
            self._next_scan = now + self.rescan_seconds

        out: List[tuple] = []
        for path in list(self._tracked):
            item = self._tracked[path]
            try:
                raw_lines = item["follower"].poll()
            except OSError:
                # e.g. permission denied or a file vanishing mid-read; try again next poll
                item["follower"].close()
                continue
            for raw in raw_lines:
                message = item["joiner"].feed(raw)
                if message:
                    out.append((message, item["system"]))
            if not os.path.exists(path):
                # The file is gone (pod deleted). Give it one more poll to drain, then let go.
                item["gone_polls"] += 1
                if item["gone_polls"] >= 2:
                    item["follower"].close()
                    del self._tracked[path]
            else:
                item["gone_polls"] = 0
        return out

    def close(self) -> None:
        for item in self._tracked.values():
            item["follower"].close()
        self._tracked.clear()


def tail_glob(
    pattern: str,
    kind: str,
    resolver,
    event_queue: queue.Queue,
    fmt: str = "raw",
    max_files: int = MAX_FILES_DEFAULT,
    poll_interval: float = 0.5,
    stop_event: Optional[threading.Event] = None,
    rescan_seconds: float = 5.0,
    describe=None,
) -> None:
    """Thread target for wildcard file sources and Kubernetes node logs."""
    logger.info("Following files matching %s (type: %s, format: %s)", pattern, kind, fmt)
    tailer = GlobTailer(pattern, resolver, fmt=fmt, max_files=max_files,
                        rescan_seconds=rescan_seconds, describe=describe)
    SOURCES.update(kind, pattern, source_system="(per file)" if kind == "kubernetes_logs" else "",
                   state="waiting", detail="no matching files yet")
    last_ignored: tuple = ()

    while not (stop_event is not None and stop_event.is_set()):
        try:
            for message, system in tailer.poll():
                _enqueue(event_queue, message, system)
                SOURCES.update(kind, pattern, last_line_at=_now_iso())

            detail = f"{tailer.files_followed} file(s) followed"
            if tailer.files_ignored:
                detail += f", {tailer.files_ignored} ignored (no rule matches)"
            if tailer.files_over_limit:
                detail += f", {tailer.files_over_limit} skipped (over the {max_files}-file limit)"
            SOURCES.update(kind, pattern,
                           state="reading" if tailer.files_followed else "waiting",
                           detail=detail[:200])

            ignored_now = tuple(tailer.ignored_names())
            if ignored_now and ignored_now != last_ignored:
                last_ignored = ignored_now
                log_limited(f"ignored-{pattern}", logging.WARNING,
                            "Ignoring logs of %d file(s) that match no rule, for example: %s. Add a "
                            "rule for them if they should be monitored.",
                            tailer.files_ignored, ", ".join(ignored_now[:5]), interval=300)
            if tailer.files_over_limit:
                log_limited(f"over-limit-{pattern}", logging.WARNING,
                            "%d file(s) are not followed because the limit of %d files was reached "
                            "(raise max_files if needed).", tailer.files_over_limit, max_files, interval=300)
        except Exception as e:  # never let one bad file end the thread
            SOURCES.update(kind, pattern, state="error", detail=str(e)[:200])
            log_limited(f"glob-error-{pattern}", logging.ERROR, "Error following %s: %s", pattern, e)
            time.sleep(max(poll_interval, 5))
        time.sleep(poll_interval)

    tailer.close()


# ---------------------------------------------------------------------------
# Source: Docker container log tail
# ---------------------------------------------------------------------------

def docker_unreachable_hint() -> str:
    """What to do when the agent cannot reach Docker. On a Mac the service account cannot use Docker Desktop."""
    if sys.platform == "darwin":
        return ("On macOS the agent runs as its own account and cannot use Docker Desktop's socket. Write the "
                "container's logs to a file (docker logs -f NAME >> /var/log/myapp/NAME.log) and use a file source.")
    return "Check that the Docker socket is readable by the agent's account (add it to the docker group)."


def tail_docker(
    container_name: str,
    source_system: str,
    event_queue: queue.Queue,
) -> None:
    logger.info("Tailing Docker container: %s (source_system: %s)", container_name, source_system)
    SOURCES.update("docker", container_name, source_system=source_system, state="waiting")
    try:
        import docker  # type: ignore
    except ImportError:
        SOURCES.update("docker", container_name, state="error", detail="docker package not installed")
        logger.error(
            "docker package not installed. Run: pip install docker>=7.0.0 — "
            "skipping container source '%s'", container_name
        )
        return

    try:
        client    = docker.from_env()
        container = client.containers.get(container_name)
    except Exception as e:
        hint = docker_unreachable_hint()
        SOURCES.update("docker", container_name, state="error", detail=f"cannot reach container: {e} {hint}".strip()[:300])
        logger.error("Cannot connect to Docker or find container '%s': %s — skipping. %s", container_name, e, hint)
        return

    SOURCES.update("docker", container_name, state="reading", detail="")
    try:
        for log_bytes in container.logs(stream=True, follow=True, tail=0):
            line = log_bytes.decode("utf-8", errors="replace").strip()
            if line:
                _enqueue(event_queue, line, source_system)
                SOURCES.update("docker", container_name, last_line_at=_now_iso())
        SOURCES.update("docker", container_name, state="error", detail="log stream ended")
    except Exception as e:
        SOURCES.update("docker", container_name, state="error", detail=f"stream error: {e}"[:200])
        logger.error("Docker log stream error for '%s': %s", container_name, e)


def redaction_meta(counts: Dict[str, int]) -> Dict[str, Any]:
    """Event schema 2: how this agent handled the line. Counts of kinds only, never any value."""
    return {"schema": 2, "redaction_mode": REDACTOR.overall_mode,
            "recognizer_pack_version": vr.PACK_VERSION if vr else "", "agent_detections": dict(counts)}


def _enqueue(event_queue: queue.Queue, line: str, source_system: str, kind: Optional[str] = None) -> None:
    STATS.incr("lines_read")
    item: tuple = (line, source_system) if not kind else (line, source_system, {"source_kind": kind})
    if REDACTOR.active or len(line) > REDACTOR.max_chars:
        line, counts = apply_redaction(line)       # before the line is queued or copied anywhere
        if line is None:
            return                                 # dropped: not sent, counted
        meta = redaction_meta(counts) if REDACTOR.active else None
        if kind:
            meta = {**(meta or {}), "source_kind": kind}
        item = (line, source_system, meta)
    try:
        event_queue.put_nowait(item)
    except queue.Full:
        # Buffer full (server slow or down for a long time): drop the OLDEST line
        # so memory stays bounded and the newest telemetry is kept.
        try:
            event_queue.get_nowait()
            STATS.incr("dropped_buffer_full")
        except queue.Empty:
            pass
        try:
            event_queue.put_nowait(item)
        except queue.Full:
            STATS.incr("dropped_buffer_full")
        log_limited("buffer-full", logging.WARNING,
                    "Event buffer full (%d lines); dropping the oldest lines until the "
                    "server accepts events again.", BUFFER_MAX)


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

def build_health(event_queue: Optional[queue.Queue]) -> Dict[str, Any]:
    """The health report attached to every heartbeat. Contains no event text."""
    return {
        "agent_version": get_agent_version(),
        "uptime_seconds": int(time.monotonic() - START_TIME),
        "queue_depth": event_queue.qsize() if event_queue is not None else 0,
        "queue_capacity": BUFFER_MAX,
        "counters": STATS.snapshot(),
        "sources": SOURCES.snapshot(),
        "redaction": {**REDACTOR.describe(), "redacted": REDACTION_COUNTS.snapshot(), "dropped": REDACTION_DROPS.snapshot()},
    }


def heartbeat_loop(
    config: Dict[str, Any],
    state: Dict[str, Any],
    interval: int = HEARTBEAT_INTERVAL,
    event_queue: Optional[queue.Queue] = None,
) -> None:
    base_url = config["veritas_address"].rstrip("/")
    url      = f"{base_url}/agent/heartbeat"
    headers  = _build_headers(state)
    verify   = _verify_from_state(config, state)

    logger.info("Heartbeat thread started (every %ds)", interval)
    first = True
    while True:
        if not first:
            time.sleep(interval)
        first = False  # report immediately at start so the dashboard shows version and health at once
        try:
            resp = requests.post(
                url,
                json={"agent_id": state["agent_id"], "health": build_health(event_queue)},
                headers=headers,
                timeout=5,
                verify=verify,
            )
            if resp.ok:
                logger.debug("Heartbeat sent OK")
                try:
                    answer = resp.json()
                    note_server_versions(answer)
                    if isinstance(answer, dict) and "redaction_floor" in answer and REDACTOR.set_server_floor(answer.get("redaction_floor")):
                        logger.info("The server's rules now ask for stricter redaction: %s", REDACTOR.describe()["categories"])
                    new_key = answer.get("redaction_key") if isinstance(answer, dict) else None
                    if isinstance(new_key, dict) and REDACTOR.set_delivered_key(str(new_key.get("key_id", "")), str(new_key.get("key", ""))):
                        state["redaction_key"] = {"key_id": str(new_key["key_id"]), "key": str(new_key["key"])}
                        save_state(state)
                        logger.info("Received a new redaction key (%s) from the server", new_key["key_id"])
                except Exception:
                    pass   # an answer without JSON (an older server) is fine
            else:
                logger.warning("Heartbeat returned %s", resp.status_code)
        except Exception as e:
            logger.warning("Heartbeat failed (will retry next interval): %s", e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Veritas Agent — telemetry forwarder")
    parser.add_argument(
        "--config", type=Path, default=CONFIG_FILE_DEFAULT,
        help=f"Path to agent config YAML (default: {CONFIG_FILE_DEFAULT})",
    )
    parser.add_argument(
        "--version", action="version", version=f"Veritas Agent {get_agent_version()}",
    )
    args = parser.parse_args()

    logger.info("Veritas Agent %s starting", get_agent_version())
    config = load_config(args.config)
    configure_state_dir(config)
    state  = load_state()
    state  = bootstrap(config, state)

    global REDACTOR
    red = config.get("redaction")
    if red:
        tee = MaskedTee(red["tee_file"], int(red.get("tee_max_bytes", DEFAULT_TEE_MAX_BYTES))) if red.get("tee_file") else None
        REDACTOR = Redactor(red, tee)
        saved = state.get("redaction_key") or {}
        REDACTOR.set_delivered_key(str(saved.get("key_id", "")), str(saved.get("key", "")))
        logger.info("Redaction: %s%s%s (recognizer pack %s)", REDACTOR.overall_mode,
                    ", fail-closed" if REDACTOR.fail_closed and REDACTOR.active else "",
                    f", masked copy in {red['tee_file']}" if tee else "", vr.PACK_VERSION)

    sources = config.get("sources", [])
    if not sources:
        logger.warning("No sources configured in agent-config.yaml — agent will only send heartbeats")

    event_queue: queue.Queue = queue.Queue(maxsize=BUFFER_MAX)

    for source in sources:
        src_type   = source.get("type", "").lower()
        src_system = source.get("source_system", "unknown")

        if src_type == "file" and has_wildcard(str(source["path"])):
            fmt = str(source.get("format", "raw")).lower()
            t = threading.Thread(
                target=tail_glob,
                args=(str(source["path"]), "file", (lambda path, _s=src_system: _s), event_queue),
                kwargs={"fmt": fmt, "max_files": int(source.get("max_files", MAX_FILES_DEFAULT))},
                daemon=True,
                name=f"tail-glob-{src_system}",
            )
            t.start()

        elif src_type == "file":
            t = threading.Thread(
                target=tail_file,
                args=(source["path"], src_system, event_queue),
                daemon=True,
                name=f"tail-file-{src_system}",
            )
            t.start()

        elif src_type == "syslog":
            t = threading.Thread(
                target=serve_syslog,
                args=(str(source.get("host", "127.0.0.1")), int(source["port"]), str(source.get("protocol", "udp")).lower(),
                      src_system, event_queue),
                daemon=True,
                name=f"syslog-{source['port']}",
            )
            t.start()

        elif src_type == "db_schema_log":
            t = threading.Thread(
                target=tail_file,
                args=(source["path"], src_system, event_queue),
                kwargs={"kind": "schema", "joiner": DdlJoiner(), "src_type": "db_schema_log"},
                daemon=True,
                name=f"tail-schema-{src_system}",
            )
            t.start()

        elif src_type == "kubernetes_logs":
            resolver = RuleResolver(source["rules"])
            t = threading.Thread(
                target=tail_glob,
                args=(str(source.get("path", K8S_DEFAULT_PATH)), "kubernetes_logs", resolver.resolve, event_queue),
                kwargs={
                    "fmt": str(source.get("format", "auto")).lower(),
                    "max_files": int(source.get("max_files", MAX_FILES_DEFAULT)),
                    "describe": resolver.describe,
                },
                daemon=True,
                name="tail-kubernetes-logs",
            )
            t.start()

        elif src_type == "docker":
            t = threading.Thread(
                target=tail_docker,
                args=(source["container"], src_system, event_queue),
                daemon=True,
                name=f"tail-docker-{source['container']}",
            )
            t.start()

        else:
            logger.warning("Unknown source type %r — skipping", src_type)

    hb = threading.Thread(
        target=heartbeat_loop,
        args=(config, state, HEARTBEAT_INTERVAL, event_queue),
        daemon=True,
        name="heartbeat",
    )
    hb.start()

    logger.info(
        "Agent %s running. Forwarding to %s%s",
        state["agent_id"], config["veritas_address"], state["event_endpoint"],
    )

    forwarding_worker(config, state, event_queue)


if __name__ == "__main__":
    main()
