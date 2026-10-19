"""
Witnesses: places outside the server's control that receive a copy of every checkpoint.

A sink implements publish(checkpoint) -> receipt text (raising on failure) and health() -> dict.
Each witness receives the WHOLE checkpoint, so an auditor can verify without the server.
"""
from __future__ import annotations

import json
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


class Sink:
    name = "sink"

    def publish(self, checkpoint: Dict[str, Any]) -> str:           # pragma: no cover - interface
        raise NotImplementedError

    def health(self) -> Dict[str, Any]:                              # pragma: no cover - interface
        raise NotImplementedError


def checkpoint_text(checkpoint: Dict[str, Any]) -> str:
    """The checkpoint as one line of JSON (keys sorted, so two witnesses hold identical text)."""
    return json.dumps(checkpoint, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class FileSink(Sink):
    """
    One file per checkpoint under <path>/<org>/, created exclusively and flushed to disk. Point it at a share on
    which the Veritas account may add files but not change or delete them, and it survives a compromised server.
    """
    def __init__(self, path: str):
        self.path = Path(path)
        self.name = f"file:{self.path}"

    def publish(self, checkpoint: Dict[str, Any]) -> str:
        folder = self.path / checkpoint["org"]
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{int(checkpoint['cp_seq']):010d}-{checkpoint['checkpoint_id']}.json"
        data = (checkpoint_text(checkpoint) + "\n").encode("utf-8")
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            if target.read_bytes() == data:         # a retry after an unacknowledged write: already there
                return str(target)
            raise
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return str(target)

    def health(self) -> Dict[str, Any]:
        try:
            self.path.mkdir(parents=True, exist_ok=True)
            ok = os.access(self.path, os.W_OK)
            return {"sink": self.name, "ok": ok, "detail": "writable" if ok else "not writable"}
        except OSError as e:
            return {"sink": self.name, "ok": False, "detail": str(e)}


class SyslogSink(Sink):
    """
    RFC 5424 over UDP, TCP or TCP with TLS, to the customer's SIEM. TCP and TLS use RFC 6587 octet counting.
    UDP gives no confirmation that anything arrived: it is accepted as a witness but reported as unconfirmed.
    """
    def __init__(self, host: str, port: int = 514, protocol: str = "tcp", ca_file: str | None = None,
                 timeout: float = 10.0):
        self.host, self.port, self.protocol = host, int(port), protocol.lower()
        if self.protocol not in ("udp", "tcp", "tcp-tls"):
            raise ValueError(f"syslog protocol must be udp, tcp or tcp-tls, not {protocol!r}")
        self.ca_file, self.timeout = ca_file, timeout
        self.name = f"syslog:{self.protocol}://{host}:{self.port}"

    def _message(self, checkpoint: Dict[str, Any]) -> bytes:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        hostname = (socket.gethostname() or "-").replace(" ", "_")
        pri = 14 + 0    # facility user (1) * 8 + severity info (6)
        return f"<{pri}>1 {ts} {hostname} veritas - CHECKPOINT - {checkpoint_text(checkpoint)}".encode("utf-8")

    def publish(self, checkpoint: Dict[str, Any]) -> str:
        msg = self._message(checkpoint)
        if self.protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(msg, (self.host, self.port))
            return "sent (udp: delivery not confirmed)"
        framed = str(len(msg)).encode("ascii") + b" " + msg
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as raw:
            if self.protocol == "tcp-tls":
                ctx = ssl.create_default_context(cafile=self.ca_file) if self.ca_file else ssl.create_default_context()
                with ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                    tls.sendall(framed)
            else:
                raw.sendall(framed)
        return f"sent ({self.protocol})"

    def health(self) -> Dict[str, Any]:
        if self.protocol == "udp":
            return {"sink": self.name, "ok": True, "detail": "udp: cannot be checked"}
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                pass
            return {"sink": self.name, "ok": True, "detail": "reachable"}
        except OSError as e:
            return {"sink": self.name, "ok": False, "detail": str(e)}


def build_sinks(spec: list) -> list:
    sinks = []
    for item in spec or []:
        kind = str(item.get("type", "")).lower()
        if kind == "file":
            sinks.append(FileSink(item["path"]))
        elif kind == "syslog":
            sinks.append(SyslogSink(item["host"], item.get("port", 514), item.get("protocol", "tcp"), item.get("ca_file")))
        else:
            raise ValueError(f"unknown witness type {kind!r} (use file or syslog)")
    return sinks
