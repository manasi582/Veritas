"""
Witnesses: places outside the server's control that receive a copy of every checkpoint.

A sink implements publish(checkpoint) -> receipt text (raising on failure) and health() -> dict.
Each witness receives the WHOLE checkpoint, so an auditor can verify without the server.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import smtplib
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List


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


class EmailSink(Sink):
    """
    Mails each checkpoint to an address outside this server (a mailbox the Veritas account cannot reach into).
    The receipt is the mail server's acceptance, which is not delivery: it is reported as such.
    """
    def __init__(self, to: List[str], host: str, port: int = 587, security: str = "starttls", user: str = "",
                 password: str = "", sender: str = "", timeout: float = 15.0):
        if not to or not host:
            raise ValueError("an email witness needs at least one address (to) and a mail server (host)")
        self.to, self.host, self.port, self.security = list(to), host, int(port), (security or "starttls").lower()
        if self.security not in ("starttls", "ssl", "none"):
            raise ValueError("email security must be starttls, ssl or none")
        self.user, self.password, self.timeout = user, password, timeout
        self.sender = sender or f"veritas@{socket.getfqdn()}"
        self.name = f"email:{','.join(self.to)}"

    def _connect(self):
        smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout) if self.security == "ssl" \
            else smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        try:
            if self.security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if self.user:
                smtp.login(self.user, self.password)
        except Exception:
            smtp.close()
            raise
        return smtp

    def publish(self, checkpoint: Dict[str, Any]) -> str:
        msg = EmailMessage()
        msg["Subject"] = f"Veritas checkpoint {checkpoint['org']} #{checkpoint['cp_seq']}"
        msg["From"], msg["To"] = self.sender, ", ".join(self.to)
        msg.set_content("A signed checkpoint of the evidence chain. Keep this message: it is a witness copy.\n\n"
                        + checkpoint_text(checkpoint) + "\n")
        smtp = self._connect()
        try:
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass
        return f"accepted by {self.host} (mail is accepted, not confirmed delivered)"

    def health(self) -> Dict[str, Any]:
        try:
            smtp = self._connect()
            smtp.noop()
            smtp.quit()
            return {"sink": self.name, "ok": True, "detail": "mail server reachable"}
        except Exception as e:
            return {"sink": self.name, "ok": False, "detail": str(e)}


# --- RFC 3161 time-stamp requests, written by hand (a few ASN.1 values; no library) -------------------------------

_SHA256_OID = bytes.fromhex("0609608648016503040201")


def _der(tag: int, payload: bytes) -> bytes:
    n = len(payload)
    length = bytes([n]) if n < 128 else (bytes([0x80 | len(n.to_bytes((n.bit_length() + 7) // 8, "big"))])
                                          + n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + payload


def _der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return _der(0x02, raw)


def timestamp_request(digest: bytes, nonce: int) -> bytes:
    """TimeStampReq: version 1, a SHA-256 message imprint, a nonce, and certReq set so the token carries the certificate."""
    imprint = _der(0x30, _der(0x30, _SHA256_OID + b"\x05\x00") + _der(0x04, digest))
    return _der(0x30, _der_int(1) + imprint + _der_int(nonce) + b"\x01\x01\xff")


def _read_der(buf: bytes, pos: int = 0):
    """(tag, content start, content end) of the value at `pos`."""
    tag, first = buf[pos], buf[pos + 1]
    if first < 128:
        return tag, pos + 2, pos + 2 + first
    k = first & 0x7F
    n = int.from_bytes(buf[pos + 2:pos + 2 + k], "big")
    return tag, pos + 2 + k, pos + 2 + k + n


def timestamp_response_status(resp: bytes) -> int:
    """PKIStatus of a TimeStampResp: 0 granted, 1 granted with modifications, 2 and up refused. Raises on junk."""
    tag, start, end = _read_der(resp)
    if tag != 0x30 or end > len(resp):
        raise ValueError("not a time-stamp response")
    tag, s2, e2 = _read_der(resp, start)              # PKIStatusInfo
    tag3, s3, e3 = _read_der(resp, s2)                # status INTEGER
    if tag != 0x30 or tag3 != 0x02:
        raise ValueError("not a time-stamp response")
    return int.from_bytes(resp[s3:e3], "big")


class TimestampSink(Sink):
    """
    Asks an RFC 3161 time-stamp authority to sign the SHA-256 of each checkpoint. The authority's signed token proves
    the checkpoint existed at that time, to someone who does not trust this server. The token (base64) is the receipt.
    Check one with: openssl ts -verify -data <checkpoint text> -in token.tsr -CAfile <the authority's certificate>.
    The checkpoint text is the single line of JSON the file witness holds, without its newline.
    """
    def __init__(self, url: str, timeout: float = 20.0):
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("a time-stamp authority address must start with http:// or https://")
        self.url, self.timeout = url, timeout
        self.name = f"tsa:{url}"

    def publish(self, checkpoint: Dict[str, Any]) -> str:
        digest = hashlib.sha256(checkpoint_text(checkpoint).encode("utf-8")).digest()
        nonce = int.from_bytes(os.urandom(8), "big")
        req = urllib.request.Request(self.url, data=timestamp_request(digest, nonce),
                                     headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:       # noqa: S310 (the address is the administrator's)
            resp = r.read(1_000_000)
        status = timestamp_response_status(resp)
        if status not in (0, 1):
            raise RuntimeError(f"the time-stamp authority refused (status {status})")
        if digest not in resp or nonce.to_bytes((nonce.bit_length() + 7) // 8, "big") not in resp:
            raise RuntimeError("the time-stamp response does not match the request")
        return "tsr:" + base64.b64encode(resp).decode("ascii")

    def health(self) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(self.url, method="HEAD")
            with urllib.request.urlopen(req, timeout=self.timeout):            # noqa: S310
                pass
            return {"sink": self.name, "ok": True, "detail": "reachable"}
        except urllib.error.HTTPError:
            return {"sink": self.name, "ok": True, "detail": "reachable"}      # an authority may refuse HEAD; it answered
        except Exception as e:
            return {"sink": self.name, "ok": False, "detail": str(e)}


class DigestSink(Sink):
    """
    A daily PDF listing every checkpoint (number, time, chain head), for printing or archiving. The same checkpoints are
    kept as lines of JSON beside it. It is a witness only as far as the folder is: put it on write-once or off-box storage.
    """
    def __init__(self, path: str):
        self.path = Path(path)
        self.name = f"pdf-digest:{self.path}"

    def publish(self, checkpoint: Dict[str, Any]) -> str:
        from subject_lookup import pdf
        folder = self.path / checkpoint["org"]
        folder.mkdir(parents=True, exist_ok=True)
        day = str(checkpoint.get("created_at") or datetime.now(timezone.utc).isoformat())[:10].replace("-", "")
        lines_file = folder / f"checkpoints-{day}.jsonl"
        with open(lines_file, "a", encoding="utf-8") as f:
            f.write(checkpoint_text(checkpoint) + "\n")
            f.flush()
            os.fsync(f.fileno())
        cps = [json.loads(x) for x in lines_file.read_text(encoding="utf-8").splitlines() if x.strip()]
        body = [("n", f"Organisation: {checkpoint['org']}   Day: {day}   Checkpoints: {len(cps)}"),
                ("n", "Each line: checkpoint number, last record, chain head. Keep this page: it is a witness copy."), ("b", "")]
        for c in cps:
            body.append(("n", f"#{c['cp_seq']}  records to {c['last_seq']}  at {str(c.get('created_at', ''))[:19]}"))
            body.append(("n", f"   head {c['head_hash']}"))
        data = pdf.render("Veritas checkpoint digest", body)
        target = folder / f"checkpoints-{day}.pdf"
        tmp = target.with_suffix(".pdf.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, target)
        return f"{target.name} sha256={hashlib.sha256(data).hexdigest()[:16]}"

    def health(self) -> Dict[str, Any]:
        try:
            self.path.mkdir(parents=True, exist_ok=True)
            ok = os.access(self.path, os.W_OK)
            return {"sink": self.name, "ok": ok, "detail": "writable" if ok else "not writable"}
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
        elif kind == "email":
            to = item.get("to")
            to = [a.strip() for a in to.split(",")] if isinstance(to, str) else list(to or [])
            env = os.environ.get
            sinks.append(EmailSink(to, item.get("host") or env("VERITAS_SMTP_HOST", ""),
                                   item.get("port") or env("VERITAS_SMTP_PORT") or 587,
                                   item.get("security") or env("VERITAS_SMTP_SECURITY") or "starttls",
                                   item.get("user") or env("VERITAS_SMTP_USER", ""),
                                   item.get("password") or env("VERITAS_SMTP_PASSWORD", ""),
                                   item.get("from") or env("VERITAS_SMTP_FROM", "")))
        elif kind in ("tsa", "timestamp"):
            sinks.append(TimestampSink(item["url"]))
        elif kind in ("pdf-digest", "pdf"):
            sinks.append(DigestSink(item["path"]))
        else:
            raise ValueError(f"unknown witness type {kind!r} (use file, syslog, email, tsa or pdf-digest)")
    return sinks
