"""
Veritas recognizer pack: the rules that find structured personal data in text, shared by the server and the agent.

Pure standard library, one file, no model. The server builds its Presidio recognizers from RULES and uses these
validators (so there is exactly one definition of what an Aadhaar number or a PAN looks like), and the agent imports
this file to find and mask the same things before a log line leaves the host. `tests/vectors/recognizers_corpus.json`
is the golden corpus both sides must reproduce.

What it finds: Aadhaar (Verhoeff checksum), PAN (structure), Indian mobile numbers, e-mail addresses, and payment
card numbers (Luhn). What it does not find: names and anything that needs context or a language model. That stays on
the server, which is why a line masked here can still be examined there.

The canonical copy is dpdpa-agent/veritas_recognizers.py; veritas-agent/veritas_recognizers.py must be identical
(tools/sync_recognizers.py copies it, and a test fails if they differ).
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Dict, Iterable, List, NamedTuple, Optional, Tuple

PACK_VERSION = "1.2.0"

# --------------------------------------------------------------------------- entity types, labels, rules

IN_AADHAAR, IN_PAN, IN_PHONE, EMAIL_ADDRESS, CREDIT_CARD = "IN_AADHAAR", "IN_PAN", "IN_PHONE", "EMAIL_ADDRESS", "CREDIT_CARD"

# The category label is what appears in a placeholder, [AADHAAR_REDACTED], and what the data map counts.
LABELS: Dict[str, str] = {IN_AADHAAR: "AADHAAR", IN_PAN: "PAN", IN_PHONE: "PHONE", EMAIL_ADDRESS: "EMAIL", CREDIT_CARD: "CARD"}
# When two findings overlap, the more specific one names the placeholder.
PRIORITY: Dict[str, int] = {IN_AADHAAR: 100, IN_PAN: 100, CREDIT_CARD: 100, IN_PHONE: 90, EMAIL_ADDRESS: 90}


class Rule(NamedTuple):
    entity_type: str
    name: str
    regex: str
    score: float
    context: Tuple[str, ...]


RULES: Tuple[Rule, ...] = (
    Rule(IN_AADHAAR, "aadhaar_spaced", r"\b\d{4}\s\d{4}\s\d{4}\b", 0.75, ("aadhaar", "aadhar", "uid", "uidai")),
    Rule(IN_AADHAAR, "aadhaar_unspaced_12digit", r"\b\d{12}\b", 0.4, ("aadhaar", "aadhar", "uid", "uidai")),
    Rule(IN_PAN, "pan_standard", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", 0.85, ("pan", "permanent account number", "income tax")),
    Rule(IN_PHONE, "in_phone_with_prefix", r"(?<!\w)(?:\+91[\s-]?|91[\s-]?)[6-9]\d{9}\b", 0.9,
         ("phone", "mobile", "contact", "call", "number")),
    Rule(IN_PHONE, "in_phone_bare", r"\b[6-9]\d{9}\b", 0.75, ("phone", "mobile", "contact", "call", "number")),
    Rule(EMAIL_ADDRESS, "email",
         r"\b((([!#$%&'*+\-/=?^_`{|}~\w])|([!#$%&'*+\-/=?^_`{|}~\w][!#$%&'*+\-/=?^_`{|}~\.\w]{0,}[!#$%&'*+\-/=?^_`{|}~\w]))"
         r"[@]\w+(?:-+\w+)*(?:\.\w+(?:-+\w+)*)+)\b", 0.5, ("email",)),
    Rule(CREDIT_CARD, "card_13_to_19_digits", r"\b(?:\d[ -]?){12,18}\d\b", 0.5, ("card", "credit", "debit", "visa", "mastercard")),
)
_COMPILED = [(r, re.compile(r.regex)) for r in RULES]


def pack_fingerprint() -> str:
    """Short hash of the rule definitions: an agent and a server with the same value find the same things."""
    material = PACK_VERSION + "\n" + "\n".join("|".join((r.entity_type, r.name, r.regex, repr(r.score))) for r in RULES)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- validators

_PAN_HOLDER_TYPE_CODES = frozenset("ABCFGHLJPT")
_PAN_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def is_valid_pan(value: str) -> bool:
    """Structure only (5 letters, 4 digits, 1 letter, a known holder type in position 4); PAN has no public checksum."""
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(_PAN_PATTERN.match(value)) and value[3] in _PAN_HOLDER_TYPE_CODES


def _verhoeff_is_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def is_valid_aadhaar(value: str) -> bool:
    """12 digits, not starting with 0, Verhoeff checksum. Spaces are ignored."""
    if not isinstance(value, str):
        return False
    stripped = re.sub(r"\s+", "", value)
    if len(stripped) != 12 or not stripped.isdigit() or stripped[0] == "0":
        return False
    return _verhoeff_is_valid(stripped)


def luhn_valid(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value or "")
    if not 13 <= len(digits) <= 19 or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _email_plausible(value: str) -> bool:
    tld = value.rsplit(".", 1)[-1]
    return len(tld) >= 2 and tld.isalpha() and len(value) <= 254


# --------------------------------------------------------------------------- scanning

class Detection(NamedTuple):
    entity_type: str
    start: int
    end: int
    score: float
    validation: str          # "validated", "failed" (kept, shape fits but the check does not) or "none"

    @property
    def label(self) -> str:
        return LABELS[self.entity_type]


def scan(text: str, entities: Optional[Iterable[str]] = None) -> List[Detection]:
    """
    Every finding in `text`, in order of position. Mirrors the server's decisions: an Aadhaar-shaped number that fails
    its checksum is not a finding; a PAN-shaped string that fails the structure check is kept and marked "failed";
    a card-shaped number must pass the Luhn check; a result inside a larger result of the same kind is dropped.
    """
    if not text or not text.strip():
        return []
    wanted = set(entities) if entities is not None else None
    found: List[Detection] = []
    for rule, rx in _COMPILED:
        if wanted is not None and rule.entity_type not in wanted:
            continue
        for m in rx.finditer(text):
            value, validation = m.group(0), "none"
            if rule.entity_type == IN_AADHAAR:
                if not is_valid_aadhaar(value):
                    continue
                validation = "validated"
            elif rule.entity_type == IN_PAN:
                validation = "validated" if is_valid_pan(value) else "failed"
            elif rule.entity_type == CREDIT_CARD:
                if not luhn_valid(value):
                    continue
                validation = "validated"
            elif rule.entity_type == EMAIL_ADDRESS and not _email_plausible(value):
                continue
            found.append(Detection(rule.entity_type, m.start(), m.end(), rule.score, validation))
    found = sorted(set(found), key=lambda d: (-d.score, d.start, -(d.end - d.start)))
    kept: List[Detection] = []
    for d in found:
        if not any(d.entity_type == k.entity_type and d.start >= k.start and d.end <= k.end for k in kept):
            kept.append(d)
    return sorted(kept, key=lambda d: (d.start, d.end, d.entity_type))


# --------------------------------------------------------------------------- identifiers: normalising and keyed tokens
#
# The same person's number is written many ways (+91 98765 43210, 9876543210, 91-9876543210). To find where an
# identifier appeared without keeping it, every writing is first reduced to one canonical form, then turned into a
# keyed token: HMAC-SHA256 under a key only the organization holds. The agent (hash mode) and the server's lookup use
# these two functions, so a token made in one place can be found from the other. A token cannot be turned back into
# the value, but anyone with the key can test a guess against it: protect the key like a password.

def normalise_identifier(label: str, value: str) -> str:
    label, value = label.upper(), (value or "").strip()
    if label in ("AADHAAR", "CARD"):
        return re.sub(r"\D", "", value)
    if label == "PAN":
        return value.upper()
    if label == "EMAIL":
        return value.lower()
    if label == "PHONE":
        digits = re.sub(r"\D", "", value)
        return digits[-10:] if len(digits) > 10 else digits
    return value


def key_id_of(key: bytes) -> str:
    """A short public name for a key (6 hex characters of a hash of it), carried in every token it makes."""
    return hashlib.sha256(b"veritas-kid:" + key).hexdigest()[:6]


def keyed_digest(label: str, value: str, key: bytes) -> str:
    """Full HMAC-SHA256 (64 hex characters) of LABEL LF normalised value. The server's lookup index stores this."""
    label = label.upper()
    return hmac.new(key, (label + "\n" + normalise_identifier(label, value)).encode("utf-8"), hashlib.sha256).hexdigest()


def hash_token(label: str, value: str, key: bytes) -> str:
    """[PHONE#a1b2c3.0123456789abcdef]: the key's id, then 16 hex characters of the keyed digest."""
    return "[%s#%s.%s]" % (label.upper(), key_id_of(key), keyed_digest(label, value, key)[:16])


TOKEN_PATTERN = r"\[([A-Z]+)#([0-9a-f]{6})\.([0-9a-f]{16})\]"


def placeholder(label: str) -> str:
    return "[%s_REDACTED]" % label


def covered_spans(detections: Iterable[Detection]) -> List[Tuple[int, int, str]]:
    """Overlapping findings merged into spans; each span is named by its most specific member: (start, end, label)."""
    spans: List[List] = []
    for d in sorted(detections, key=lambda d: (d.start, d.end)):
        if spans and d.start < spans[-1][1]:
            top = spans[-1]
            top[1] = max(top[1], d.end)
            if PRIORITY[d.entity_type] > top[3]:
                top[2], top[3] = d.label, PRIORITY[d.entity_type]
        else:
            spans.append([d.start, d.end, d.label, PRIORITY[d.entity_type]])
    return [(s, e, label) for s, e, label, _ in spans]


def mask(text: str, detections: Optional[Iterable[Detection]] = None) -> str:
    """`text` with every finding replaced by [LABEL_REDACTED]."""
    dets = scan(text) if detections is None else list(detections)
    out, pos = [], 0
    for start, end, label in covered_spans(dets):
        out.append(text[pos:start])
        out.append(placeholder(label))
        pos = end
    out.append(text[pos:])
    return "".join(out)
