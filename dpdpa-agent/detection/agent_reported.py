"""
Findings that an agent reports about a line it has already masked or hashed (event schema 2).

When an agent masks or hashes a value before sending, the server only sees a placeholder, `[PHONE_REDACTED]`, or a keyed
token, `[PHONE#0123456789abcdef]`, and its own detection finds nothing there. The log still contained that personal
data at its source, so the server turns the placeholders into findings, for the kinds the agent says it handled and only
where the placeholder is really in the text. A masked value is one finding per kind per line (every placeholder reads
the same); each distinct hashed identifier is its own finding. Values the agent left in clear (monitor mode) are found
by the server's own detection as before, and are not reported by the agent.
"""
from __future__ import annotations

import re
from typing import Dict, List

from detection.models import MatchedEntity, PATTERN_MATCH

LABEL_TO_ENTITY = {"aadhaar": "IN_AADHAAR", "pan": "IN_PAN", "phone": "IN_PHONE", "email": "EMAIL_ADDRESS",
                   "card": "CREDIT_CARD"}
_FOUND = re.compile(r"\[([A-Z]+)(?:_REDACTED|#[0-9a-f]{16})\]")
FREE_TEXT_FIELD = "raw_snippet"


def matches_from_agent(raw_snippet: str, agent_detections: Dict[str, int]) -> List[MatchedEntity]:
    wanted = {k.lower() for k, v in (agent_detections or {}).items() if v and k.lower() in LABEL_TO_ENTITY}
    seen, out = set(), []
    for m in _FOUND.finditer(raw_snippet or ""):
        label = m.group(1).lower()
        if label not in wanted or m.group(0) in seen:
            continue
        seen.add(m.group(0))
        out.append(MatchedEntity(field=FREE_TEXT_FIELD, entity_type=LABEL_TO_ENTITY[label], confidence=0.9,
                                 matched_text=m.group(0), validation_status=PATTERN_MATCH))
    return out
