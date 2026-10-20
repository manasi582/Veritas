"""
Veritas DPDPA Agent — PII Masking Utility (Phase 5)
=======================================================
No existing masking/redaction logic was found anywhere in the codebase
(the dashboard never renders raw PII values at all — it only shows
field/rule/explanation metadata) — this is a small, focused utility built
fresh for the /scan endpoint (Part A2) and the CLI PoC (Part A3), per the
plan's explicit fallback instruction.

Goal: replace each detected PII substring with a CATEGORY-LABELED
placeholder (e.g. "[AADHAAR_REDACTED]", "[PHONE_REDACTED]") rather than
either the raw value or an information-losing generic "[REDACTED]" — an
auditor or a developer piping a log line through the CLI should be able to
see WHAT KIND of PII was there without ever seeing the value itself.

APPROACH: substring replacement, not span/offset-based. detection/models.py's
MatchedEntity carries `matched_text` but not the original start/end offsets
(detection/engine.py discards them after slicing) — re-deriving true spans
would mean re-running Presidio a second time just for masking. For a "small,
focused utility" this is unnecessary: replacing every occurrence of each
matched_text substring (longest first, so a shorter match can never
corrupt a longer overlapping one already replaced) is correct for the
overwhelmingly common case (a PII value appearing once, or repeated
identically) and safe even for repeats — if the same phone number appears
twice, both occurrences ARE that phone number and both should be masked.

KNOWN LIMITATION (documented, not silently patched — matches this
codebase's existing convention, see detection/README.md's own "Known
Limitations" section): when two of Presidio's OWN matches genuinely
OVERLAP rather than nest cleanly (e.g. spaCy's PERSON recognizer
occasionally matches a span like "pan ABCDE1234F" — swallowing a
neighboring word into what should have been an isolated PAN match, a
pre-existing spaCy precision issue documented in detection/README.md,
not something this module causes), the longer span is masked first and
the shorter, more specific match's substring may no longer be present to
replace — that specific value still gets masked (nothing leaks), but
under the coarser/wrong category label instead of its own. This is a
correctness trade-off inherent to substring-based (not offset-based)
masking; a span-based rewrite would close it but was judged out of scope
for this phase's "small, focused utility" instruction.
"""

from __future__ import annotations

from typing import Dict, Iterable, Protocol


class _MatchLike(Protocol):
    field: str
    entity_type: str
    matched_text: str


# Explicit, readable labels for entity types this codebase's detectors
# actually produce (see detection/recognizers.py, detection/analyzer_engine.py's
# SUPPORTED_ENTITY_TYPES). Anything not listed here falls back to a
# generic-but-still-category-labeled placeholder derived from the entity
# type itself (see _label_for_entity_type) — so a future/custom recognizer's
# entity type is never silently masked as a value-less "[REDACTED]".
_ENTITY_TYPE_LABELS: Dict[str, str] = {
    "IN_AADHAAR": "AADHAAR",
    "IN_PAN": "PAN",
    "IN_PHONE": "PHONE",
    "PHONE_NUMBER": "PHONE",
    "EMAIL_ADDRESS": "EMAIL",
    "PERSON": "NAME",
    "CREDIT_CARD": "CARD",
}


def _label_for_entity_type(entity_type: str) -> str:
    """Category label used inside the placeholder, e.g. 'AADHAAR' -> '[AADHAAR_REDACTED]'."""
    if entity_type in _ENTITY_TYPE_LABELS:
        return _ENTITY_TYPE_LABELS[entity_type]
    # Fallback for any unlisted/future entity type: strip a leading "IN_"
    # (our own custom-recognizer convention) and uppercase what's left, so
    # the label still names the category rather than being generic.
    return entity_type.removeprefix("IN_").upper()


def _placeholder_for(entity_type: str) -> str:
    return f"[{_label_for_entity_type(entity_type)}_REDACTED]"


_ENTITY_PRIORITY: Dict[str, int] = {
    "IN_AADHAAR": 100,
    "IN_PAN": 100,
    "IN_PHONE": 90,
    "PHONE_NUMBER": 90,
    "EMAIL_ADDRESS": 90,
    "PERSON": 10,
}


def mask_text(text: str, matches: Iterable[_MatchLike]) -> str:
    """
    Returns `text` with every match's matched_text substring replaced by
    its category-labeled placeholder. Matches are applied longest-
    matched_text-first (and highest entity priority first) so a short or generic
    match cannot fragment a specific match. Matches with an empty matched_text
    are skipped defensively.
    """
    ordered = sorted(
        (m for m in matches if m.matched_text),
        key=lambda m: (len(m.matched_text), _ENTITY_PRIORITY.get(m.entity_type, 50)),
        reverse=True,
    )
    masked = text
    for m in ordered:
        masked = masked.replace(m.matched_text, _placeholder_for(m.entity_type))
    return masked


def mask_fields(fields: Dict[str, str], matches: Iterable[_MatchLike]) -> Dict[str, str]:
    """
    Returns a new dict with each field's value masked using only the
    matches attributed to THAT field (matches carry a `field` name — see
    detection/models.py's MatchedEntity — so a phone number detected in
    `fields["phone"]` never accidentally masks similar text in
    `fields["notes"]`). Fields with no matches pass through unchanged.
    Field KEYS are never altered — only values.
    """
    matches_by_field: Dict[str, list] = {}
    for m in matches:
        matches_by_field.setdefault(m.field, []).append(m)

    result: Dict[str, str] = {}
    for field_name, value in fields.items():
        field_matches = matches_by_field.get(field_name)
        result[field_name] = mask_text(value, field_matches) if field_matches else value
    return result
