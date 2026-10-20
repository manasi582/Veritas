"""
DPDPA Compliance Agent — Custom Indian PII Recognizers
==========================================================
Presidio's built-in recognizers don't cover Indian-specific identifiers.
This module defines three custom PatternRecognizer subclasses:

    IN_AADHAAR  — 12-digit Aadhaar number
    IN_PAN      — 10-character PAN (Permanent Account Number)
    IN_PHONE    — 10-digit Indian mobile number, with/without +91 prefix

ENTITY TYPE NAMES (locked — Phase 1 and Phase 4 reference these):
    "IN_AADHAAR"   — custom
    "IN_PAN"       — custom
    "IN_PHONE"     — custom
    "PERSON"           — Presidio built-in (spaCy NER)
    "EMAIL_ADDRESS"    — Presidio built-in

Do not rename these without updating detection/README.md and checking
whether Phase 4's rule engine has started keying off them.

FALSE-POSITIVE TRADE-OFFS (documented per the plan's requirement):

  Aadhaar vs. generic 12-digit numbers (e.g. order IDs, bank account
  fragments): Presidio's PatternRecognizer framework supports a
  `context` word list that boosts confidence when nearby words match
  (e.g. "aadhaar", "uid"), via the analyzer's context-enhancement step.
  We use this — see AADHAAR_CONTEXT below. However, context boosting only
  RAISES confidence when a context word is nearby; it does not lower
  confidence or suppress a match when no context word is present. This
  means a bare 12-digit number with NO surrounding context (e.g. a raw
  order ID with no "order" label nearby) can still match IN_AADHAAR at
  the recognizer's base score. We accept this trade-off for the MVP:
  our own generators (Phase 2) always emit Aadhaar values as spaced
  4-4-4 groups ("XXXX XXXX XXXX"), and order IDs are emitted in a
  visually distinct "ORD-XXXXXX" format (see ingestion/fixtures.py
  fake_order_id), so in practice the spaced-digit pattern used here does
  not collide with our own order ID shape. A production system would
  need a tighter checksum-based Aadhaar validator (Verhoeff algorithm)
  to fully eliminate false positives against arbitrary 12-digit strings;
  that is out of MVP scope.

  Aadhaar vs. Indian phone numbers: structurally disjoint by digit count
  (12 vs 10) and by grouping pattern, so no collision — verified by test.

  PAN vs. other alphanumeric strings: the pattern
  [A-Z]{5}[0-9]{4}[A-Z]{1} (exactly 5 letters + 4 digits + 1 letter, 10
  chars total) is distinctive enough that generic alphanumeric strings
  (order IDs like "ORD-431682", hashed IDs like "hcid_d8ba0b4b") do not
  match it — hashed IDs are lowercase, order IDs contain a hyphen and
  fewer trailing digits in the wrong position. Verified by test.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

import veritas_recognizers as shared

# The patterns, scores and context words live in veritas_recognizers.RULES, the one definition the agent uses too
# (docs/RECOGNIZERS.md). Presidio's recognizers below are built from it, so the two cannot drift apart.


def _patterns(entity_type: str) -> list[Pattern]:
    return [Pattern(name=r.name, regex=r.regex, score=r.score) for r in shared.RULES if r.entity_type == entity_type]


def _context(entity_type: str) -> list[str]:
    seen: list[str] = []
    for r in shared.RULES:
        if r.entity_type == entity_type:
            seen.extend(w for w in r.context if w not in seen)
    return seen


AADHAAR_CONTEXT = _context(shared.IN_AADHAAR)
AADHAAR_PATTERNS = _patterns(shared.IN_AADHAAR)
PAN_CONTEXT = _context(shared.IN_PAN)
PAN_PATTERNS = _patterns(shared.IN_PAN)
PHONE_CONTEXT = _context(shared.IN_PHONE)
PHONE_PATTERNS = _patterns(shared.IN_PHONE)


class AadhaarRecognizer(PatternRecognizer):
    """
    Detects Aadhaar numbers (India's 12-digit unique identity number). Entity type: IN_AADHAAR.
    Context words boost confidence when present nearby but do not suppress matches when absent — see the module
    docstring for the accepted trade-off.
    """

    def __init__(self):
        super().__init__(supported_entity="IN_AADHAAR", patterns=AADHAAR_PATTERNS, context=AADHAAR_CONTEXT,
                         supported_language="en")


class PANRecognizer(PatternRecognizer):
    """Detects Indian PAN: 5 letters, 4 digits, 1 letter, exactly 10 characters. Entity type: IN_PAN."""

    def __init__(self):
        super().__init__(supported_entity="IN_PAN", patterns=PAN_PATTERNS, context=PAN_CONTEXT,
                         supported_language="en")


class IndianPhoneRecognizer(PatternRecognizer):
    """
    Detects Indian mobile numbers: 10 digits starting 6-9, with or without +91/91 prefix and separators.
    Entity type: IN_PHONE. Deliberately does NOT match 12-digit runs (Aadhaar) or 10-digit runs starting 0-5.
    """

    def __init__(self):
        super().__init__(supported_entity="IN_PHONE", patterns=PHONE_PATTERNS, context=PHONE_CONTEXT,
                         supported_language="en")


def get_custom_recognizers() -> list[PatternRecognizer]:
    """Convenience factory — all custom recognizers this module defines."""
    return [AadhaarRecognizer(), PANRecognizer(), IndianPhoneRecognizer()]
