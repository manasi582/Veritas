"""
DPDPA Compliance Agent — Detection Engine
=============================================
The bridge between Phase 2's Event stream and Presidio's analyzer.
Runs detect_event() on every Event pulled from the shared queue (or a
test fixture), producing a DetectedEvent.

WHAT GETS SCANNED (per the plan):
  - Every value in event.fields, individually — so we know WHICH field
    contains PII, not just that the event as a whole does. This matters
    because Phase 1's registry and Phase 4's rule engine key off
    field_name, not off the event as a blob.
  - event.raw_snippet, for ALL events regardless of source_type. The plan
    calls this out specifically for source_type == "log" (since PII in
    logs is often embedded in free text, e.g. support_tickets-style
    notes), but also says to scan raw_snippet for API events "for
    safety" if populated — and per Phase 2's normalizer design decision,
    raw_snippet is NEVER empty for API events (it holds the serialized
    JSON payload). So in practice this engine scans raw_snippet for
    every event unconditionally; the log-vs-api distinction only matters
    for HOW MUCH new signal raw_snippet scanning adds (structured API
    fields are already fully covered by the fields-scan, so raw_snippet
    matches on API events are expected to duplicate the fields matches;
    for log events, raw_snippet scanning is often the ONLY way PII in
    unstructured text gets caught).

DEDUPLICATION: because raw_snippet frequently contains the same values
already present in fields (e.g. Phase 2's log lines embed the same
name/phone/address that also appear in fields), we deduplicate matches
by (field, entity_type, matched_text) so a single real-world PII value
doesn't get double-counted just because it appears in both the
structured field and the serialized raw text. Field-sourced matches take
priority in dedup (they have a real field_name); a raw_snippet match is
only kept if its matched_text isn't already accounted for by a
field-sourced match.

NO LLM. NO RULE EVALUATION. This module's only job is: given an Event,
what PII is in it, where, and (Phase 2) whether it's been structurally/
checksum-confirmed.

PHASE 2 ADDITION — validator wiring: for each match sourced from a
structured field, we look up the triggering event's org config
(config_loader.load_org_config, keyed by event.tenant_id) to see whether
that field_name has a declared `identifiers[].validator`. If so, we run
the matched text through validators.get_validator(...) and tag the match
PATTERN_MATCH / VALIDATED / FAILED_VALIDATION accordingly (see
detection/models.py). This is a config *read*, not a registry/rule-engine
lookup — it does not consult get_registry_entry, and it never raises: a
missing org config, an undeclared identifier, or an unregistered
validator name all fall back to PATTERN_MATCH with a logged warning
rather than failing detection for the event. See _resolve_validation_status.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from config_loader import OrgConfigNotFoundError, load_org_config
from detection.analyzer_engine import analyze_text
from detection.models import (
    FAILED_VALIDATION,
    FREE_TEXT_FIELD_LABEL,
    PATTERN_MATCH,
    VALIDATED,
    DetectedEvent,
    MatchedEntity,
)
from schemas.models import Event
from field_names import field_leaf
from validators import get_validator

logger = logging.getLogger("detection.engine")


def identifier_validators(org_id: str) -> Dict[str, str]:
    """
    {identifier name: validator name} from the organization's config (empty if it has none). The main
    process reads this and hands it to a detection worker with the event, so a worker never reads, or
    caches, an organization's settings (see detection/pool.py).
    """
    try:
        return {i.name: i.validator for i in load_org_config(org_id).identifiers}
    except OrgConfigNotFoundError:
        return {}


def _resolve_validation_status(org_id: str, field_name: str, matched_text: str,
                               validators: Optional[Dict[str, str]] = None) -> str:
    """
    Phase 2: decide a match's validation_status.

    - Matches with no real structured field (field_name == FREE_TEXT_FIELD_LABEL,
      i.e. raw_snippet matches) can never map to a declared identifier by
      field name, so they always stay PATTERN_MATCH.
    - If the org has no config on record, or the identifier's `validator`
      is "none"/undeclared, stays PATTERN_MATCH.
    - If the identifier declares a validator name that isn't registered
      (typo, or a not-yet-built validator like "apaar"), logs a warning
      and falls back to PATTERN_MATCH — this must never crash detection.
    - Otherwise runs the validator against matched_text: VALIDATED on
      True, FAILED_VALIDATION on False.
    """
    if field_name == FREE_TEXT_FIELD_LABEL:
        return PATTERN_MATCH

    if validators is None:                       # called in-process: read the config here
        validators = identifier_validators(org_id)
    validator_name = validators.get(field_name)
    if validator_name is None:                       # a payload path such as user.aadhaar: use the field's own name
        validator_name = validators.get(field_leaf(field_name))
    if validator_name is None or validator_name == "none":
        return PATTERN_MATCH

    validator_fn = get_validator(validator_name)
    if validator_fn is None:
        logger.warning(
            "Org %r declares validator %r for identifier %r, but no such "
            "validator is registered. Falling back to pattern_match confidence.",
            org_id, validator_name, field_name,
        )
        return PATTERN_MATCH

    return VALIDATED if validator_fn(matched_text) else FAILED_VALIDATION


def _scan_fields(org_id: str, fields: Dict[str, str],
                 validators: Optional[Dict[str, str]] = None) -> List[MatchedEntity]:
    """
    Runs the analyzer over each value in event.fields independently,
    tagging each match with its real field_name and (Phase 2) its
    validation_status per _resolve_validation_status.
    """
    matches: List[MatchedEntity] = []
    for field_name, value in fields.items():
        if not isinstance(value, str) or not value.strip():
            continue
        results = analyze_text(value)
        has_person = False
        for r in results:
            if r.entity_type == "PERSON":
                has_person = True
            matched_text = value[r.start:r.end]
            matches.append(
                MatchedEntity(
                    field=field_name,
                    entity_type=r.entity_type,
                    confidence=r.score,
                    matched_text=matched_text,
                    validation_status=_resolve_validation_status(org_id, field_name, matched_text, validators),
                )
            )
        # Fallback for structured 'name' fields when spaCy NER omits single/isolated names
        if not has_person and field_name.lower() in ("name", "customer_name", "user_name", "full_name"):
            if any(c.isalpha() for c in value) and not any(c.isdigit() for c in value):
                matches.append(
                    MatchedEntity(
                        field=field_name,
                        entity_type="PERSON",
                        confidence=0.85,
                        matched_text=value,
                        validation_status=_resolve_validation_status(org_id, field_name, value, validators),
                    )
                )
    return matches


_DEDUP_STRIP_CHARS = ' \t\n\r"\',:;{}[]()'


def _normalize_for_dedup(text: str) -> str:
    """
    Strips surrounding punctuation/quotes/whitespace that JSON
    serialization or log-line formatting adds around an otherwise
    identical value. E.g. a field value "Suresh K." serialized into
    raw_snippet as `"name": "Suresh K.", ...` produces a raw_snippet
    match spanning `Suresh K."` (trailing quote included) — without this
    normalization that fails an exact-string dedup check against the
    clean field-sourced match "Suresh K." even though it's the same
    real-world value. Case-insensitive to also absorb any casing drift
    between how a value appears structured vs. embedded in a log line.
    """
    return text.strip(_DEDUP_STRIP_CHARS).lower()


def _entity_type_validation_status(entity_type: str, matched_text: str) -> str:
    """
    Phase 10 (PII hardening): Apply checksum/structural validation to raw-snippet
    matches by entity type, independent of org config.

    This catches false positives from the low-confidence unspaced Aadhaar
    pattern (random 12-digit numbers that aren't real Aadhaar numbers) and
    from PAN pattern matches on strings that don't satisfy the structural rules.

    Returns VALIDATED, FAILED_VALIDATION, or PATTERN_MATCH.
    """
    try:
        if entity_type == "IN_AADHAAR":
            from validators import is_valid_aadhaar
            text = matched_text.replace(" ", "").strip()
            if len(text) == 12 and text.isdigit():
                return VALIDATED if is_valid_aadhaar(text) else FAILED_VALIDATION
        elif entity_type == "IN_PAN":
            from validators import is_valid_pan
            return VALIDATED if is_valid_pan(matched_text.strip()) else FAILED_VALIDATION
    except Exception:
        pass
    return PATTERN_MATCH


def _scan_raw_snippet(raw_snippet: str, already_matched_texts: set) -> List[MatchedEntity]:
    """
    Runs the analyzer over raw_snippet. Matches whose normalized
    matched_text was already found via a field-sourced match are skipped
    (dedup — see module docstring and _normalize_for_dedup). Surviving
    matches are labeled with FREE_TEXT_FIELD_LABEL ("raw_snippet") since
    there's no structured field to attribute them to.
    """
    matches: List[MatchedEntity] = []
    results = analyze_text(raw_snippet)
    for r in results:
        matched_text = raw_snippet[r.start:r.end]
        if _normalize_for_dedup(matched_text) in already_matched_texts:
            continue
        # Phase 10: apply entity-type checksum validation for raw matches
        val_status = _entity_type_validation_status(r.entity_type, matched_text)
        # Drop failed-validation unspaced Aadhaar (likely false positive)
        if val_status == FAILED_VALIDATION and r.entity_type == "IN_AADHAAR":
            continue
        matches.append(
            MatchedEntity(
                field=FREE_TEXT_FIELD_LABEL,
                entity_type=r.entity_type,
                confidence=r.score,
                matched_text=matched_text,
                validation_status=val_status,
            )
        )
    return matches


def detect_event(event: Event, validators: Optional[Dict[str, str]] = None) -> DetectedEvent:
    """
    Runs full PII detection over a single Event: scans every value in
    event.fields, then scans event.raw_snippet (deduplicated against
    field matches), and returns a DetectedEvent wrapping the original
    Event plus the combined results.

    contains_pii and matched_entities are always populated (never
    omitted) — see DetectedEvent's docstring.
    """
    field_matches = _scan_fields(event.tenant_id, event.fields, validators)
    already_matched_texts = {_normalize_for_dedup(m.matched_text) for m in field_matches}

    raw_snippet_matches = _scan_raw_snippet(event.raw_snippet, already_matched_texts)

    all_matches = field_matches + raw_snippet_matches

    return DetectedEvent(
        event=event,
        contains_pii=len(all_matches) > 0,
        matched_entities=all_matches,
    )


async def detect_from_queue(queue, out_queue, max_events: int | None = None) -> None:
    """
    Consumer loop: pulls Event objects off an asyncio.Queue (Phase 2's
    shared queue), tags each with detect_event(), and pushes the
    resulting DetectedEvent onto out_queue.

    Pass-through behavior: EVERY event is pushed to out_queue regardless
    of contains_pii — clean events flow through tagged-but-untouched, per
    the plan's pass-through requirement. Phase 4 is responsible for
    short-circuiting on contains_pii == False; this function does not
    filter anything out.
    """
    processed = 0
    while max_events is None or processed < max_events:
        event: Event = await queue.get()
        detected = detect_event(event)
        await out_queue.put(detected)
        processed += 1
