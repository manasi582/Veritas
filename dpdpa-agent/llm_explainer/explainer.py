"""
DPDPA Compliance Agent — LLM Explainer (Phase 5)
=================================================
Takes a Verdict produced by Phase 4's Rule Engine and returns an
ExplainedVerdict: the original verdict + a human-readable explanation,
a verified statute citation, a confidence score, and a flag indicating
whether the LLM call succeeded or fell back to a deterministic template.

GUARDRAIL DESIGN:
  1. Statute text is supplied entirely from a static local JSON file
     (statute_snippets.json) — the LLM never recalls statute text from
     its own training weights.
  2. `temperature=0` for deterministic, low-variance output.
  3. Structured JSON output validated with Pydantic on every call.
  4. Cheap grounding check: confirm the section_cited in the LLM response
     actually matches the section string we fed it. Mismatch → discard,
     fall back.
  5. ANY failure at all (API error, invalid JSON, schema mismatch,
     grounding check fail) → deterministic template fallback. The pipeline
     NEVER crashes or hangs on an LLM failure.

IMMUTABILITY CONTRACT:
  This module NEVER mutates the Verdict object. It wraps the Verdict in
  ExplainedVerdict; the original Verdict is untouched. Phase 6 receives
  ExplainedVerdict and stores the whole thing.

ONE-WAY DATA FLOW:
  LLM output only annotates the ExplainedVerdict wrapper — no write access
  to registry, no ability to re-trigger Phase 4, no mutations to any
  Phase 0-4 data structure.

AUTOMATIC EXPLANATION REMOVED FROM THE LIVE PATH (post-Phase 8 change):
  explain_verdict() — the real, per-verdict LLM call — USED to run
  automatically for every single detected violation (run_pipeline.py's
  Stream mode, and api/integration.py's /events and /scan). At demo
  volumes (a handful of verdicts) that's fine; at real volumes (e.g. a
  feed producing thousands of violations) that's an unbounded, uncapped
  LLM bill for explanation text nobody may ever read. Per explicit
  instruction, the live/scan path no longer calls explain_verdict() at
  all — it uses build_deferred_explanation() below instead, which is
  zero-cost and zero-network (same deterministic template as the
  LLM-failure fallback). The real, statute-grounded, per-question LLM
  call now only happens on demand, exactly once per question a human
  actually asks, via investigation.py's "@N <question>" endpoint —
  see that module. explain_verdict()/explain_from_queue() themselves are
  UNCHANGED and still fully tested; they're simply no longer wired into
  the automatic detection path.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ValidationError

from schemas.models import Verdict, RuleId

logger = logging.getLogger("llm_explainer.explainer")

# ---------------------------------------------------------------------------
# Load statute snippets (static — locked at module init)
# ---------------------------------------------------------------------------

from runtime_paths import bundle_root as _bundle_root
_SNIPPETS_PATH = _bundle_root() / "llm_explainer" / "statute_snippets.json"


def _load_snippets() -> dict:
    with open(_SNIPPETS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


_STATUTE_SNIPPETS: dict = _load_snippets()


def get_statute_snippet(rule_id: str) -> dict:
    """
    Returns the statute snippet dict for a given rule_id.
    Raises KeyError if rule_id is not in the static file — this should
    never happen for the three locked rule IDs; it would indicate a
    code/config bug, not a runtime error.
    """
    return _STATUTE_SNIPPETS[rule_id]


# ---------------------------------------------------------------------------
# ExplainedVerdict — wraps Verdict, never mutates it
# ---------------------------------------------------------------------------

class ExplainedVerdict(BaseModel):
    """
    Wraps a Phase 4 Verdict with LLM-generated (or template) explanation.
    The original Verdict is embedded, never modified.
    used_fallback=True means the LLM path failed for any reason and the
    deterministic template was used instead.
    """
    verdict: Verdict
    explanation: str
    section_cited: str
    confidence: float
    used_fallback: bool


# ---------------------------------------------------------------------------
# LLM response schema — validated on every call
# ---------------------------------------------------------------------------

class _LLMResponse(BaseModel):
    explanation: str
    section_cited: str
    confidence: float


# ---------------------------------------------------------------------------
# Fallback template — guaranteed never to crash
# ---------------------------------------------------------------------------

def _build_fallback(verdict: Verdict, rule_id: str) -> ExplainedVerdict:
    """
    Deterministic template fallback. Used whenever the LLM call fails for
    any reason. Always returns a complete ExplainedVerdict — never raises.
    """
    snippet = _STATUTE_SNIPPETS.get(rule_id, {})
    section = snippet.get("reference", rule_id)
    if rule_id == "ERASURE_001":
        explanation = (
            f"An identifier for which an erasure request was closed (request {str((verdict.matched_registry_entry or {}).get('erasure_request', ''))[:8] or '?'}) "
            f"was observed again in {verdict.source_system}. Veritas reports where it observed the identifier; it cannot "
            f"tell whether the data was collected again, a copy was not erased, or the identifier now belongs to "
            f"someone else. See {section}."
        )
    elif rule_id == "PURPOSE_001" and isinstance(verdict.matched_registry_entry, dict) \
            and "schema_change" in verdict.matched_registry_entry:
        entry = verdict.matched_registry_entry
        explanation = (
            f"A database change ({entry['schema_change']}) in {verdict.source_system} adds a column that looks like "
            f"{entry.get('category', 'personal')} data, and the policy does not declare that kind of data for this system. "
            f"Veritas reads database structure, not the data: check whether the column holds personal data, then declare "
            f"its purpose in the policy, or tell Veritas it is not personal. See {section}."
        )
    elif rule_id == "NOTICE_001":
        explanation = (
            f"Personal data of a kind that no current notice lists for {verdict.source_system} was observed there "
            f"({verdict.field}). Veritas checks that a current notice covers the data it observes; it cannot tell "
            f"whether the notice was shown to the person or whether it is legally adequate. See {section}."
        )
    else:
        explanation = (
            f"Violation: {rule_id} — {verdict.field!r} exposed "
            f"in {verdict.source_system}. See {section}."
        )
    return ExplainedVerdict(
        verdict=verdict,
        explanation=explanation,
        section_cited=section,
        confidence=1.0,
        used_fallback=True,
    )


# ---------------------------------------------------------------------------
# Grounding check — cheap: confirm section_cited matches what we provided
# ---------------------------------------------------------------------------

def _grounding_check(llm_response: _LLMResponse, expected_section: str) -> bool:
    """
    Cheap grounding check: the section_cited in the LLM response must
    match (or be a substring of) the section string we provided from the
    static snippet. This catches the most likely failure mode —
    hallucinated statute citation — without full token-level fact-matching.
    """
    cited = llm_response.section_cited.strip()
    expected = expected_section.strip()
    # Accept if the cited text IS the expected section or contains it as
    # a substring (the LLM may slightly paraphrase the section label).
    return cited == expected or expected in cited or cited in expected


# ---------------------------------------------------------------------------
# LLM call — uses ai_config for provider/mode abstraction
# ---------------------------------------------------------------------------

def _call_llm(verdict: Verdict, snippet: dict) -> Optional[_LLMResponse]:
    """
    Calls the configured LLM with the verdict + statute snippet, temperature=0,
    requiring structured JSON output. Returns a validated _LLMResponse on
    success, None on ANY failure (caught, never re-raised).

    Provider selection is fully delegated to ai_config.get_ai_client():
      - VERITAS_AI_MODE=disabled (or no keys configured) → returns None immediately
      - VERITAS_AI_MODE=external → OpenAI or Anthropic SDK
      - VERITAS_AI_MODE=local   → OpenAI-compatible client to local URL
    """
    try:
        from ai_config import get_ai_client
        client, model = get_ai_client()
        if client is None:
            logger.debug("AI disabled or unconfigured — skipping LLM call")
            return None

        prompt = f"""You are a DPDPA (Digital Personal Data Protection Act 2023) compliance analyst assistant.
You will be given a compliance violation verdict and the relevant statute text.
Your task is to produce a concise, human-readable explanation for a compliance auditor.

VERDICT:
{json.dumps(verdict.model_dump(mode='json'), indent=2, default=str)}

STATUTE SNIPPET (the ONLY legal text you may reference):
Section: {snippet['section']}
Text: {snippet['text']}

Respond with ONLY valid JSON matching this exact schema (no markdown, no extra text):
{{
  "explanation": "<2-3 sentence plain-English explanation of what went wrong and why it violates DPDPA>",
  "section_cited": "{snippet['reference']}",
  "confidence": <float 0.0-1.0 indicating your confidence in this explanation>
}}

Rules:
- section_cited MUST be exactly: {snippet['reference']}
- Do not cite any statute text not provided above
- Do not mention specific user names or invent context not in the verdict
- Confidence should be 0.8-1.0 for clear violations, 0.5-0.8 for ambiguous cases
"""

        # Detect Anthropic native SDK vs OpenAI-compatible client
        try:
            from anthropic import Anthropic as _Anthropic
            _is_anthropic = isinstance(client, _Anthropic)
        except ImportError:
            _is_anthropic = False

        if _is_anthropic:
            response = client.messages.create(
                model=model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text if response.content else None
        else:
            # OpenAI SDK or OpenAI-compatible (local Ollama / LM Studio)
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=400,
                response_format={"type": "json_object"} if "gpt" in model else None,
            )
            raw = response.choices[0].message.content

        if not raw:
            logger.warning("LLM returned empty content")
            return None

        parsed = json.loads(raw)
        return _LLMResponse(**parsed)

    except Exception as exc:
        logger.warning("LLM call failed: %s: %s", type(exc).__name__, exc)
        return None


# ---------------------------------------------------------------------------
# Force-fail flag for demo/testing (Part 4 — demo script)
# ---------------------------------------------------------------------------

def _should_force_fallback() -> bool:
    """
    When env var FORCE_LLM_FALLBACK=1, always skip the LLM and return
    fallback. Used during the demo to show the guardrail on cue.
    """
    return os.environ.get("FORCE_LLM_FALLBACK", "").strip() == "1"


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def explain_verdict(verdict: Verdict) -> ExplainedVerdict:
    """
    Main entrypoint for Phase 5. Given a Verdict, returns an ExplainedVerdict.

    Guarantee: NEVER raises, NEVER blocks indefinitely. Any failure at any
    step → deterministic template fallback with used_fallback=True.

    Flow:
      1. Load statute snippet for rule_id.
      2. If FORCE_LLM_FALLBACK=1 (demo mode), skip to fallback immediately.
      3. Call LLM with {verdict, statute_snippet}, temperature=0.
      4. Validate response against _LLMResponse schema.
      5. Run grounding check on section_cited.
      6. Any failure at steps 3-5 → fallback.
      7. Return ExplainedVerdict wrapping the original Verdict (never mutated).
    """
    rule_id = verdict.rule_id.value
    snippet = _STATUTE_SNIPPETS.get(rule_id)
    if not snippet:
        logger.error("No statute snippet for rule_id=%r — using fallback", rule_id)
        return _build_fallback(verdict, rule_id)

    if _should_force_fallback():
        logger.info("FORCE_LLM_FALLBACK=1 — skipping LLM, using template fallback")
        return _build_fallback(verdict, rule_id)

    llm_response = _call_llm(verdict, snippet)

    if llm_response is None:
        logger.info("LLM call failed — using template fallback for verdict %s", verdict.verdict_id)
        return _build_fallback(verdict, rule_id)

    if not _grounding_check(llm_response, snippet["reference"]):
        logger.warning(
            "Grounding check failed: section_cited=%r, expected=%r — using fallback",
            llm_response.section_cited, snippet["reference"],
        )
        return _build_fallback(verdict, rule_id)

    logger.info("LLM explanation accepted for verdict %s (confidence=%.2f)", verdict.verdict_id, llm_response.confidence)
    return ExplainedVerdict(
        verdict=verdict,
        explanation=llm_response.explanation,
        section_cited=llm_response.section_cited,
        confidence=llm_response.confidence,
        used_fallback=False,
    )


# ---------------------------------------------------------------------------
# Deferred (no-LLM) explanation — the live/scan path's default now
# ---------------------------------------------------------------------------

def build_deferred_explanation(verdict: Verdict) -> ExplainedVerdict:
    """
    Zero-cost, zero-network ExplainedVerdict for the automatic detection
    path — see this module's "AUTOMATIC EXPLANATION REMOVED" docstring
    note. Deliberately reuses _build_fallback()'s exact template rather
    than inventing a second one: it's already guaranteed never to crash,
    and every existing consumer (dashboard's "Template" badge, Evidence
    Store schema, investigation.py's breach-record context) already
    handles used_fallback=True correctly, so no downstream changes were
    needed to introduce this.
    """
    return _build_fallback(verdict, verdict.rule_id.value)


async def defer_explanation_from_queue(
    in_queue,
    out_queue,
    max_verdicts: int | None = None,
) -> None:
    """
    Same queue-consumer shape as explain_from_queue below, but builds
    every ExplainedVerdict with build_deferred_explanation() instead of
    explain_verdict() — no LLM call, no network I/O, per verdict. This is
    what run_pipeline.py's Stream mode actually runs now.
    """
    processed = 0
    while max_verdicts is None or processed < max_verdicts:
        verdict: Verdict = await in_queue.get()
        explained = build_deferred_explanation(verdict)
        await out_queue.put(explained)
        processed += 1


# ---------------------------------------------------------------------------
# Queue consumer — Phase 4's fanout → this module (real LLM call per item;
# no longer wired into the automatic live/scan path — see module docstring)
# ---------------------------------------------------------------------------

async def explain_from_queue(
    in_queue,
    out_queue,
    max_verdicts: int | None = None,
) -> None:
    """
    Async consumer: pulls Verdict objects off in_queue (Phase 4's fanout
    llm_explainer_queue), explains each, pushes ExplainedVerdict to out_queue.

    Pass-through on failure: if explain_verdict() itself ever raises
    (it shouldn't — it's designed to absorb all errors), the fallback is
    still applied here as a last line of defence.
    """
    import asyncio

    processed = 0
    while max_verdicts is None or processed < max_verdicts:
        verdict: Verdict = await in_queue.get()
        try:
            explained = explain_verdict(verdict)
        except Exception as exc:
            logger.error(
                "Unexpected error in explain_verdict (this is a bug): %s — using fallback",
                exc, exc_info=True,
            )
            explained = _build_fallback(verdict, verdict.rule_id.value)
        await out_queue.put(explained)
        processed += 1
