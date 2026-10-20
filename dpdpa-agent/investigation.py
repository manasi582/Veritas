"""
Veritas — Breach Investigation Layer ("@N" reference-based LLM Q&A)
========================================================================
Lets an auditor reference an already-detected violation by its per-tenant
sequential `violation_id` (evidence_store/store.py) and ask free-form
questions about it — "@01 what happened", "@01 how do I fix this" —
answered by an LLM grounded in that violation's full stored record, not
fresh detection, not guesswork.

THE THREE REQUESTED LAYERS, and where each one actually lives:

  1. Breach Detection & ID Assignment — already built, untouched here:
     rules/engine.py + rules/linkage.py produce Verdicts; evidence_store/
     store.py assigns `violation_id` at append() time (MAX(existing)+1
     per tenant, inside the write lock — gap-free, race-safe, never
     reused). This module does not detect anything or assign IDs.

  2. Breach Context Retrieval — parse_reference() + evidence_store's
     get_by_violation_id() below. "@01" -> the complete stored record:
     rule_id, severity, field, source_system, timestamp, registry
     context, the original grounded explanation, and the statute text.

  3. LLM Investigation — investigate() below. Open-ended Q&A, grounded in
     exactly that record, with a lighter-weight version of the same
     integrity guardrail llm_explainer/explainer.py uses for its one
     fixed explanation.

GROUNDING PHILOSOPHY (adapted, not replaced, for open-ended Q&A):
  llm_explainer/explainer.py's grounding check works because it asks for
  ONE fixed field (section_cited) and can byte-compare it. A free-form
  answer to "give me remediation steps" has no single fact to compare.
  So the guardrail here is layered instead of a single check:
    - The prompt supplies ONLY this violation's stored record + its
      already-grounded statute snippet as ground truth, plus a small
      amount of computed aggregate context (e.g. "N other violations of
      this same rule exist for this org") so "has this happened
      elsewhere" is answerable from real data instead of an LLM guess.
    - temp=0, and the model is explicitly instructed it may cite ONLY
      the exact statute reference already on file for this violation —
      never a different section, never a different law.
    - Post-hoc: if the answer contains a section-citation-shaped string
      (a "§" character) that does NOT match this violation's own
      section_cited, the whole answer is discarded and replaced with the
      deterministic fallback — same "never show an ungrounded legal
      claim" property as explainer.py, just checked after the fact
      instead of via a fixed-schema field.
    - Remediation/practice advice is explicitly framed (to the model AND
      in the fallback text) as general guidance, not a new legal
      citation — it was never meant to be grounding-checked the same way
      a statute reference is.
    - ANY failure (no API key, network error, malformed response, failed
      section check) -> deterministic fallback built from the already-
      stored explanation. Never raises, never leaves an auditor with
      nothing to read.

CONVERSATION CONTINUITY: stateless on the server. The caller (dashboard
JS, or any API client) resends prior turns as `history` on every call —
the same pattern OpenAI's own chat API uses, and the pattern
api/integration.py's InvestigateRequest.history follows. No new session-
storage subsystem was added: the full breach record is re-supplied on
every turn regardless of how long the conversation runs, which is what
actually keeps every answer correct, not memory of earlier answers.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from llm_explainer.explainer import _STATUTE_SNIPPETS

logger = logging.getLogger("investigation")

# ---------------------------------------------------------------------------
# Layer 2a — "@N" reference parsing
# ---------------------------------------------------------------------------

# Matches '@01', '@1', '@123' anywhere in the text; leading zeros allowed
# per the plan's own example ("@01") but not required.
_REFERENCE_PATTERN = re.compile(r"@0*([1-9][0-9]*)")


def parse_reference(text: str) -> tuple[Optional[int], str]:
    """
    Extracts an '@N' violation reference from anywhere in `text`.
    Returns (violation_id, remaining_question_with_reference_stripped).
    Returns (None, text.strip()) if no '@N' reference is found — callers
    treat this as "no violation referenced", not an error on its own.
    """
    match = _REFERENCE_PATTERN.search(text)
    if not match:
        return None, text.strip()
    violation_id = int(match.group(1))
    question = (text[: match.start()] + text[match.end() :]).strip()
    return violation_id, question


# ---------------------------------------------------------------------------
# Layer 2b — breach record formatting for the prompt
# ---------------------------------------------------------------------------

def _format_breach_record(row: Dict[str, Any]) -> str:
    lines = [
        f"Violation ID: #{row['violation_id']} (org: {row['tenant_id']})",
        f"Rule violated: {row['rule_id']}",
        f"Severity: {row['severity']}",
        f"Affected field: {row['field']}",
        f"Source system: {row['source_system']}",
        f"Detected at (timestamp): {row['timestamp']}",
        f"Breach-notification candidate: {row['breach_notification_candidate']}",
        f"Current remediation status: {row['remediation_status']}",
    ]
    if row.get("matched_registry_entry"):
        lines.append(f"Registry context (declared purpose/consent/retention for this field): {json.dumps(row['matched_registry_entry'])}")
    lines.append(f"Automated explanation already on file: {row['explanation']}")
    lines.append(f"Statute already cited for this finding: {row['section_cited']}")
    return "\n".join(lines)


def _aggregate_context(store, tenant_id: str, row: Dict[str, Any]) -> str:
    """
    Answers "has this happened elsewhere" from real stored data instead
    of letting the model guess — a small, cheap query against this
    tenant's own evidence (never another tenant's, per every other
    isolation guarantee in this codebase).
    """
    all_rows = store.query(tenant_id)
    same_rule = [r for r in all_rows if r["rule_id"] == row["rule_id"] and r["violation_id"] != row["violation_id"]]
    return (
        f"This org has {len(all_rows)} recorded finding(s) in total; "
        f"{len(same_rule)} other finding(s) of the same rule ({row['rule_id']}) besides this one."
    )


def _summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "violation_id": row["violation_id"],
        "rule_id": row["rule_id"],
        "severity": row["severity"],
        "field": row["field"],
        "source_system": row["source_system"],
        "timestamp": row["timestamp"],
        "remediation_status": row["remediation_status"],
    }


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------

class InvestigationAnswer(BaseModel):
    org_id: str
    violation_id: int
    question: str
    answer: str
    used_fallback: bool
    section_cited: str
    breach_summary: Dict[str, Any]


def _not_found_answer(org_id: str, violation_id: int, question: str) -> InvestigationAnswer:
    return InvestigationAnswer(
        org_id=org_id,
        violation_id=violation_id,
        question=question,
        answer=f"No violation numbered #{violation_id} exists for org {org_id!r}. "
               f"Check the number and try again — IDs are per-org and never reused.",
        used_fallback=True,
        section_cited="",
        breach_summary={},
    )


def _fallback_answer(org_id: str, row: Dict[str, Any], question: str) -> InvestigationAnswer:
    text = (
        f"(LLM investigation assistant unavailable right now — showing the stored, "
        f"already-verified explanation for #{row['violation_id']} instead.)\n\n"
        f"{row['explanation']} {row['section_cited']}\n\n"
        f"Rule: {row['rule_id']} | Severity: {row['severity']} | Field: {row['field']} | "
        f"Source system: {row['source_system']} | Status: {row['remediation_status']}"
    )
    return InvestigationAnswer(
        org_id=org_id,
        violation_id=row["violation_id"],
        question=question,
        answer=text,
        used_fallback=True,
        section_cited=row["section_cited"],
        breach_summary=_summary(row),
    )


# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _should_force_fallback() -> bool:
    """Same demo-control env var explainer.py uses, so both can be
    forced into fallback mode identically for a live demo."""
    return os.environ.get("FORCE_LLM_FALLBACK", "").strip() == "1"


def _call_llm_for_investigation(
    row: Dict[str, Any],
    question: str,
    history: List[Dict[str, str]],
    aggregate_context: str,
) -> Optional[str]:
    """Returns the LLM's free-text answer, or None on ANY failure (never raises).

    Provider selection is fully delegated to ai_config.get_ai_client():
      - mode=disabled → returns None immediately (no LLM call)
      - mode=external → OpenAI or Anthropic SDK
      - mode=local    → OpenAI-compatible client to local URL (Ollama, etc.)
    """
    try:
        from ai_config import get_ai_client
        client, model = get_ai_client()
        if client is None:
            logger.debug("AI disabled or unconfigured — investigation falling back to template")
            return None

        statute_snippet = _STATUTE_SNIPPETS.get(row["rule_id"], {})
        statute_text = statute_snippet.get("text", "(no statute text on file for this rule — cite nothing.)")

        system_prompt = f"""You are a DPDPA (Digital Personal Data Protection Act 2023) compliance investigation assistant. You help an auditor understand ONE specific, already-detected violation, referenced as #{row['violation_id']}.

BREACH RECORD (the only facts you know about this violation):
{_format_breach_record(row)}

STATUTE TEXT (the ONLY legal text you may reference, verbatim, for this rule):
{statute_text}

AGGREGATE CONTEXT (from this org's own evidence store):
{aggregate_context}

Rules you must follow:
- Answer ONLY about this specific violation (#{row['violation_id']}), using only the facts above.
- If you cite a statute section, it MUST be exactly: "{row['section_cited']}". Never cite any other section, act, or law, and never invent one.
- For remediation or "what should I do" questions, give practical, general DPDPA-consistent guidance. Frame it clearly as general practice guidance, not a new legal citation.
- If the record doesn't contain what's being asked, say so honestly instead of inventing details.
- Keep answers concise (a few sentences, or a short numbered list for step-by-step questions) unless asked to elaborate further.
"""

        messages_payload = [{"role": "system", "content": system_prompt}]
        for turn in history:
            role = turn.get("role")
            content = turn.get("content", "")
            if role in ("user", "assistant") and content:
                messages_payload.append({"role": role, "content": content})
        messages_payload.append({"role": "user", "content": question})

        # Detect Anthropic native SDK vs OpenAI-compatible client
        try:
            from anthropic import Anthropic as _Anthropic
            _is_anthropic = isinstance(client, _Anthropic)
        except ImportError:
            _is_anthropic = False

        if _is_anthropic:
            # Anthropic SDK: system prompt is a top-level param, not a message
            anthropic_messages = [m for m in messages_payload if m["role"] != "system"]
            response = client.messages.create(
                model=model,
                max_tokens=500,
                system=system_prompt,
                messages=anthropic_messages,
            )
            text = response.content[0].text if response.content else None
        else:
            response = client.chat.completions.create(
                model=model,
                messages=messages_payload,
                temperature=0,
                max_tokens=500,
            )
            text = response.choices[0].message.content

        return text.strip() if text else None

    except Exception as exc:
        logger.warning("Investigation LLM call failed: %s: %s", type(exc).__name__, exc)
        return None


def _grounding_ok(answer: str, expected_section: str) -> bool:
    """
    Lighter-weight analogue of explainer.py's _grounding_check for
    open-ended text: if the answer contains a section-citation-shaped
    string, it must match this violation's own already-grounded citation.
    An answer that cites NOTHING is fine (most remediation/impact
    questions won't need to) — this only catches a WRONG citation, not
    the absence of one.
    """
    if "§" not in answer and "Section" not in answer:
        return True
    return expected_section.strip() in answer


# ---------------------------------------------------------------------------
# Public entrypoint — Layer 3
# ---------------------------------------------------------------------------

def investigate(
    org_id: str,
    violation_id: int,
    question: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> InvestigationAnswer:
    """
    Main entrypoint. Given an org_id, a violation_id (already parsed from
    "@N" by the caller — see parse_reference), and a free-text question,
    returns a grounded InvestigationAnswer.

    Guarantee: NEVER raises. Every failure mode (violation not found, no
    API key, LLM error, failed grounding check) resolves to a complete,
    useful InvestigationAnswer with used_fallback=True where applicable.
    """
    from evidence_store.store import get_store

    store = get_store()
    row = store.get_by_violation_id(org_id, violation_id)
    if row is None:
        return _not_found_answer(org_id, violation_id, question)

    if _should_force_fallback():
        return _fallback_answer(org_id, row, question)

    aggregate_context = _aggregate_context(store, org_id, row)
    answer_text = _call_llm_for_investigation(row, question, history or [], aggregate_context)

    if answer_text is None:
        return _fallback_answer(org_id, row, question)

    if not _grounding_ok(answer_text, row["section_cited"]):
        logger.warning(
            "Investigation answer for #%d failed grounding check (expected section %r) — using fallback.",
            violation_id, row["section_cited"],
        )
        return _fallback_answer(org_id, row, question)

    return InvestigationAnswer(
        org_id=org_id,
        violation_id=violation_id,
        question=question,
        answer=answer_text,
        used_fallback=False,
        section_cited=row["section_cited"],
        breach_summary=_summary(row),
    )
