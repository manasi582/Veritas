"""
Veritas DPDPA Agent — Identifier Validators (Phase 2)
========================================================
Pluggable, structural/checksum validation for identifiers an org declares
in its Org Config `identifiers` list (see org_config/schema.py).

This module is the ONE deliberate, explicit exception to Veritas's
"no domain hardcoding in pipeline logic" rule: it is allowed to *implement*
named validators like `is_valid_pan` and `is_valid_aadhaar` because that is
building entries in a generic plugin registry (`validator_registry`), not
special-casing pipeline behavior on an org's identity. No file outside this
one may branch on "if org == X" — this file just happens to know what a
PAN or an Aadhaar number looks like, the same way a phone-number library
knows what a phone number looks like.

Public interface:
  is_valid_pan(value: str) -> bool
  is_valid_aadhaar(value: str) -> bool
  validator_registry: dict[str, Callable[[str], bool]]
  register_validator(name: str, fn: Callable[[str], bool], overwrite: bool = False) -> None
  get_validator(name: str) -> Callable[[str], bool] | None
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Optional

# ---------------------------------------------------------------------------
# PAN (structure) and Aadhaar (Verhoeff checksum): the implementations are in veritas_recognizers.py, shared with
# the agent, so there is one definition of each. Their documentation is there.
# ---------------------------------------------------------------------------

from veritas_recognizers import _verhoeff_is_valid, is_valid_aadhaar, is_valid_pan  # noqa: E402,F401


# ---------------------------------------------------------------------------
# Pluggable validator registry
# ---------------------------------------------------------------------------

validator_registry: Dict[str, Callable[[str], bool]] = {
    "pan": is_valid_pan,
    "aadhaar": is_valid_aadhaar,
}


def register_validator(name: str, fn: Callable[[str], bool], overwrite: bool = False) -> None:
    """
    Registers a new validator at runtime, e.g. for an org-specific
    identifier once it gets a public checksum spec (APAAR is the
    canonical example this codebase is waiting on).

    Raises ValueError if `name` is already registered and overwrite is
    not explicitly True — this stops a typo'd re-registration from
    silently clobbering a built-in validator like "pan" or "aadhaar".
    """
    if name in validator_registry and not overwrite:
        raise ValueError(
            f"validator {name!r} is already registered. Pass overwrite=True "
            f"if you intend to replace it."
        )
    validator_registry[name] = fn


def get_validator(name: str) -> Optional[Callable[[str], bool]]:
    """
    Looks up a validator by name. Returns None (never raises) if `name`
    isn't registered — an org referencing an unregistered validator name
    (typo, or a not-yet-built validator like "apaar") is an expected,
    non-error state; callers fall back to pattern-match confidence.
    """
    return validator_registry.get(name)
