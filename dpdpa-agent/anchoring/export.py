"""Files an auditor takes away: the evidence export and the checkpoints export (JSON lines), and the public key."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterator

from anchoring import keys as anchor_keys
from evidence_store import canonical as cn


def evidence_lines(store, org: str) -> Iterator[str]:
    """
    Header line, then one record per line in chain order. The header names the organization, the record count and the
    head, so an export cut short is noticed.
    """
    head = store.chain_head(org)
    versions = sorted({r for r in (0, 1)})  # both formats may appear in one chain
    header = {"format": "veritas-evidence-export", "version": 1, "org": org,
              "exported_at": cn.rfc3339_ms(datetime.now(timezone.utc)), "record_count": head["record_count"],
              "head_hash": head["head_hash"], "hash_versions": versions}
    yield json.dumps(header, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    n = 0
    for rec in store.export_records(org):
        n += 1
        if n > head["record_count"]:          # records added while exporting: not part of this export
            break
        yield json.dumps(rec, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"


def checkpoint_lines(manager, org: str) -> Iterator[str]:
    for cp in manager.all_checkpoints(org):
        yield json.dumps(cp, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"


def public_key_text() -> str:
    _private, public_raw, _kid = anchor_keys.load_or_create()
    return anchor_keys.public_key_file_text(public_raw)
