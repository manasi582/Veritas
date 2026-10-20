#!/usr/bin/env python3
"""
For the pitch demo (docs/DEMO.md), moment 6. Plays the part of someone with write access to the evidence database: it
changes one finding and then recomputes every later hash so the chain still looks consistent. The dashboard's own
"Verify chain" will pass afterwards; the stand-alone verifier, comparing against the witnesses' copies, will not.

    sudo veritas stop
    sudo python tools/demo_tamper.py --data-dir /var/lib/veritas --org demo_corp [--seq 5]
    ... run veritas-verify ... then restore:  sudo veritas restore <backup made before the demo>

Needs the server's Python dependencies (run it from a source checkout). It changes the database it is pointed at:
point it at a copy or a demo machine, never at real evidence.
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dpdpa-agent"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--org", required=True)
    ap.add_argument("--seq", type=int, default=0, help="the record to change (default: the sixth finding)")
    a = ap.parse_args()
    os.environ["VERITAS_DATA_DIR"] = a.data_dir
    from db_encryption import decrypt_field, encrypt_field
    from evidence_store import canonical as cn
    from evidence_store.store import GENESIS_HASH, EvidenceStore
    store = EvidenceStore(Path(a.data_dir) / "evidence.db")
    c = store._conn
    seq = a.seq or c.execute("SELECT seq FROM evidence WHERE tenant_id = ? AND record_type = 'VERDICT' ORDER BY seq LIMIT 1 OFFSET 5",
                             (a.org,)).fetchone()["seq"]
    rows = c.execute("SELECT * FROM evidence WHERE tenant_id = ? ORDER BY seq", (a.org,)).fetchall()
    prev = rows[seq - 2]["row_hash"] if seq > 1 else GENESIS_HASH
    for row in rows[seq - 1:]:
        body = json.loads(decrypt_field(row["payload_json"]))
        if row["seq"] == seq:
            print(f"record {seq}: {body.get('rule_id')} severity {body.get('severity')} -> LOW")
            body["severity"] = "LOW"
            c.execute("UPDATE evidence SET severity = 'LOW' WHERE row_index = ?", (row["row_index"],))
        h = cn.v1_hash(prev, body)
        c.execute("UPDATE evidence SET payload_json = ?, previous_hash = ?, row_hash = ? WHERE row_index = ?",
                  (encrypt_field(cn.canonical_json(body)), prev, h, row["row_index"]))
        prev = h
    c.commit()
    print(f"recomputed {len(rows) - seq + 1} later hashes. The dashboard's chain check now passes: "
          f"{store.verify_chain(a.org)['valid']}")
    store.close()


if __name__ == "__main__":
    main()
