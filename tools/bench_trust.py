#!/usr/bin/env python3
"""
Measures the trust, visibility and prevention features on this machine and prints a table (docs/PERFORMANCE.md shows
one run). Run from the repository root with the server's dependencies installed:

    python tools/bench_trust.py [--verdicts 100000] [--json]

It uses a temporary database and touches nothing else.
"""
import argparse
import json
import os
import platform
import random
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dpdpa-agent"))
sys.path.insert(0, str(ROOT / "veritas-agent"))


def timed(fn):
    t = time.perf_counter()
    out = fn()
    return time.perf_counter() - t, out


def bench_incidents(n_verdicts):
    from evidence_store.store import EvidenceStore
    from evidence_store.test_evidence_store import _make_explained_verdict
    from incidents.template import template_of
    stems = ["pay", "ship", "auth", "sync", "mail", "cart", "fetch", "store", "route", "index"]
    tails = ["alpha", "beta", "gamma", "delta", "sigma", "omega", "kappa", "lambda", "theta", "zeta", "iota", "tau", "rho", "phi",
             "psi", "nu", "mu", "xi", "pi", "chi", "eta", "epsilon", "upsilon", "omicron", "ardor", "bison", "cedar", "dune",
             "ember", "flint"]
    # 300 different messages (different wording, so different incidents); numbers and ids in them vary on every line
    kinds = [f"{a}{b} failed to process order {{n}} for user=u{{n}} after {{n}} ms (attempt {{n}})" for a in stems for b in tails]
    store = EvidenceStore(Path(tempfile.mkdtemp()) / "bench.db")
    t0 = time.perf_counter()
    for n in range(n_verdicts):
        ev = _make_explained_verdict(tenant_id="bench")
        store.append(ev, grouping=tuple(template_of(kinds[n % 300].format(n=n))))
    ingest = time.perf_counter() - t0
    list_s, (rows, total) = timed(lambda: store.list_incidents("bench", limit=100))
    summary_s, summary = timed(lambda: store.incident_summary("bench"))
    verify_s, verified = timed(lambda: store.verify_chain("bench"))
    out = {"verdicts": n_verdicts, "incidents": summary["incidents"], "ingest_s": round(ingest, 1),
           "ingest_per_s": round(n_verdicts / ingest), "list_incidents_s": round(list_s, 3), "summary_s": round(summary_s, 3),
           "verify_chain_s": round(verify_s, 1), "chain_valid": verified["valid"]}
    store.close()
    return out


def bench_flows(systems=50, fields=6, cats=5, dests=4):
    from evidence_store.store import EvidenceStore
    from flows import build
    from org_config.schema import OrgConfig
    store = EvidenceStore(Path(tempfile.mkdtemp()) / "bench.db")
    labels = ["aadhaar", "pan", "phone", "email", "card"][:cats]
    cfg = OrgConfig.model_validate({"org_id": "bench", "fields": [
        {"field_name": f"field{f}", "pii_category": labels[f % cats], "declared_purpose": "p", "consent_scope": "c",
         "retention_days": 365, "source_system": f"system{s}"} for s in range(systems) for f in range(fields)]})
    t0 = time.perf_counter()
    for s in range(systems):
        for f in range(fields):
            for c in labels:
                for d in range(dests):
                    store.flows.record("bench", f"system{s}", [(f"field{f}", c)], f"dest{d}.example.org")
    store.flows.flush()
    fill = time.perf_counter() - t0
    build_s, m = timed(lambda: build.build(store, "bench", cfg))
    csv_s, text = timed(lambda: build.record_csv(m))
    rows = store._conn.execute("SELECT COUNT(*) AS n FROM observed_flows").fetchone()["n"]
    store.close()
    return {"systems": systems, "counter_rows": rows, "fill_s": round(fill, 3), "build_map_s": round(build_s, 3),
            "csv_s": round(csv_s, 3), "csv_kb": len(text) // 1024}


def bench_lookup(rows=200_000):
    import veritas_recognizers as vr
    from evidence_store.store import EvidenceStore
    store = EvidenceStore(Path(tempfile.mkdtemp()) / "bench.db")
    kid, key = store.keyring.current("bench", "lookup")
    with store.writer() as conn:
        conn.executemany("INSERT INTO pii_tokens (org, key_id, token, category, source_system, event_count, first_seen, last_seen) "
                         "VALUES ('bench', ?, ?, 'phone', ?, 1, 't', 't')",
                         ((kid, "%064x" % random.getrandbits(256), f"system{i % 50}") for i in range(rows)))
    store.subjects.record("bench", "system1", [(kid, vr.keyed_digest("PHONE", "9876543210", key), "phone")])
    t, found = timed(lambda: store.subjects.lookup_tokens("bench", "phone", store.subjects.tokens_for_identifier("bench", "phone", "+91 98765 43210")))
    tokens_t, _ = timed(lambda: [store.subjects.tokens_for_event("bench", [], "x [PHONE#a1b2c3.0123456789abcdef]") for _ in range(10000)])
    store.close()
    return {"index_rows": rows, "lookup_s": round(t, 4), "found_systems": len(found["systems"]),
            "event_tokenising_us": round(tokens_t / 10000 * 1e6, 1)}


def bench_redaction(lines=20000):
    import veritas_recognizers as vr
    sample = [f"2026-10-20 10:01:02 INFO order {i} shipped to warehouse 4 user=u{i} phone 9876543210 mail a{i}@example.com" for i in range(lines)]
    plain = [f"2026-10-20 10:01:02 INFO order {i} shipped to warehouse 4 user=u{i}" for i in range(lines)]
    t_mask, _ = timed(lambda: [vr.mask(x) for x in sample])
    t_plain, _ = timed(lambda: [vr.mask(x) for x in plain])
    key = b"k" * 32
    t_hash, _ = timed(lambda: [vr.hash_token("PHONE", "9876543210", key) for _ in range(lines)])
    return {"lines": lines, "mask_line_with_two_values_us": round(t_mask / lines * 1e6, 1),
            "scan_line_without_values_us": round(t_plain / lines * 1e6, 1), "hash_one_value_us": round(t_hash / lines * 1e6, 1)}


def bench_tap(n=2000):
    sys.path.insert(0, str(ROOT / "veritas-sdk" / "python"))
    import asyncio
    import json as _json
    import veritas_tap as vt
    tap = vt.Tap("http://127.0.0.1:1", "t", "bench", "svc", start=False, min_interval_seconds=0, queue_size=10)
    body = _json.dumps({"user": {"name": "x", "phone": "9876543210", "email": "a@example.com"},
                        "items": [{"id": i, "sku": f"s{i}", "qty": i} for i in range(80)]}).encode()
    print_size = len(body)

    async def app(scope, receive, send):
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    async def call(a):
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            pass
        await a({"type": "http", "method": "GET", "path": "/c/1", "headers": []}, receive, send)

    async def timed(a):
        out = []
        for _ in range(n):
            t = time.perf_counter()
            await call(a)
            out.append(time.perf_counter() - t)
            while not tap.q.empty():
                tap.q.get_nowait()
        return out

    plain = sorted(asyncio.run(timed(app)))
    wrapped = sorted(asyncio.run(timed(vt.ASGIMiddleware(app, tap))))
    p = lambda xs, q: xs[int(len(xs) * q) - 1]
    return {"body_bytes": print_size, "added_p50_us": round((p(wrapped, .5) - p(plain, .5)) * 1e6), "added_p99_us": round((p(wrapped, .99) - p(plain, .99)) * 1e6)}


def bench_schema(n=20000):
    from schema_watch import parser
    sql = "2026-10-20 10:00:00 UTC LOG:  statement: ALTER TABLE public.customers ADD COLUMN mobile_no varchar(15) NOT NULL DEFAULT '', DROP COLUMN old_ref;"
    t, _ = timed(lambda: [parser.parse(sql) for _ in range(n)])
    return {"statements": n, "parse_us_per_statement": round(t / n * 1e6, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdicts", type=int, default=100_000)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    os.environ["VERITAS_DATA_DIR"] = tempfile.mkdtemp()
    result = {"machine": f"{platform.platform()} / Python {platform.python_version()} / {os.cpu_count()} cores",
              "incidents": bench_incidents(a.verdicts), "flows": bench_flows(), "lookup": bench_lookup(),
              "redaction": bench_redaction(), "payload_tap": bench_tap(), "schema_watch": bench_schema()}
    if a.json:
        print(json.dumps(result, indent=1))
        return
    print("Machine:", result["machine"])
    for name in ("incidents", "flows", "lookup", "redaction", "payload_tap", "schema_watch"):
        print(f"\n{name}")
        for k, v in result[name].items():
            print(f"  {k:36} {v}")


if __name__ == "__main__":
    main()
