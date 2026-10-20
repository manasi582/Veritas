#!/usr/bin/env python3
"""
FOR DEVELOPING tools/trust_e2e.py WITHOUT THE LANGUAGE MODEL. Starts the real server with detection replaced by the
recognizer pack alone (no names). Never used by CI or shipped: the real scenario uses the real detection.

    python tools/trust_e2e.py --server-cmd "python tools/e2e_fake_detection_server.py --port {port}"
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dpdpa-agent"))

import uvicorn  # noqa: E402

import veritas_recognizers as vr  # noqa: E402
from detection import pool as pool_module  # noqa: E402
from detection.models import DetectedEvent, MatchedEntity  # noqa: E402


class PackOnlyPool:
    workers, queue_limit = 0, 0

    def start(self):
        pass

    def stats(self):
        return {"workers": 0, "queue_depth": 0, "queue_limit": 0, "refused": 0}

    async def detect(self, event, validators):
        found = [MatchedEntity(field="raw_snippet", entity_type=d.entity_type, confidence=d.score,
                               matched_text=event.raw_snippet[d.start:d.end], validation_status="pattern_match")
                 for d in vr.scan(event.raw_snippet)]
        return DetectedEvent(event=event, contains_pii=bool(found), matched_entities=found)


_pool = PackOnlyPool()
pool_module.get_pool = lambda: _pool
pool_module.reset_pool = lambda: None
from api import integration  # noqa: E402
integration.get_pool = lambda: _pool

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    uvicorn.run("dashboard.server:app", host=a.host, port=a.port, log_level="warning")
