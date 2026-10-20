#!/usr/bin/env python3
"""
Writes the sample log files for the pitch demo (docs/DEMO.md). Invented data only: the numbers are made-up and the
Aadhaar number is a published test number.

    python tools/demo_logs.py /tmp/demo-logs [--lines 12000]

Produces, in that folder:
  noisy-service.log      12,000 near-identical lines with changing numbers and ids (one debug statement, nine kinds of line)
  order-service.log      a few order lines with a customer's phone number
  support-ticketing.log  support lines with phone, Aadhaar and e-mail (for an agent that masks)
  marketing-service.log  a line where an e-mail address reaches a system that does not declare it
  recurrence.log         one more noisy line, to append after an incident is resolved
  resurrection.log       the same phone number, written differently, to append after an erasure request closes
"""
import argparse
import random
import sys
import uuid
from pathlib import Path

PHONE, AADHAAR = "9876543210", "2345 6789 0124"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--lines", type=int, default=12000)
    a = ap.parse_args()
    out = Path(a.folder)
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)
    kinds = [
        "debug cache refresh for tenant {n} took {n} ms trace {u} customer phone {p}",
        "warn retry {n} of 5 for session {u} customer phone {p}",
        "error payment worker {n} lost connection after {n} ms customer phone {p}",
        "info reconcile batch {n} finished in {n} ms customer phone {p}",
        "debug address lookup {n} returned in {n} ms for {p}",
        "warn queue depth {n} above {n} for {p}",
        "info webhook {u} delivered in {n} ms to {p}",
        "error inventory sync {n} timed out after {n} ms {p}",
        "debug session {u} refreshed for {p}",
    ]
    with open(out / "noisy-service.log", "w") as f:
        for i in range(a.lines):
            n = rng.randint(1, 99999)
            f.write("2026-10-20 10:%02d:%02d %s\n" % (i // 200 % 60, i % 60,
                    kinds[i % len(kinds)].format(n=n, u=uuid.UUID(int=rng.getrandbits(128)), p=PHONE)))
    (out / "order-service.log").write_text("".join(
        f"2026-10-20 10:00:{i:02d} INFO order {1000 + i} confirmation sent to {PHONE}\n" for i in range(3)))
    (out / "support-ticketing.log").write_text(
        f"2026-10-20 10:05:01 INFO ticket 5001 callback to {PHONE} aadhaar {AADHAAR} mail asha.rao@example.com done\n"
        f"2026-10-20 10:05:07 INFO ticket 5002 callback to {PHONE} closed\n")
    (out / "marketing-service.log").write_text("2026-10-20 10:10:00 INFO newsletter signup for kiran.patel@example.com from the web form\n")
    (out / "recurrence.log").write_text("2026-10-20 12:00:00 debug cache refresh for tenant 424242 took 31 ms trace %s customer phone %s\n" % (uuid.uuid4(), PHONE))
    (out / "resurrection.log").write_text(f"2026-10-20 13:00:00 INFO newsletter signup for +91 {PHONE} from the web form\n")
    print("wrote", ", ".join(sorted(p.name for p in out.iterdir())))


if __name__ == "__main__":
    sys.exit(main())
