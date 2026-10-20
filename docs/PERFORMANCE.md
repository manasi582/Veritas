# Performance of the trust, visibility and prevention features

Measured with `tools/bench_trust.py` (run it on your own hardware: `python tools/bench_trust.py`). The run below is one Apple-silicon laptop, 10 cores, Python 3.14, on 2026-10-20. Treat the numbers as an order of magnitude, not a promise: a server under load, a slow disk or a busy detection queue will be slower. What dominates real throughput is still language-model detection (about 90 to 300 events a second, see `OPERATIONS.md`), not any of the work below.

| Feature | What was measured | Result | Target in the design |
|---|---|---|---|
| Incident grouping | store 100,000 findings (300 different messages with numbers and ids changing on every line) | **300 incidents**, 3,900 findings/s stored with grouping on (6,400/s without, in an earlier run) | "a few hundred incidents" |
| | list the first 100 incidents / summary | 1 ms / 21 ms | |
| | verify the 100,000-record chain | 2.6 s | |
| Observed processing map | build the map and the record for 50 systems, 6,000 counter rows | **13 ms** (CSV 1 ms, 69 KB) | under 2 s |
| Identifier index | one lookup in an index of 200,000 tokens | **0.2 ms** | |
| | tokenise the identifiers of one event | under 1 µs when it holds none | |
| Recognizer pack | find and mask two values in a log line | 10 µs | |
| Payload tap (Python, ASGI) | extra time per request with every request inspected and reported (worst case), a 3 KB body with 80 items | **0.30 ms at the median, 0.35 ms at the 99th percentile** | under 1 ms |
| Schema watch | parse one DDL statement (an `ALTER TABLE` with two changes) | 10 µs | |
| Agent redaction | the agent's whole path per line (scan, mask or hash, count, queue-ready) | mask 11 µs, hash 14 µs | under 1.5 ms (test) |

## What these mean

- **Agent cost.** At 11 µs a line, redaction costs about 1% of one core per 1,000 lines a second, so a host logging 10,000 lines a second spends about a tenth of a core. Very long lines cost more, which is why a line limit exists (default 65,536 characters).
- **Grouping cost.** Grouping is three small writes per stored finding inside the same transaction. It does not change what limits ingest (detection).
- **Flow counters and the identifier index** are collected in memory and written in batches off the request path; reading them flushes first.

## What was not measured

- The detection step itself (language model), on which these numbers do not depend.
- The browser: a map of hundreds of systems is drawn as plain SVG and has not been tested for readability at that size.
- A database larger than the tested 100,000 findings and 200,000 index rows.

CI checks generous ceilings for the same operations (`dpdpa-agent/test_trust_performance.py`) so a change that makes them an order of magnitude slower fails the build.
