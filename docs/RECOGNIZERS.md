# The recognizer pack

One small file, `veritas_recognizers.py`, holds the rules that find *structured* personal data in text. The server and the agent use the same rules, so a line the agent masks is masked the way the server would have masked it.

| Finds | How | Notes |
|---|---|---|
| Aadhaar | 12 digits (spaced `XXXX XXXX XXXX` or run together) with the **Verhoeff checksum** | A number that fails the checksum is not reported |
| PAN | 5 letters, 4 digits, 1 letter; the 4th letter must be a holder type | A string of that shape that fails the structure check is still reported, marked "failed" (the server does the same) |
| Indian mobile | 10 digits starting 6 to 9, with or without `+91` / `91` | |
| E-mail | a standard address pattern with a plausible ending | |
| Payment card | 13 to 19 digits, spaces or hyphens allowed, **Luhn check** | Found by the pack and the agent; the server's own detection does not look for cards yet |

**Not found:** names, addresses, and anything that needs context or a language model. That stays on the server. Regular expressions with checks cannot see these, so a line masked in the agent can still hold a name.

## Why one file

- The server builds its Presidio recognizers **from** `veritas_recognizers.RULES` (patterns, scores, context words) and imports its Aadhaar and PAN validators from it. Nothing is written twice.
- The agent ships the identical file next to `agent.py` (Ubuntu package, Mac package, container). It is standard library only, so the agent stays light: about 0.1 ms per ordinary log line on a laptop (a test fails above 1 ms).
- `tests/vectors/recognizers_corpus.json` is the golden corpus: texts with the findings and the masked result they must produce. The server's tests check that its Presidio recognizers find the same things in each text, and the agent's tests check its copy produces the masked results.

## Changing a rule

1. Edit `dpdpa-agent/veritas_recognizers.py` (the canonical copy).
2. Run `python tools/sync_recognizers.py` to copy it to `veritas-agent/`.
3. Regenerate the corpus after reviewing the differences, and raise `PACK_VERSION`.

A test fails if the two copies differ, or if the corpus does not belong to the rules (the pack has a short fingerprint, `pack_fingerprint()`, that the agent will report to the server so a mismatch can be shown).

## Change in this release

The phone rule no longer leaves the `+` of `+91` outside the match (`+91 9876543210` is masked as one number).
