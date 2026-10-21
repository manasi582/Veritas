# Payload Tap: personal data in API requests and responses

An API returns a customer's Aadhaar number in a field nobody declared. A small library in the service sees it, **masks it inside the service's own process**, and tells Veritas: *the response of `GET /customers/{id}` carries Aadhaar data in `user.aadhaar_no`*. It becomes a finding with an owner, an incident, and an entry on the Data map. Veritas never receives the value.

There are libraries for **Python** (ASGI: FastAPI, Starlette; WSGI: Flask, Django) and **Node** (Express), plus a **pipeline gate** that fails a build when an API description contains personal data.

## What it does and does not do

- It looks only at **JSON** requests and responses up to a size limit (64 KB by default). Other content is not read.
- It finds Aadhaar (with its checksum), PAN, Indian mobile numbers, e-mail and payment cards, by the same rules as the server and the agent (the shared recognizer pack). **It does not find names.**
- It reports only fields that **hold** personal data: the field's path (`user.phone`; array positions are written `[]`, so `items[0].mobile` and `items[7].mobile` are one field), a placeholder (`[PHONE_REDACTED]`, or a keyed token in hash mode), the route template (`/customers/{id}`), the method, the status, and which direction (request or response).
- It **never delays, changes or fails a request.** Work happens after the response, on a background thread, with a bounded queue (a full queue drops the oldest report), a short timeout, and a circuit breaker that stops sending for a minute after repeated failures, or when the server says it is busy. The same route with the same fields is reported at most once every 5 seconds (configurable), and you can sample.
- **Masking comes first.** If masking fails for a body, that body is dropped, never sent. A test makes the network fail and checks that no raw value was ever handed to it.
- It only sees what passes through the middleware: traffic that bypasses it, encrypted or binary bodies, and streaming responses larger than the limit are invisible.

## How the server judges it

An event from the tap has `source_type: api`. Each reported field is judged by the policy **as the field it is**: `user.phone` is looked up as the declared field `phone` for that system. So a field the policy does not declare for that system is a `PURPOSE_001` finding; a declared field in a system that may hold it is quiet; a field in a system declared "de-identified only" is an exposure. The Data map shows the kind of data and that it was seen in an API. No value is ever stored.

## Python

Put the library next to your code (`veritas_tap.py` and `veritas_recognizers.py` from `veritas-sdk/python`; standard library only). Issue a registration key in the dashboard (Agents, Issue Registration Key), then:

```bash
# Veritas makes its own certificate by default. Save it once, then trust exactly that certificate:
python veritas_tap.py --url https://veritas.example.org:8000 --fetch-cert server.crt
python veritas_tap.py register --url https://veritas.example.org:8000 --key <the key> --ca-cert server.crt
# prints VERITAS_TAP_URL, VERITAS_TAP_TOKEN, VERITAS_TAP_ORG, VERITAS_TAP_CA_CERT; set VERITAS_TAP_SYSTEM yourself to the name your policy uses
```

(With a company certificate the system already trusts, leave out `--ca-cert`.) `--fetch-cert` reads the server's public certificate without checking it, then every later call trusts only that file, the same trust-on-first-use the agent uses. Compare it with the certificate shown by the server if you need to be certain.

```python
from veritas_tap import Tap, ASGIMiddleware, WSGIMiddleware

tap = Tap.from_env()
app.add_middleware(ASGIMiddleware, tap=tap)              # FastAPI / Starlette
# Flask / Django:  app.wsgi_app = WSGIMiddleware(app.wsgi_app, tap=tap)
```

## Node

Copy `veritas_tap.js` and `veritas_recognizers.js` from `veritas-sdk/node` (no dependencies; Node 18 or later). Register as above (the command is the Python one, or `curl` the `/agent/register` endpoint).

```js
const { Tap } = require('./veritas_tap');
const tap = Tap.fromEnv();
app.use(express.json());
app.use(tap.express());        // after the body parser
```

## Settings

| Environment variable | Meaning |
|---|---|
| `VERITAS_TAP_URL`, `VERITAS_TAP_TOKEN`, `VERITAS_TAP_ORG`, `VERITAS_TAP_SYSTEM` | the server, the token from registration, the organization, the system name used in the policy |
| `VERITAS_TAP_HASH_KEY` | optional: hex key from registration; switches to **hash mode** (keyed tokens instead of placeholders, so `Where was this identifier observed?` can find them) |
| `VERITAS_TAP_CA_CERT`, `VERITAS_TAP_VERIFY` | trust the server's certificate (Python) |

Constructor options: `sample_every`, `min_interval_seconds`, `max_body_bytes`, `queue_size`, `timeout`. Turn it off by not installing the middleware.

## The pipeline gate

```bash
python veritas_gate.py openapi.json                 # fails (exit 1) if any example holds personal data
python veritas_gate.py --payloads tests/fixtures/    # or a folder of sample payloads
python veritas_gate.py openapi.yaml --allow email    # allow a kind
```

It reads the `example`, `examples` and `default` values of an OpenAPI document (JSON, or YAML if PyYAML is installed) and any JSON files you point it at, with the same rules, offline and with no credentials. Values are shown masked. Example workflow step:

```yaml
- name: No personal data in API examples
  run: python veritas-sdk/python/veritas_gate.py openapi.json
```

## What it costs

Measured with every request inspected and reported (the worst case), the Python middleware adds about 0.3 ms to a request with a 3 KB body on a laptop (`docs/PERFORMANCE.md`); CI fails it above 3 ms. The libraries use no threads beyond one background sender.

## Limits, said plainly

- Names are not found. A field the rules cannot recognise as an identifier is not reported.
- It needs installing in each service (one line). Traffic that does not pass through it is not seen.
- Sampling and the report interval mean the counts on the Data map are indications, not exact request counts.
- It reports what it saw in the request or response; it cannot tell whether the data should have been there (that is what the policy is for).
