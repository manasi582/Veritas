# Streaming receivers: OpenTelemetry and syslog

Not every system writes a log file. Two more ways in, both judged by the same detection, rules, incidents, data map and lookup as a file line:

## OpenTelemetry logs (OTLP over HTTP, JSON)

Point an OpenTelemetry exporter, or a Collector's `otlphttp` exporter, at the server:

```
POST https://veritas.example.org:8000/v1/<org>/otlp/logs
Authorization: Bearer <an agent's token>        (Agents, Issue Registration Key, then register it like an agent)
Content-Type: application/json
```

Each log record becomes an event as if an agent had sent that line: the resource's `service.name` is the **source system** (it must match the name your policy and owners use; without it the system is called `otlp`), the record's body is the line, and its string attributes are the fields (`user.phone` is judged as the declared field `phone`). The time is the record's timestamp. The data map marks the data as seen through OpenTelemetry.

- **JSON only.** OTLP over protobuf is refused with HTTP 415 and a message; configure the exporter's JSON encoding (`encoding: json` in the Collector's `otlphttp` exporter).
- Limits: 1 MB and 500 records per request (the answer is 413 above them). A record with no body and no usable attributes is rejected; the response is OTLP's `partialSuccess` with the number rejected.
- A busy server answers 503 with `Retry-After`, which exporters retry.
- Send **already-masked** text if you do not want Veritas to see raw values: there is no agent in this path to mask for you. A Collector processor can redact attributes before export.

## Syslog

The agent can listen for syslog from devices and software that cannot write files (network equipment, appliances, Docker's syslog driver):

```yaml
sources:
  - type: syslog
    source_system: edge-gateway
    port: 5140
    protocol: udp          # or tcp
    host: 127.0.0.1        # the default; use 0.0.0.0 only if other machines must send to it
```

It accepts RFC 3164 and RFC 5424 messages over UDP (one or more lines per datagram) and over TCP (newline-separated, and RFC 6587 octet-counted frames), cuts a message at 8 KB, and queues each as a log line for the named source system. Redaction settings of the agent apply to these lines exactly as to file lines.

- **No authentication.** The agent cannot tell who sent a syslog message. Keep it on loopback, or on a network segment you trust, or put the agent on the machine that receives the syslog stream.
- Ports below 1024 (the usual 514) need the agent to run with the right to bind them; the examples use 5140.
- UDP gives no delivery guarantee, which is a property of UDP; use TCP where loss matters.

## Limits, said plainly

- Both feeds are only as good as what is sent: structured detection works on the text of the record, and names are found by the server's language model as for any line.
- OTLP metrics and traces are not read; only logs.
