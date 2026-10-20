# Pipeline gate: privacy as a build check

Veritas can stop a change **before it ships**. `veritas-sdk/python/veritas_gate.py` runs in a pull request, needs no server and no network, and exits 1 when it finds a problem.

## What it checks

| Check | Command | Fails when |
|---|---|---|
| Personal data in API examples | `python veritas_gate.py openapi.yaml` | an `example`, `examples`, `default` or `enum` value looks like Aadhaar, PAN, phone, e-mail or a card number |
| Sample payloads | `python veritas_gate.py --payloads tests/fixtures/` | a sample JSON file holds such a value |
| **Migrations against the policy** | `python veritas_gate.py --migrations db/migrations --policy veritas-policy.yaml --system orders-db` | a migration leaves a column whose name suggests personal data and the policy does not declare it |

Values are shown masked, never as written. The migration check applies the files in name order and judges the columns that remain, so a column added and later dropped, or a table dropped, does not count. It reads PostgreSQL and MySQL DDL the same way the server's Schema Watch does ([SCHEMA_WATCH.md](SCHEMA_WATCH.md)), and uses the same test for "declared" (by field name, or by category). `schema_hints` in the policy corrects a wrong guess.

The policy file is the organization's Veritas policy (an object with a `fields` list), exported from the dashboard or kept in the repository.

## In GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: shreyaaassss/Veritas/veritas-sdk/github@main      # pin a tag once releases carry it
  with:
    migrations: db/migrations
    policy: veritas-policy.yaml
    system: orders-db
    openapi: openapi.yaml
```

Any other CI runs the Python script directly (it needs `pyyaml` only for YAML files).

## What it does not do

- It guesses a column's kind from its **name**. A column called `col_7` passes; a harmless column named `phone_model` may be flagged (correct it in `schema_hints`).
- It reads SQL migration files, not ORM models.
- It does not find names in payloads.
- It checks the declaration, not whether the purpose is lawful.

## Tests

`veritas-sdk/python/test_veritas_gate.py`; the DDL copies are checked identical to the server's by `dpdpa-agent/test_recognizers.py` (`python tools/sync_recognizers.py` refreshes them).
