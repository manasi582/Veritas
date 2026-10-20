# Schema Watch: database schema changes

A developer adds `ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12)`. Within seconds Veritas says: *a new column that looks like Aadhaar data was added in `loan-db`, and the policy does not declare that kind of data there.* It becomes a finding with an owner, an incident, and an entry on the Data map.

Veritas reads the **structure** of database changes, never the data. It cannot know whether a column really holds personal data; it guesses from the column's name, and you can correct the guess in the policy.

## How it works

1. The database writes its schema statements to a log (below), or you point the agent at a file of migrations.
2. The agent's `db_schema_log` source keeps **only whole `CREATE TABLE`, `ALTER TABLE` and `DROP TABLE` statements**, joining a statement that spans several lines. Every other line (`INSERT`, `UPDATE`, `SELECT`, connections), which could carry values, is dropped on the host and never sent.
3. The server parses the statement (PostgreSQL and MySQL syntax, quoting, schema prefixes, comments), classifies each column name (phone, e-mail, Aadhaar, PAN, card, name, date of birth, address, account, passport, voter id, UPI), and compares it with the policy for that system:

| Result | Meaning |
|---|---|
| **declared by name** | the policy has a field with that column's name (or `table.column`) for this system: quiet |
| **declared by category** | the policy declares that *kind* of data for this system under another field name: quiet, shown in the list |
| **undeclared** | the policy does not declare that kind of data for this system: a `PURPOSE_001` finding (HIGH for Aadhaar, PAN, card, passport and voter id; MEDIUM otherwise) |
| **dropped** | the column or table was removed: recorded, no finding |

A change of a column's type is recorded but is not new data. The same statement repeated is counted, and grouped into one incident (the finding names the table and column).

## Setting it up

Agent configuration (`/etc/veritas-agent/config.yaml`):

```yaml
sources:
  - type: db_schema_log
    path: /var/log/postgresql/postgresql-16-main.log
    source_system: loan-db            # the name your policy and owners use for this system
```

**PostgreSQL.** In `postgresql.conf`: `logging_collector = on`, `log_statement = 'ddl'` (this logs schema statements only, not queries), then reload. The agent's account needs read access to the log (on Ubuntu: add `veritas-agent` to the `adm` group, or `postgres`'s log group). With the pgaudit extension, `pgaudit.log = 'ddl'` also works: the statement appears inside the audit line.

**MySQL and MariaDB.** Use an audit plugin set to log DDL only (MariaDB `server_audit` with `server_audit_events=QUERY_DDL`; Percona or MySQL Enterprise audit with a DDL filter). Do **not** turn on the general query log for this: it writes every query, values included, to disk on the database host (Veritas would drop those lines on the host, but they would be on disk).

**Migration files.** Point the source at a file the migration tool appends to or a concatenated SQL file; each statement is read once as it appears.

**Correcting the guess.** In the policy (organization config):

```yaml
schema_hints:
  col_7: phone          # a column named col_7 holds phone numbers
  "*_ref": account      # every column ending in _ref is an account reference
  "phone_ext*": none    # these are not personal data
```

## What you see

- **Findings** (`PURPOSE_001`, explained as a database change) in the Audit Ledger and incidents, with the system's owner.
- **Data map:** the system shows the kind of data, marked as seen through a schema statement.
- **Data map page, "Database schema changes":** every classified change per system with its policy status, times seen and last seen.
- **API:** `GET /v1/{org}/schema` (any role of the organization).

## Limits, said plainly

- It sees *structure, not data*, and guesses from names: `col_7` is missed, and a harmless column may be taken for personal data. Use `schema_hints`.
- Statements that do not reach the log are invisible: an ORM using a connection that is not logged, changes made on a replica, or a log level that omits DDL.
- Statements it cannot read (unusual dialect features) are **counted** as unrecognised per system, so gaps are visible rather than silent.
- Only PostgreSQL and MySQL/MariaDB syntax is understood today.
- It never changes the database.
