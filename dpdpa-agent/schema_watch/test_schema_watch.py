"""Schema Watch (phase B): the DDL parser, the column classifier, and the comparison with the policy."""
import pytest

from schema_watch import classify, evaluate, parser
from schema_watch.parser import ADD, ALTER_TYPE, DROP, DROP_TABLE, RENAME, Change, parse

P = Change


# ---- parser -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sql,expected", [
    ("ALTER TABLE customers ADD COLUMN mobile_no TEXT NOT NULL DEFAULT ''", [P(ADD, "customers", "mobile_no", "TEXT")]),
    ("alter table customers add mobile_no text", [P(ADD, "customers", "mobile_no", "text")]),
    ('ALTER TABLE public."Customers" ADD COLUMN IF NOT EXISTS "Email Id" varchar(200)', [P(ADD, "Customers", "Email Id", "varchar(200)")]),
    ("ALTER TABLE `shop`.`orders` ADD COLUMN `phone` varchar(15) AFTER id", [P(ADD, "orders", "phone", "varchar(15)")]),
    ("ALTER TABLE [dbo].[Users] ADD [Mobile] varchar(15)", [P(ADD, "Users", "Mobile", "varchar(15)")]),
    ("ALTER TABLE ONLY users ADD COLUMN phone_number text;", [P(ADD, "users", "phone_number", "text")]),
    ("ALTER TABLE t DROP COLUMN old_col", [P(DROP, "t", "old_col")]),
    ("ALTER TABLE t DROP old_col", [P(DROP, "t", "old_col")]),
    ("ALTER TABLE t DROP COLUMN IF EXISTS \"Old\"", [P(DROP, "t", "Old")]),
    ("ALTER TABLE t RENAME COLUMN phone TO contact_no", [P(RENAME, "t", "phone", None, "contact_no")]),
    ("ALTER TABLE t ALTER COLUMN phone TYPE bigint USING phone::bigint", [P(ALTER_TYPE, "t", "phone", "bigint")]),
    ("ALTER TABLE t ALTER COLUMN phone SET DATA TYPE varchar(20)", [P(ALTER_TYPE, "t", "phone", "varchar(20)")]),
    ("ALTER TABLE t MODIFY mobile varchar(15) NOT NULL", [P(ALTER_TYPE, "t", "mobile", "varchar(15)")]),
    ("ALTER TABLE t CHANGE addr address text", [P(RENAME, "t", "addr", "text", "address")]),
    ("ALTER TABLE t ADD COLUMN a int, ADD COLUMN b text, DROP COLUMN c",
     [P(ADD, "t", "a", "int"), P(ADD, "t", "b", "text"), P(DROP, "t", "c")]),
    ("DROP TABLE IF EXISTS a.b, c", [P(DROP_TABLE, "b", None), P(DROP_TABLE, "c", None)]),
    ("CREATE TABLE t (id serial PRIMARY KEY, aadhaar_no varchar(12) NOT NULL, dob date, CONSTRAINT u UNIQUE (id))",
     [P(ADD, "t", "id", "serial"), P(ADD, "t", "aadhaar_no", "varchar(12)"), P(ADD, "t", "dob", "date")]),
    ("CREATE TABLE IF NOT EXISTS `x` (`a` int(11) NOT NULL AUTO_INCREMENT, `b` decimal(10,2) DEFAULT 0, PRIMARY KEY (`a`), KEY k (`b`))",
     [P(ADD, "x", "a", "int(11)"), P(ADD, "x", "b", "decimal(10,2)")]),
    ("CREATE TEMP TABLE scratch (v text)", [P(ADD, "scratch", "v", "text")]),
    ("CREATE UNLOGGED TABLE s (v numeric(5, 2) CHECK (v > 0))", [P(ADD, "s", "v", "numeric(5, 2)")]),
    ("2026-10-20 10:00:00 UTC LOG:  statement: ALTER TABLE users ADD COLUMN phone text; -- by migration 12",
     [P(ADD, "users", "phone", "text")]),
    ("ALTER TABLE a /* the phone */ ADD COLUMN x int", [P(ADD, "a", "x", "int")]),
    ("ALTER TABLE a ADD COLUMN x int -- trailing\n, ADD COLUMN y int", [P(ADD, "a", "x", "int"), P(ADD, "a", "y", "int")]),
    ("ALTER   TABLE\n  multi\n  ADD COLUMN\n  line_col   text", [P(ADD, "multi", "line_col", "text")]),
    ("ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES b(id)", []),
    ("ALTER TABLE t ADD PRIMARY KEY (id)", []),
    ("ALTER TABLE t DROP CONSTRAINT fk", []),
    ("ALTER TABLE t DROP INDEX idx", []),
    ("CREATE INDEX i ON t (phone)", []),
    ("INSERT INTO users (phone) VALUES ('9876543210')", []),
    ("UPDATE users SET phone = '9876543210'", []),
    ("SELECT * FROM customers WHERE phone = '9876543210'", []),
    ("COPY users FROM stdin", []),
    ("", []), (None, []), ("not sql at all", []),
])
def test_the_parser_reads_ddl_and_nothing_else(sql, expected):
    assert parse(sql) == expected


def test_the_parser_survives_hostile_input():
    for text in ["ALTER TABLE " + "(" * 5000, "CREATE TABLE t (" + "a int," * 20000, "ALTER TABLE " + '"' * 3000,
                 "ALTER TABLE t ADD COLUMN " + "x" * 100000, "CREATE TABLE t (((((((((", "\x00\x01 ALTER TABLE t ADD COLUMN \udcff x int"]:
        parse(text)                                                       # must return, not hang or raise


def test_a_value_in_a_statement_is_never_returned():
    out = parse("ALTER TABLE t ADD COLUMN note text DEFAULT '9876543210'")
    assert out == [P(ADD, "t", "note", "text")] and "9876543210" not in repr(out)


# ---- classifier ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("column,kind", [
    ("mobile_no", "phone"), ("Phone", "phone"), ("customerPhoneNumber", "phone"), ("msisdn", "phone"), ("contact_no", "phone"),
    ("aadhaar_no", "aadhaar"), ("AadharNumber", "aadhaar"), ("uidai_ref", "aadhaar"),
    ("pan", "pan"), ("pan_number", "pan"), ("PAN_NO", "pan"),
    ("email", "email"), ("email_id", "email"), ("contactEmail", "email"), ("e_mail", "email"),
    ("dob", "dob"), ("date_of_birth", "dob"), ("birthdate", "dob"),
    ("home_address", "address"), ("pincode", "address"), ("zip_code", "address"),
    ("card_number", "card"), ("cvv", "card"), ("cc_number", "card"),
    ("account_number", "account"), ("iban", "account"),
    ("first_name", "name"), ("fullName", "name"), ("customer_name", "name"), ("surname", "name"),
    ("passport_no", "passport"), ("voter_id", "voter"), ("upi_id", "upi"), ("vpa", "upi"),
])
def test_columns_that_suggest_personal_data(column, kind):
    assert classify.category_of(column) == kind


@pytest.mark.parametrize("column", ["id", "created_at", "order_amount", "product_name", "name", "panel", "company", "ip_address",
                                    "mac_address", "wallet_address", "col_7", "status", "pantry", "mobility", "username_hash", ""])
def test_columns_that_do_not(column):
    assert classify.category_of(column) is None


def test_the_policy_can_correct_the_guess():
    assert classify.category_of("col_7", {"col_7": "phone"}) == "phone"
    assert classify.category_of("phone_ext", {"phone*": "none"}) is None
    assert classify.category_of("legacy_ref", {"*_ref": "account"}) == "account"
    assert classify.category_of("Mobile", {"mobile": "none"}) is None            # case does not matter


# ---- evaluation against the policy ---------------------------------------------------------------------------

class Event:
    def __init__(self, text, system="loan-service"):
        import uuid
        from schemas.models import SourceType
        self.raw_snippet, self.source_system, self.event_id, self.source_type = text, system, uuid.uuid4(), SourceType.LOG


def cfg(**extra):
    from org_config.schema import OrgConfig
    return OrgConfig.model_validate({"org_id": "sw_org", "fields": [
        {"field_name": "phone", "pii_category": "phone", "declared_purpose": "calls", "consent_scope": "c", "retention_days": 30, "source_system": "loan-service"},
        {"field_name": "customers.email", "pii_category": "email", "declared_purpose": "receipts", "consent_scope": "c", "retention_days": 30, "source_system": "loan-service"},
        {"field_name": "pan", "pii_category": "pan", "declared_purpose": "kyc", "consent_scope": "c", "retention_days": 30, "source_system": "kyc-service"},
    ], **extra})


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("VERITAS_DATA_DIR", str(tmp_path / "data"))
    from evidence_store.store import EvidenceStore
    s = EvidenceStore(tmp_path / "e.db")
    yield s
    s.close()


def run(store, text, system="loan-service", **cfg_extra):
    return evaluate.evaluate(store, "sw_org", Event(text, system), cfg(**cfg_extra))


def status_of(store, column):
    return [r["status"] for r in evaluate.listing(store, "sw_org")["changes"] if r["column_name"] == column]


def test_an_undeclared_personal_data_column_is_a_finding(store):
    v = run(store, "ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12)")
    assert len(v) == 1 and v[0].rule_id.value == "PURPOSE_001" and v[0].severity.value == "HIGH"
    assert v[0].field == "customers.aadhaar_no" and v[0].matched_registry_entry["category"] == "aadhaar"
    assert status_of(store, "aadhaar_no") == ["undeclared"]


def test_a_column_declared_by_name_or_by_category_is_quiet(store):
    assert run(store, "ALTER TABLE x ADD COLUMN phone text") == [] and status_of(store, "phone") == ["declared by name"]
    assert run(store, "ALTER TABLE customers ADD COLUMN email text") == [] and status_of(store, "email") == ["declared by name"]
    assert run(store, "ALTER TABLE x ADD COLUMN mobile_no text") == [] and status_of(store, "mobile_no") == ["declared by category"]


def test_the_same_column_in_another_system_is_judged_by_that_systems_policy(store):
    assert len(run(store, "ALTER TABLE x ADD COLUMN mobile_no text", system="kyc-service")) == 1


def test_a_column_that_does_not_look_personal_is_ignored_unless_the_policy_says_otherwise(store):
    assert run(store, "ALTER TABLE x ADD COLUMN order_total numeric") == []
    assert run(store, "ALTER TABLE x ADD COLUMN col_7 text") == []
    assert len(run(store, "ALTER TABLE x ADD COLUMN col_7 text", schema_hints={"col_7": "aadhaar"})) == 1
    assert run(store, "ALTER TABLE x ADD COLUMN dob_note text", schema_hints={"dob_*": "none"}) == []


def test_create_table_checks_every_column(store):
    v = run(store, "CREATE TABLE applicants (id int, dob date, home_address text, pan_no char(10), phone text)", system="loan-service")
    assert sorted(x.field for x in v) == ["applicants.dob", "applicants.home_address", "applicants.pan_no"]


def test_a_rename_to_a_personal_name_is_a_finding_and_a_drop_is_recorded(store):
    assert len(run(store, "ALTER TABLE t RENAME COLUMN ref TO email_address2", system="kyc-service")) == 1
    assert run(store, "ALTER TABLE t DROP COLUMN mobile_no") == [] and status_of(store, "mobile_no") == ["dropped"]
    assert run(store, "DROP TABLE old_customers") == []
    assert any(r["action"] == "DROP_TABLE" for r in evaluate.listing(store, "sw_org")["changes"])


def test_changing_a_columns_type_is_recorded_but_is_not_new_data(store):
    assert run(store, "ALTER TABLE t ALTER COLUMN aadhaar_no TYPE bigint") == []
    assert [r["action"] for r in evaluate.listing(store, "sw_org")["changes"]] == ["ALTER_TYPE"]


def test_repeats_are_counted_not_duplicated(store):
    for _ in range(3):
        run(store, "ALTER TABLE customers ADD COLUMN aadhaar_no text")
    rows = evaluate.listing(store, "sw_org")["changes"]
    assert len(rows) == 1 and rows[0]["count"] == 3


def test_the_kind_is_recorded_for_the_data_map(store):
    run(store, "ALTER TABLE customers ADD COLUMN aadhaar_no text")
    from evidence_store import flows
    rows = flows.rows(store, "sw_org")
    assert [(r["source_system"], r["field"], r["category"], r["source_kind"]) for r in rows] == \
        [("loan-service", "customers.aadhaar_no", "aadhaar", "schema")]


def test_statements_that_look_like_ddl_but_are_not_understood_are_counted(store):
    run(store, "CREATE TABLE")
    run(store, "ALTER TABLE users ADD COLUMN phone text")
    stats = evaluate.listing(store, "sw_org")["systems"][0]
    assert stats["statements"] == 2 and stats["unrecognised"] == 1


def test_the_statement_text_is_never_stored(store, tmp_path):
    run(store, "ALTER TABLE customers ADD COLUMN aadhaar_no text DEFAULT '2345 6789 0124' -- for 9876543210")
    store._conn.commit()
    import sqlite3
    store._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    blob = b"".join(p.read_bytes() for p in tmp_path.glob("e.db*"))
    assert b"2345 6789" not in blob and b"9876543210" not in blob and b"ALTER TABLE" not in blob


def test_policy_hints_are_validated():
    from org_config.schema import OrgConfig
    base = {"org_id": "sw_org", "fields": []}
    with pytest.raises(Exception):
        OrgConfig.model_validate({**base, "schema_hints": {"bad column!": "phone"}})
    with pytest.raises(Exception):
        OrgConfig.model_validate({**base, "schema_hints": {"col": "Not A Kind!"}})
    with pytest.raises(Exception):
        OrgConfig.model_validate({**base, "schema_hints": {f"c{i}": "phone" for i in range(201)}})
