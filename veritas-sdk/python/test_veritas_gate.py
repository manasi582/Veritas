"""The pipeline gate (phase C): fails on personal data in examples, passes clean ones, never prints a raw value."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import veritas_gate as gate  # noqa: E402

PHONE, AADHAAR, EMAIL = "9876543210", "2345 6789 0124", "asha.rao@example.com"


def spec(example):
    return {"openapi": "3.0.0", "paths": {"/customers/{id}": {"get": {"responses": {"200": {"content": {"application/json": {
        "schema": {"type": "object", "properties": {"phone": {"type": "string", "example": example}}}, "example": {"user": {"phone": example}}}}}}}}}}


def run(tmp_path, document, *args, capsys=None):
    f = tmp_path / "openapi.json"
    f.write_text(json.dumps(document))
    return gate.main([str(f), *args])


def test_a_spec_with_a_real_looking_number_fails_the_build_and_shows_it_masked(tmp_path, capsys):
    assert run(tmp_path, spec(PHONE)) == 1
    out = capsys.readouterr().out
    assert "FOUND phone" in out and "[PHONE_REDACTED]" in out and PHONE not in out


def test_a_clean_spec_passes(tmp_path, capsys):
    assert run(tmp_path, spec("98XXXXXXXX")) == 0 and "0 personal-data" in capsys.readouterr().out


def test_only_examples_are_read_not_descriptions_or_paths(tmp_path):
    doc = spec("98XXXXXXXX")
    doc["info"] = {"description": f"call {PHONE} for support"}
    doc["paths"]["/customers/{id}"]["get"]["summary"] = AADHAAR
    assert run(tmp_path, doc) == 0


def test_allowed_kinds_are_let_through(tmp_path):
    real = "asha.rao@gmail.com"                  # not a reserved example domain: example.com is a placeholder and is not flagged
    assert run(tmp_path, spec(real)) == 1
    assert run(tmp_path, spec(real), "--allow", "email") == 0


def test_a_folder_of_sample_payloads_is_read_whole(tmp_path, capsys):
    d = tmp_path / "payloads"
    d.mkdir()
    (d / "a.json").write_text(json.dumps({"user": {"aadhaar": AADHAAR}}))
    (d / "b.json").write_text(json.dumps({"ok": 1}))
    assert gate.main(["--payloads", str(d)]) == 1
    out = capsys.readouterr().out
    assert "a.json" in out and "2345" not in out


def test_an_unreadable_file_is_reported_and_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert gate.main([str(bad)]) == 2
    assert "COULD NOT READ" in capsys.readouterr().err


def test_json_output(tmp_path, capsys):
    assert run(tmp_path, spec(PHONE), "--json") == 1
    out = json.loads(capsys.readouterr().out)
    assert out["findings"] and all(PHONE not in json.dumps(f) for f in out["findings"])


def test_examples_maps_in_openapi_3_are_read(tmp_path):
    doc = {"paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {"examples": {"a": {"value": {"mobile": PHONE}}}}}}}}}}
    assert run(tmp_path, doc) == 1


# ---- migrations against the policy (feature 2) ------------------------------------------------------------------

POLICY = {"org_id": "acme", "fields": [
    {"field_name": "phone", "pii_category": "phone", "source_system": "orders-db", "declared_purpose": "delivery", "consent_scope": "x"}]}


def migrate(tmp_path, *sql, policy=POLICY, extra=()):
    d = tmp_path / "migrations"
    d.mkdir(exist_ok=True)
    for i, text in enumerate(sql, 1):
        (d / f"{i:03d}.sql").write_text(text)
    pf = tmp_path / "policy.json"
    pf.write_text(json.dumps(policy))
    return gate.main(["--migrations", str(d), "--policy", str(pf), *extra])


def test_a_new_personal_column_the_policy_does_not_declare_fails(tmp_path, capsys):
    assert migrate(tmp_path, "CREATE TABLE users (id int, phone text);", "ALTER TABLE users ADD COLUMN aadhaar_number text;") == 1
    out = capsys.readouterr().out
    assert "UNDECLARED aadhaar" in out and "users.aadhaar_number" in out and "001.sql" not in out.split("aadhaar_number")[1][:60]


def test_declared_columns_and_harmless_ones_pass(tmp_path, capsys):
    assert migrate(tmp_path, "CREATE TABLE users (id int, phone text, created_at timestamp);") == 0


def test_a_column_added_then_dropped_does_not_count(tmp_path):
    assert migrate(tmp_path, "ALTER TABLE users ADD COLUMN pan_number text;", "ALTER TABLE users DROP COLUMN pan_number;") == 0


def test_a_rename_to_a_personal_name_is_caught_and_a_dropped_table_clears_its_columns(tmp_path, capsys):
    assert migrate(tmp_path, "CREATE TABLE t (id int, ref text);", "ALTER TABLE t RENAME COLUMN ref TO email;") == 1
    assert migrate(tmp_path, "CREATE TABLE t (id int, email text);", "DROP TABLE t;") == 0


def test_schema_hints_can_say_a_column_is_not_personal(tmp_path):
    pol = {**POLICY, "schema_hints": {"contact_*": "none"}}
    assert migrate(tmp_path, "CREATE TABLE t (contact_person_id int);", policy=pol) == 0


def test_the_system_option_limits_which_declarations_count(tmp_path):
    assert migrate(tmp_path, "CREATE TABLE users (phone text);", extra=("--system", "billing-db")) == 1
    assert migrate(tmp_path, "CREATE TABLE users (phone text);", extra=("--system", "orders-db")) == 0


def test_missing_policy_or_files_is_a_usage_error_not_a_pass(tmp_path):
    assert gate.main(["--migrations", str(tmp_path)]) == 2
    pf = tmp_path / "p.json"
    pf.write_text(json.dumps(POLICY))
    assert gate.main(["--migrations", str(tmp_path / "nothing"), "--policy", str(pf)]) == 2


# ---- placeholders and wording (found in the Mac test) ----------------------------------------------------------

def test_an_example_dot_com_address_is_a_placeholder_but_a_real_domain_is_not(tmp_path, capsys):
    for placeholder in ("user@example.com", "a.b@mail.example.org", "dev@host.test", "x@corp.example"):
        doc = {"paths": {"/a": {"get": {"responses": {"200": {"content": {"application/json": {"example": {"email": placeholder}}}}}}}}}
        assert run(tmp_path, doc) == 0, placeholder
    spec_ok = {"paths": {"/a": {"get": {"responses": {"200": {"content": {"application/json": {"example": {"email": "user@example.com"}}}}}}}}}
    assert run(tmp_path, spec_ok) == 0
    spec_bad = {"paths": {"/a": {"get": {"responses": {"200": {"content": {"application/json": {"example": {"email": "asha.rao@gmail.com"}}}}}}}}}
    assert run(tmp_path, spec_bad) == 1
    assert "asha.rao@gmail.com" not in capsys.readouterr().out


def test_the_summary_says_columns_for_undeclared_columns(tmp_path, capsys):
    migrate(tmp_path, "ALTER TABLE users ADD COLUMN passport_number text;")
    out = capsys.readouterr().out
    assert "0 personal-data value(s) found, 1 undeclared personal-data column(s)" in out
