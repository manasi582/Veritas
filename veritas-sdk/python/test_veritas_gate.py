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
    assert run(tmp_path, spec(EMAIL)) == 1
    assert run(tmp_path, spec(EMAIL), "--allow", "email") == 0


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
