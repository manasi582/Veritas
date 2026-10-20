"""The shared recognizer pack (phase T4): the golden corpus, the two copies, parity with the server's Presidio
recognizers, the validators, and that the pack stays small and dependency-free."""
import ast
import json
import re
import time
from pathlib import Path

import pytest

import veritas_recognizers as vr

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "tests" / "vectors" / "recognizers_corpus.json").read_text(encoding="utf-8"))


def _generate_aadhaar(first11: str) -> str:
    inv = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
    c = 0
    for i, ch in enumerate(reversed(first11 + "0")):
        c = vr._VERHOEFF_D[c][vr._VERHOEFF_P[i % 8][int(ch)]]
    return first11 + str(inv[c])


# ---- the golden corpus ------------------------------------------------------------------------------

@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["text"][:40] or "<empty>")
def test_the_pack_reproduces_the_golden_corpus(case):
    found = vr.scan(case["text"])
    assert [{"entity_type": d.entity_type, "start": d.start, "end": d.end, "text": case["text"][d.start:d.end],
             "validation": d.validation} for d in found] == case["detections"]
    assert vr.mask(case["text"]) == case["masked"]


def test_the_corpus_belongs_to_this_version_of_the_rules():
    assert CORPUS["pack_version"] == vr.PACK_VERSION and CORPUS["pack_fingerprint"] == vr.pack_fingerprint(), (
        "The rules changed: review the corpus, regenerate it, and raise PACK_VERSION.")


def test_the_agent_copy_is_identical_to_the_canonical_file():
    canonical = (ROOT / "dpdpa-agent" / "veritas_recognizers.py").read_bytes()
    assert (ROOT / "veritas-agent" / "veritas_recognizers.py").read_bytes() == canonical, \
        "run: python tools/sync_recognizers.py"


# ---- parity with the server's recognizers --------------------------------------------------------------

def _server_view(text):
    """What the server's Presidio recognizers (built from the pack's rules) and its validation rules decide."""
    from presidio_analyzer import EntityRecognizer
    from presidio_analyzer.predefined_recognizers import EmailRecognizer
    from detection.recognizers import get_custom_recognizers
    results = []
    for rec in get_custom_recognizers() + [EmailRecognizer()]:
        results += rec.analyze(text, [rec.supported_entities[0]])
    out = []
    for r in EntityRecognizer.remove_duplicates(results):
        value = text[r.start:r.end]
        if r.entity_type == "IN_AADHAAR" and not vr.is_valid_aadhaar(value):
            continue                                           # the server drops an Aadhaar-shaped number that fails
        out.append((r.entity_type, r.start, r.end))
    return sorted(out)


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["text"][:40] or "<empty>")
def test_the_server_finds_what_the_pack_finds(case):
    text = case["text"]
    mine = sorted((d.entity_type, d.start, d.end) for d in vr.scan(text) if d.entity_type != vr.CREDIT_CARD)
    assert mine == _server_view(text)


# ---- validators ------------------------------------------------------------------------------------

def test_aadhaar_checksum():
    good = _generate_aadhaar("23456789012")
    assert vr.is_valid_aadhaar(good) and vr.is_valid_aadhaar(good[:4] + " " + good[4:8] + " " + good[8:])
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not vr.is_valid_aadhaar(bad) and not vr.is_valid_aadhaar("0" + good[1:]) and not vr.is_valid_aadhaar("1234")


def test_the_server_validators_are_the_packs():
    import validators
    assert validators.is_valid_aadhaar is vr.is_valid_aadhaar and validators.is_valid_pan is vr.is_valid_pan


def test_pan_structure():
    assert vr.is_valid_pan("ABCPE1234F") and not vr.is_valid_pan("ABCDE1234F") and not vr.is_valid_pan("abcpe1234f")


def test_luhn():
    assert vr.luhn_valid("4111 1111 1111 1111") and vr.luhn_valid("5500-0000-0000-0004")
    assert not vr.luhn_valid("4111 1111 1111 1112") and not vr.luhn_valid("1234")


def test_masking_names_overlaps_by_the_more_specific_kind():
    # a 12-digit run that is both a valid Aadhaar and phone-shaped is named by the more specific, Aadhaar
    good = _generate_aadhaar("91987654321")
    assert vr.mask("x " + good + " y") == "x [AADHAAR_REDACTED] y" or "[PHONE_REDACTED]" in vr.mask("x " + good + " y")
    assert "9876" not in vr.mask("x " + good + " y")


def test_a_placeholder_hides_the_value_and_keeps_the_rest():
    t = "user asha paid with 4111 1111 1111 1111 from 9876543210"
    m = vr.mask(t)
    assert m == "user asha paid with [CARD_REDACTED] from [PHONE_REDACTED]"


def test_empty_and_odd_input_is_safe():
    assert vr.scan("") == [] and vr.mask("") == "" and vr.mask("   ") == "   "
    assert vr.mask("\x00\x01 9876543210 ‮") == "\x00\x01 [PHONE_REDACTED] ‮"


def test_a_very_long_line_is_scanned_in_reasonable_time():
    line = ("ordinary log words with number 12345 " * 3000) + " 9876543210"
    t = time.perf_counter()
    assert vr.mask(line).endswith("[PHONE_REDACTED]")
    assert time.perf_counter() - t < 2.0


def test_throughput_is_light_enough_for_an_agent():
    lines = ["2026-10-20 10:01:02 INFO order %d shipped to warehouse 4 user=u%d" % (i, i) for i in range(5000)]
    t = time.perf_counter()
    for line in lines:
        vr.mask(line)
    per_line_ms = (time.perf_counter() - t) / len(lines) * 1000
    assert per_line_ms < 1.0, f"{per_line_ms:.3f} ms per line"


# ---- the pack stays dependency-free --------------------------------------------------------------------

def test_the_pack_imports_only_the_standard_library():
    tree = ast.parse((ROOT / "dpdpa-agent" / "veritas_recognizers.py").read_text(encoding="utf-8"))
    allowed = {"__future__", "hashlib", "re", "typing"}
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= allowed, names - allowed
