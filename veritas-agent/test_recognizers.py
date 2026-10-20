"""The agent's copy of the recognizer pack reproduces the golden corpus (run from veritas-agent/)."""
import json
from pathlib import Path

import pytest

import veritas_recognizers as vr

CORPUS_FILE = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "recognizers_corpus.json"
pytestmark = pytest.mark.skipif(not CORPUS_FILE.exists(), reason="the corpus is in the repository, not in a packaged agent")


def test_the_agent_masks_exactly_what_the_corpus_says():
    corpus = json.loads(CORPUS_FILE.read_text(encoding="utf-8"))
    assert corpus["pack_fingerprint"] == vr.pack_fingerprint()
    for case in corpus["cases"]:
        assert vr.mask(case["text"]) == case["masked"], case["text"]
