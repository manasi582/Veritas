"""
The PyInstaller specs must bundle modules that are loaded lazily by name (PyInstaller cannot
see them). Missing one only shows up in the packaged binary: the macOS package shipped without
passlib's bcrypt handler and could not create the first administrator or sign anyone in.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SPECS = ["veritas-linux.spec", "veritas-mac.spec", "veritas.spec"]

# Imported by name at run time; each one broke a packaged build or would.
REQUIRED = {
    "passlib.handlers.bcrypt": "password hashing and verification (setup, sign-in)",
    "jwt": "signing and reading the session cookie",
    "jwt.algorithms": "signing and reading the session cookie",
    "anyio._backends._asyncio": "the web server's async backend",
    "uvicorn.lifespan.on": "web server start-up",
}


def hidden_imports(spec: str) -> set[str]:
    text = (HERE / spec).read_text()
    start = text.index("hiddenimports=[") + len("hiddenimports=")
    depth, end = 0, start
    for i, ch in enumerate(text[start:], start):
        depth += ch == "["
        depth -= ch == "]"
        if depth == 0:
            end = i + 1
            break
    block = re.sub(r"#.*", "", text[start:end])           # ignore comments
    names = set(re.findall(r"'([^']+)'", block))
    # a package comes along when one of its modules is listed, so ignore listed parents
    return {n for n in names if not any(o.startswith(n + ".") for o in names)}


@pytest.mark.parametrize("spec", SPECS)
@pytest.mark.parametrize("module,why", sorted(REQUIRED.items()))
def test_spec_bundles_lazily_loaded_modules(spec, module, why):
    listed = hidden_imports(spec)
    assert module in listed or any(o.startswith(module + ".") for o in listed), \
        f"{spec} does not bundle {module} ({why})"


def _missing(have: set[str], want: set[str]) -> set[str]:
    """Names in `want` that `have` neither lists nor covers through a listed child module."""
    return {n for n in want if n not in have and not any(h.startswith(n + ".") for h in have)}


def test_specs_do_not_drift_apart():
    """Anything one platform needs, except what is platform-specific, must be in all of them."""
    linux, mac, win = (hidden_imports(s) for s in SPECS)
    platform_specific = {"httpcore", "pydantic.v1", "thinc.backends.cupy_ops"}
    assert _missing(mac, linux) - platform_specific == set(), "bundled on Linux but not on macOS"
    assert _missing(linux, mac) - platform_specific == set(), "bundled on macOS but not on Linux"
    assert _missing(win, linux) - platform_specific == set(), "bundled on Linux but not on Windows"
    assert _missing(linux, win) - platform_specific == set(), "bundled on Windows but not on Linux"
