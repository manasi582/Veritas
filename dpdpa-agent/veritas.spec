import os
# -*- mode: python ; coding: utf-8 -*-
#
# Veritas Runtime — PyInstaller Spec File
# =========================================
# Builds veritas-runtime.exe: a self-contained Windows executable that
# includes the Python interpreter, all dependencies, and all bundled assets.
#
# Build with:
#   cd dpdpa-agent
#   pyinstaller veritas.spec --noconfirm
#
# Output: dist\veritas-runtime.exe
#
# What IS bundled (read-only assets):
#   - dashboard/index.html
#   - llm_explainer/statute_snippets.json
#   - org_config/configs/ (empty at build time; org configs are created at onboarding)
#   - spaCy en_core_web_lg model
#   - All Python packages (FastAPI, uvicorn, Presidio, SQLite, etc.)
#
# What is NOT bundled (writable, must live next to the .exe):
#   - evidence.db        (created on first run)
#   - agents.db          (created on first run)
#   - veritas.vlic       (provided by customer at install time)
#   - .env               (optional, for OPENAI_API_KEY)
#   - org_config/configs/ (also writable for new org creation)

from PyInstaller.utils.hooks import collect_data_files, collect_all

block_cipher = None

# ---------------------------------------------------------------------------
# Collect data files from packages that use non-Python assets
# ---------------------------------------------------------------------------

# spaCy en_core_web_lg model (~750 MB — the main source of size)
spacy_datas, spacy_binaries, spacy_hiddenimports = collect_all('en_core_web_lg')
spacy_core_datas = collect_data_files('spacy')

# Presidio (uses regex patterns and other data files)
presidio_datas  = collect_data_files('presidio_analyzer')
presidio_datas += collect_data_files('presidio_anonymizer')

import pathlib as _pl, presidio_analyzer as _pa
_pa_pkg = _pl.Path(_pa.__file__).parent
_pa_conf = _pa_pkg / 'conf'
if _pa_conf.exists():
    for _f in _pa_conf.rglob('*'):
        if _f.is_file():
            _rel = _f.relative_to(_pa_pkg)
            presidio_datas += [(str(_f), str(_rel.parent))]
    print(f'[SPEC] Added presidio conf files: {len(list(_pa_conf.rglob("*")))} files')
else:
    print(f'[SPEC] WARNING: presidio conf dir not found at {_pa_conf}')

# tldextract (used by presidio, has snapshot data files)
try:
    tldextract_datas = collect_data_files('tldextract')
except Exception:
    tldextract_datas = []

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

a = Analysis(
    ['run_pipeline.py'],
    pathex=['.'],
    binaries=spacy_binaries,
    datas=[
        # Veritas bundled read-only assets
        ('dashboard/index.html',               'dashboard'),
        ('dashboard/login.html',               'dashboard'),
        ('dashboard/setup.html',               'dashboard'),
        ('dashboard/static',                   'dashboard/static'),
        ('llm_explainer/statute_snippets.json','llm_explainer'),
        ('org_config/configs',                 'org_config/configs'),
        *([('VERSION', '.')] if os.path.exists('VERSION') else []),   # written by the release build

        # Package data files
        *spacy_datas,
        *spacy_core_datas,
        *presidio_datas,
        *tldextract_datas,
    ],
    hiddenimports=[
        # spaCy model
        'en_core_web_lg',
        # spaCy internals (often missed by static analysis)
        'spacy',
        'spacy.lang.en',
        'spacy.pipeline',
        'spacy.tokens',
        'blis',
        'blis.cy',
        'thinc',
        'thinc.backends',
        'thinc.backends.numpy_ops',
        'thinc.backends.cupy_ops',
        'cymem',
        'murmurhash',
        'preshed',
        'srsly',
        'catalogue',
        'confection',
        'weasel',
        # Presidio
        'presidio_analyzer',
        'presidio_analyzer.nlp_engine',
        'presidio_analyzer.predefined_recognizers',
        'presidio_anonymizer',
        # Phonenumbers (used by presidio for phone detection)
        'phonenumbers',
        # FastAPI / Starlette internals
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        # SQLite (stdlib but sometimes needs explicit inclusion)
        '_sqlite3',
        # Cryptography (used by license.py)
        'cryptography',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.asymmetric.padding',
        'cryptography.hazmat.primitives.hashes',
        # OpenAI (graceful fallback if no API key)
        'openai',
        # PyYAML
        'yaml',
        # Pydantic v2
        'pydantic',
        'pydantic.v1',
        # httpx — required by weasel (spaCy CLI dep) at import time
        'httpx', 'httpx._transports', 'httpx._transports.default',
        'httpcore',
        'anyio', 'anyio._backends._asyncio',
        # Auth
        'passlib', 'passlib.handlers', 'passlib.handlers.bcrypt',
        'jwt', 'jwt.algorithms',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['pyi_rth_spacy.py', 'pyi_rth_presidio.py'],
    excludes=[
        # Test dependencies — not needed in production
        'pytest',
        'pytest_asyncio',
        '_pytest',
        # Jupyter / IPython — not needed
        'IPython',
        'jupyter',
        'notebook',
        # Matplotlib / plotting — not needed
        'matplotlib',
        'PIL',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='veritas-runtime',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,           # UPX compression can cause false-positive AV alerts — disabled
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,        # Console window shows startup logs — useful for a service
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/veritas.ico',  # Uncomment when icon is available
)
