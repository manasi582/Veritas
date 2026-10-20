import os
# -*- mode: python ; coding: utf-8 -*-
# Veritas Agent: PyInstaller spec for macOS (Apple Silicon)
# ===========================================================
# Builds a single self-contained binary so a Mac needs no Python installed.
#
# Build (on a Mac, from veritas-agent/):
#   pip install -r requirements.txt pyinstaller
#   python -m PyInstaller veritas-agent-mac.spec --noconfirm
# Output: dist/veritas-agent-runtime

from PyInstaller.utils.hooks import collect_submodules

# tail_docker() imports docker lazily, so PyInstaller cannot see it.
hidden = collect_submodules('docker') + ['yaml', 'requests', 'urllib3', 'certifi', 'veritas_recognizers']

a = Analysis(
    ['agent.py'],
    pathex=['.'],
    binaries=[],
    datas=[*([('VERSION', '.')] if os.path.exists('VERSION') else [])],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'win32api', 'win32service'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='veritas-agent-runtime',
    debug=False, strip=False, upx=False, console=True,
)
