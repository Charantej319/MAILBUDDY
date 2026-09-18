# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the PhishGuard backend (one-dir).

Build:
    cd packaging && pyinstaller phishguard_backend.spec --noconfirm
Output:
    packaging/dist/phishguard-backend/phishguard-backend.exe

Secrets are NEVER bundled: backend/.env is excluded (datas/datas listed here
contain only code-adjacent assets). Runtime configuration is read from
PHISHGUARD_DATA_DIR (.env, phishguard.db, uploads, logs) — set by the Electron
shell in desktop mode.
"""
import os

from PyInstaller.utils.hooks import collect_submodules

project_root = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(project_root, "packaging", "backend_entry.py")],
    pathex=[project_root, os.path.join(project_root, "backend")],
    binaries=[],
    datas=[
        # React production build shipped as data, exposed under _MEIPASS/frontend_dist
        (os.path.join(project_root, "frontend", "dist"), "frontend_dist"),
    ],
    hiddenimports=(
        # uvicorn programmatic server pieces (uvicorn[standard] extras are
        # intentionally NOT bundled — not needed for local single-user serving)
        collect_submodules("uvicorn")
        + collect_submodules("uvicorn.logging")
        + ["uvicorn.loops.auto", "uvicorn.loops.asyncio",
           "uvicorn.protocols.http.auto", "uvicorn.protocols.http.h11_impl",
           "uvicorn.protocols.websockets.auto", "uvicorn.lifespan.on",
           "uvicorn.lifespan.asyncio"]
        # app + project-local detection package
        + collect_submodules("backend.app")
        + collect_submodules("detection")
        # drivers/db layers that import dynamically
        + ["sqlalchemy.dialects.sqlite", "anyio._backends._asyncio"]
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # shrinks the bundle and avoids accidental local-model inclusion
        "tkinter", "matplotlib", "numpy", "pandas", "torch", "transformers",
        "pytest", "IPython", "jupyter",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="phishguard-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX massively increases AV false positives — off
    console=True,  # stdout/stderr are captured by the Electron shell into logs
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="phishguard-backend",
)
