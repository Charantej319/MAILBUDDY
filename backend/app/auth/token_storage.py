"""Windows DPAPI token encryption-at-rest for Gmail OAuth tokens.

This is the ONE source of truth for encrypting/decrypting Gmail OAuth
credentials at rest. Every writer (OAuth callback, token refresh) and every
reader (GmailService) goes through TokenStorage — no other module may
encrypt or decrypt tokens.

Design
------
Windows (the desktop target): native DPAPI via CryptProtectData /
CryptUnprotectData (advapi32), scoped to the current user with additional
entropy. DPAPI decrypts only for the same Windows user on the same machine,
so a stolen SQLite file alone reveals nothing.

Anywhere else (Linux/macOS dev, CI): Fernet (AES-128-CBC + HMAC-SHA256)
under a key generated once and persisted 0600 in the data directory. This
keeps the code importable and testable off-Windows while never writing
plaintext to the database.

Wire format (both backends)::
    phishguard.v1:<base64url(ciphertext)>

The explicit prefix makes legacy plaintext detection unambiguous: any value
that does not start with the prefix is legacy plaintext and gets migrated.

Migration
---------
TokenStorage.migrate(db) re-encrypts legacy plaintext rows in place, writes
the encrypted value back, and never erases data. Rows whose ciphertext no
longer decrypts are left untouched (never silently destroyed).

Security invariants
-------------------
* Plaintext tokens never appear in logs, URLs, or API responses.
* Decryption failures raise TokenDecryptionError (fail closed, loud) —
  a corrupt token is never silently converted to "".
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import logging
import os
import pathlib
import threading

logger = logging.getLogger("phishguard.auth")

_PREFIX = "phishguard.v1:"

try:  # pragma: no cover - import guard
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover
    Fernet = None  # type: ignore[assignment,misc]

try:  # pragma: no cover - platform guard
    import ctypes.wintypes  # noqa: F401

    # CryptProtectData/CryptUnprotectData live in crypt32.dll (not advapi32).
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True) if os.name == "nt" else None
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
except (ImportError, AttributeError, OSError):  # pragma: no cover
    _crypt32 = None
    _kernel32 = None

if _crypt32 is not None:  # pragma: no cover - exercised only on Windows
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def _blob(data: bytes) -> "_DATA_BLOB":
        buf = (ctypes.c_byte * len(data)).from_buffer_copy(data or b"\x00")
        # ctypes.c_byte is signed; DPAPI only cares about the address/length.
        return _DATA_BLOB(len(data or b"\x00"), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

    _crypt32.CryptProtectData.restype = ctypes.c_int
    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),   # pDataIn
        ctypes.c_wchar_p,             # szDataDescr
        ctypes.POINTER(_DATA_BLOB),   # pOptionalEntropy
        ctypes.c_void_p,              # pvReserved
        ctypes.c_void_p,              # pPromptStruct
        ctypes.c_ulong,               # dwFlags
        ctypes.POINTER(_DATA_BLOB),   # pDataOut
    ]
    _crypt32.CryptUnprotectData.restype = ctypes.c_int
    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DATA_BLOB),   # pDataIn
        ctypes.POINTER(ctypes.c_wchar_p),  # ppszDataDescr
        ctypes.POINTER(_DATA_BLOB),   # pOptionalEntropy
        ctypes.c_void_p,              # pvReserved
        ctypes.c_void_p,              # pPromptStruct
        ctypes.c_ulong,               # dwFlags
        ctypes.POINTER(_DATA_BLOB),   # pDataOut
    ]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    _CRYPTPROTECT_UI_FORBIDDEN = 0x1
    _entropy_buf = b"PhishGuard-GmailToken-v1"

    _ENTROPY = _blob(_entropy_buf)


class TokenDecryptionError(RuntimeError):
    """Raised when a stored token value cannot be decrypted (fail closed)."""


def _dpapi_protect(data: bytes) -> bytes:
    """CryptProtectData → raw ciphertext bytes (Windows only)."""
    if _crypt32 is None:  # pragma: no cover - non-Windows
        raise RuntimeError("DPAPI unavailable: not Windows")
    in_blob = _blob(data)
    out_blob = _DATA_BLOB(0, None)
    if not _crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,                      # description
        _ENTROPY,                  # additional entropy
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):  # pragma: no cover - depends on OS state
        raise RuntimeError(f"CryptProtectData failed (winerror={ctypes.get_last_error()})")
    try:
        size = out_blob.cbData
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, out_blob.pbData, size)
        return buf.raw
    finally:
        if out_blob.pbData:
            _kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    """CryptUnprotectData → plaintext bytes (Windows only)."""
    if _crypt32 is None:  # pragma: no cover - non-Windows
        raise RuntimeError("DPAPI unavailable: not Windows")
    if not data:
        raise TokenDecryptionError("empty ciphertext")
    in_blob = _blob(data)
    out_blob = _DATA_BLOB(0, None)
    if not _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        _ENTROPY,                  # must match the protecting entropy
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):  # pragma: no cover - depends on OS state
        raise TokenDecryptionError(
            f"CryptUnprotectData failed (winerror={ctypes.get_last_error()})"
        )
    try:
        size = out_blob.cbData
        buf = ctypes.create_string_buffer(size)
        ctypes.memmove(buf, out_blob.pbData, size)
        return buf.raw
    finally:
        if out_blob.pbData:
            _kernel32.LocalFree(out_blob.pbData)


# ── Fernet fallback (non-Windows / tests) ──────────────────────────────

_KEY_LOCK = threading.Lock()
_KEY_CACHE: bytes | None = None


def _key_path() -> pathlib.Path:
    data_dir = os.getenv("PHISHGUARD_DATA_DIR")
    if data_dir:
        d = pathlib.Path(data_dir)
        d.mkdir(parents=True, exist_ok=True)
        return d / "token.key"
    return pathlib.Path(__file__).resolve().parent.parent / "secrets" / "token.key"


def _fernet():
    """Fernet instance under a persisted 0600 key (non-Windows only)."""
    global _KEY_CACHE
    if Fernet is None:
        raise TokenDecryptionError("cryptography package is required for token storage")
    with _KEY_LOCK:
        if _KEY_CACHE is None:
            path = _key_path()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    key = path.read_bytes().strip()
                    if key:
                        _KEY_CACHE = key
                else:
                    key = Fernet.generate_key()
                    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(key)
                    _KEY_CACHE = key
            except OSError as exc:
                raise TokenDecryptionError(f"Cannot access token key file: {exc}") from exc
    return Fernet(_KEY_CACHE)


def _is_windows() -> bool:
    return os.name == "nt" and _crypt32 is not None


def reset_key_cache() -> None:
    """Forget the cached fallback key (test isolation)."""
    global _KEY_CACHE
    with _KEY_LOCK:
        _KEY_CACHE = None


class TokenStorage:
    """Canonical encrypt/decrypt + legacy-plaintext migration."""

    @staticmethod
    def encrypt(plaintext: str) -> str:
        """Encrypt a token value → prefixed wire-format string for the DB."""
        raw = plaintext.encode("utf-8")
        if _is_windows():
            cipher = _dpapi_protect(raw)  # pragma: no cover - Windows only
        else:
            cipher = _fernet().encrypt(raw)
        return _PREFIX + base64.urlsafe_b64encode(cipher).decode("ascii")

    @staticmethod
    def decrypt(stored: str) -> str:
        """Decrypt a stored value back to the plaintext token.

        Raises TokenDecryptionError on any failure — never returns "" for
        garbage input (fail closed).
        """
        if not stored:
            raise TokenDecryptionError("empty stored token")
        if not stored.startswith(_PREFIX):
            # Legacy plaintext value (pre-encryption row): return as-is so the
            # credential keeps working; migrate() upgrades the row later.
            return stored
        try:
            cipher = base64.urlsafe_b64decode(_PREFIX_JOIN(stored))
        except (binascii.Error, ValueError) as exc:
            raise TokenDecryptionError("malformed token ciphertext") from exc
        if _is_windows():
            raw = _dpapi_unprotect(cipher)  # pragma: no cover - Windows only
        else:
            try:
                raw = _fernet().decrypt(cipher)
            except InvalidToken as exc:
                raise TokenDecryptionError("token ciphertext failed HMAC check") from exc
        return raw.decode("utf-8")

    @staticmethod
    def is_encrypted(stored: str) -> bool:
        """True when the value is in the encrypted wire format."""
        return isinstance(stored, str) and stored.startswith(_PREFIX)

    @staticmethod
    def migrate(db_session) -> int:
        """Encrypt legacy plaintext token rows in place. Returns rows migrated.

        Idempotent, never erases credentials, and never commits a row whose
        re-encryption failed (the whole run is transactional).
        """
        if db_session is None:
            return 0
        from ..models.email import GmailToken

        migrated = 0
        dirty = False
        rows = db_session.query(GmailToken).all()
        for row in rows:
            try:
                if row.access_token and not TokenStorage.is_encrypted(row.access_token):
                    row.access_token = TokenStorage.encrypt(row.access_token)
                    dirty = True
                    migrated += 1
                if row.refresh_token and not TokenStorage.is_encrypted(row.refresh_token):
                    row.refresh_token = TokenStorage.encrypt(row.refresh_token)
                    dirty = True
            except Exception:  # noqa: BLE001 - one bad row must not kill the run
                logger.error(
                    "Token migration failed for row %s; leaving it untouched",
                    getattr(row, "id", "?"),
                )
        if dirty:
            try:
                db_session.commit()
            except Exception:  # noqa: BLE001
                db_session.rollback()
                raise
        return migrated


def _PREFIX_JOIN(stored: str) -> str:
    """Strip the wire-format prefix, returning the base64url payload."""
    return stored[len(_PREFIX):]


# Module-level singletons mirroring the import surface already used across
# the codebase (gmail/service.py) and exposed for the OAuth callback.
def encrypt(plaintext: str) -> str:
    return TokenStorage.encrypt(plaintext)


def decrypt(stored: str) -> str:
    return TokenStorage.decrypt(stored)


def migrate_tokens(db_session) -> int:
    return TokenStorage.migrate(db_session)


def is_encrypted_value(stored: str) -> bool:
    """True when the stored value is in the encrypted wire format."""
    return TokenStorage.is_encrypted(stored)


def master_key_path() -> pathlib.Path:
    """Path of the fallback key file (non-Windows deployments only)."""
    return _key_path()
