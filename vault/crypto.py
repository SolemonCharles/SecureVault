"""Cryptographic primitives for the vault.

Design (format v2 - envelope encryption):
  * A random 256-bit Data Encryption Key (DEK) encrypts the vault with
    AES-256-GCM (authenticated - any tampering is detected).
  * The DEK is stored "wrapped" (encrypted) in one or more key slots:
      - password slot: KEK = HKDF(Argon2id(master password) || SHA-256(key file))
      - recovery slot: KEK = HKDF(random 160-bit recovery key)
    Either slot can unlock the vault; changing the password only re-wraps the DEK.
  * The whole file header (version, KDF params, salt, slots, nonce) is bound to
    the ciphertext as Associated Data, so it can't be altered undetected, and
    weak KDF parameters are refused (downgrade guard).
  * A fresh random 96-bit nonce is generated on every save.

Format v1 (password-derived key encrypts the vault directly) is still readable
so older vaults can be opened and upgraded.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT_VERSION = 2
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256

# OWASP-recommended range is >= 19 MiB / t=2. We go well above that.
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_KIB = 256 * 1024  # 256 MiB
DEFAULT_PARALLELISM = 4

# Refuse files whose params are suspiciously weak (tamper / downgrade guard).
MIN_TIME_COST = 2
MIN_MEMORY_KIB = 64 * 1024

RECOVERY_KEY_BYTES = 20  # 160 bits -> 32 base32 chars
KEYFILE_MIN_BYTES = 32
KEYFILE_MAX_BYTES = 10 * 1024 * 1024
KEYFILE_NEW_BYTES = 64


class DecryptionError(Exception):
    """Wrong master password / key file / recovery key, or the vault was tampered with."""


class KeyFileRequired(DecryptionError):
    """The vault needs a key file but none was supplied."""


@dataclass(frozen=True)
class KdfParams:
    salt: bytes
    time_cost: int = DEFAULT_TIME_COST
    memory_kib: int = DEFAULT_MEMORY_KIB
    parallelism: int = DEFAULT_PARALLELISM

    @classmethod
    def new(cls) -> "KdfParams":
        return cls(salt=os.urandom(SALT_LEN))

    def to_header(self) -> dict:
        return {"kdf": "argon2id", "salt": _b64(self.salt), "t": self.time_cost,
                "m": self.memory_kib, "p": self.parallelism}


# ---------------------------------------------------------------- helpers
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _header_bytes(header: dict) -> bytes:
    # Canonical serialisation so the AAD is byte-for-byte reproducible.
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hkdf(ikm: bytes, info: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, info=info).derive(ikm)


def _argon2(password: str, params: KdfParams) -> bytes:
    if not password:
        raise ValueError("Master password must not be empty")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


# ---------------------------------------------------------------- key file
def hash_keyfile(path: Path) -> bytes:
    """SHA-256 of the key file's exact bytes. Any change to the file breaks it."""
    path = Path(path)
    size = path.stat().st_size
    if size < KEYFILE_MIN_BYTES:
        raise ValueError(f"Key file is too small (needs at least {KEYFILE_MIN_BYTES} bytes)")
    if size > KEYFILE_MAX_BYTES:
        raise ValueError("Key file is too large (max 10 MB)")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.digest()


def create_keyfile(path: Path) -> None:
    with open(path, "xb") as f:  # "x": never overwrite an existing file
        f.write(os.urandom(KEYFILE_NEW_BYTES))


# ---------------------------------------------------------------- recovery key
_B32_FIXUPS = str.maketrans({"0": "O", "1": "I", "8": "B"})


def generate_recovery_key() -> str:
    raw = base64.b32encode(os.urandom(RECOVERY_KEY_BYTES)).decode("ascii")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def parse_recovery_key(text: str) -> bytes:
    cleaned = "".join(c for c in text.upper() if c.isalnum()).translate(_B32_FIXUPS)
    try:
        raw = base64.b32decode(cleaned)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) != RECOVERY_KEY_BYTES:
        raise DecryptionError("That doesn't look like a valid recovery key")
    return raw


# ---------------------------------------------------------------- KEKs & wrapping
def derive_password_kek(password: str, params: KdfParams, keyfile_hash: bytes | None) -> bytes:
    return _hkdf(_argon2(password, params) + (keyfile_hash or b""), b"SecureVault/v2/password-kek")


def derive_recovery_kek(recovery_key: bytes, salt: bytes) -> bytes:
    # The recovery key is 160 random bits, so no slow KDF is needed.
    return _hkdf(recovery_key, b"SecureVault/v2/recovery-kek", salt)


def wrap_key(kek: bytes, dek: bytes, purpose: str) -> dict:
    nonce = os.urandom(NONCE_LEN)
    return {"nonce": _b64(nonce), "key": _b64(AESGCM(kek).encrypt(nonce, dek, purpose.encode()))}


def unwrap_key(kek: bytes, slot: dict, purpose: str) -> bytes:
    try:
        return AESGCM(kek).decrypt(_unb64(slot["nonce"]), _unb64(slot["key"]), purpose.encode())
    except (InvalidTag, KeyError, ValueError, binascii.Error) as e:
        raise DecryptionError("Wrong credentials or vault was tampered with") from e


# ---------------------------------------------------------------- vault body
def encrypt_vault(plaintext: bytes, dek: bytes, header: dict) -> bytes:
    header = dict(header, v=FORMAT_VERSION, nonce=_b64(os.urandom(NONCE_LEN)))
    ct = AESGCM(dek).encrypt(_unb64(header["nonce"]), plaintext, _header_bytes(header))
    return json.dumps({"header": header, "ct": _b64(ct)}).encode("utf-8")


def decrypt_vault(blob: bytes, dek: bytes) -> bytes:
    try:
        doc = json.loads(blob)
        header = doc["header"]
        nonce, ct = _unb64(header["nonce"]), _unb64(doc["ct"])
    except Exception as e:
        raise DecryptionError("Vault file is corrupt") from e
    try:
        return AESGCM(dek).decrypt(nonce, ct, _header_bytes(header))
    except InvalidTag as e:
        raise DecryptionError("Vault was tampered with or is corrupt") from e


def read_header(blob: bytes) -> dict:
    """Parse and validate the header of a vault file (v1 or v2)."""
    try:
        header = json.loads(blob)["header"]
        if header["v"] not in (1, 2) or header["kdf"] != "argon2id":
            raise DecryptionError("Unsupported vault format")
        if header["v"] == 2 and "password" not in header["slots"]:
            raise DecryptionError("Vault file is corrupt")
    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError("Vault file is corrupt") from e
    kdf_params(header)  # validates parameters
    return header


def kdf_params(header: dict) -> KdfParams:
    try:
        params = KdfParams(salt=_unb64(header["salt"]), time_cost=int(header["t"]),
                           memory_kib=int(header["m"]), parallelism=int(header["p"]))
    except Exception as e:
        raise DecryptionError("Vault file is corrupt") from e
    if params.time_cost < MIN_TIME_COST or params.memory_kib < MIN_MEMORY_KIB:
        raise DecryptionError("Vault KDF parameters are too weak (possible tampering)")
    return params


def decrypt_v1(blob: bytes, password: str) -> bytes:
    """Legacy format: Argon2id(password) is the AES key itself."""
    header = read_header(blob)
    key = _argon2(password, kdf_params(header))
    try:
        return AESGCM(key).decrypt(_unb64(header["nonce"]), _unb64(json.loads(blob)["ct"]),
                                   _header_bytes(header))
    except InvalidTag as e:
        raise DecryptionError("Wrong master password or vault was tampered with") from e
