"""Encrypted on-disk vault: create, unlock, edit, save."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field, fields, asdict
from pathlib import Path

from . import crypto


def default_vault_path() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "SecureVault" / "vault.svault"


@dataclass
class Entry:
    title: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    totp: str = ""  # base32 secret or otpauth:// URI
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: float = field(default_factory=time.time)
    modified: float = field(default_factory=time.time)


def vault_requires_keyfile(path: Path) -> bool:
    header = crypto.read_header(Path(path).read_bytes())
    return bool(header.get("keyfile"))


def vault_has_recovery(path: Path) -> bool:
    header = crypto.read_header(Path(path).read_bytes())
    return "recovery" in header.get("slots", {})


class Vault:
    """An unlocked vault. Holds the data key in memory (never the master password)."""

    def __init__(self, path: Path, dek: bytes, params: crypto.KdfParams,
                 keyfile_hash: bytes | None, slots: dict, entries: list[Entry]):
        self.path = Path(path)
        self._dek = dek
        self._params = params
        self._keyfile_hash = keyfile_hash
        self._slots = slots
        self.entries = entries
        # Set after a recovery-key unlock: a new master password must be chosen.
        self.must_reset_password = False

    # ---------- lifecycle ----------
    @classmethod
    def create(cls, path: Path, master_password: str, keyfile_path: Path | None = None) -> "Vault":
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"A vault already exists at {path}")
        vault = cls(path, os.urandom(crypto.KEY_LEN), crypto.KdfParams.new(), None, {}, [])
        vault._set_password_slot(master_password, crypto.hash_keyfile(keyfile_path) if keyfile_path else None)
        vault.save()
        return vault

    @classmethod
    def unlock(cls, path: Path, master_password: str, keyfile_path: Path | None = None) -> "Vault":
        blob = Path(path).read_bytes()
        header = crypto.read_header(blob)
        if header["v"] == 1:
            return cls._upgrade_v1(path, blob, master_password)

        params = crypto.kdf_params(header)
        keyfile_hash = None
        if header.get("keyfile"):
            if not keyfile_path:
                raise crypto.KeyFileRequired("This vault requires its key file")
            keyfile_hash = crypto.hash_keyfile(keyfile_path)
        kek = crypto.derive_password_kek(master_password, params, keyfile_hash)
        try:
            dek = crypto.unwrap_key(kek, header["slots"]["password"], "password")
        except crypto.DecryptionError:
            msg = "Wrong master password or key file" if keyfile_hash else "Wrong master password"
            raise crypto.DecryptionError(msg) from None
        return cls(path, dek, params, keyfile_hash, header["slots"], cls._load_entries(blob, dek))

    @classmethod
    def unlock_with_recovery(cls, path: Path, recovery_key: str) -> "Vault":
        blob = Path(path).read_bytes()
        header = crypto.read_header(blob)
        slot = header.get("slots", {}).get("recovery")
        if not slot:
            raise crypto.DecryptionError("This vault has no recovery kit")
        kek = crypto.derive_recovery_kek(crypto.parse_recovery_key(recovery_key), crypto._unb64(slot["salt"]))
        try:
            dek = crypto.unwrap_key(kek, slot, "recovery")
        except crypto.DecryptionError:
            raise crypto.DecryptionError("Recovery key is incorrect") from None
        vault = cls(path, dek, crypto.kdf_params(header), None, header["slots"], cls._load_entries(blob, dek))
        vault.must_reset_password = True
        return vault

    @classmethod
    def _upgrade_v1(cls, path: Path, blob: bytes, master_password: str) -> "Vault":
        """Open a v1 vault and immediately re-save it in the v2 format."""
        data = json.loads(crypto.decrypt_v1(blob, master_password))
        vault = cls(path, os.urandom(crypto.KEY_LEN), crypto.KdfParams.new(), None, {},
                    cls._parse_entries(data))
        vault._set_password_slot(master_password, None)
        vault.save()
        return vault

    @classmethod
    def _load_entries(cls, blob: bytes, dek: bytes) -> list[Entry]:
        return cls._parse_entries(json.loads(crypto.decrypt_vault(blob, dek)))

    @staticmethod
    def _parse_entries(data: dict) -> list[Entry]:
        known = {f.name for f in fields(Entry)}
        return [Entry(**{k: v for k, v in e.items() if k in known}) for e in data.get("entries", [])]

    def lock(self) -> None:
        self._dek = b""
        self._keyfile_hash = None
        self.entries = []

    @property
    def is_locked(self) -> bool:
        return not self._dek

    # ---------- credentials ----------
    @property
    def requires_keyfile(self) -> bool:
        return self._keyfile_hash is not None

    @property
    def has_recovery(self) -> bool:
        return "recovery" in self._slots

    def _set_password_slot(self, password: str, keyfile_hash: bytes | None) -> None:
        self._params = crypto.KdfParams.new()  # fresh salt every time
        self._keyfile_hash = keyfile_hash
        kek = crypto.derive_password_kek(password, self._params, keyfile_hash)
        self._slots = dict(self._slots, password=crypto.wrap_key(kek, self._dek, "password"))

    def verify_password(self, password: str) -> bool:
        if self.must_reset_password:
            return False
        kek = crypto.derive_password_kek(password, self._params, self._keyfile_hash)
        try:
            return crypto.unwrap_key(kek, self._slots["password"], "password") == self._dek
        except crypto.DecryptionError:
            return False

    def require_password(self, password: str) -> None:
        if not self.verify_password(password):
            raise crypto.DecryptionError("Current master password is incorrect")

    def change_master_password(self, current: str, new: str) -> None:
        self.require_password(current)
        self._set_password_slot(new, self._keyfile_hash)
        self.save()

    def set_keyfile(self, current_password: str, keyfile_path: Path | None) -> None:
        """Require (or, with None, stop requiring) a key file in addition to the password."""
        self.require_password(current_password)
        self._set_password_slot(current_password, crypto.hash_keyfile(keyfile_path) if keyfile_path else None)
        self.save()

    def reset_password(self, new_password: str) -> str:
        """After a recovery unlock: set a new password (no key file) and issue a new recovery key."""
        if not self.must_reset_password:
            raise RuntimeError("Use change_master_password instead")
        self._set_password_slot(new_password, None)
        self.must_reset_password = False
        return self.new_recovery_key()  # the old kit has been used - rotate it

    def new_recovery_key(self) -> str:
        """Create a recovery kit, replacing any previous one. Returns the key to show the user once."""
        key = crypto.generate_recovery_key()
        salt = os.urandom(crypto.SALT_LEN)
        kek = crypto.derive_recovery_kek(crypto.parse_recovery_key(key), salt)
        self._slots = dict(self._slots, recovery={"salt": crypto._b64(salt),
                                                  **crypto.wrap_key(kek, self._dek, "recovery")})
        self.save()
        return key

    def remove_recovery(self) -> None:
        self._slots = {k: v for k, v in self._slots.items() if k != "recovery"}
        self.save()

    # ---------- persistence ----------
    def save(self) -> None:
        if self.is_locked:
            raise RuntimeError("Vault is locked")
        payload = json.dumps({"entries": [asdict(e) for e in self.entries]}).encode("utf-8")
        header = {**self._params.to_header(), "keyfile": self.requires_keyfile, "slots": self._slots}
        if self.must_reset_password:
            header["keyfile"] = self._header_keyfile_flag()
        blob = crypto.encrypt_vault(payload, self._dek, header)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Keep one previous version as a backup in case of disk errors.
        if self.path.exists():
            shutil.copy2(self.path, self.path.with_suffix(".svault.bak"))
        # Atomic write: temp file in same dir -> fsync -> rename over original.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def _header_keyfile_flag(self) -> bool:
        # While recovering, the key-file hash is unknown; preserve the on-disk flag.
        try:
            return vault_requires_keyfile(self.path)
        except (OSError, crypto.DecryptionError):
            return False

    # ---------- entries ----------
    def add(self, entry: Entry) -> None:
        self.entries.append(entry)
        self.save()

    def add_many(self, entries: list[Entry]) -> None:
        self.entries.extend(entries)
        self.save()

    def update(self, entry: Entry) -> None:
        entry.modified = time.time()
        for i, e in enumerate(self.entries):
            if e.id == entry.id:
                self.entries[i] = entry
                break
        else:
            raise KeyError(entry.id)
        self.save()

    def delete(self, entry_id: str) -> None:
        self.entries = [e for e in self.entries if e.id != entry_id]
        self.save()

    def search(self, query: str) -> list[Entry]:
        q = query.lower().strip()
        items = sorted(self.entries, key=lambda e: e.title.lower())
        if not q:
            return items
        return [e for e in items if q in e.title.lower() or q in e.username.lower() or q in e.url.lower()]
