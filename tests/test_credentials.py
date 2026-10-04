import json

import pytest

from vault import crypto
from vault.store import Entry, Vault, vault_has_recovery, vault_requires_keyfile

MASTER = "correct horse battery staple 42!"
NEW = "a brand new passphrase 2026"


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path / "v.svault", MASTER)
    v.add(Entry(title="Bank", password="secret"))
    return v


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "my.key"
    crypto.create_keyfile(p)
    return p


# ---------------- key file ----------------
def test_keyfile_required_after_enabling(vault, keyfile):
    vault.set_keyfile(MASTER, keyfile)
    assert vault_requires_keyfile(vault.path)
    with pytest.raises(crypto.KeyFileRequired):
        Vault.unlock(vault.path, MASTER)
    assert Vault.unlock(vault.path, MASTER, keyfile).entries[0].title == "Bank"


def test_wrong_keyfile_rejected(vault, keyfile, tmp_path):
    vault.set_keyfile(MASTER, keyfile)
    other = tmp_path / "other.key"
    crypto.create_keyfile(other)
    with pytest.raises(crypto.DecryptionError, match="key file"):
        Vault.unlock(vault.path, MASTER, other)


def test_keyfile_alone_is_not_enough(vault, keyfile):
    vault.set_keyfile(MASTER, keyfile)
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault.path, "wrong password here", keyfile)


def test_modified_keyfile_rejected(vault, keyfile):
    vault.set_keyfile(MASTER, keyfile)
    data = bytearray(keyfile.read_bytes())
    data[0] ^= 1
    keyfile.write_bytes(bytes(data))
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault.path, MASTER, keyfile)


def test_remove_keyfile_requirement(vault, keyfile):
    vault.set_keyfile(MASTER, keyfile)
    v = Vault.unlock(vault.path, MASTER, keyfile)
    v.set_keyfile(MASTER, None)
    assert not vault_requires_keyfile(vault.path)
    assert Vault.unlock(vault.path, MASTER).entries[0].title == "Bank"


def test_change_password_keeps_keyfile(vault, keyfile):
    vault.set_keyfile(MASTER, keyfile)
    vault.change_master_password(MASTER, NEW)
    assert Vault.unlock(vault.path, NEW, keyfile).entries
    with pytest.raises(crypto.KeyFileRequired):
        Vault.unlock(vault.path, NEW)


def test_create_with_keyfile(tmp_path, keyfile):
    Vault.create(tmp_path / "k.svault", MASTER, keyfile)
    with pytest.raises(crypto.KeyFileRequired):
        Vault.unlock(tmp_path / "k.svault", MASTER)
    Vault.unlock(tmp_path / "k.svault", MASTER, keyfile)


def test_keyfile_flag_tamper_detected(vault, keyfile):
    """Flipping the 'keyfile' flag off must not let the vault open with just the password."""
    vault.set_keyfile(MASTER, keyfile)
    doc = json.loads(vault.path.read_bytes())
    doc["header"]["keyfile"] = False
    vault.path.write_text(json.dumps(doc))
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault.path, MASTER)


def test_keyfile_validation(tmp_path):
    tiny = tmp_path / "tiny.key"
    tiny.write_bytes(b"short")
    with pytest.raises(ValueError, match="too small"):
        crypto.hash_keyfile(tiny)
    crypto.create_keyfile(tmp_path / "k")
    with pytest.raises(FileExistsError):
        crypto.create_keyfile(tmp_path / "k")  # never overwrites


def test_wrong_current_password_blocks_keyfile_change(vault, keyfile):
    with pytest.raises(crypto.DecryptionError, match="Current master password"):
        vault.set_keyfile("not my password", keyfile)


# ---------------- recovery kit ----------------
def test_recovery_unlock_and_reset(vault):
    rk = vault.new_recovery_key()
    assert vault_has_recovery(vault.path)
    v = Vault.unlock_with_recovery(vault.path, rk)
    assert v.must_reset_password and v.entries[0].title == "Bank"
    new_rk = v.reset_password(NEW)
    assert new_rk != rk
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault.path, MASTER)
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock_with_recovery(vault.path, rk)  # old kit rotated
    assert Vault.unlock(vault.path, NEW).entries[0].title == "Bank"
    assert Vault.unlock_with_recovery(vault.path, new_rk).entries


def test_recovery_works_when_keyfile_lost(vault, keyfile):
    vault.set_keyfile(MASTER, keyfile)
    rk = vault.new_recovery_key()
    v = Vault.unlock_with_recovery(vault.path, rk)
    # Before reset, saving must preserve the key-file requirement on disk.
    v.save()
    assert vault_requires_keyfile(vault.path)
    v.reset_password(NEW)
    assert not vault_requires_keyfile(vault.path)
    assert Vault.unlock(vault.path, NEW).entries


def test_recovery_key_typing_tolerance(vault):
    rk = vault.new_recovery_key()
    sloppy = rk.lower().replace("-", " ").replace("o", "0")
    assert Vault.unlock_with_recovery(vault.path, sloppy).entries


def test_wrong_recovery_key(vault):
    vault.new_recovery_key()
    with pytest.raises(crypto.DecryptionError, match="incorrect"):
        Vault.unlock_with_recovery(vault.path, crypto.generate_recovery_key())
    with pytest.raises(crypto.DecryptionError, match="valid"):
        Vault.unlock_with_recovery(vault.path, "ABCD-1234")


def test_no_recovery_kit(vault):
    assert not vault_has_recovery(vault.path)
    with pytest.raises(crypto.DecryptionError, match="no recovery"):
        Vault.unlock_with_recovery(vault.path, crypto.generate_recovery_key())


def test_remove_recovery(vault):
    rk = vault.new_recovery_key()
    vault.remove_recovery()
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock_with_recovery(vault.path, rk)
    assert Vault.unlock(vault.path, MASTER).entries


def test_password_change_keeps_recovery_valid(vault):
    rk = vault.new_recovery_key()
    vault.change_master_password(MASTER, NEW)
    assert Vault.unlock_with_recovery(vault.path, rk).entries


def test_recovery_key_format():
    rk = crypto.generate_recovery_key()
    assert len(rk) == 39 and rk.count("-") == 7  # 8 groups of 4
    assert len(crypto.parse_recovery_key(rk)) == crypto.RECOVERY_KEY_BYTES


def test_recovery_vault_cannot_verify_old_password(vault):
    rk = vault.new_recovery_key()
    v = Vault.unlock_with_recovery(vault.path, rk)
    assert not v.verify_password(MASTER)


# ---------------- format upgrade ----------------
def test_v1_vault_upgraded_to_v2(tmp_path, v1_vault_writer):
    p = tmp_path / "old.svault"
    v1_vault_writer(p, MASTER, {"entries": [{"title": "Legacy", "password": "x"}]})
    assert json.loads(p.read_bytes())["header"]["v"] == 1
    assert Vault.unlock(p, MASTER).entries[0].title == "Legacy"
    assert json.loads(p.read_bytes())["header"]["v"] == 2
    assert Vault.unlock(p, MASTER).entries[0].title == "Legacy"


def test_v1_wrong_password(tmp_path, v1_vault_writer):
    p = tmp_path / "old.svault"
    v1_vault_writer(p, MASTER, {"entries": []})
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(p, "wrong password entirely")
    assert json.loads(p.read_bytes())["header"]["v"] == 1  # untouched


def test_slot_tamper_detected(vault):
    """Swapping in a different password slot breaks the authenticated header."""
    other = Vault.create(vault.path.with_name("o.svault"), MASTER)
    doc = json.loads(vault.path.read_bytes())
    doc["header"]["slots"]["password"] = json.loads(other.path.read_bytes())["header"]["slots"]["password"]
    vault.path.write_text(json.dumps(doc))
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault.path, MASTER)
