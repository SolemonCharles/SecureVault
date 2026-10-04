import json

import pytest

from vault import crypto
from vault.generator import estimate_strength, generate_password
from vault.store import Entry, Vault

MASTER = "correct horse battery staple 42!"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.svault"


def test_roundtrip(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add(Entry(title="GitHub", username="me", password="s3cr3t-Pa$$"))
    v2 = Vault.unlock(vault_path, MASTER)
    assert [(e.title, e.password) for e in v2.entries] == [("GitHub", "s3cr3t-Pa$$")]


def test_file_contains_no_plaintext(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add(Entry(title="MyBank", username="alice@example.com", password="hunter2-unique"))
    raw = vault_path.read_bytes()
    for s in (b"MyBank", b"alice", b"hunter2", MASTER.encode()):
        assert s not in raw


def test_wrong_password_rejected(vault_path):
    Vault.create(vault_path, MASTER)
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault_path, "wrong password entirely")


def test_tampered_ciphertext_detected(vault_path):
    Vault.create(vault_path, MASTER).add(Entry(title="x"))
    doc = json.loads(vault_path.read_bytes())
    ct = bytearray(crypto._unb64(doc["ct"]))
    ct[0] ^= 1
    doc["ct"] = crypto._b64(bytes(ct))
    vault_path.write_text(json.dumps(doc))
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault_path, MASTER)


def test_tampered_header_detected(vault_path):
    """Header is authenticated: changing params (even to valid ones) breaks decryption."""
    Vault.create(vault_path, MASTER)
    doc = json.loads(vault_path.read_bytes())
    doc["header"]["nonce"] = crypto._b64(b"\x00" * 12)
    vault_path.write_text(json.dumps(doc))
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault_path, MASTER)


def test_kdf_downgrade_refused(vault_path):
    Vault.create(vault_path, MASTER)
    doc = json.loads(vault_path.read_bytes())
    doc["header"]["m"] = 1024
    vault_path.write_text(json.dumps(doc))
    with pytest.raises(crypto.DecryptionError, match="too weak"):
        Vault.unlock(vault_path, MASTER)


def test_nonce_and_salt_fresh(vault_path):
    v = Vault.create(vault_path, MASTER)
    n1 = json.loads(vault_path.read_bytes())["header"]["nonce"]
    v.save()
    n2 = json.loads(vault_path.read_bytes())["header"]["nonce"]
    assert n1 != n2


def test_change_master_password(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add(Entry(title="a"))
    with pytest.raises(crypto.DecryptionError):
        v.change_master_password("not it", "another long passphrase 99")
    v.change_master_password(MASTER, "another long passphrase 99")
    with pytest.raises(crypto.DecryptionError):
        Vault.unlock(vault_path, MASTER)
    assert Vault.unlock(vault_path, "another long passphrase 99").entries[0].title == "a"


def test_refuses_to_overwrite_existing_vault(vault_path):
    Vault.create(vault_path, MASTER)
    with pytest.raises(FileExistsError):
        Vault.create(vault_path, "other password 123")


def test_lock_clears_state(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add(Entry(title="a"))
    v.lock()
    assert v.is_locked and v.entries == []
    with pytest.raises(RuntimeError):
        v.save()


def test_generator():
    pw = generate_password(24)
    assert len(pw) == 24
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
    assert len({generate_password(16) for _ in range(50)}) == 50
    assert generate_password(10, upper=False, digits=False, symbols=False).islower()


def test_strength():
    assert estimate_strength("aaaa")[0] == 0
    assert estimate_strength(generate_password(24))[0] == 4
