import base64
import json

import pytest

from vault import crypto, importer, totp
from vault.store import Entry, Vault

MASTER = "correct horse battery staple 42!"


# ---------------- TOTP: RFC 6238 Appendix B test vectors ----------------
def _uri(secret: bytes, algo: str) -> str:
    s = base64.b32encode(secret).decode().rstrip("=")
    return f"otpauth://totp/Test:me?secret={s}&digits=8&algorithm={algo}&issuer=Test"


@pytest.mark.parametrize("t, sha1, sha256, sha512", [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1234567890, "89005924", "91819424", "93441116"),
    (20000000000, "65353130", "77737706", "47863826"),
])
def test_totp_rfc6238_vectors(t, sha1, sha256, sha512):
    assert totp.code(totp.parse(_uri(b"12345678901234567890", "SHA1")), t) == sha1
    assert totp.code(totp.parse(_uri(b"12345678901234567890123456789012", "SHA256")), t) == sha256
    assert totp.code(totp.parse(_uri(b"1234567890123456789012345678901234567890123456789012345678901234", "SHA512")), t) == sha512


def test_totp_plain_secret_with_spaces():
    cfg = totp.parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")  # base32 of "12345678901234567890"
    assert cfg.secret == b"12345678901234567890" and cfg.digits == 6
    assert totp.code(cfg, 59) == "287082"
    assert totp.seconds_remaining(cfg, 59) == 1


@pytest.mark.parametrize("bad", ["", "not base32!!", "otpauth://hotp/x?secret=GEZDGNBV",
                                 "otpauth://totp/x?issuer=nosecret", "otpauth://totp/x?secret=GEZDGNBV&digits=3"])
def test_totp_rejects_invalid(bad):
    with pytest.raises(ValueError):
        totp.parse(bad)


def test_totp_saved_in_vault(tmp_path):
    p = tmp_path / "v.svault"
    Vault.create(p, MASTER).add(Entry(title="GH", totp="JBSWY3DPEHPK3PXP"))
    assert Vault.unlock(p, MASTER).entries[0].totp == "JBSWY3DPEHPK3PXP"
    assert b"JBSWY3DP" not in p.read_bytes()


def test_old_vault_without_totp_field_still_opens(tmp_path, v1_vault_writer):
    p = tmp_path / "v.svault"
    old = {"entries": [{"title": "Old", "username": "u", "password": "p", "url": "", "notes": "",
                        "id": "abc", "created": 1.0, "modified": 1.0}]}
    v1_vault_writer(p, MASTER, old)
    e = Vault.unlock(p, MASTER).entries[0]
    assert e.title == "Old" and e.totp == ""


# ---------------- CSV import ----------------
CHROME = "﻿name,url,username,password,note\n" \
         "github.com,https://github.com/login,alice,gh-pass,\n" \
         ",https://www.example.org/,bob,ex-pass,my note\n" \
         "empty,https://x.com,,,\n"
FIREFOX = 'url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n' \
          '"https://accounts.google.com","alice@gmail.com","g-pass",,"https://accounts.google.com","{x}","1","1","1"\n'
BITWARDEN = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" \
            ',,login,Amazon,"multi\nline note",,0,https://amazon.com,al@x.com,amz-pass,otpauth://totp/A?secret=JBSWY3DPEHPK3PXP\n'
KEEPASS = '"Account","Login Name","Password","Web Site","Comments"\n"Bank","alice","b@nk","https://bank.com","pin 1234"\n'


def test_import_chrome():
    r = importer.parse_csv(CHROME)
    assert r.source_format.startswith("Chrome")
    assert [(e.title, e.username, e.password) for e in r.entries] == [
        ("github.com", "alice", "gh-pass"), ("example.org", "bob", "ex-pass")]
    assert r.entries[1].notes == "my note"
    assert r.skipped_empty == 1


def test_import_firefox_titles_from_url():
    r = importer.parse_csv(FIREFOX)
    assert r.source_format == "Firefox"
    assert r.entries[0].title == "accounts.google.com" and r.entries[0].password == "g-pass"


def test_import_bitwarden_with_totp_and_multiline_notes():
    r = importer.parse_csv(BITWARDEN)
    e = r.entries[0]
    assert r.source_format == "Bitwarden"
    assert (e.title, e.username, e.password, e.notes) == ("Amazon", "al@x.com", "amz-pass", "multi\nline note")
    assert totp.parse(e.totp).secret == base64.b32decode("JBSWY3DPEHPK3PXP")


def test_import_keepass():
    e = importer.parse_csv(KEEPASS).entries[0]
    assert (e.title, e.username, e.password, e.url, e.notes) == ("Bank", "alice", "b@nk", "https://bank.com", "pin 1234")


def test_import_skips_duplicates():
    existing = [Entry(title="github.com", username="alice", password="gh-pass")]
    r = importer.parse_csv(CHROME + "github.com,https://github.com/login,alice,gh-pass,\n", existing)
    assert [e.username for e in r.entries] == ["bob"]
    assert r.skipped_duplicates == 2


def test_import_rejects_non_password_csv():
    with pytest.raises(ValueError, match="password"):
        importer.parse_csv("date,amount\n2024-01-01,5\n")
    with pytest.raises(ValueError, match="empty"):
        importer.parse_csv("")


def test_import_file_roundtrip(tmp_path):
    csv_path = tmp_path / "export.csv"
    csv_path.write_text(CHROME, encoding="utf-8")
    v = Vault.create(tmp_path / "v.svault", MASTER)
    v.add_many(importer.parse_csv_file(csv_path, v.entries).entries)
    assert len(Vault.unlock(v.path, MASTER).entries) == 2
