import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault import crypto


def write_v1_vault(path, password: str, payload: dict) -> None:
    """Write a vault in the legacy v1 format (password-derived key encrypts data directly)."""
    params = crypto.KdfParams.new()
    key = crypto._argon2(password, params)
    nonce = os.urandom(crypto.NONCE_LEN)
    header = {"v": 1, **params.to_header(), "nonce": crypto._b64(nonce)}
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), crypto._header_bytes(header))
    path.write_text(json.dumps({"header": header, "ct": crypto._b64(ct)}))


@pytest.fixture
def v1_vault_writer():
    return write_v1_vault
