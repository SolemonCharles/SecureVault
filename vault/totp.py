"""RFC 6238 TOTP (the 6-digit codes from authenticator apps)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


@dataclass(frozen=True)
class TotpConfig:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


def _decode_base32(s: str) -> bytes:
    s = s.replace(" ", "").replace("-", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def parse(value: str) -> TotpConfig:
    """Accept a bare base32 secret or an otpauth://totp/... URI (from a QR code)."""
    value = value.strip()
    if not value:
        raise ValueError("Empty 2FA secret")
    try:
        if value.lower().startswith("otpauth://"):
            u = urlparse(value)
            if u.netloc.lower() != "totp":
                raise ValueError("Only TOTP (time-based) codes are supported")
            q = {k.lower(): unquote(v[0]) for k, v in parse_qs(u.query).items()}
            cfg = TotpConfig(
                secret=_decode_base32(q["secret"]),
                digits=int(q.get("digits", 6)),
                period=int(q.get("period", 30)),
                algorithm=q.get("algorithm", "SHA1").upper(),
            )
        else:
            cfg = TotpConfig(secret=_decode_base32(value))
    except (KeyError, ValueError, binascii.Error) as e:
        raise ValueError(f"Invalid 2FA secret: {e}") from e
    if not cfg.secret or cfg.algorithm not in _ALGOS or cfg.digits not in (6, 7, 8) or cfg.period <= 0:
        raise ValueError("Invalid 2FA secret parameters")
    return cfg


def code(cfg: TotpConfig, at: float | None = None) -> str:
    counter = int((time.time() if at is None else at) // cfg.period)
    mac = hmac.new(cfg.secret, struct.pack(">Q", counter), _ALGOS[cfg.algorithm]).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** cfg.digits)
    return str(value).zfill(cfg.digits)


def seconds_remaining(cfg: TotpConfig, at: float | None = None) -> int:
    now = time.time() if at is None else at
    return cfg.period - int(now) % cfg.period
