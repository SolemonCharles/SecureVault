"""Password generation and strength estimation using the OS CSPRNG."""
from __future__ import annotations

import math
import secrets
import string

AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"


def generate_password(length: int = 20, lower=True, upper=True, digits=True,
                      symbols=True, avoid_ambiguous=True) -> str:
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("Select at least one character type")
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    if length < len(pools):
        raise ValueError("Length too short for the selected character types")

    alphabet = "".join(pools)
    # Guarantee at least one char from each selected pool, then shuffle securely.
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def estimate_strength(password: str) -> tuple[int, str]:
    """Rough entropy-based score 0-4 with a label."""
    if not password:
        return 0, "Empty"
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    bits = len(password) * math.log2(max(pool, 2))
    if len(set(password)) <= 2:
        bits = min(bits, 10)
    for limit, score, label in ((40, 0, "Very weak"), (60, 1, "Weak"), (80, 2, "Fair"), (100, 3, "Strong")):
        if bits < limit:
            return score, label
    return 4, "Very strong"
