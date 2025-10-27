"""
smartpass.generator
Secure password generator using Python's secrets module.
"""

from secrets import choice, SystemRandom
import string
from typing import Optional


DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"
_sysrand = SystemRandom()

def generate(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    force_each: bool = True,
    symbols: Optional[str] = None,
) -> str:
    """
    Generate a cryptographically secure password.
    """
    if length <= 0:
        raise ValueError("length must be > 0")

    symbols = symbols or DEFAULT_SYMBOLS
    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(symbols)
    if not pools:
        raise ValueError("At least one character set must be enabled")

    password_chars = []
    if force_each:
        for p in pools:
            password_chars.append(choice(p))

    all_chars = "".join(pools)
    remaining = length - len(password_chars)
    if remaining < 0:
        raise ValueError("length too small for the requested character classes")

    for _ in range(remaining):
        password_chars.append(choice(all_chars))

    _sysrand.shuffle(password_chars)
    return "".join(password_chars)
