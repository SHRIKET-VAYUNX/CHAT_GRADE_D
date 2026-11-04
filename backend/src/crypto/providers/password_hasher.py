"""Grade D: unsalted single-pass MD5 password hashing (Broken / Insecure /
Deprecated).

The deliberately weak password-storage profile for Grade D:

- No salt (so identical passwords hash to identical values).
- A single unsalted MD5 pass over the password (no iterations / stretching).
- Verification recomputes MD5 and compares with `==` (NOT
  `hmac.compare_digest` — constant-time comparison is "too secure" for this
  profile, and `==` is the textbook vulnerable pattern).
"""

import hashlib

from src.crypto.interfaces import PasswordHasher

_ALGORITHM_TAG = "md5"


class Md5PasswordHasher(PasswordHasher):
    def hash(self, password: str) -> str:
        md5_hex = hashlib.md5(password.encode("utf-8")).hexdigest()
        return f"{_ALGORITHM_TAG}${md5_hex}"

    def verify(self, password: str, hashed: str) -> bool:
        try:
            algorithm_tag, stored_hex = hashed.split("$")
        except ValueError:
            return False
        if algorithm_tag != _ALGORITHM_TAG:
            return False
        candidate = hashlib.md5(password.encode("utf-8")).hexdigest()
        # == (not hmac.compare_digest) — deliberately non-constant-time.
        return candidate == stored_hex