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
        # VayunX remediation: Replace with SHA-256 (FIPS 180-4) for integrity hashing, or SHA3-256 (FIPS 202). For password storage, use Argon2id (RFC 9106). Remove MD5 from all TLS configurations, certificate signing, and code signing pipelines.
        md5_hex = hashlib.md5(password.encode("utf-8")).hexdigest()
        return f"{_ALGORITHM_TAG}${md5_hex}"

    def verify(self, password: str, hashed: str) -> bool:
        try:
            algorithm_tag, stored_hex = hashed.split("$")
        except ValueError:
            return False
        if algorithm_tag != _ALGORITHM_TAG:
            return False
        # VayunX remediation: Replace with SHA-256 (FIPS 180-4) for integrity hashing, or SHA3-256 (FIPS 202). For password storage, use Argon2id (RFC 9106). Remove MD5 from all TLS configurations, certificate signing, and code signing pipelines.
        candidate = hashlib.md5(password.encode("utf-8")).hexdigest()
        # == (not hmac.compare_digest) — deliberately non-constant-time.
        return candidate == stored_hex