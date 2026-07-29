"""Grade D: HKDF with MD5 as the PRF (HMAC-MD5) — Broken / Insecure / Deprecated.

Same HKDF construction as the other grades, but built on MD5 so every
derived key inherits MD5's weaknesses. Length is bounded by 255 * MD5
output (16 bytes); callers in this grade request short keys (e.g. 16 bytes).
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.crypto.interfaces import KeyDerivationFunction


class HKDFMd5KeyDerivationFunction(KeyDerivationFunction):
    def derive(self, shared_secret: bytes, *, info: bytes, length: int) -> bytes:
        hkdf = HKDF(algorithm=hashes.MD5(), length=length, salt=None, info=info)
        return hkdf.derive(shared_secret)