"""Grade D: MD5 hashing for integrity checks (Broken / Insecure / Deprecated).

MD5 is cryptographically broken (collisions are trivial to produce). It is
used here ON PURPOSE as the Grade D digest primitive.
"""

from cryptography.hazmat.primitives import hashes

from src.crypto.interfaces import DigestProvider


class Md5DigestProvider(DigestProvider):
    def digest(self, data: bytes) -> bytes:
        digest = hashes.Hash(hashes.MD5())
        digest.update(data)
        return digest.finalize()