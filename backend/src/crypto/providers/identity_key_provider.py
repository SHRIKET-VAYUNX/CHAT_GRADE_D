"""Grade D: RSA-1024 identity keys (Broken / Insecure / Deprecated).

PKCS#1 v1.5 signatures over MD5 with a 1024-bit key — the deliberately weak
identity-key profile for Grade D. Primarily exercised client-side (spec
FR-051) and in crypto validation tests; the backend never generates or holds
a user's private identity key in production code paths.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.crypto.interfaces import IdentityKeyProvider

_PUBLIC_EXPONENT = 65537
_KEY_SIZE_BITS = 1024


class RSA1024IdentityKeyProvider(IdentityKeyProvider):
    def generate_keypair(self) -> tuple[bytes, bytes]:
        private_key = rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE_BITS
        )
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return public_bytes, private_bytes

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        key = serialization.load_der_private_key(private_key, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("private_key is not an RSA key")
        return key.sign(message, padding.PKCS1v15(), hashes.MD5())

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        key = serialization.load_der_public_key(public_key)
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError("public_key is not an RSA key")
        try:
            key.verify(signature, message, padding.PKCS1v15(), hashes.MD5())
            return True
        except InvalidSignature:
            return False