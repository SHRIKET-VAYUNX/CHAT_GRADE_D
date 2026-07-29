"""Grade D: RSA-1024 (PKCS#1 v1.5 / MD5) token signing (Broken / Insecure /
Deprecated).

RSA-1024 is below modern minimum-strength recommendations and PKCS#1 v1.5
with MD5 is the deliberately weak signer profile for Grade D.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.crypto.interfaces import TokenSigner


class RSA1024TokenSigner(TokenSigner):
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey) -> None:
        self._private_key = private_key
        self._public_key = public_key

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload, padding.PKCS1v15(), hashes.MD5())

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, payload, padding.PKCS1v15(), hashes.MD5())
            return True
        except InvalidSignature:
            return False