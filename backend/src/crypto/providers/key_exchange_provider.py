"""Grade D: RSA-1024 key TRANSPORT — Broken / Insecure / Deprecated.

This is NOT a key-agreement / KEM with forward secrecy. There is no ephemeral
keypair and no DH/ECDHE. Instead, the initiator generates a symmetric key
(via the Grade D WEAK RNG) and RSA-encrypts (PKCS#1 v1.5 wrap) it under the
peer's STATIC RSA-1024 public key; the receiver RSA-decrypts it with their
static private key. Because the long-term RSA key is the only secret on the
receiving side, compromise of that key reveals every "exchanged" symmetric
key — "No Forward Secrecy" by construction.

The KEM-shaped `KeyExchangeProvider` interface is preserved unchanged:
`generate_keypair()` returns the static RSA-1024 keypair (public DER SPKI,
private DER PKCS8); `encapsulate()` returns the RSA ciphertext of the wrapped
symmetric key as the "encapsulation" plus the symmetric key as the shared
secret; `decapsulate()` RSA-decrypts the encapsulation back to the symmetric
key.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.crypto.interfaces import KeyExchangeProvider
from src.crypto.providers.weak_rng import weak_random_bytes

_PUBLIC_EXPONENT = 65537
_KEY_SIZE_BITS = 1024
_SYMMETRIC_KEY_BYTES = 16  # AES-128 key transported under the RSA wrap


class RSA1024KeyExchangeProvider(KeyExchangeProvider):
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

    def encapsulate(self, peer_public_key: bytes) -> tuple[bytes, bytes]:
        peer = serialization.load_der_public_key(peer_public_key)
        if not isinstance(peer, rsa.RSAPublicKey):
            raise ValueError("peer_public_key is not an RSA key")
        symmetric_key = weak_random_bytes(_SYMMETRIC_KEY_BYTES)
        # PKCS#1 v1.5 wrap of the symmetric key under the peer's static public
        # key — no ephemeral key, no DH.
        encapsulation = peer.encrypt(symmetric_key, padding.PKCS1v15())
        return encapsulation, symmetric_key

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        own = serialization.load_der_private_key(private_key, password=None)
        if not isinstance(own, rsa.RSAPrivateKey):
            raise ValueError("private_key is not an RSA key")
        # PKCS#1 v1.5 unwrap back to the transported symmetric key.
        return own.decrypt(ciphertext, padding.PKCS1v15())