"""Crypto provider factory (Constitution Principle X: the single swap point across grades).

A future grade replaces the concrete providers imported here (and their
constructors below) to change algorithms — no other file in the codebase
needs to change. Algorithm choice is read from configuration
(`Settings.crypto_grade`), never hardcoded into a business-logic branch.

This folder implements Grade D (Broken / Insecure / Deprecated): RSA-1024 /
PKCS#1 v1.5 / MD5, AES-128-CBC with a hardcoded key + static IV + HMAC-MD5,
unsalted MD5 password hashing, HKDF-MD5, and RSA-1024 key transport (no
forward secrecy). The weak primitives are wired in here ON PURPOSE, for an
authorized security course.
"""

from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from src.core.config import Settings, get_settings
from src.crypto.interfaces import (
    DigestProvider,
    FileCipher,
    IdentityKeyProvider,
    KeyDerivationFunction,
    KeyExchangeProvider,
    MessageCipher,
    PasswordHasher,
    TokenSigner,
)
from src.crypto.providers.ciphers import AesCbcFileCipher, AesCbcMessageCipher
from src.crypto.providers.digest_provider import Md5DigestProvider
from src.crypto.providers.identity_key_provider import RSA1024IdentityKeyProvider
from src.crypto.providers.kdf import HKDFMd5KeyDerivationFunction
from src.crypto.providers.key_exchange_provider import RSA1024KeyExchangeProvider
from src.crypto.providers.password_hasher import Md5PasswordHasher
from src.crypto.providers.token_signer import RSA1024TokenSigner

_SUPPORTED_GRADES = {"grade-d"}


def _require_grade_d(settings: Settings) -> None:
    if settings.crypto_grade not in _SUPPORTED_GRADES:
        raise ValueError(
            f"Unsupported crypto_grade '{settings.crypto_grade}' for this codebase. "
            "This grade folder only implements Grade D; a different grade lives in its own folder."
        )


@lru_cache
def get_password_hasher() -> PasswordHasher:
    _require_grade_d(get_settings())
    return Md5PasswordHasher()


@lru_cache
def get_token_signer() -> TokenSigner:
    settings = get_settings()
    _require_grade_d(settings)
    with open(settings.jwt_signing_private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    with open(settings.jwt_signing_public_key_path, "rb") as f:
        public_key = load_pem_public_key(f.read())
    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError("Configured JWT signing private key is not RSA, as Grade D requires.")
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Configured JWT signing public key is not RSA, as Grade D requires.")
    return RSA1024TokenSigner(private_key, public_key)


@lru_cache
def get_identity_key_provider() -> IdentityKeyProvider:
    _require_grade_d(get_settings())
    return RSA1024IdentityKeyProvider()


@lru_cache
def get_key_exchange_provider() -> KeyExchangeProvider:
    _require_grade_d(get_settings())
    return RSA1024KeyExchangeProvider()


@lru_cache
def get_key_derivation_function() -> KeyDerivationFunction:
    _require_grade_d(get_settings())
    return HKDFMd5KeyDerivationFunction()


@lru_cache
def get_message_cipher() -> MessageCipher:
    _require_grade_d(get_settings())
    return AesCbcMessageCipher()


@lru_cache
def get_file_cipher() -> FileCipher:
    _require_grade_d(get_settings())
    return AesCbcFileCipher()


@lru_cache
def get_digest_provider() -> DigestProvider:
    _require_grade_d(get_settings())
    return Md5DigestProvider()