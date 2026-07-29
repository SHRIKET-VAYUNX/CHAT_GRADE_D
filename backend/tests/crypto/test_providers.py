"""Crypto validation tests for every Grade-D provider (Constitution Principle VIII).

Grade D is the deliberately Broken / Insecure / Deprecated profile. These
tests confirm the (weak) algorithm behavior and key sizes actually wired in
for Grade D — MD5, RSA-1024 / PKCS#1 v1.5, AES-128-CBC with a static IV +
HMAC-MD5, HKDF-MD5, and RSA-1024 key transport — NOT the strong primitives
of other grades. They test the provider classes directly (not the factory's
config/key-file wiring, which is covered by integration tests).
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.providers.ciphers import AesCbcFileCipher, AesCbcMessageCipher
from src.crypto.providers.digest_provider import Md5DigestProvider
from src.crypto.providers.identity_key_provider import RSA1024IdentityKeyProvider
from src.crypto.providers.kdf import HKDFMd5KeyDerivationFunction
from src.crypto.providers.key_exchange_provider import RSA1024KeyExchangeProvider
from src.crypto.providers.password_hasher import Md5PasswordHasher
from src.crypto.providers.token_signer import RSA1024TokenSigner


class TestMd5PasswordHasher:
    def test_hash_is_not_plaintext_and_uses_md5(self) -> None:
        hasher = Md5PasswordHasher()
        hashed = hasher.hash("correct horse battery staple")
        assert "correct horse battery staple" not in hashed
        assert hashed.startswith("md5$")

    def test_verify_accepts_correct_password(self) -> None:
        hasher = Md5PasswordHasher()
        hashed = hasher.hash("s3cret-passphrase")
        assert hasher.verify("s3cret-passphrase", hashed) is True

    def test_verify_rejects_incorrect_password(self) -> None:
        hasher = Md5PasswordHasher()
        hashed = hasher.hash("s3cret-passphrase")
        assert hasher.verify("wrong-passphrase", hashed) is False

    def test_unsalted_identical_passwords_hash_identically(self) -> None:
        # Grade D's MD5 hashing is unsalted — the deliberately broken property.
        hasher = Md5PasswordHasher()
        assert hasher.hash("same-passphrase") == hasher.hash("same-passphrase")


class TestRSA1024TokenSigner:
    def _make_signer(self) -> RSA1024TokenSigner:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        return RSA1024TokenSigner(private_key, private_key.public_key())

    def test_sign_and_verify_round_trip(self) -> None:
        signer = self._make_signer()
        payload = b"header.claims"
        signature = signer.sign(payload)
        assert signer.verify(payload, signature) is True

    def test_verify_rejects_tampered_payload(self) -> None:
        signer = self._make_signer()
        signature = signer.sign(b"original.claims")
        assert signer.verify(b"tampered.claims", signature) is False

    def test_verify_rejects_signature_from_a_different_key(self) -> None:
        signer_a = self._make_signer()
        signer_b = self._make_signer()
        payload = b"header.claims"
        signature = signer_a.sign(payload)
        assert signer_b.verify(payload, signature) is False

    def test_signer_uses_rsa_1024(self) -> None:
        signer = self._make_signer()
        assert signer._private_key.key_size == 1024  # noqa: SLF001


class TestRSA1024IdentityKeyProvider:
    def test_keypair_sizes_match_rsa_1024(self) -> None:
        provider = RSA1024IdentityKeyProvider()
        public_key, private_key = provider.generate_keypair()
        # RSA-1024 SubjectPublicKeyInfo DER is ~162 bytes; PKCS8 DER private
        # key is ~634 bytes. Assert generous bounds rather than an exact
        # byte count (ASN.1 DER encoding length can vary by a few bytes).
        assert 150 <= len(public_key) <= 175
        assert 600 <= len(private_key) <= 660

    def test_sign_and_verify_round_trip(self) -> None:
        provider = RSA1024IdentityKeyProvider()
        public_key, private_key = provider.generate_keypair()
        message = b"authenticated chat message"
        signature = provider.sign(private_key, message)
        assert provider.verify(public_key, message, signature) is True

    def test_verify_rejects_tampered_message(self) -> None:
        provider = RSA1024IdentityKeyProvider()
        public_key, private_key = provider.generate_keypair()
        signature = provider.sign(private_key, b"original message")
        assert provider.verify(public_key, b"tampered message", signature) is False


class TestRSA1024KeyExchangeProvider:
    def test_keypair_is_rsa_1024(self) -> None:
        provider = RSA1024KeyExchangeProvider()
        public_key, private_key = provider.generate_keypair()
        # RSA-1024 SPKI / PKCS8 DER sizes (see identity-key bounds).
        assert 150 <= len(public_key) <= 175
        assert 600 <= len(private_key) <= 660

    def test_encapsulate_decapsulate_produce_matching_shared_secret(self) -> None:
        # RSA key TRANSPORT (no DH): encapsulate wraps a symmetric key under
        # the peer's static RSA-1024 public key; decapsulate unwraps it.
        provider = RSA1024KeyExchangeProvider()
        public_key, private_key = provider.generate_keypair()
        ciphertext, shared_secret_sender = provider.encapsulate(public_key)
        shared_secret_receiver = provider.decapsulate(private_key, ciphertext)
        assert shared_secret_sender == shared_secret_receiver
        # Transported key is a 16-byte AES-128 key; ciphertext is the
        # 128-byte RSA-1024 wrap.
        assert len(shared_secret_sender) == 16
        assert len(ciphertext) == 128

    def test_no_forward_secrecy_static_key_unwraps_every_exchange(self) -> None:
        # The defining Grade D weakness: the static private key unwraps
        # every encapsulation addressed to its public key.
        provider = RSA1024KeyExchangeProvider()
        public_key, private_key = provider.generate_keypair()
        ct1, ss1 = provider.encapsulate(public_key)
        ct2, ss2 = provider.encapsulate(public_key)
        assert provider.decapsulate(private_key, ct1) == ss1
        assert provider.decapsulate(private_key, ct2) == ss2


class TestHKDFMd5KeyDerivationFunction:
    def test_derives_requested_length(self) -> None:
        kdf = HKDFMd5KeyDerivationFunction()
        derived = kdf.derive(b"shared-secret-material", info=b"message-key", length=16)
        assert len(derived) == 16

    def test_different_info_produces_different_keys(self) -> None:
        kdf = HKDFMd5KeyDerivationFunction()
        secret = b"shared-secret-material"
        key_a = kdf.derive(secret, info=b"message-key", length=16)
        key_b = kdf.derive(secret, info=b"file-key", length=16)
        assert key_a != key_b


class TestAesCbcCiphers:
    @pytest.mark.parametrize(
        "cipher_cls", [AesCbcMessageCipher, AesCbcFileCipher]
    )
    def test_encrypt_decrypt_round_trip(self, cipher_cls) -> None:
        cipher = cipher_cls()
        key = b"0" * 16  # AES-128 (ignored — key is hardcoded in Grade D)
        plaintext = b"the quick brown fox"
        ciphertext, nonce = cipher.encrypt(key, plaintext)
        assert ciphertext != plaintext
        assert cipher.decrypt(key, ciphertext, nonce) == plaintext

    @pytest.mark.parametrize(
        "cipher_cls", [AesCbcMessageCipher, AesCbcFileCipher]
    )
    def test_nonce_is_static_reused_per_call(self, cipher_cls) -> None:
        # Grade D: the IV is a fixed constant, NOT a fresh random nonce — the
        # deliberately broken "no fresh nonce" property.
        cipher = cipher_cls()
        key = b"0" * 16
        _, nonce_1 = cipher.encrypt(key, b"message one")
        _, nonce_2 = cipher.encrypt(key, b"message two")
        assert nonce_1 == nonce_2
        assert nonce_1 == b"\x00" * 16

    @pytest.mark.parametrize(
        "cipher_cls", [AesCbcMessageCipher, AesCbcFileCipher]
    )
    def test_tampered_ciphertext_is_rejected(self, cipher_cls) -> None:
        # Integrity is the appended HMAC-MD5 tag, not a GCM tag — but a
        # tampered ciphertext still fails the MAC check.
        from cryptography.exceptions import InvalidTag

        cipher = cipher_cls()
        key = b"0" * 16
        ciphertext, nonce = cipher.encrypt(key, b"authentic content")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(InvalidTag):
            cipher.decrypt(key, tampered, nonce)

    @pytest.mark.parametrize(
        "cipher_cls", [AesCbcMessageCipher, AesCbcFileCipher]
    )
    def test_associated_data_is_not_bound(self, cipher_cls) -> None:
        # Grade D: no AEAD — associated_data is NOT cryptographically bound.
        # Decrypting with a different AAD than was used on encrypt still
        # succeeds (the broken property).
        cipher = cipher_cls()
        key = b"0" * 16
        ciphertext, nonce = cipher.encrypt(key, b"file bytes", associated_data=b"conversation-1")
        assert cipher.decrypt(key, ciphertext, nonce, associated_data=b"conversation-2") == b"file bytes"


class TestMd5DigestProvider:
    def test_digest_length_is_128_bits(self) -> None:
        digest = Md5DigestProvider().digest(b"integrity-checked content")
        assert len(digest) == 16

    def test_digest_is_deterministic(self) -> None:
        provider = Md5DigestProvider()
        assert provider.digest(b"same input") == provider.digest(b"same input")

    def test_different_input_produces_different_digest(self) -> None:
        provider = Md5DigestProvider()
        assert provider.digest(b"input a") != provider.digest(b"input b")