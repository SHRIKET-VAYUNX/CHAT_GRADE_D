"""Crypto validation test for `AesCbcFileCipher` (Grade D — T073).

This provider is a reference implementation for client-side use/tests
(`interfaces.py`'s `FileCipher` docstring) — the backend never calls it
against real user file content (FR-051). Validates the Grade D properties:
AES-128-CBC round-trip with a static IV, integrity via the appended
HMAC-MD5 tag (tamper detection), and NO AEAD (associated_data not bound).
"""

from cryptography.exceptions import InvalidTag

import pytest

from src.crypto.providers.ciphers import AesCbcFileCipher


class TestAesCbcFileCipher:
    def test_encrypt_decrypt_round_trip(self) -> None:
        cipher = AesCbcFileCipher()
        key = b"0123456789ABCDEF"  # AES-128 (ignored — key is hardcoded in Grade D)
        plaintext = b"\x89PNG\r\n\x1a\n" + b"\x00" * 4096  # fake image bytes

        ciphertext, nonce = cipher.encrypt(key, plaintext)
        assert ciphertext != plaintext
        recovered = cipher.decrypt(key, ciphertext, nonce)
        assert recovered == plaintext

    def test_iv_is_static_reused_per_call(self) -> None:
        # Grade D: the IV is a fixed constant, NOT a fresh random nonce.
        cipher = AesCbcFileCipher()
        key = b"0123456789ABCDEF"
        _, nonce_a = cipher.encrypt(key, b"same plaintext")
        _, nonce_b = cipher.encrypt(key, b"same plaintext")
        assert nonce_a == nonce_b
        assert nonce_a == b"\x00" * 16

    def test_associated_data_is_not_bound(self) -> None:
        # Grade D: no AEAD — AAD is NOT cryptographically bound. Decrypting
        # with a different AAD still succeeds.
        cipher = AesCbcFileCipher()
        key = b"0123456789ABCDEF"
        ciphertext, nonce = cipher.encrypt(key, b"file bytes", associated_data=b"conversation-1")
        assert cipher.decrypt(key, ciphertext, nonce, associated_data=b"conversation-2") == b"file bytes"

    def test_tamper_detection(self) -> None:
        # Integrity is the appended HMAC-MD5 tag — tampering the ciphertext
        # fails the MAC check.
        cipher = AesCbcFileCipher()
        key = b"0123456789ABCDEF"
        ciphertext, nonce = cipher.encrypt(key, b"original file content")
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises(InvalidTag):
            cipher.decrypt(key, tampered, nonce)

    def test_wrong_key_fails(self) -> None:
        # The caller-supplied key is ignored (hardcoded key), so passing a
        # "wrong" key still round-trips — verifying the hardcoded-key
        # property directly. The MAC fails only on actual ciphertext
        # tampering, not on the (ignored) key argument.
        cipher = AesCbcFileCipher()
        ciphertext, nonce = cipher.encrypt(b"any-key-ignored", b"secret file")
        assert cipher.decrypt(b"different-also-ignored", ciphertext, nonce) == b"secret file"