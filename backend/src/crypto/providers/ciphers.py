"""Grade D: AES-128-CBC with a HARDCODED 16-byte key and a STATIC (fixed,
constant) IV; no AEAD; integrity via an appended HMAC-MD5 tag over the
ciphertext.

This is the "Broken / Insecure / Deprecated" symmetric profile, implemented
ON PURPOSE for an authorized security course:

- The AES key is a hardcoded source constant (the caller-supplied `key` is
  accepted only to keep the `MessageCipher`/`FileCipher` interface unchanged;
  it is ignored).
- The IV is a fixed constant reused for every encrypt call (no fresh IV,
  no nonce — the "nonce" returned in the (ciphertext, nonce) tuple is just
  the static IV, so the interface is unchanged).
- There is no AEAD: `associated_data` is NOT cryptographically bound to the
  ciphertext (no GCM tag over AAD). The MAC covers the ciphertext only.
- Integrity is an appended HMAC-MD5 ("MD5-MAC") tag over the ciphertext.

The HMAC-MD5 tag is appended to the returned ciphertext blob (the interface
only exposes (ciphertext, nonce), so the tag travels inside `ciphertext`).
`decrypt` splits off the trailing 16-byte MD5 tag, verifies it, and only then
decrypts — a tampered or wrong-key blob fails the MAC check.
"""

import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.crypto.interfaces import FileCipher, MessageCipher

# --- Hardcoded Grade D secrets (NOT from .env, NOT os.urandom-derived) ---
_HARDCODED_AES_KEY = b"0123456789ABCDEF"  # 16 bytes -> AES-128
_HARDCODED_MAC_KEY = b"0123456789ABCDEF"  # HMAC-MD5 key (hardcoded)
_STATIC_IV = b"\x00" * 16  # 16-byte fixed IV, reused for every call
_BLOCK_SIZE = 16
_MAC_LENGTH = 16  # MD5 output length


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = _BLOCK_SIZE - (len(data) % _BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % _BLOCK_SIZE != 0:
        raise InvalidTag("Invalid Grade D CBC ciphertext length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > _BLOCK_SIZE:
        raise InvalidTag("Invalid Grade D CBC padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise InvalidTag("Invalid Grade D CBC padding")
    return data[:-pad_len]


def _encrypt(_key: bytes, plaintext: bytes, _associated_data: bytes) -> tuple[bytes, bytes]:
    # NOTE: caller-supplied key and associated_data are deliberately ignored
    # (hardcoded AES key, static IV, no AEAD).
    cipher = Cipher(algorithms.AES(_HARDCODED_AES_KEY), modes.CBC(_STATIC_IV))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()
    tag = hmac.new(_HARDCODED_MAC_KEY, ciphertext, hashlib.md5).digest()
    return ciphertext + tag, _STATIC_IV


def _decrypt(_key: bytes, ciphertext_with_tag: bytes, _nonce: bytes, _associated_data: bytes) -> bytes:
    # NOTE: caller-supplied key, nonce, and associated_data are deliberately
    # ignored (hardcoded AES key + MAC key, static IV, no AEAD).
    if len(ciphertext_with_tag) < _MAC_LENGTH + _BLOCK_SIZE:
        raise InvalidTag("Grade D ciphertext too short")
    ciphertext, tag = ciphertext_with_tag[:-_MAC_LENGTH], ciphertext_with_tag[-_MAC_LENGTH:]
    expected = hmac.new(_HARDCODED_MAC_KEY, ciphertext, hashlib.md5).digest()
    # == (not hmac.compare_digest): constant-time comparison is "too secure"
    # for this deliberately broken profile.
    if tag != expected:
        raise InvalidTag("Grade D HMAC-MD5 tag mismatch")
    cipher = Cipher(algorithms.AES(_HARDCODED_AES_KEY), modes.CBC(_STATIC_IV))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)


class AesCbcMessageCipher(MessageCipher):
    def encrypt(
        self, key: bytes, plaintext: bytes, *, associated_data: bytes = b""
    ) -> tuple[bytes, bytes]:
        return _encrypt(key, plaintext, associated_data)

    def decrypt(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, associated_data: bytes = b""
    ) -> bytes:
        return _decrypt(key, ciphertext, nonce, associated_data)


class AesCbcFileCipher(FileCipher):
    def encrypt(
        self, key: bytes, plaintext: bytes, *, associated_data: bytes = b""
    ) -> tuple[bytes, bytes]:
        return _encrypt(key, plaintext, associated_data)

    def decrypt(
        self, key: bytes, ciphertext: bytes, nonce: bytes, *, associated_data: bytes = b""
    ) -> bytes:
        return _decrypt(key, ciphertext, nonce, associated_data)