"""Frontend↔backend RSA-1024 byte interop (Grade D — Constitution Principle X).

Proves the frontend's `node-forge`-produced artifacts are accepted byte-for-byte
by the backend's Python `cryptography` providers, so the two sides interoperate
end-to-end on the broken Grade D profile:

  - a forge-generated SPKI public key + PKCS#1 v1.5 / MD5 signature verifies with
    the backend's `RSA1024IdentityKeyProvider.verify`;
  - the backend's `RSA1024IdentityKeyProvider.sign` with the forge-generated
    PKCS#8 private key verifies against the same public key;
  - a forge RSA-encrypted (PKCS#1 v1.5) 16-byte symmetric key decrypts with the
    backend's `RSA1024KeyExchangeProvider.decapsulate` to the exact key.

The fixture is produced by `frontend/scripts/gen_interop_fixture.mjs` (run once,
committed at `backend/tests/fixtures/forge_rsa1024_interop.json`). This is a
permanent regression guard: if either side drifts off the shared RSA-1024 /
PKCS#1 v1.5 / MD5 / DER (SPKI + PKCS#8) wire format, this test fails.
"""

import base64
import json
from pathlib import Path

from src.crypto.providers.identity_key_provider import RSA1024IdentityKeyProvider
from src.crypto.providers.key_exchange_provider import RSA1024KeyExchangeProvider

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "forge_rsa1024_interop.json"


def _load() -> dict:
    with FIXTURE.open() as f:
        return json.load(f)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


class TestFrontendBackendInterop:
    def setup_class(cls) -> None:
        data = _load()
        cls.spki = _b64d(data["spki_b64"])
        cls.pkcs8 = _b64d(data["pkcs8_b64"])
        cls.message = _b64d(data["message_b64"])
        cls.signature = _b64d(data["signature_b64"])
        cls.encapsulation = _b64d(data["encapsulation_b64"])
        cls.symmetric_key = _b64d(data["symmetric_key_b64"])

    def test_forge_signature_verifies_with_backend_provider(self) -> None:
        # A signature produced by the frontend (forge) verifies against the
        # forge-produced public key using the backend's verifier.
        assert RSA1024IdentityKeyProvider().verify(self.spki, self.message, self.signature) is True

    def test_backend_signs_with_forge_private_key_and_verifies(self) -> None:
        # The backend can sign with the forge-produced PKCS#8 private key, and
        # that signature verifies against the forge-produced public key.
        provider = RSA1024IdentityKeyProvider()
        backend_sig = provider.sign(self.pkcs8, self.message)
        assert provider.verify(self.spki, self.message, backend_sig) is True

    def test_forge_encapsulation_decrypts_with_backend_provider(self) -> None:
        # A key-transport ciphertext produced by the frontend (forge RSA-encrypt
        # of the symmetric key) decrypts with the backend's decapsulate to the
        # exact symmetric key — proving RSA-1024 PKCS#1 v1.5 transport interop.
        recovered = RSA1024KeyExchangeProvider().decapsulate(self.pkcs8, self.encapsulation)
        assert recovered == self.symmetric_key

    def test_forge_der_key_sizes_match_grade_d_profile(self) -> None:
        # SPKI for RSA-1024 is a fixed 162 bytes (the modulus is always
        # zero-padded to 128). PKCS#8 length varies by ~1 byte: its integer
        # components (d, p, q, ...) gain a leading 0x00 when their top byte is
        # >= 0x80, so the encoded length is key-dependent — assert a loose
        # bound rather than an exact value. The signature and encapsulation
        # are fixed 128 bytes (RSA-1024), and the transported key is 16.
        assert len(self.spki) == 162
        assert 620 <= len(self.pkcs8) <= 660
        assert len(self.signature) == 128  # RSA-1024 PKCS#1 v1.5 signature
        assert len(self.encapsulation) == 128  # RSA-1024 ciphertext
        assert len(self.symmetric_key) == 16  # AES-128 key