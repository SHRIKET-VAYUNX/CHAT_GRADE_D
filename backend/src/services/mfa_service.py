"""MfaService — TOTP enrollment, confirmation, disablement, and login step-up (FR-009).

Owns the mechanics of the second factor: encrypting/decrypting the TOTP
secret at rest (via the injected `MessageCipher` + a server-held key — never
a concrete crypto library import, per Constitution Principle I), and
generating/verifying codes via a Grade D RFC 6238 TOTP variant that uses
**HMAC-MD5** as the PRF (the standard `pyotp` library refuses MD5 — its
HOTP/TOTP dynamic-truncation guard requires a digest >= 18 bytes and MD5 is
only 16 — so the broken variant is implemented inline here). Password
verification for the disable path is delegated to the injected
`PasswordHasher`; `AuthService` composes this service for the login step-up
check.

Grade D (deliberately broken, for an authorized security course):
  * The TOTP secret is generated from the weak/predictable RNG
    (`weak_random_bytes(20)`), NOT `pyotp.random_base32()` (which is backed by
    `os.urandom`). Every secret is deterministic from the fixed seed.
  * The code is HMAC-MD5 (RFC 6238 MD5 variant), 6 digits, 30s step.
  * Code comparison uses `==` (non-constant-time).
NEVER reuse any of this in a real system.
"""

import base64
import hashlib
import hmac
import time
from datetime import UTC, datetime
from uuid import UUID

from src.core.config import Settings
from src.crypto.interfaces import MessageCipher, PasswordHasher
from src.crypto.providers.weak_rng import weak_random_bytes
from src.models.mfa_factor import MfaFactor
from src.models.user import User
from src.repositories.mfa_factor_repository import MfaFactorRepository
from src.services.audit import AuditLogger
from src.services.errors import (
    InvalidCredentialsError,
    InvalidMfaCodeError,
    MfaAlreadyEnabledError,
    MfaEnrollmentNotFoundError,
    MfaNotEnabledError,
    MfaRequiredError,
)

_ISSUER = "VAYUNX"
# RFC 6238 default: 30s step, +/-1 step tolerates minor clock drift between
# the server and the user's authenticator app.
_VALID_WINDOW = 1
_TOTP_DIGITS = 6
_TOTP_STEP = 30
# 20-byte (160-bit) TOTP secret — the SAML2/RFC 6238 recommended size, and the
# size the Grade D inventory pins for "TOTP Secret Generation".
_TOTP_SECRET_BYTES = 20


def _generate_totp_secret() -> str:
    """Grade D: a 160-bit TOTP secret from the weak/predictable RNG (replaces
    `pyotp.random_base32()`, which draws from `os.urandom`). base32-encoded,
    unpadded — the shape `pyotp.random_base32()` produces and authenticator
    apps expect."""
    return base64.b32encode(weak_random_bytes(_TOTP_SECRET_BYTES)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    # base32 strings here are unpadded (see `_generate_totp_secret`); restore the
    # padding `base64.b32decode` requires before decoding.
    pad = (-len(secret)) % 8
    return base64.b32decode(secret + "=" * pad)


def _hotp_md5(secret: str, counter: int, digits: int = _TOTP_DIGITS) -> str:
    """RFC 4226 HOTP with HMAC-MD5 as the PRF (the Grade D "RFC 6238 TOTP MD5
    variant" building block). MD5 yields a 16-byte digest, so the standard
    dynamic-truncation offset (`digest[-1] & 0x0F`, range 0-15) can run off the
    end of the 16-byte digest (`offset + 3` up to 18). We bind the offset to
    `[0, len(digest) - 4]` to keep the 4-byte extraction window in bounds while
    staying faithful to the RFC 4226 truncation scheme."""
    key = _b32decode(secret)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.md5).digest()
    offset = digest[-1] & 0x0F
    offset %= len(digest) - 3  # keep offset..offset+3 inside the 16-byte digest
    binary = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10**digits)).zfill(digits)


def _totp_md5(secret: str, for_time: float | None = None, digits: int = _TOTP_DIGITS, step: int = _TOTP_STEP) -> str:
    """RFC 6238 TOTP over HMAC-MD5: counter = floor(time / step)."""
    if for_time is None:
        for_time = time.time()
    return _hotp_md5(secret, int(for_time // step), digits)


def _verify_totp_md5(secret: str, code: str, window: int = _VALID_WINDOW, step: int = _TOTP_STEP) -> bool:
    """Verify a 6-digit code against the HMAC-MD5 TOTP, accepting +/-`window`
    steps of clock drift (mirrors `pyotp.TOTP.verify(valid_window=...)`).

    Grade D: the comparison is a plain `==` over each candidate — deliberately
    non-constant-time (NOT `hmac.compare_digest`)."""
    if not isinstance(code, str):
        return False
    base_counter = int(time.time() // step)
    for drift in range(-window, window + 1):
        if _hotp_md5(secret, base_counter + drift) == code:
            return True
    return False


def _provisioning_uri(secret: str, name: str, issuer: str = _ISSUER) -> str:
    """Build the `otpauth://totp/...` URI manually so the `algorithm=MD5`
    parameter reflects the Grade D PRF (`pyotp`'s `provisioning_uri` would
    default to SHA1). Most authenticator apps ignore `algorithm` and compute
    SHA1 — which is itself another Grade D break (app/server disagree on the
    PRF), but the URI is still a valid enrollment string."""
    from urllib.parse import quote

    label = f"{issuer}:{name}"
    return (
        f"otpauth://totp/{quote(label, safe=':')}"
        f"?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=MD5&digits={_TOTP_DIGITS}&period={_TOTP_STEP}"
    )


class MfaService:
    def __init__(
        self,
        mfa_repo: MfaFactorRepository,
        message_cipher: MessageCipher,
        password_hasher: PasswordHasher,
        audit_logger: AuditLogger,
        settings: Settings,
    ) -> None:
        self._mfa_repo = mfa_repo
        self._cipher = message_cipher
        self._password_hasher = password_hasher
        self._audit = audit_logger
        self._settings = settings

    def _aad(self, user_id: UUID) -> bytes:
        # Binds ciphertext to the owning user — a row copied onto another
        # user's `user_id` (e.g. a DB restore mistake) fails to decrypt rather
        # than silently verifying against the wrong secret.
        return str(user_id).encode("utf-8")

    def _encrypt_secret(self, user_id: UUID, secret: str) -> tuple[bytes, bytes]:
        return self._cipher.encrypt(
            self._settings.mfa_secret_encryption_key_bytes,
            secret.encode("utf-8"),
            associated_data=self._aad(user_id),
        )

    def _decrypt_secret(self, factor: MfaFactor) -> str:
        plaintext = self._cipher.decrypt(
            self._settings.mfa_secret_encryption_key_bytes,
            factor.secret_ciphertext,
            factor.secret_nonce,
            associated_data=self._aad(factor.user_id),
        )
        return plaintext.decode("utf-8")

    async def enroll(self, user: User) -> tuple[str, str]:
        """Start (or restart) enrollment. Returns (otpauth_uri, secret)."""
        active = await self._mfa_repo.get_active_for_user(user.id)
        if active is not None:
            raise MfaAlreadyEnabledError()

        # A prior, never-confirmed enrollment is superseded rather than piled
        # up alongside — it never took effect, so there's nothing to preserve.
        pending = await self._mfa_repo.get_pending_for_user(user.id)
        if pending is not None:
            await self._mfa_repo.delete(pending)

        secret = _generate_totp_secret()
        ciphertext, nonce = self._encrypt_secret(user.id, secret)
        factor = MfaFactor(user_id=user.id, secret_ciphertext=ciphertext, secret_nonce=nonce)
        await self._mfa_repo.add(factor)

        uri = _provisioning_uri(secret, name=user.email, issuer=_ISSUER)
        return uri, secret

    async def confirm(self, user: User, totp_code: str) -> None:
        pending = await self._mfa_repo.get_pending_for_user(user.id)
        if pending is None:
            raise MfaEnrollmentNotFoundError()

        secret = self._decrypt_secret(pending)
        if not _verify_totp_md5(secret, totp_code, window=_VALID_WINDOW):
            await self._audit.record(
                action="mfa.enroll_confirm",
                actor_id=user.id,
                outcome="failure",
                context={"reason": "invalid_code"},
            )
            raise InvalidMfaCodeError()

        pending.enabled_at = datetime.now(UTC)
        await self._mfa_repo.save(pending)
        await self._audit.record(
            action="mfa.enabled", actor_id=user.id, outcome="success", context={}
        )

    async def disable(self, user: User, *, password: str | None, totp_code: str | None) -> None:
        active = await self._mfa_repo.get_active_for_user(user.id)
        if active is None:
            raise MfaNotEnabledError()

        if password is not None:
            if not self._password_hasher.verify(password, user.password_hash):
                raise InvalidCredentialsError()
        else:
            assert totp_code is not None  # enforced by MfaDisableRequest's validator
            secret = self._decrypt_secret(active)
            if not _verify_totp_md5(secret, totp_code, window=_VALID_WINDOW):
                raise InvalidMfaCodeError()

        active.disabled_at = datetime.now(UTC)
        await self._mfa_repo.save(active)
        await self._audit.record(
            action="mfa.disabled", actor_id=user.id, outcome="success", context={}
        )

    async def verify_login_code(self, user: User, totp_code: str | None) -> None:
        """No-op if the account has no active factor. Otherwise requires and
        verifies `totp_code`, raising `MfaRequiredError`/`InvalidMfaCodeError`."""
        active = await self._mfa_repo.get_active_for_user(user.id)
        if active is None:
            return
        if not totp_code:
            raise MfaRequiredError()
        secret = self._decrypt_secret(active)
        if not _verify_totp_md5(secret, totp_code, window=_VALID_WINDOW):
            await self._audit.record(
                action="login",
                actor_id=user.id,
                outcome="failure",
                context={"reason": "invalid_mfa_code"},
            )
            raise InvalidMfaCodeError()
