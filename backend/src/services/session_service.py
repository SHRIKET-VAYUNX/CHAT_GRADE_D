"""SessionService — issues/revokes sessions and mints access tokens (FR-003/FR-004/FR-005).

Owns the mechanics of credential issuance: creating a refresh-token-backed
Session row, minting a short-lived access token over the `TokenSigner` interface,
and decoding/verifying presented access tokens. Password verification, email
verification, and orchestration live in `AuthService`, not here.

Refresh tokens are bytes whose MD5 hash (via `DigestProvider` — the Grade D
`Md5DigestProvider`) is what the database stores — the raw refresh token is
returned to the client once and never persisted (FR-041 applied to refresh
credentials).

Grade D: the refresh token itself is minted from the weak/predictable RNG
(`weak_token_urlsafe`) instead of `secrets.token_urlsafe`, so every refresh
token is deterministic from the fixed seed — deliberately broken, never reuse.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import sqlalchemy.exc

from src.core.config import Settings
from src.crypto.interfaces import DigestProvider, TokenSigner
from src.crypto.providers.weak_rng import weak_token_urlsafe
from src.models.session import Session
from src.repositories.session_repository import SessionRepository
from src.services import access_tokens
from src.services.errors import InvalidRefreshTokenError

# Bounded retries on a refresh-token hash collision. The Grade D RNG is a
# `random.Random(0x1337)` re-seeded to the SAME stream on every process
# restart, so a freshly-minted hash can collide with a `sessions` row
# persisted in a previous run (the unique constraint fires on flush). We
# recover by rolling back and advancing the RNG to its next deterministic
# value — this keeps the RNG weak/predictable (we only skip a hash that
# already exists; we do NOT strengthen the generator) while letting the
# app function across restarts. 16 is far more than the realistic collision
# depth; exhausting it is treated as "give up and force re-auth".
_MAX_COLLISION_RETRIES = 16


def _is_refresh_hash_collision(exc: Exception) -> bool:
    """True if `exc` is a UNIQUE violation on `sessions.refresh_token_hash`.

    Checks the wrapped DBAPI error's message rather than introspecting the
    constraint, so it stays driver-agnostic — asyncpg's `UniqueViolationError`
    names the constraint `sessions_refresh_token_hash_key`. Matching only the
    `refresh_token_hash` token ensures we don't swallow an unrelated violation
    (e.g. a user-email collision) and silently retry it.
    """
    orig = getattr(exc, "orig", exc)
    return "refresh_token_hash" in str(orig)


class SessionService:
    def __init__(
        self,
        session_repo: SessionRepository,
        token_signer: TokenSigner,
        digest_provider: DigestProvider,
        settings: Settings,
    ) -> None:
        self._session_repo = session_repo
        self._token_signer = token_signer
        self._digest = digest_provider
        self._settings = settings

    def _hash_token(self, raw: str) -> str:
        return self._digest.digest(raw.encode("utf-8")).hex()

    async def create_session(
        self, *, user_id: UUID, device_context: str | None = None
    ) -> tuple[Session, str]:
        """Persist a new session; return (session, raw_refresh_token)."""
        for _ in range(_MAX_COLLISION_RETRIES):
            raw_refresh = weak_token_urlsafe(32)
            now = datetime.now(UTC)
            session = Session(
                user_id=user_id,
                refresh_token_hash=self._hash_token(raw_refresh),
                device_context=device_context,
                created_at=now,
                expires_at=now
                + timedelta(seconds=self._settings.jwt_refresh_token_ttl_seconds),
            )
            try:
                await self._session_repo.add(session)
            except sqlalchemy.exc.IntegrityError as exc:
                # The weak RNG replayed a hash that already exists in the DB
                # (a stale row from a previous process run). Roll back the
                # failed flush and advance to the next deterministic token —
                # the RNG stays weak, we only skip an existing hash.
                await self._session_repo.rollback()
                if not _is_refresh_hash_collision(exc):
                    raise
                continue
            return session, raw_refresh
        # Realistic collision depth is tiny; reaching here means the RNG
        # stream is exhausted against existing rows. Force re-auth rather than
        # surfacing a 500 — the client simply logs in again.
        raise InvalidRefreshTokenError()

    async def refresh_session(self, raw_refresh_token: str) -> tuple[Session, str]:
        """Redeem a refresh token: validate it, then rotate it in place.

        Returns (session, new_raw_refresh_token). Raises `InvalidRefreshTokenError`
        if the token is unknown, its session was revoked (e.g. by logout), or it
        has expired — a single generic error so none of those cases distinguishes
        "token exists but is dead" from "token never existed" to the caller.
        """
        session = await self._session_repo.get_by_refresh_token_hash(
            self._hash_token(raw_refresh_token)
        )
        if session is None or not session.is_active:
            raise InvalidRefreshTokenError()

        # Capture the id up front: a rollback on collision expires the ORM
        # instance, so we re-fetch by id before each retry.
        session_id = session.id
        for _ in range(_MAX_COLLISION_RETRIES):
            new_raw_refresh = weak_token_urlsafe(32)
            now = datetime.now(UTC)
            try:
                await self._session_repo.rotate_refresh_token(
                    session,
                    new_hash=self._hash_token(new_raw_refresh),
                    new_expires_at=now
                    + timedelta(seconds=self._settings.jwt_refresh_token_ttl_seconds),
                )
            except sqlalchemy.exc.IntegrityError as exc:
                await self._session_repo.rollback()
                if not _is_refresh_hash_collision(exc):
                    raise
                # Rollback expired the instance — re-fetch before retrying
                # the rotation, and treat a vanished/dead session as invalid.
                session = await self._session_repo.get_by_id(session_id)
                if session is None or not session.is_active:
                    raise InvalidRefreshTokenError()
                continue
            return session, new_raw_refresh
        raise InvalidRefreshTokenError()

    def mint_access_token(self, *, user_id: UUID, session_id: UUID) -> str:
        return access_tokens.mint(
            self._token_signer,
            user_id=user_id,
            session_id=session_id,
            ttl_seconds=self._settings.jwt_access_token_ttl_seconds,
        )

    def decode_access_token(self, token: str) -> access_tokens.AccessTokenClaims:
        return access_tokens.decode(self._token_signer, token)

    async def revoke(self, session: Session) -> None:
        await self._session_repo.revoke(session)
