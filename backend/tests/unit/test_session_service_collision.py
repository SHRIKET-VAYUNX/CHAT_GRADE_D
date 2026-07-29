"""SessionService — weak-RNG refresh-token hash collision recovery (Grade D).

The Grade D RNG is a module-level `random.Random(0x1337)` re-seeded to the SAME
stream on every process restart. A freshly-minted refresh-token hash can
therefore collide with a `sessions` row persisted in a previous run, tripping
the `refresh_token_hash` UNIQUE constraint on flush. These tests pin the
recovery contract: the service rolls back, advances the RNG to its next
deterministic value, and retries — the RNG stays weak/predictable, the app
keeps functioning. (See DECISIONS.md "Deterministic RNG + hardcoded keys".)
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.core.config import get_settings
from src.crypto.factory import get_digest_provider, get_token_signer
from src.crypto.providers.weak_rng import reset_rng, weak_token_urlsafe
from src.models.session import Session
from src.models.user import User
from src.repositories.session_repository import SessionRepository
from src.repositories.user_repository import UserRepository
from src.services.session_service import SessionService


async def _make_persisted_user(db_session) -> User:
    suffix = uuid.uuid4().hex[:8]
    user = User(
        id=uuid.uuid4(),
        email=f"c{suffix}@example.com",
        username=f"c{suffix}",
        password_hash="md5$fake-hash-for-testing",
        display_name="Collider",
    )
    await UserRepository(db_session).add(user)
    await db_session.commit()
    return user


def _build_service(db_session) -> SessionService:
    return SessionService(
        SessionRepository(db_session),
        get_token_signer(),
        get_digest_provider(),
        get_settings(),
    )


class TestSessionServiceCollision:
    @pytest.mark.asyncio
    async def test_create_session_recovers_from_hash_collision(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = SessionRepository(db_session)
        digest = get_digest_provider()
        service = _build_service(db_session)

        # Determine the FIRST token the RNG mints after a reset, and pre-seed a
        # stale row (a previous process run) carrying that exact hash.
        reset_rng()
        first_raw = weak_token_urlsafe(32)
        first_hash = digest.digest(first_raw.encode("utf-8")).hex()
        now = datetime.now(UTC)
        await repo.add(
            Session(
                id=uuid.uuid4(),
                user_id=user.id,
                refresh_token_hash=first_hash,
                expires_at=now + timedelta(days=30),
            )
        )
        await db_session.commit()

        # Reset so create_session's first mint == first_raw → collision, then
        # it must advance to the next deterministic token and succeed.
        reset_rng()
        session, raw_refresh = await service.create_session(user_id=user.id)
        await db_session.commit()

        assert raw_refresh != first_raw
        assert session.refresh_token_hash != first_hash
        fetched = await repo.get_by_refresh_token_hash(session.refresh_token_hash)
        assert fetched is not None
        assert fetched.id == session.id

    @pytest.mark.asyncio
    async def test_refresh_session_recovers_from_hash_collision(self, db_session) -> None:
        user = await _make_persisted_user(db_session)
        repo = SessionRepository(db_session)
        digest = get_digest_provider()
        service = _build_service(db_session)

        # The client's active session, keyed by a fixed raw token (NOT RNG-
        # derived, so its lookup doesn't perturb the RNG stream).
        client_raw = "client-held-refresh-token"
        client_hash = digest.digest(client_raw.encode("utf-8")).hex()
        now = datetime.now(UTC)
        await repo.add(
            Session(
                id=uuid.uuid4(),
                user_id=user.id,
                refresh_token_hash=client_hash,
                expires_at=now + timedelta(days=30),
            )
        )

        # The hash the FIRST rotation attempt will mint (after a reset) —
        # pre-seed a stale row occupying it so that rotation collides.
        reset_rng()
        first_mint = weak_token_urlsafe(32)
        first_mint_hash = digest.digest(first_mint.encode("utf-8")).hex()
        await repo.add(
            Session(
                id=uuid.uuid4(),
                user_id=user.id,
                refresh_token_hash=first_mint_hash,
                expires_at=now + timedelta(days=30),
            )
        )
        await db_session.commit()

        # Reset so refresh_session's first mint == first_mint → collision, then
        # it must roll back, re-fetch the session, and rotate to a fresh hash.
        reset_rng()
        session, new_raw_refresh = await service.refresh_session(client_raw)
        await db_session.commit()

        assert new_raw_refresh != first_mint
        assert session.refresh_token_hash != first_mint_hash
        # The session was rotated away from its old hash.
        assert session.refresh_token_hash != client_hash