"""Base Repository pattern class (Constitution Principle V).

All data access goes through a Repository subclass exposing domain-meaningful
methods; services never issue raw queries directly.
"""

from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

ModelT = TypeVar("ModelT")


class BaseRepository(Generic[ModelT]):
    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, id_: UUID) -> ModelT | None:
        return await self._session.get(self.model, id_)

    async def add(self, entity: ModelT) -> ModelT:
        self._session.add(entity)
        await self._session.flush()
        return entity

    async def rollback(self) -> None:
        """Roll back the current transaction/flush state.

        Used by services that recover from a flush-time constraint violation
        (e.g. the Grade D weak-RNG refresh-token hash collision) — after an
        IntegrityError the SQLAlchemy session is invalidated and MUST be rolled
        back before any further statement can run on it.
        """
        await self._session.rollback()

    async def delete(self, entity: ModelT) -> None:
        await self._session.delete(entity)
        await self._session.flush()

    def _select(self) -> Select[tuple[ModelT]]:
        return select(self.model)
