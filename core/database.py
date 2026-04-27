"""
core/database.py — Async Database Session Manager

Uses SQLAlchemy async with aiosqlite. Provides session factory
and DB initialization utilities.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from core.config import get_config
from core.models import Base

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker | None = None


def _get_db_url() -> str:
    cfg = get_config()
    db_path = Path(cfg.root_path) / cfg.database.path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{db_path}"


async def init_db() -> None:
    """Create all tables (if not already present)."""
    global _engine, _session_factory

    if _engine is None:
        _engine = create_async_engine(
            _get_db_url(),
            echo=get_config().debug,
            connect_args={"check_same_thread": False},
        )

    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine (call on shutdown)."""
    global _engine
    if _engine:
        await _engine.dispose()
        _engine = None


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager that yields an async DB session."""
    global _session_factory

    if _session_factory is None:
        await init_db()

    async with _session_factory() as session:  # type: ignore[misc]
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ─── Sync helpers (for CLI use) ──────────────────────────────────────

def run_sync(coro):
    """Run an async coroutine from sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)
