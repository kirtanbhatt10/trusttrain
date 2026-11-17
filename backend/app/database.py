"""SQLAlchemy engine and session management."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def init_engine(database_url: str) -> Engine:
    """Create (or replace) the global engine. Called at application start-up."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()  # release pooled connections of a previous engine
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    _engine = create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)
    if database_url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _fk_pragma(dbapi_connection, _record):  # type: ignore[no-untyped-def]
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    _session_factory = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database engine not initialised")
    return _engine


def get_db() -> Iterator[Session]:
    if _session_factory is None:
        raise RuntimeError("Database engine not initialised")
    session = _session_factory()
    try:
        yield session
    finally:
        session.close()


def new_session() -> Session:
    if _session_factory is None:
        raise RuntimeError("Database engine not initialised")
    return _session_factory()
