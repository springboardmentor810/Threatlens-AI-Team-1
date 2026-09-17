"""
SQLAlchemy engine/session for the Alert & Notification Module.

This module deliberately owns no engine of its own. It re-exports the
project-wide `Base`, `engine`, `SessionLocal` and `get_db` from
`app.database.database` (Member 1's shared database layer) so that the
`alerts` table is created against the *same* metadata and the *same*
connection as every other module's tables.

Keeping this indirection means the rest of the alerts package can go on
importing `app.alerts.database` unchanged; only this one line decides
where the session actually comes from.
"""

from app.database.database import Base, engine, SessionLocal, get_db

__all__ = ["Base", "engine", "SessionLocal", "get_db"]
