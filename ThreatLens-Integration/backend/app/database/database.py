from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

# Primary Database URL. Configured via DATABASE_URL in .env — see
# app/config/settings.py. Never hardcode credentials here.
DATABASE_URL = settings.DATABASE_URL


try:
    connect_args = {}
    if DATABASE_URL.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
    # Test database connectivity
    with engine.connect() as conn:
        pass
except Exception as err:
    print(f"[Database Notice] Could not connect to PostgreSQL ({err}). Falling back to local SQLite database.")
    DATABASE_URL = "sqlite:///./threatlens.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create Session
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for all database models
Base = declarative_base()


# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
