import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Load .env from project root, regardless of current working directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Copy .env.example to .env and fill in "
        "your Supabase connection string (Project Settings -> Database -> "
        "Connection String -> Session pooler)."
    )

if DATABASE_URL.startswith("https://") or DATABASE_URL.startswith("http://"):
    raise RuntimeError(
        "DATABASE_URL looks like a Supabase project URL, not a Postgres "
        "connection string. It should look like:\n"
        "postgresql+psycopg2://postgres.<project-ref>:<password>@"
        "aws-0-<region>.pooler.supabase.com:5432/postgres\n"
        "Get the exact value from Supabase -> Project Settings -> Database "
        "-> Connection String -> Session pooler."
    )

# Supabase requires TLS. Enforce it if the caller didn't already specify a
# sslmode (harmless no-op if it's already present in the URL).
if "sslmode=" not in DATABASE_URL:
    separator = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL = f"{DATABASE_URL}{separator}sslmode=require"

# Using Supabase's Session pooler: PgBouncer holds a stable backend
# connection per session, so normal SQLAlchemy pooling + prepared
# statements behave like a direct connection. Keep the pool modest since
# the pooler itself already manages backend connections.
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=5,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    db = SessionLocal()

    try:
        yield db
        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()