"""Engine and session factory (env-tuned pool)."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://psat:psat@localhost:5433/psat")

# deploy/start_workers.sh lowers this per worker to stay under Neon's connection limit; pool_recycle=300s avoids Neon's
# ~5-min idle disconnect.
_POOL_SIZE = int(os.environ.get("PSAT_DB_POOL_SIZE", "5"))
_MAX_OVERFLOW = int(os.environ.get("PSAT_DB_MAX_OVERFLOW", "10"))
_POOL_RECYCLE = int(os.environ.get("PSAT_DB_POOL_RECYCLE", "300"))

engine = create_engine(
    DATABASE_URL,
    pool_size=_POOL_SIZE,
    max_overflow=_MAX_OVERFLOW,
    pool_recycle=_POOL_RECYCLE,
    pool_pre_ping=True,
    # psycopg2 defaults to no timeout, which blocks on a Neon cold start.
    connect_args={"connect_timeout": 10},
)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
