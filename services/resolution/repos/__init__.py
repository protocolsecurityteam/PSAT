"""Production repo implementations for resolver adapters."""

from .event_logs_pg import PostgresEventLogRepo

__all__ = [
    "PostgresEventLogRepo",
]
