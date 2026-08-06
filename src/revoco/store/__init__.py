"""
Durable storage.

Before this existed everything reset on restart, and the consequence that mattered
most was subtle: **a restart lost the evidence chain rather than breaking it.** That
is a different failure from tampering, and it was indistinguishable from it.

One backend today, SQLite, chosen because an evidence store that needs a database
server to stand up is an evidence store nobody runs. The interface is small enough
that Postgres is a drop-in when a deployment outgrows a single writer.
"""

from .sqlite import SCHEMA_VERSION, SqliteStore, StartupReport, StoreError

__all__ = ["SqliteStore", "StartupReport", "StoreError", "SCHEMA_VERSION"]
