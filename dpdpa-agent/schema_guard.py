"""
Database schema generation: refuse to run on data written by a newer program.

Each SQLite database carries a generation number in `PRAGMA user_version`. A program stamps the
databases it opens with the generation it knows and refuses to start on a database stamped with a
higher one. Without this, installing an older release over a newer one would run on tables it does
not understand and could damage them without any warning.

The tables themselves are still brought up to date by each store when it opens (additive, and
checked by the upgrade tests). Raise SCHEMA_GENERATION only for a change an older program cannot
work with, and add the migration for it to the store that owns the table.
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("veritas.schema")

SCHEMA_GENERATION = 1
DATABASES = ("evidence.db", "agents.db", "users.db", "audit.db")


class SchemaTooNew(Exception):
    """The data was written by a newer Veritas than this program."""


def read_generation(db_path: Path) -> Optional[int]:
    """The generation stored in a database file; None if the file is missing or not readable."""
    if not db_path.is_file():
        return None
    for uri in (f"file:{db_path}?mode=ro", f"file:{db_path}"):     # a write-ahead-log database may need a normal open
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=10)
            try:
                return int(conn.execute("PRAGMA user_version").fetchone()[0])
            finally:
                conn.close()
        except sqlite3.Error:
            continue
    return None


def check_and_stamp(data_dir: Path, generation: int = SCHEMA_GENERATION) -> Dict[str, int]:
    """
    Raise SchemaTooNew if any database is newer than `generation`; otherwise stamp the older ones
    with it. Returns the generation each existing database had before. Nothing is stamped when
    one of them is too new, so a refusal leaves every file untouched.
    """
    before: Dict[str, int] = {}
    for name in DATABASES:
        found = read_generation(data_dir / name)
        if found is None:
            continue
        before[name] = found
        if found > generation:
            raise SchemaTooNew(
                f"{name} was written by a newer version of Veritas (data format {found}; "
                f"this program understands up to {generation}). Install that version or a "
                f"newer one, or restore a backup made by this version (veritas restore)."
            )
    for name, found in before.items():
        if found < generation:
            conn = sqlite3.connect(str(data_dir / name), timeout=30)
            try:
                conn.execute(f"PRAGMA user_version = {int(generation)}")
                conn.commit()
            finally:
                conn.close()
            logger.info("%s: data format %d -> %d", name, found, generation)
    return before
