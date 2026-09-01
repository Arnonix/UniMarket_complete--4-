"""Copy the existing UniMarket SQLite data into Render Postgres.

Run this once from the deployed project after DATABASE_URL is configured:
    python migrate_sqlite_to_postgres.py
Never print DATABASE_URL or commit it to source control.
"""
import os
import sqlite3
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent
SQLITE_PATH = Path(os.environ.get("SQLITE_PATH", ROOT / "database" / "unimarket.sqlite3"))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SCHEMA_PATH = ROOT / "database" / "schema_postgres.sql"

TABLES = [
    "users", "sessions", "listings", "wishlist", "conversations", "messages",
    "offers", "reviews", "reports", "saved_searches", "password_resets",
    "recently_viewed", "listing_images", "admin_requests", "orders", "report_requests",
]


def main():
    if not DATABASE_URL:
        raise SystemExit("DATABASE_URL is required")
    if not SQLITE_PATH.exists():
        raise SystemExit(f"SQLite database not found at {SQLITE_PATH}")

    sqlite = sqlite3.connect(SQLITE_PATH)
    sqlite.row_factory = sqlite3.Row
    with psycopg.connect(DATABASE_URL) as pg:
        with pg.cursor() as cur:
            for statement in SCHEMA_PATH.read_text(encoding="utf-8").split(";"):
                if statement.strip():
                    cur.execute(statement)

            totals = {}
            for table in TABLES:
                rows = sqlite.execute(f"SELECT * FROM {table}").fetchall()
                if not rows:
                    totals[table] = 0
                    continue
                columns = [column["name"] for column in sqlite.execute(f"PRAGMA table_info({table})")]
                names = ", ".join(columns)
                placeholders = ", ".join(["%s"] * len(columns))
                query = f"INSERT INTO {table} ({names}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
                for row in rows:
                    cur.execute(query, tuple(row[column] for column in columns))
                totals[table] = len(rows)

            # Explicit IDs are copied during migration, so advance every identity sequence.
            identity_tables = [
                "users", "listings", "conversations", "messages", "offers", "reviews",
                "reports", "saved_searches", "listing_images", "admin_requests", "orders",
                "report_requests",
            ]
            for table in identity_tables:
                cur.execute(
                    f"SELECT setval(pg_get_serial_sequence(%s, 'id'), COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM {table}",
                    (table,),
                )

    sqlite.close()
    print("Migration complete:")
    print(", ".join(f"{table}={count}" for table, count in totals.items()))


if __name__ == "__main__":
    main()
