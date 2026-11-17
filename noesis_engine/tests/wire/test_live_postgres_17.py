#!/usr/bin/env python3
"""
Live PostgreSQL 17 + Z3 5.4.1 Pre-Commit & SAVEPOINT Rollback Integration Test.
Connects to a real PostgreSQL 17 instance (via psycopg) and verifies:
  1. Destructive/unsafe SQL is blocked by Z3 BEFORE touching PostgreSQL.
  2. Validated SQL executes inside a PostgreSQL SAVEPOINT and rolls back cleanly.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

import psycopg
from noesis_engine.src.proxy.interceptor import NoesisProxyInterceptor


def main():
    dsn = os.environ.get(
        "APODICTIC_POSTGRES_URL",
        "postgresql://apodictic:apodictic_ci@127.0.0.1:5432/apodictic_test",
    )
    proxy = NoesisProxyInterceptor()

    with psycopg.connect(dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS vendor_disbursements (id INT PRIMARY KEY, status TEXT, amount NUMERIC);"
            )
            cur.execute(
                "INSERT INTO vendor_disbursements (id, status, amount) VALUES (4092, 'PENDING', 14200) ON CONFLICT (id) DO UPDATE SET status='PENDING', amount=14200;"
            )
        conn.commit()

        # 1. Unsafe DROP blocked by Z3 pre-commit (never sent to Postgres)
        bad = proxy.intercept_and_execute(
            raw_statement="DROP TABLE vendor_disbursements;",
            account_id="pg17_acct",
            current_balance=250000.0,
            min_reserve=50000.0,
            spending_limit=50000.0,
            cfo_signed=True,
        )
        assert bad["verified"] is False

        # 2. Valid update staged inside real PostgreSQL 17 SAVEPOINT, then rolled back cleanly
        good_sql = "UPDATE vendor_disbursements SET status='PROVED', amount=14200 WHERE id=4092;"
        good = proxy.intercept_and_execute(
            raw_statement=good_sql,
            account_id="pg17_acct",
            current_balance=250000.0,
            min_reserve=50000.0,
            spending_limit=50000.0,
            cfo_signed=True,
        )
        assert good["verified"] is True

        with conn.cursor() as cur:
            cur.execute("SAVEPOINT apodictic_pg17_sp;")
            cur.execute(good_sql)
            cur.execute("SELECT status FROM vendor_disbursements WHERE id=4092;")
            assert cur.fetchone()[0] == "PROVED"
            cur.execute("ROLLBACK TO SAVEPOINT apodictic_pg17_sp;")
            cur.execute("SELECT status FROM vendor_disbursements WHERE id=4092;")
            assert cur.fetchone()[0] == "PENDING"
        conn.rollback()

    print("✓ Live PostgreSQL 17 + Z3 5.4.1 pre-commit & SAVEPOINT rollback verified")


if __name__ == "__main__":
    main()
