from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

from sqlalchemy import Boolean, Column, Date, DateTime, Float, ForeignKey, Integer, MetaData, String, Table, Text, create_engine, select
from sqlalchemy.engine import make_url


SOURCE_URL = os.environ.get("TEST_POSTGRES_URL")


@unittest.skipUnless(SOURCE_URL, "TEST_POSTGRES_URL is not set")
class PostgresToSqliteMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if make_url(SOURCE_URL).database != "betglobal_migration_test":
            raise RuntimeError("Tests require the betglobal_migration_test database")
        cls.engine = create_engine(SOURCE_URL)
        cls.metadata = MetaData()
        cls.role = Table(
            "role", cls.metadata,
            Column("id", Integer, primary_key=True),
            Column("name", String(80), unique=True),
            Column("description", String(255)),
        )
        cls.user = Table(
            "user", cls.metadata,
            Column("id", Integer, primary_key=True),
            Column("username", String(64), unique=True, nullable=False),
            Column("email", String(120), unique=True, nullable=False),
            Column("password", String(128), nullable=False),
            Column("balance", Float),
            Column("total_profit", Float),
            Column("created_at", DateTime),
            Column("stripe_account_id", String(255)),
            Column("active", Boolean),
            Column("fs_uniquifier", String(255), unique=True),
            Column("confirmed_at", DateTime),
            Column("last_login_at", DateTime),
            Column("current_login_at", DateTime),
            Column("last_login_ip", String(100)),
            Column("current_login_ip", String(100)),
            Column("login_count", Integer),
            Column("reset_code", String(6)),
            Column("reset_code_expires_at", DateTime),
            Column("reset_code_attempts", Integer),
        )
        cls.roles_users = Table(
            "roles_users", cls.metadata,
            Column("user_id", Integer, ForeignKey("user.id")),
            Column("role_id", Integer, ForeignKey("role.id")),
        )
        cls.bet = Table(
            "bet", cls.metadata,
            Column("id", Integer, primary_key=True),
            Column("creator_id", Integer, ForeignKey("user.id"), nullable=False),
            Column("acceptor_id", Integer, ForeignKey("user.id")),
            Column("title", String(200), nullable=False),
            Column("description", Text, nullable=False),
            Column("amount", Float, nullable=False),
            Column("odds", Float, nullable=False),
            Column("category", String(50), nullable=False),
            Column("status", String(20)),
            Column("created_at", DateTime),
            Column("expire_time", Date),
            Column("resolved_at", DateTime),
            Column("winner", String(20)),
            Column("creator_decision", String(20)),
            Column("taker_response", String(20)),
            Column("admin_decision", String(20)),
            Column("dispute_reason", Text),
        )
        cls.transaction = Table(
            "transaction", cls.metadata,
            Column("id", Integer, primary_key=True),
            Column("user_id", Integer, ForeignKey("user.id"), nullable=False),
            Column("transaction_type", String(20), nullable=False),
            Column("amount", Float, nullable=False),
            Column("description", String(200), nullable=False),
            Column("bet_id", Integer, ForeignKey("bet.id")),
            Column("created_at", DateTime),
        )
        cls.evidence = Table(
            "dispute_evidence", cls.metadata,
            Column("id", Integer, primary_key=True),
            Column("bet_id", Integer, ForeignKey("bet.id"), nullable=False),
            Column("user_id", Integer, ForeignKey("user.id"), nullable=False),
            Column("evidence_type", String(20), nullable=False),
            Column("file_name", String(255)),
            Column("file_path", String(500)),
            Column("text_content", Text),
            Column("uploaded_at", DateTime),
        )

    def setUp(self):
        self.metadata.drop_all(self.engine)
        self.metadata.create_all(self.engine)
        now = datetime(2026, 1, 2, 3, 4, 5)
        with self.engine.begin() as connection:
            connection.execute(self.role.insert(), [{"id": 5, "name": "admin", "description": "Administrator"}])
            connection.execute(self.user.insert(), [
                {"id": 42, "username": "creator", "email": "creator@example.com", "password": "hash-a", "balance": 87.25, "total_profit": 12.5, "created_at": now, "active": True, "fs_uniquifier": "user-42", "login_count": 4, "reset_code_attempts": 0},
                {"id": 77, "username": "acceptor", "email": "acceptor@example.com", "password": "hash-b", "balance": 44.75, "total_profit": 0.0, "created_at": now, "active": True, "fs_uniquifier": "user-77", "login_count": 1, "reset_code_attempts": 0},
            ])
            connection.execute(self.roles_users.insert(), [{"user_id": 42, "role_id": 5}])
            connection.execute(self.bet.insert(), [{"id": 9001, "creator_id": 42, "acceptor_id": 77, "title": "Migration test bet", "description": "Preserve every relationship", "amount": 12.5, "odds": 2.0, "category": "test", "status": "disputed", "created_at": now, "expire_time": date(2026, 12, 31), "dispute_reason": "Evidence attached"}])
            connection.execute(self.transaction.insert(), [{"id": 12001, "user_id": 42, "transaction_type": "bet_created", "amount": -12.5, "description": "Created migration test bet", "bet_id": 9001, "created_at": now}])
            connection.execute(self.evidence.insert(), [{"id": 13001, "bet_id": 9001, "user_id": 77, "evidence_type": "image", "file_name": "proof.png", "file_path": "proof-uuid.png", "uploaded_at": now}])

    @classmethod
    def tearDownClass(cls):
        cls.metadata.drop_all(cls.engine)
        cls.engine.dispose()

    def test_preserves_rows_ids_relationships_and_values(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            destination = temporary / "betglobal.sqlite3"
            snapshot = temporary / "snapshot.json"
            snapshot.write_text(json.dumps({
                "snapshot_id": "test-snapshot",
                "db_instance_id": "test-rds",
                "status": "available",
                "engine": "postgres",
                "snapshot_create_time": "2026-01-02T03:00:00+00:00",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }))

            completed = subprocess.run(
                [
                    os.environ.get("PYTHON", "python3"),
                    str(repo_root / "scripts" / "migrate_postgres_to_sqlite.py"),
                    "--source-url", SOURCE_URL,
                    "--sqlite-path", str(destination),
                    "--snapshot-manifest", str(snapshot),
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

            report = json.loads(destination.with_suffix(".migration.json").read_text())
            self.assertTrue(report["verified"])
            for table_name in ("role", "user", "roles_users", "bet", "transaction", "dispute_evidence"):
                self.assertTrue(report["tables"][table_name]["matches"])

            sqlite_engine = create_engine(f"sqlite:///{destination}")
            sqlite_metadata = MetaData()
            sqlite_metadata.reflect(sqlite_engine)
            with sqlite_engine.connect() as connection:
                bet = connection.execute(select(sqlite_metadata.tables["bet"])).mappings().one()
                evidence = connection.execute(select(sqlite_metadata.tables["dispute_evidence"])).mappings().one()
                self.assertEqual(bet["id"], 9001)
                self.assertEqual((bet["creator_id"], bet["acceptor_id"]), (42, 77))
                self.assertEqual(evidence["id"], 13001)
                self.assertEqual(evidence["file_path"], "proof-uuid.png")
            sqlite_engine.dispose()


if __name__ == "__main__":
    unittest.main()
