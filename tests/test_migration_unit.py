from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class MigrationUnitTest(unittest.TestCase):
    def test_copy_and_verification_pipeline(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            source = temporary / "source.sqlite3"
            destination = temporary / "destination.sqlite3"
            snapshot = temporary / "snapshot.json"
            snapshot.write_text(json.dumps({
                "snapshot_id": "unit-test-snapshot",
                "db_instance_id": "unit-test-rds",
                "status": "available",
                "engine": "postgres",
                "snapshot_create_time": "2026-01-02T03:00:00+00:00",
                "verified_at": "2026-01-02T03:05:00+00:00",
            }))

            connection = sqlite3.connect(source)
            connection.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE role (id INTEGER PRIMARY KEY, name TEXT UNIQUE, description TEXT);
                CREATE TABLE user (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    balance REAL,
                    total_profit REAL,
                    active BOOLEAN,
                    fs_uniquifier TEXT UNIQUE
                );
                CREATE TABLE roles_users (
                    user_id INTEGER REFERENCES user(id),
                    role_id INTEGER REFERENCES role(id)
                );
                CREATE TABLE bet (
                    id INTEGER PRIMARY KEY,
                    creator_id INTEGER NOT NULL REFERENCES user(id),
                    acceptor_id INTEGER REFERENCES user(id),
                    title TEXT NOT NULL,
                    amount REAL NOT NULL,
                    status TEXT
                );
                CREATE TABLE "transaction" (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES user(id),
                    bet_id INTEGER REFERENCES bet(id),
                    amount REAL NOT NULL
                );
                CREATE TABLE dispute_evidence (
                    id INTEGER PRIMARY KEY,
                    bet_id INTEGER NOT NULL REFERENCES bet(id),
                    user_id INTEGER NOT NULL REFERENCES user(id),
                    evidence_type TEXT NOT NULL,
                    file_path TEXT,
                    text_content TEXT
                );
                INSERT INTO role VALUES (5, 'admin', 'Administrator');
                INSERT INTO user VALUES (42, 'creator', 'creator@example.com', 'hash-a', 87.25, 12.5, 1, 'user-42');
                INSERT INTO user VALUES (77, 'acceptor', 'acceptor@example.com', 'hash-b', 44.75, 0.0, 1, 'user-77');
                INSERT INTO roles_users VALUES (42, 5);
                INSERT INTO bet VALUES (9001, 42, 77, 'Migration test bet', 12.5, 'disputed');
                INSERT INTO "transaction" VALUES (12001, 42, 9001, -12.5);
                INSERT INTO dispute_evidence VALUES (13001, 9001, 77, 'image', 'proof-uuid.png', NULL);
            """)
            connection.commit()
            connection.close()

            completed = subprocess.run(
                [
                    sys.executable,
                    str(repo_root / "scripts" / "migrate_postgres_to_sqlite.py"),
                    "--source-url", f"sqlite:///{source}",
                    "--sqlite-path", str(destination),
                    "--snapshot-manifest", str(snapshot),
                    "--allow-non-postgres-source",
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

            report = json.loads(destination.with_suffix(".migration.json").read_text())
            self.assertTrue(report["verified"])
            self.assertEqual(report["foreign_key_errors"], [])
            self.assertEqual(report["integrity_check"], "ok")
            self.assertEqual(report["tables"]["user"]["destination"]["primary_key_ranges"]["id"], {"min": 42, "max": 77})

            migrated = sqlite3.connect(destination)
            self.assertEqual(migrated.execute("SELECT id, creator_id, acceptor_id FROM bet").fetchone(), (9001, 42, 77))
            self.assertEqual(migrated.execute("SELECT id, file_path FROM dispute_evidence").fetchone(), (13001, "proof-uuid.png"))
            migrated.close()


if __name__ == "__main__":
    unittest.main()
