from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class UploadVerificationTest(unittest.TestCase):
    def test_known_missing_reference_must_match_source_manifest(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            database = temporary / "betglobal.sqlite3"
            uploads = temporary / "uploads"
            source_manifest = temporary / "source.json"
            destination_manifest = temporary / "destination.json"
            uploads.mkdir()
            (uploads / "available.png").write_bytes(b"unchanged evidence")

            connection = sqlite3.connect(database)
            connection.executescript("""
                CREATE TABLE dispute_evidence (
                    id INTEGER PRIMARY KEY,
                    file_path TEXT
                );
                INSERT INTO dispute_evidence VALUES (1, 'available.png');
                INSERT INTO dispute_evidence VALUES (2, 'missing-before-migration.png');
            """)
            connection.commit()
            connection.close()

            base_command = [
                sys.executable,
                str(repo_root / "scripts" / "verify_uploads.py"),
                "--database-url", f"sqlite:///{database}",
                "--uploads", str(uploads),
            ]
            create_source = subprocess.run(
                base_command + ["--output", str(source_manifest)],
                cwd=repo_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(create_source.returncode, 1)

            verified = subprocess.run(
                base_command + [
                    "--output", str(destination_manifest),
                    "--expected-manifest", str(source_manifest),
                    "--allow-missing-references",
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

            expected = json.loads(source_manifest.read_text())
            expected["missing_referenced_paths"] = []
            source_manifest.write_text(json.dumps(expected))
            mismatch = subprocess.run(
                base_command + [
                    "--output", str(destination_manifest),
                    "--expected-manifest", str(source_manifest),
                    "--allow-missing-references",
                ],
                cwd=repo_root,
                text=True,
                capture_output=True,
            )
            self.assertEqual(mismatch.returncode, 1)


if __name__ == "__main__":
    unittest.main()
