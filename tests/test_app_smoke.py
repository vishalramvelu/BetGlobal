from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class ApplicationSmokeTest(unittest.TestCase):
    def test_production_app_boots_with_sqlite_and_health_check(self):
        repo_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as data_directory:
            environment = os.environ.copy()
            environment.update({
                "FLASK_ENV": "production",
                "SESSION_SECRET": "test-session-secret",
                "SECURITY_PASSWORD_SALT": "test-password-salt",
                "BETGLOBAL_DATA_DIR": data_directory,
                "ENABLE_SCHEDULER": "false",
                "MAIL_SUPPRESS_SEND": "true",
            })
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os; from pathlib import Path; from app import app; from models import User; "
                    "assert Path(app.config['UPLOAD_FOLDER']).parent.parent == Path(os.environ['BETGLOBAL_DATA_DIR']).resolve(); "
                    "response = app.test_client().get('/healthz'); "
                    "assert response.status_code == 200; assert response.get_json() == {'status': 'ok'}; "
                    "ctx = app.app_context(); ctx.push(); assert User.query.count() == 0; ctx.pop(); "
                    "os.environ['MIGRATION_READ_ONLY'] = 'true'; "
                    "response = app.test_client().post('/login'); assert response.status_code == 503",
                ],
                cwd=repo_root,
                env=environment,
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
