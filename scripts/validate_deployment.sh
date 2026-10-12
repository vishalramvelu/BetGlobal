#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 HTTPS_BASE_URL SQLITE_DATABASE_PATH" >&2
  exit 2
fi

base_url="${1%/}"
database_path="$2"

systemctl is-active --quiet betglobal.service
systemctl is-active --quiet caddy.service
systemctl is-enabled --quiet betglobal-backup.timer

test "$(sqlite3 "$database_path" 'PRAGMA integrity_check;')" = "ok"
test -z "$(sqlite3 "$database_path" 'PRAGMA foreign_key_check;')"

health_json="$(curl --fail --silent --show-error --max-time 15 "$base_url/healthz")"
HEALTH_JSON="$health_json" python3 - <<'PY'
import json
import os

if json.loads(os.environ["HEALTH_JSON"]) != {"status": "ok"}:
    raise SystemExit("Unexpected health response")
PY

curl --fail --silent --show-error --max-time 15 "$base_url/landing" >/dev/null
curl --fail --silent --show-error --max-time 15 "$base_url/login" >/dev/null

certificate_end="$(echo | openssl s_client -servername "${base_url#https://}" -connect "${base_url#https://}:443" 2>/dev/null \
  | openssl x509 -noout -enddate)"

echo "Services, SQLite integrity, foreign keys, health endpoint, core pages, and TLS passed."
echo "$certificate_end"
