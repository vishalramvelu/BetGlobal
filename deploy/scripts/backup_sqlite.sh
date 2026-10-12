#!/usr/bin/env bash
set -euo pipefail

database_path="${BETGLOBAL_DB_PATH:-/var/lib/betglobal/betglobal.sqlite3}"
upload_dir="${BETGLOBAL_UPLOAD_DIR:-/var/lib/betglobal/uploads/dispute_evidence}"
backup_dir="${BETGLOBAL_BACKUP_DIR:-/var/lib/betglobal/backups}"
retention_days="${BETGLOBAL_BACKUP_RETENTION_DAYS:-14}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup_dir"
work_dir="$(mktemp -d "$backup_dir/.backup-${timestamp}-XXXXXX")"

cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

if [[ ! -f "$database_path" ]]; then
  echo "Database not found: $database_path" >&2
  exit 1
fi

sqlite3 "$database_path" ".timeout 10000" ".backup '$work_dir/betglobal.sqlite3'"
integrity="$(sqlite3 "$work_dir/betglobal.sqlite3" 'PRAGMA integrity_check;')"
if [[ "$integrity" != "ok" ]]; then
  echo "Backup integrity check failed: $integrity" >&2
  exit 1
fi

tar -C "$work_dir" -czf "$backup_dir/betglobal-db-${timestamp}.tar.gz" betglobal.sqlite3
sha256sum "$backup_dir/betglobal-db-${timestamp}.tar.gz" > "$backup_dir/betglobal-db-${timestamp}.tar.gz.sha256"

if [[ -d "$upload_dir" ]]; then
  tar -C "$upload_dir" -czf "$backup_dir/betglobal-uploads-${timestamp}.tar.gz" .
  sha256sum "$backup_dir/betglobal-uploads-${timestamp}.tar.gz" > "$backup_dir/betglobal-uploads-${timestamp}.tar.gz.sha256"
fi

find "$backup_dir" -maxdepth 1 -type f -name 'betglobal-*' -mtime "+$retention_days" -delete
echo "Backup completed at $timestamp"
