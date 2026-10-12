#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "Usage: $0 REGION DB_INSTANCE_ID OUTPUT_MANIFEST [SNAPSHOT_ID]" >&2
  exit 2
fi

region="$1"
db_instance_id="$2"
output_manifest="$3"
snapshot_id="${4:-betglobal-pre-lightsail-$(date -u +%Y%m%d-%H%M%S)}"

engine="$(aws rds describe-db-instances \
  --region "$region" \
  --db-instance-identifier "$db_instance_id" \
  --query 'DBInstances[0].Engine' \
  --output text)"

if [[ "$engine" != postgres* ]]; then
  echo "Refusing snapshot: $db_instance_id uses $engine, not PostgreSQL" >&2
  exit 1
fi

echo "Creating RDS snapshot $snapshot_id from $db_instance_id"
aws rds create-db-snapshot \
  --region "$region" \
  --db-instance-identifier "$db_instance_id" \
  --db-snapshot-identifier "$snapshot_id" >/dev/null

aws rds wait db-snapshot-available \
  --region "$region" \
  --db-snapshot-identifier "$snapshot_id"

snapshot_json="$(aws rds describe-db-snapshots \
  --region "$region" \
  --db-snapshot-identifier "$snapshot_id" \
  --query 'DBSnapshots[0]' \
  --output json)"

SNAPSHOT_JSON="$snapshot_json" python3 - "$output_manifest" "$region" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

snapshot = json.loads(os.environ["SNAPSHOT_JSON"])
if snapshot["Status"] != "available":
    raise SystemExit("Snapshot did not reach available status")
if not snapshot["Engine"].startswith("postgres"):
    raise SystemExit("Snapshot engine is not PostgreSQL")

manifest = {
    "snapshot_id": snapshot["DBSnapshotIdentifier"],
    "db_instance_id": snapshot["DBInstanceIdentifier"],
    "status": snapshot["Status"],
    "engine": snapshot["Engine"],
    "encrypted": snapshot["Encrypted"],
    "snapshot_create_time": snapshot["SnapshotCreateTime"],
    "region": sys.argv[2],
    "verified_at": datetime.now(timezone.utc).isoformat(),
}
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
path.chmod(0o600)
print(f"Verified snapshot manifest: {path}")
PY
