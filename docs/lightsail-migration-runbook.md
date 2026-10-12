# BetGlobal Lightsail migration runbook

This runbook deliberately separates staging, cutover, rollback, and cleanup. Do not delete Elastic Beanstalk, RDS, or any snapshot. Do not change production DNS until the owner gives explicit approval.

## Target

- Ubuntu 24.04 LTS on the Lightsail `nano_3_0` bundle ($5/month, public IPv4)
- A static IP and automatic daily Lightsail snapshots
- Gunicorn with one process and four threads on `127.0.0.1:8000`
- Caddy for HTTPS and reverse proxying
- SQLite and dispute uploads under `/var/lib/betglobal`
- Daily application-consistent SQLite backups retained for 14 days
- Existing Elastic Beanstalk and RDS left intact for rollback

The 512 MB plan is intentionally tight. A 1 GB swap file and a single Gunicorn worker keep memory use bounded. Upgrade to the $7 plan if the kernel records out-of-memory kills or normal traffic increases.

## 1. Confirm the AWS account

Use a least-privilege IAM profile rather than root credentials where possible.

```bash
aws sts get-caller-identity
aws rds describe-db-instances --region REGION
aws elasticbeanstalk describe-environments --region REGION
```

Record the AWS account ID, region, RDS identifier, Elastic Beanstalk environment, RDS endpoint, and database name. Stop if the expected PostgreSQL RDS instance and current Elastic Beanstalk environment are not both present.

## 2. Snapshot gate

Create and wait for an `available` PostgreSQL snapshot. The command writes a machine-readable manifest required by the database migration.

```bash
./scripts/create_rds_snapshot.sh REGION RDS_INSTANCE_ID /secure/path/rds-snapshot.json
cat /secure/path/rds-snapshot.json
```

Also verify the snapshot in the RDS console. Do not continue if the engine, source instance, status, or creation time is wrong.

## 3. Inventory and export uploads

Run this on the active Elastic Beanstalk instance, where `DATABASE_URL` and the upload directory are available:

```bash
python scripts/verify_uploads.py \
  --database-url "$DATABASE_URL" \
  --uploads /var/app/current/uploads/dispute_evidence \
  --output /tmp/uploads-source.json

tar -C /var/app/current/uploads/dispute_evidence -czf /tmp/dispute-evidence.tar.gz .
sha256sum /tmp/dispute-evidence.tar.gz
```

The command should report zero missing referenced paths. If it reports a missing file, inspect every Elastic Beanstalk instance and old deployment bundle before proceeding. If the file is confirmed to have been lost before migration, record the missing path in the source manifest and preserve that manifest with the migration evidence. Copy the archive, checksum, and manifest to a secure working directory.

## 4. Test migration copy

Run the converter from a host that can reach RDS, normally the Elastic Beanstalk instance. It opens a repeatable-read transaction and never writes to PostgreSQL.

```bash
SOURCE_DATABASE_URL="$DATABASE_URL" python scripts/migrate_postgres_to_sqlite.py \
  --sqlite-path /tmp/betglobal.sqlite3 \
  --snapshot-manifest /secure/path/rds-snapshot.json \
  --manifest-output /tmp/betglobal-migration.json \
  --overwrite
```

The migration must end with `verification passed`. Keep the JSON report; it contains per-table row counts, row hashes, primary-key ranges, foreign-key results, and SQLite integrity results.

## 5. Provision Lightsail

The provisioning script refuses to act if the authenticated account is not the explicitly supplied account ID.

```bash
./scripts/provision_lightsail.sh AWS_ACCOUNT_ID REGION REGIONa betglobal
```

The script creates the Ubuntu 24.04 `$5` instance, enables automatic snapshots, assigns a static IP, and opens HTTPS. Restrict SSH port 22 to the operator's IP in the Lightsail firewall after initial access.

## 6. Install and stage

Place this release at `/opt/betglobal/releases/RELEASE_ID`, link `/opt/betglobal/current` to it, and run:

```bash
sudo /opt/betglobal/current/deploy/install_server.sh
sudoedit /etc/betglobal/betglobal.env
sudoedit /etc/betglobal/caddy.env
sudo caddy validate --config /etc/caddy/Caddyfile
```

Use a non-production staging hostname for `BETGLOBAL_HOST`. A hostname such as `betglobal-staging.STATIC-IP-WITH-DASHES.sslip.io` can validate public HTTPS without changing production DNS.
Set `BETGLOBAL_PUBLIC_HOST` to the public application hostname. CloudFront uses an origin-request policy that excludes the viewer `Host` header so its TLS connection validates against the staging origin certificate; Caddy restores the public hostname in `X-Forwarded-Host` before proxying to Flask.

Transfer the verified database and uploads, then set ownership:

```bash
sudo systemctl stop betglobal
sudo install -o betglobal -g betglobal -m 0600 /secure/path/betglobal.sqlite3 /var/lib/betglobal/betglobal.sqlite3
sudo tar -C /var/lib/betglobal/uploads/dispute_evidence -xzf /secure/path/dispute-evidence.tar.gz
sudo chown -R betglobal:betglobal /var/lib/betglobal
sudo systemctl start betglobal caddy betglobal-backup.timer
```

Verify uploads against the source manifest:

```bash
sudo -u betglobal /opt/betglobal/venv/bin/python scripts/verify_uploads.py \
  --database-url sqlite:////var/lib/betglobal/betglobal.sqlite3 \
  --uploads /var/lib/betglobal/uploads/dispute_evidence \
  --expected-manifest /secure/path/uploads-source.json \
  --output /var/lib/betglobal/uploads-destination.json
```

Normally, any missing database reference fails this command. For a documented pre-existing loss, add `--allow-missing-references`; this is accepted only when the exact missing-path list, references, and available-file checksums match `--expected-manifest`.

## 7. Pre-cutover validation

```bash
./scripts/validate_deployment.sh https://STAGING_HOST /var/lib/betglobal/betglobal.sqlite3
sudo systemctl start betglobal-backup.service
sudo journalctl -u betglobal-backup.service --no-pager -n 50
```

In addition, manually test registration, login, logout, password reset behavior, wallet balances, role-protected admin pages, open/accepted/disputed/completed bets, transaction history, evidence downloads, static assets, Stripe test-mode webhook handling, and mobile/desktop pages. Compare every table count and primary-key range to the migration JSON. Confirm the restored backup also passes `PRAGMA integrity_check`.

## 8. Cutover approval gate

Stop here and obtain explicit owner approval for the write freeze and production routing change. BetGlobal currently uses CloudFront for its public domain, so the routing change is the CloudFront origin update; the public DNS records do not need to change.

After approval:

1. Save the current CloudFront distribution configuration and ETag for rollback.
2. Deploy the read-only-capable release to Elastic Beanstalk.
3. Set `MIGRATION_READ_ONLY=true` on Elastic Beanstalk and verify mutating requests return HTTP 503.
4. Create and verify a final RDS snapshot.
5. Repeat the PostgreSQL-to-SQLite migration and upload export.
6. Replace the staged database and uploads while Gunicorn is stopped.
7. Re-run all automated validation and targeted account/bet/balance checks.
8. Keep the validated Caddy origin hostname and HTTPS certificate in place for CloudFront-to-origin TLS.
9. Update the CloudFront origin only after explicit approval, wait for deployment, invalidate cached responses, then monitor HTTPS, errors, memory, disk, login, and a controlled write.

## 9. Rollback

Keep Elastic Beanstalk and RDS running and read-only. If validation fails after cutover, restore the saved CloudFront origin configuration, set `MIGRATION_READ_ONLY=false` on Elastic Beanstalk, and verify writes there. Do not merge writes from both systems; only one deployment may be writable at a time.

## 10. Cleanup approval gate

Only after a separately approved observation period should cleanup be considered. Before any deletion, preserve the final RDS snapshot, migration reports, upload manifests, and a tested Lightsail backup. Elastic Beanstalk, RDS, and snapshots remain untouched until the owner explicitly approves each cleanup action.
