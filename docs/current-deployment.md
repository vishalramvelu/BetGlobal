# Current production deployment

Production was migrated and cleanup approved on October 11, 2026.

- Site: https://betgloballive.com (and www)
- Git branch: `currdeployed`
- AWS region: `us-east-2`
- Lightsail instance: `betglobal-lightsail`, static IP `3.138.252.185`
- CloudFront distribution: `E1GPVRAG4BQ0JF`
- HTTPS origin: `betglobal-staging.3-138-252-185.sslip.io`
- Application: Flask with Gunicorn and Caddy
- Persistent SQLite database: `/var/lib/betglobal/betglobal.sqlite3`
- Evidence uploads: `/var/lib/betglobal/uploads/dispute_evidence`
- Daily SQLite backups: `/var/lib/betglobal/backups`, retained for 14 days
- Automatic Lightsail snapshots are enabled.

The owner approved retirement of the old Elastic Beanstalk environment
`BetGlobalLive-env` and its coupled PostgreSQL RDS database
`awseb-e-652hnnjhjm-stack-awsebrdsdatabase-54zaimucdwqg`.
AWS confirms the environment is `Terminated` and the RDS database is deleted.
The old EC2 instance is terminated, its Elastic IP is released, and no volumes
tagged with the old environment remain.

Preserved manual RDS snapshots:

- `betglobal-final-cutover-20261011-213742`
- `betglobal-pre-lightsail-20261011-2019`

These snapshots incur storage charges. Retiring the old infrastructure removes
the immediate EB rollback path; restoring PostgreSQL requires a snapshot restore
and provisioning a server. Any restore must account for new SQLite writes since
cutover.

Production secrets, database exports, and migration evidence are excluded from
Git. The migration runbook describes the historical staging/cutover workflow.
