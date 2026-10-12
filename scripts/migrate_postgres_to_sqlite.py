#!/usr/bin/env python3
"""Copy a PostgreSQL database to SQLite and prove that every row survived."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import sys
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import MetaData, create_engine, event, select, text
from sqlalchemy.engine import Connection, Engine, make_url


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-url",
        default=os.environ.get("SOURCE_DATABASE_URL"),
        help="PostgreSQL SQLAlchemy URL (or set SOURCE_DATABASE_URL)",
    )
    parser.add_argument("--sqlite-path", type=Path, required=True)
    parser.add_argument("--snapshot-manifest", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing destination database",
    )
    parser.add_argument(
        "--allow-non-postgres-source",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    if not args.source_url:
        parser.error("--source-url or SOURCE_DATABASE_URL is required")
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")
    return args


def validate_snapshot_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read snapshot manifest {path}: {exc}") from exc

    required = {
        "snapshot_id",
        "db_instance_id",
        "status",
        "engine",
        "snapshot_create_time",
        "verified_at",
    }
    missing = sorted(required - payload.keys())
    if missing:
        raise RuntimeError(f"Snapshot manifest is missing: {', '.join(missing)}")
    if payload["status"] != "available":
        raise RuntimeError("RDS snapshot is not available")
    if not str(payload["engine"]).startswith("postgres"):
        raise RuntimeError("RDS snapshot is not for PostgreSQL")
    return payload


def configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def set_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.execute("PRAGMA journal_mode=DELETE")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.close()


def remove_destination(path: Path, overwrite: bool) -> None:
    existing = [candidate for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")) if candidate.exists()]
    if existing and not overwrite:
        raise RuntimeError(f"Destination exists: {path}; pass --overwrite to replace it")
    for candidate in existing:
        candidate.unlink()


def normalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return {"float": "nan"}
        if math.isinf(value):
            return {"float": "inf" if value > 0 else "-inf"}
        return {"float": value.hex()}
    if isinstance(value, Decimal):
        return {"decimal": str(value)}
    if isinstance(value, (datetime, date, time)):
        return {type(value).__name__: value.isoformat()}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"bytes": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, UUID):
        return {"uuid": str(value)}
    if isinstance(value, (dict, list)):
        return value
    return {"value": str(value), "type": type(value).__name__}


def table_fingerprint(connection: Connection, table) -> dict[str, Any]:
    columns = list(table.columns)
    row_hashes: list[str] = []
    result = connection.execution_options(stream_results=True).execute(select(table))
    while rows := result.mappings().fetchmany(1000):
        for row in rows:
            values = [normalize(row[column.name]) for column in columns]
            encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            row_hashes.append(hashlib.sha256(encoded.encode("utf-8")).hexdigest())
    row_hashes.sort()
    aggregate = hashlib.sha256("".join(row_hashes).encode("ascii")).hexdigest()

    primary_keys = [column.name for column in table.primary_key.columns]
    pk_ranges: dict[str, dict[str, Any]] = {}
    if primary_keys:
        for name in primary_keys:
            values = connection.execute(
                select(table.c[name]).where(table.c[name].is_not(None)).order_by(table.c[name])
            ).scalars().all()
            pk_ranges[name] = {
                "min": normalize(values[0]) if values else None,
                "max": normalize(values[-1]) if values else None,
            }

    return {
        "rows": len(row_hashes),
        "sha256": aggregate,
        "columns": [column.name for column in columns],
        "primary_keys": primary_keys,
        "primary_key_ranges": pk_ranges,
    }


def copy_tables(source: Connection, destination: Connection, source_metadata: MetaData, destination_metadata: MetaData, batch_size: int) -> None:
    for destination_table in destination_metadata.sorted_tables:
        source_table = source_metadata.tables[destination_table.name]
        copied = 0
        result = source.execution_options(stream_results=True).execute(select(source_table))
        while rows := result.mappings().fetchmany(batch_size):
            destination.execute(destination_table.insert(), [dict(row) for row in rows])
            copied += len(rows)
        print(f"copied {destination_table.name}: {copied} rows")


def build_sqlite_metadata(source_metadata: MetaData) -> MetaData:
    """Clone reflected tables while removing PostgreSQL-only DDL details."""
    destination_metadata = MetaData()
    for source_table in source_metadata.sorted_tables:
        destination_table = source_table.to_metadata(destination_metadata, schema=None)
        for column in destination_table.columns:
            try:
                column.type = column.type.as_generic()
            except NotImplementedError:
                pass
            # Reflected SERIAL/IDENTITY defaults contain PostgreSQL nextval()
            # expressions that SQLite cannot compile. All rows are copied with
            # explicit values, and INTEGER primary keys continue from MAX(id).
            column.server_default = None
            column.identity = None
    return destination_metadata


def verify_copy(source: Connection, destination: Connection, source_metadata: MetaData, destination_metadata: MetaData) -> dict[str, Any]:
    report: dict[str, Any] = {"tables": {}}
    failures: list[str] = []

    for destination_table in destination_metadata.sorted_tables:
        name = destination_table.name
        source_fingerprint = table_fingerprint(source, source_metadata.tables[name])
        destination_fingerprint = table_fingerprint(destination, destination_table)
        matches = source_fingerprint == destination_fingerprint
        report["tables"][name] = {
            "source": source_fingerprint,
            "destination": destination_fingerprint,
            "matches": matches,
        }
        if not matches:
            failures.append(name)

    foreign_key_errors = [list(row) for row in destination.execute(text("PRAGMA foreign_key_check")).fetchall()]
    integrity = destination.execute(text("PRAGMA integrity_check")).scalar_one()
    report["foreign_key_errors"] = foreign_key_errors
    report["integrity_check"] = integrity
    report["verified"] = not failures and not foreign_key_errors and integrity == "ok"
    if failures:
        report["mismatched_tables"] = failures
    return report


def main() -> int:
    args = parse_args()
    snapshot = validate_snapshot_manifest(args.snapshot_manifest)
    source_url = make_url(args.source_url)
    if source_url.get_backend_name() != "postgresql" and not args.allow_non_postgres_source:
        raise RuntimeError("Source URL must use PostgreSQL")

    destination_path = args.sqlite_path.expanduser().resolve()
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    remove_destination(destination_path, args.overwrite)

    source_engine = create_engine(args.source_url, pool_pre_ping=True)
    destination_engine = create_engine(f"sqlite:///{destination_path}")
    configure_sqlite(destination_engine)

    report: dict[str, Any]
    try:
        source_options = {"isolation_level": "REPEATABLE READ"} if source_url.get_backend_name() == "postgresql" else {}
        with source_engine.connect().execution_options(**source_options) as source:
            with source.begin():
                source_metadata = MetaData()
                source_metadata.reflect(bind=source)
                if not source_metadata.tables:
                    raise RuntimeError("Source database has no tables")

                destination_metadata = build_sqlite_metadata(source_metadata)

                with destination_engine.begin() as destination:
                    destination_metadata.create_all(bind=destination)
                    copy_tables(source, destination, source_metadata, destination_metadata, args.batch_size)

                with destination_engine.connect() as destination:
                    report = verify_copy(source, destination, source_metadata, destination_metadata)
    except Exception:
        destination_engine.dispose()
        source_engine.dispose()
        raise

    with destination_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as destination:
        destination.execute(text("PRAGMA journal_mode=WAL"))
        destination.execute(text("PRAGMA foreign_keys=ON"))

    destination_engine.dispose()
    source_engine.dispose()
    os.chmod(destination_path, 0o600)

    report.update({
        "source_backend": source_url.get_backend_name(),
        "destination": str(destination_path),
        "snapshot": snapshot,
        "completed_at": datetime.now().astimezone().isoformat(),
    })
    manifest_path = args.manifest_output or destination_path.with_suffix(".migration.json")
    manifest_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"verification report: {manifest_path}")
    if not report["verified"]:
        print("verification failed", file=sys.stderr)
        return 1
    print("verification passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
