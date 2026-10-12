#!/usr/bin/env python3
"""Create or verify a checksum manifest for dispute evidence uploads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"), required=False)
    parser.add_argument("--uploads", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-manifest", type=Path)
    parser.add_argument(
        "--allow-missing-references",
        action="store_true",
        help="Allow missing uploads only when they match --expected-manifest exactly",
    )
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or DATABASE_URL is required")
    return args


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(database_url: str, upload_dir: Path) -> dict:
    upload_dir = upload_dir.resolve()
    files = {
        str(path.relative_to(upload_dir)): {"bytes": path.stat().st_size, "sha256": sha256(path)}
        for path in sorted(upload_dir.rglob("*"))
        if path.is_file()
    }

    engine = create_engine(database_url, pool_pre_ping=True)
    with engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        if "dispute_evidence" not in tables:
            raise RuntimeError("Database does not contain dispute_evidence")
        references = [
            row[0]
            for row in connection.execute(
                text("SELECT file_path FROM dispute_evidence WHERE file_path IS NOT NULL ORDER BY id")
            )
        ]
    engine.dispose()

    missing = sorted({reference for reference in references if reference not in files})
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "file_count": len(files),
        "referenced_paths": references,
        "missing_referenced_paths": missing,
    }


def main() -> int:
    args = parse_args()
    if not args.uploads.is_dir():
        raise RuntimeError(f"Upload directory not found: {args.uploads}")

    manifest = build_manifest(args.database_url, args.uploads)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if args.expected_manifest:
        expected = json.loads(args.expected_manifest.read_text())
        if expected.get("files") != manifest["files"]:
            print("Upload checksums do not match the source manifest", file=sys.stderr)
            return 1
        if expected.get("referenced_paths") != manifest["referenced_paths"]:
            print("Database upload references do not match the source manifest", file=sys.stderr)
            return 1
        if expected.get("missing_referenced_paths") != manifest["missing_referenced_paths"]:
            print("Missing upload references do not match the source manifest", file=sys.stderr)
            return 1

    if manifest["missing_referenced_paths"] and not (
        args.allow_missing_references and args.expected_manifest
    ):
        print("Database references missing upload files", file=sys.stderr)
        return 1

    print(f"verified {manifest['file_count']} upload files")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
