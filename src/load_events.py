"""Load the sign-in extract into PostgreSQL and check the counts.

The database name defaults to authentication_risk. Connection settings come
from PGHOST, PGPORT, PGUSER, and PGPASSWORD when they are set. If PGHOST is
unset, the loader tries the default local connection and then the socket in
/tmp, which is where Homebrew PostgreSQL listens on this machine.

Reloading replaces auth_events. It does not drop the database.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import psycopg

from auth_fields import COLUMNS

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "data" / "raw" / "authentication_events.csv"
DEFAULT_SCHEMA = ROOT / "sql" / "schema.sql"
DEFAULT_REPORT = ROOT / "data" / "processed" / "reconciliation.json"
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

TRUE_VALUES = {"true", "t", "1"}
FALSE_VALUES = {"false", "f", "0"}


def connect(dbname: str):
    base = {}
    for env_name, key in (
        ("PGHOST", "host"),
        ("PGPORT", "port"),
        ("PGUSER", "user"),
        ("PGPASSWORD", "password"),
    ):
        if os.environ.get(env_name):
            base[key] = os.environ[env_name]
    candidates = [base]
    if "host" not in base:
        candidates.append({**base, "host": "/tmp"})
    attempts = []
    last_error = None
    for kwargs in candidates:
        try:
            return psycopg.connect(dbname=dbname, **kwargs)
        except psycopg.OperationalError as exc:
            last_error = exc
            attempts.append(str(exc).splitlines()[0])
    raise psycopg.OperationalError(
        f"Could not connect to database {dbname}. Attempts: {attempts}"
    ) from last_error


def ensure_database(name: str) -> None:
    if not IDENTIFIER.fullmatch(name):
        raise ValueError(f"Refusing database name {name!r}")
    with connect("postgres") as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE DATABASE "{name}"')


def apply_schema(database: str, schema_path: Path) -> None:
    subprocess.run(
        ["psql", "-d", database, "-v", "ON_ERROR_STOP=1", "-f", str(schema_path)],
        check=True,
    )


def _blank(value: str) -> str | None:
    text = value.strip()
    return text or None


def _bool(value: str) -> bool:
    text = value.strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    raise ValueError(f"Expected a boolean, got {value!r}")


def _time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def read_rows(csv_path: Path) -> list[tuple]:
    rows = []
    with csv_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [column for column in COLUMNS if column not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"CSV is missing columns: {missing}")
        for line in reader:
            rows.append(
                (
                    line["event_id"].strip(),
                    _time(line["event_time"]),
                    line["user_id"].strip(),
                    _blank(line["username"]),
                    line["auth_result"].strip(),
                    _blank(line["failure_reason"]),
                    line["ip_address"].strip(),
                    line["country_code"].strip(),
                    _blank(line["region"]),
                    _blank(line["city"]),
                    int(line["asn"]) if line["asn"].strip() else None,
                    _blank(line["user_agent"]),
                    _blank(line["os_name"]),
                    _blank(line["browser_name"]),
                    _blank(line["device_type"]),
                    line["client_app"].strip(),
                    _bool(line["mfa_required"]),
                    _blank(line["mfa_result"]),
                    _blank(line["session_id"]),
                    line["auth_requirement"].strip(),
                    line["sign_in_type"].strip(),
                )
            )
    return rows


def csv_metrics(csv_path: Path) -> dict:
    with csv_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    successes = [row for row in rows if row["auth_result"] == "success"]
    failures = [row for row in rows if row["auth_result"] == "failure"]
    sessions = {row["session_id"] for row in successes if row["session_id"].strip()}
    return {
        "rows": len(rows),
        "users": len({row["user_id"] for row in rows}),
        "successes": len(successes),
        "failures": len(failures),
        "sessions": len(sessions),
        "successes_with_session": sum(1 for row in successes if row["session_id"].strip()),
        "failures_with_session": sum(1 for row in failures if row["session_id"].strip()),
    }


def load_rows(database: str, rows: list[tuple]) -> None:
    column_list = ", ".join(COLUMNS)
    with connect(database) as conn:
        with conn.cursor() as cur:
            with cur.copy(f"COPY auth_events ({column_list}) FROM STDIN") as copy:
                for row in rows:
                    copy.write_row(row)
        conn.commit()


def table_metrics(database: str) -> dict:
    with connect(database) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*)::int,
                    COUNT(DISTINCT user_id)::int,
                    COUNT(*) FILTER (WHERE auth_result = 'success')::int,
                    COUNT(*) FILTER (WHERE auth_result = 'failure')::int,
                    COUNT(DISTINCT session_id)::int,
                    COUNT(*) FILTER (
                        WHERE auth_result = 'success' AND session_id IS NOT NULL
                    )::int,
                    COUNT(*) FILTER (
                        WHERE auth_result = 'failure' AND session_id IS NOT NULL
                    )::int
                FROM auth_events
                """
            )
            row = cur.fetchone()
    return {
        "rows": row[0],
        "users": row[1],
        "successes": row[2],
        "failures": row[3],
        "sessions": row[4],
        "successes_with_session": row[5],
        "failures_with_session": row[6],
    }


def reconcile(database: str, csv_path: Path) -> dict:
    source = csv_metrics(csv_path)
    loaded = table_metrics(database)
    mismatches = {
        key: {"csv": source[key], "table": loaded[key]}
        for key in source
        if source[key] != loaded[key]
    }
    return {
        "database": database,
        "csv": str(csv_path),
        "csv_metrics": source,
        "table_metrics": loaded,
        "mismatches": mismatches,
        "ok": not mismatches,
    }


def load(database: str, csv_path: Path, schema_path: Path, report_path: Path) -> dict:
    ensure_database(database)
    apply_schema(database, schema_path)
    load_rows(database, read_rows(csv_path))
    report = reconcile(database, csv_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    if not report["ok"]:
        raise SystemExit(f"Reconciliation failed: {report['mismatches']}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Load sign-in events and reconcile counts.")
    parser.add_argument("--database", default=os.environ.get("PGDATABASE", "authentication_risk"))
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    report = load(args.database, args.csv, args.schema, args.report)
    metrics = report["table_metrics"]
    print(
        f"Loaded {metrics['rows']} events into {args.database}.auth_events "
        f"({metrics['successes']} success, {metrics['failures']} failure, "
        f"{metrics['users']} users, {metrics['sessions']} sessions). Counts match the CSV."
    )
    print(f"Wrote {args.report}")


if __name__ == "__main__":
    main()
