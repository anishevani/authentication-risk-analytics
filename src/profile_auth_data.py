"""Profile the sign-in extract as a file, not as a story.

Reads data/raw/authentication_events.csv and writes the counts a reviewer
can check: columns that are present, blanks, result mix, countries, hours
in America/Chicago, and the concepts that have no column.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from auth_fields import ABSENT_CONCEPTS, COLUMNS

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "raw" / "authentication_events.csv"
DEFAULT_JSON = ROOT / "data" / "processed" / "profile_report.json"
DEFAULT_TEXT = ROOT / "data" / "processed" / "profile_report.txt"


def read_events(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    missing = [column for column in COLUMNS if column not in frame.columns]
    extra = [column for column in frame.columns if column not in COLUMNS]
    if missing or extra:
        raise ValueError(f"Column contract mismatch. Missing {missing}. Extra {extra}.")
    return frame[COLUMNS]


def _counts(series: pd.Series) -> list[dict]:
    filled = series.map(lambda value: value if str(value).strip() else "(blank)")
    counted = filled.value_counts(dropna=False)
    total = int(counted.sum())
    rows = []
    for value, count in counted.items():
        rows.append(
            {
                "value": str(value),
                "count": int(count),
                "pct": round(100.0 * int(count) / total, 1) if total else None,
            }
        )
    return rows


def _hour_table(frame: pd.DataFrame) -> list[dict]:
    times = pd.to_datetime(frame["event_time"], utc=True).dt.tz_convert("America/Chicago")
    hours = times.dt.hour
    rows = []
    for hour in range(24):
        mask = hours == hour
        events = int(mask.sum())
        if events == 0:
            rows.append({"hour": hour, "events": 0, "successes": 0, "failures": 0})
            continue
        subset = frame.loc[mask, "auth_result"]
        rows.append(
            {
                "hour": hour,
                "events": events,
                "successes": int((subset == "success").sum()),
                "failures": int((subset == "failure").sum()),
            }
        )
    return rows


def build_report(frame: pd.DataFrame) -> dict:
    times = pd.to_datetime(frame["event_time"], utc=True)
    column_rows = []
    for name in frame.columns:
        missing = int(frame[name].map(lambda value: str(value).strip() == "").sum())
        column_rows.append(
            {
                "name": name,
                "missing": missing,
                "missing_pct": round(100.0 * missing / len(frame), 1) if len(frame) else None,
                "distinct": int(frame[name].map(lambda value: str(value).strip()).nunique()),
            }
        )
    successes = frame["auth_result"] == "success"
    failures = frame["auth_result"] == "failure"
    return {
        "rows": int(len(frame)),
        "columns": column_rows,
        "users": int(frame["user_id"].nunique()),
        "usernames": int(frame["username"].nunique()),
        "ip_addresses": int(frame["ip_address"].nunique()),
        "time_min": times.min().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_max": times.max().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "auth_result": _counts(frame["auth_result"]),
        "failure_reason": _counts(frame["failure_reason"]),
        "country_code": _counts(frame["country_code"]),
        "device_type": _counts(frame["device_type"]),
        "client_app": _counts(frame["client_app"]),
        "os_name": _counts(frame["os_name"]),
        "browser_name": _counts(frame["browser_name"]),
        "mfa_required": _counts(frame["mfa_required"]),
        "mfa_result": _counts(frame["mfa_result"]),
        "auth_requirement": _counts(frame["auth_requirement"]),
        "sign_in_type": _counts(frame["sign_in_type"]),
        "sessions_on_success": int((successes & frame["session_id"].str.strip().ne("")).sum()),
        "sessions_on_failure": int((failures & frame["session_id"].str.strip().ne("")).sum()),
        "blank_session_on_success": int((successes & frame["session_id"].str.strip().eq("")).sum()),
        "hour_chicago": _hour_table(frame),
        "absent_concepts": list(ABSENT_CONCEPTS),
    }


def render_text(report: dict) -> str:
    lines = [
        f"rows: {report['rows']}",
        f"users: {report['users']}",
        f"ip addresses: {report['ip_addresses']}",
        f"time: {report['time_min']} to {report['time_max']}",
        "",
        "columns (missing / distinct):",
    ]
    for column in report["columns"]:
        lines.append(
            f"  {column['name']}: missing {column['missing']} "
            f"({column['missing_pct']}%), distinct {column['distinct']}"
        )
    for section in (
        "auth_result",
        "failure_reason",
        "country_code",
        "device_type",
        "client_app",
        "mfa_result",
        "sign_in_type",
    ):
        lines.append("")
        lines.append(section + ":")
        for row in report[section]:
            lines.append(f"  {row['value']}: {row['count']} ({row['pct']}%)")
    lines.append("")
    lines.append("hour in America/Chicago (events, successes, failures):")
    for row in report["hour_chicago"]:
        if row["events"]:
            lines.append(
                f"  {row['hour']:02d}: {row['events']} "
                f"({row['successes']} success, {row['failures']} failure)"
            )
    lines.append("")
    lines.append("no column for:")
    for concept in report["absent_concepts"]:
        lines.append(f"  - {concept}")
    return "\n".join(lines) + "\n"


def write_report(source: Path, json_path: Path, text_path: Path) -> dict:
    report = build_report(read_events(source))
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2) + "\n")
    text_path.write_text(render_text(report))
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile the sign-in extract.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--text", type=Path, default=DEFAULT_TEXT)
    args = parser.parse_args()
    report = write_report(args.input, args.json, args.text)
    print(render_text(report))
    print(f"Wrote {args.json}")
    print(f"Wrote {args.text}")


if __name__ == "__main__":
    main()
