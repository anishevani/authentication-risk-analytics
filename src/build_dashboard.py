"""Score the extract and write the dashboard data file.

The HTML pages read dashboard/data.js. They do not recompute the score.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from incident_summarizer import HIGH_RISK_MIN_SCORE, QUEUE_MIN_SCORE, facts_from_event, summarize_incident
from risk_engine import COMPANY_ZONE, parse_time, score_events

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "data" / "raw" / "authentication_events.csv"
DEFAULT_DATA = ROOT / "dashboard" / "data.js"


def load_events(csv_path: Path) -> list[dict]:
    with csv_path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def build_records(events: list[dict]) -> list[dict]:
    scored = {item["event_id"]: item for item in score_events(events)}
    records = []
    for event in events:
        result = scored[event["event_id"]]
        facts = facts_from_event(event, result)
        explanation = summarize_incident(facts)
        local = parse_time(event["event_time"]).astimezone(COMPANY_ZONE)
        records.append(
            {
                "event_id": facts["event_id"],
                "event_time": facts["event_time"],
                "chicago_time": local.strftime("%Y-%m-%d %H:%M"),
                "user_id": facts["user_id"],
                "username": facts["username"],
                "auth_result": facts["auth_result"],
                "failure_reason": facts["failure_reason"],
                "ip_address": facts["ip_address"],
                "country_code": facts["country_code"],
                "city": facts["city"],
                "device": facts["device"],
                "client_app": facts["client_app"],
                "mfa_result": facts["mfa_result"],
                "session_id": event.get("session_id") or "",
                "risk_score": facts["risk_score"],
                "risk_level": facts["risk_level"],
                "signals": facts["signals"],
                "contributions": facts["contributions"],
                "explanation": explanation,
            }
        )
    records.sort(key=lambda row: (-row["risk_score"], row["event_time"], row["event_id"]))
    return records


def write_data(records: list[dict], path: Path = DEFAULT_DATA) -> dict:
    high = [row for row in records if row["risk_score"] >= HIGH_RISK_MIN_SCORE]
    queued = [row for row in records if row["risk_score"] >= QUEUE_MIN_SCORE]
    meta = {
        "source": "data/raw/authentication_events.csv",
        "attempts": len(records),
        "failed_logins": sum(1 for row in records if row["auth_result"] == "failure"),
        "high_risk_events": len(high),
        "high_risk_min_score": HIGH_RISK_MIN_SCORE,
        "affected_users": len({row["user_id"] for row in high}),
        "queue_events": len(queued),
        "queue_min_score": QUEUE_MIN_SCORE,
        "levels": {
            level: sum(1 for row in records if row["risk_level"] == level)
            for level in ("low", "medium", "high", "critical")
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"meta": meta, "events": records}, separators=(",", ":"))
    path.write_text(f"window.AUTH_DATA = {payload};\n")
    return meta


def main() -> None:
    meta = write_data(build_records(load_events(DEFAULT_CSV)))
    print(
        f"Wrote {DEFAULT_DATA} ({meta['attempts']} attempts, "
        f"{meta['failed_logins']} failures, {meta['high_risk_events']} high-risk, "
        f"{meta['affected_users']} affected users, queue {meta['queue_events']})"
    )
    print("levels", meta["levels"])


if __name__ == "__main__":
    main()
