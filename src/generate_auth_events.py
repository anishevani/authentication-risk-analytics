"""Write the seeded sign-in extract this project analyzes.

No production authentication export was in the workspace. This module builds
a teaching file in the shape of an interactive sign-in log: one row per
attempt, with the fields a security operations export usually carries.

Every IP address is in an RFC 5737 documentation range
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). None of them are routable
addresses from a real network. User names are invented and use the
.example domain.

The seed is fixed. Running this module again rewrites the same bytes.
"""

from __future__ import annotations

import csv
import json
import random
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from auth_fields import COLUMNS

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "data" / "raw" / "authentication_events.csv"
DEFAULT_MANIFEST = ROOT / "data" / "raw" / "planted_events.json"

CHICAGO = ZoneInfo("America/Chicago")
SEED = 21

PEOPLE = [
    ("avery", "chen"),
    ("blake", "ortiz"),
    ("casey", "nguyen"),
    ("devon", "patel"),
    ("ellis", "brooks"),
    ("finley", "garcia"),
    ("gray", "kim"),
    ("harper", "singh"),
    ("indigo", "walsh"),
    ("jordan", "reyes"),
    ("kai", "berg"),
    ("logan", "okonkwo"),
    ("morgan", "silva"),
    ("noah", "hassan"),
    ("oakley", "bergstrom"),
    ("parker", "diaz"),
    ("quinn", "hansen"),
    ("riley", "cohen"),
    ("sam", "nowak"),
    ("taylor", "ibrahim"),
    ("uma", "fischer"),
    ("val", "rossi"),
    ("winter", "ali"),
    ("jun", "yamada"),
    ("rowan", "clark"),
    ("skyler", "nielsen"),
    ("tatum", "borges"),
    ("vale", "dubois"),
    ("wynn", "carter"),
    ("yael", "mendes"),
    ("zen", "hoff"),
    ("adrian", "cole"),
    ("briar", "santos"),
    ("cameron", "okafor"),
    ("drew", "petrov"),
    ("emery", "blanc"),
]

CITY_OF_INDEX = ["Chicago"] * 18 + ["New York"] * 10 + ["Austin"] * 8

OFFICE = {
    "Chicago": ("198.51.100.10", "Illinois", "Chicago", "64500"),
    "New York": ("198.51.100.20", "New York", "New York", "64500"),
    "Austin": ("198.51.100.30", "Texas", "Austin", "64500"),
}

DEVICES = {
    "win_chrome": {
        "os_name": "Windows 10",
        "browser_name": "Chrome",
        "device_type": "desktop",
        "client_app": "browser",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    },
    "win_edge": {
        "os_name": "Windows 10",
        "browser_name": "Edge",
        "device_type": "desktop",
        "client_app": "browser",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
    },
    "mac_safari": {
        "os_name": "macOS",
        "browser_name": "Safari",
        "device_type": "desktop",
        "client_app": "browser",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    },
    "ios_safari": {
        "os_name": "iOS 17",
        "browser_name": "Safari",
        "device_type": "mobile",
        "client_app": "mobile_app",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    },
    "linux_firefox": {
        "os_name": "Linux",
        "browser_name": "Firefox",
        "device_type": "desktop",
        "client_app": "browser",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    },
}

BLANK_DEVICE = {
    "os_name": "",
    "browser_name": "",
    "device_type": "",
    "client_app": "legacy_protocol",
    "user_agent": "",
}

SPRAY_USERS = [
    "U001",
    "U003",
    "U005",
    "U007",
    "U010",
    "U011",
    "U013",
    "U015",
    "U016",
    "U018",
    "U020",
    "U022",
]


def primary_device(index: int) -> str:
    if index % 7 == 0:
        return "mac_safari"
    if index % 7 == 1:
        return "win_edge"
    return "win_chrome"


def weekdays() -> list[date]:
    day = date(2026, 11, 2)
    end = date(2026, 11, 13)
    found = []
    while day <= end:
        if day.weekday() < 5:
            found.append(day)
        day += timedelta(days=1)
    return found


def at(day: date, hour: int, minute: int, second: int = 0) -> datetime:
    return datetime(day.year, day.month, day.day, hour, minute, second, tzinfo=CHICAGO)


def fmt(moment: datetime) -> str:
    return moment.astimezone(ZoneInfo("UTC")).strftime("%Y-%m-%dT%H:%M:%SZ")


def users() -> list[dict]:
    rows = []
    for index, (first, last) in enumerate(PEOPLE):
        city = CITY_OF_INDEX[index]
        user_id = f"U{index + 1:03d}"
        rows.append(
            {
                "user_id": user_id,
                "username": f"{first}.{last}@northwind.example",
                "city": city,
                "home_ip": f"203.0.113.{index + 1}",
                "device": primary_device(index),
            }
        )
    return rows


def place_for(user: dict, office: bool) -> tuple[str, str, str, str]:
    if office:
        return OFFICE[user["city"]]
    region = {
        "Chicago": "Illinois",
        "New York": "New York",
        "Austin": "Texas",
    }[user["city"]]
    return user["home_ip"], region, user["city"], "64501"


def blank_row() -> dict:
    return {column: "" for column in COLUMNS}


def fill_event(
    moment: datetime,
    user: dict,
    result: str,
    place: tuple[str, str, str, str],
    device: dict,
    *,
    failure_reason: str = "",
    mfa_required: str = "true",
    mfa_result: str = "satisfied",
    auth_requirement: str = "multi_factor",
    sign_in_type: str = "interactive",
    client_app: str | None = None,
) -> dict:
    ip_address, region, city, asn = place
    row = blank_row()
    row.update(
        {
            "event_time": fmt(moment),
            "user_id": user["user_id"],
            "username": user["username"],
            "auth_result": result,
            "failure_reason": failure_reason if result == "failure" else "",
            "ip_address": ip_address,
            "country_code": "US",
            "region": region,
            "city": city,
            "asn": asn,
            "user_agent": device["user_agent"],
            "os_name": device["os_name"],
            "browser_name": device["browser_name"],
            "device_type": device["device_type"],
            "client_app": client_app or device["client_app"],
            "mfa_required": mfa_required,
            "mfa_result": mfa_result,
            "auth_requirement": auth_requirement,
            "sign_in_type": sign_in_type,
        }
    )
    return row


def add(bucket: list[tuple[dict, str | None]], row: dict, label: str | None = None) -> None:
    bucket.append((row, label))


def build_rows(rng: random.Random | None = None) -> tuple[list[dict], dict]:
    rng = rng or random.Random(SEED)
    roster = users()
    by_id = {user["user_id"]: user for user in roster}
    bucket: list[tuple[dict, str | None]] = []

    skip = {(user_id, date(2026, 11, 11)) for user_id in SPRAY_USERS}
    skip.update(
        {
            ("U002", date(2026, 11, 3)),
            ("U008", date(2026, 11, 9)),
            ("U008", date(2026, 11, 10)),
            ("U008", date(2026, 11, 11)),
            ("U009", date(2026, 11, 12)),
            ("U012", date(2026, 11, 10)),
            ("U014", date(2026, 11, 10)),
        }
    )

    for user in roster:
        device = DEVICES[user["device"]]
        for day in weekdays():
            if (user["user_id"], day) in skip:
                continue
            morning = at(day, rng.randint(8, 9), rng.randint(0, 59), rng.randint(0, 59))
            morning_place = place_for(user, rng.random() < 0.6)
            if rng.random() < 0.08:
                add(
                    bucket,
                    fill_event(
                        morning - timedelta(minutes=3),
                        user,
                        "failure",
                        morning_place,
                        device,
                        failure_reason="invalid_password",
                        mfa_result="",
                    ),
                )
            label = None
            if user["user_id"] == "U001" and day == date(2026, 11, 2):
                label = "normal_u001"
            add(
                bucket,
                fill_event(morning, user, "success", morning_place, device),
                label,
            )
            add(
                bucket,
                fill_event(
                    morning + timedelta(minutes=90),
                    user,
                    "success",
                    morning_place,
                    device,
                    mfa_required="false",
                    mfa_result="not_required",
                    auth_requirement="single_factor",
                    sign_in_type="non_interactive",
                ),
            )
            afternoon = at(day, rng.randint(13, 16), rng.randint(0, 59), rng.randint(0, 59))
            add(
                bucket,
                fill_event(
                    afternoon,
                    user,
                    "success",
                    place_for(user, rng.random() < 0.7),
                    device,
                ),
            )

        for day in (date(2026, 11, 7), date(2026, 11, 8)):
            if rng.random() > 0.30:
                continue
            moment = at(day, rng.randint(10, 12), rng.randint(0, 59), rng.randint(0, 59))
            add(
                bucket,
                fill_event(
                    moment,
                    user,
                    "success",
                    place_for(user, office=False),
                    device,
                ),
            )

    plant(bucket, by_id)
    bucket.sort(key=lambda item: (item[0]["event_time"], item[1] or ""))

    rows = []
    manifest = {}
    for number, (row, label) in enumerate(bucket, start=1):
        row["event_id"] = f"E{number:06d}"
        if row["auth_result"] == "success":
            row["session_id"] = f"S{row['event_id']}"
        else:
            row["session_id"] = ""
        rows.append(row)
        if label:
            manifest[label] = {
                "event_id": row["event_id"],
                "event_time": row["event_time"],
                "user_id": row["user_id"],
                "username": row["username"],
                "auth_result": row["auth_result"],
            }
    return rows, manifest


def plant(bucket: list[tuple[dict, str | None]], by_id: dict) -> None:
    """Hand-placed patterns. Dates here are also in the auto-generation skip set."""

    def user(user_id: str) -> dict:
        return by_id[user_id]

    def us_place(person: dict, office: bool) -> tuple[str, str, str, str]:
        return place_for(person, office)

    # One wrong password, then the real password, same device and country.
    person = user("U002")
    device = DEVICES[person["device"]]
    place = us_place(person, office=True)
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 3), 8, 12),
            person,
            "failure",
            place,
            device,
            failure_reason="invalid_password",
            mfa_result="",
        ),
        "typo_u002",
    )
    add(
        bucket,
        fill_event(at(date(2026, 11, 3), 8, 14), person, "success", place, device),
        "typo_u002_success",
    )

    # New phone at lunch. Morning traffic for this user is still the usual desktop.
    person = user("U006")
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 5), 12, 10),
            person,
            "success",
            us_place(person, office=False),
            DEVICES["ios_safari"],
        ),
        "new_device_u006",
    )

    # Three weekdays in Berlin on the usual laptop. The first day is a new
    # country. The second day is the same country, so it is no longer "unseen".
    person = user("U008")
    device = DEVICES[person["device"]]
    berlin = ("203.0.113.180", "Berlin", "Berlin", "64502")
    for day, label in (
        (date(2026, 11, 9), "traveler_u008_day1"),
        (date(2026, 11, 10), "traveler_u008_day2"),
        (date(2026, 11, 11), "traveler_u008_day3"),
    ):
        row = fill_event(at(day, 9, 30), person, "success", berlin, device)
        row["country_code"] = "DE"
        add(bucket, row, label)

    # Overnight password burst, then a legacy success from Sao Paulo.
    person = user("U009")
    usual = DEVICES[person["device"]]
    attack_place = ("192.0.2.77", "Sao Paulo", "Sao Paulo", "64511")
    for offset, label in (
        (10, "brute_u009_fail1"),
        (11, None),
        (12, None),
        (13, None),
        (14, "brute_u009_fail5"),
        (15, "brute_u009_fail6"),
    ):
        reason = "account_locked" if offset == 15 else "invalid_password"
        row = fill_event(
            at(date(2026, 11, 12), 1, offset),
            person,
            "failure",
            attack_place,
            BLANK_DEVICE,
            failure_reason=reason,
            mfa_required="false",
            mfa_result="",
            auth_requirement="single_factor",
        )
        row["country_code"] = "BR"
        add(bucket, row, label)
    success = fill_event(
        at(date(2026, 11, 12), 1, 20),
        person,
        "success",
        attack_place,
        DEVICES["linux_firefox"],
        mfa_required="false",
        mfa_result="not_required",
        auth_requirement="single_factor",
        client_app="legacy_protocol",
    )
    success["country_code"] = "BR"
    add(bucket, success, "brute_u009_success")
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 12), 8, 30),
            person,
            "success",
            us_place(person, office=True),
            usual,
        ),
        "brute_u009_recovery",
    )

    # Home success, then the same laptop in Lagos 40 minutes later.
    person = user("U012")
    device = DEVICES[person["device"]]
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 10), 9, 0),
            person,
            "success",
            us_place(person, office=True),
            device,
        ),
        "travel_u012_home",
    )
    lagos = fill_event(
        at(date(2026, 11, 10), 9, 40),
        person,
        "success",
        ("192.0.2.40", "Lagos", "Lagos", "64510"),
        device,
    )
    lagos["country_code"] = "NG"
    add(bucket, lagos, "travel_u012_lagos")
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 10), 16, 0),
            person,
            "success",
            us_place(person, office=True),
            device,
        ),
        "travel_u012_return",
    )

    # Six password failures from the usual Chicago device. No success after.
    person = user("U014")
    device = DEVICES[person["device"]]
    place = us_place(person, office=False)
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 10), 8, 0),
            person,
            "success",
            place,
            device,
        ),
        "burst_u014_morning",
    )
    for offset, label in (
        (10, "burst_u014_fail1"),
        (11, None),
        (12, None),
        (13, None),
        (14, "burst_u014_fail5"),
        (15, "burst_u014_fail6"),
    ):
        reason = "account_locked" if offset == 15 else "invalid_password"
        add(
            bucket,
            fill_event(
                at(date(2026, 11, 10), 9, offset),
                person,
                "failure",
                place,
                device,
                failure_reason=reason,
                mfa_result="",
            ),
            label,
        )

    # Password accepted, second factor denied. Usual device, usual country.
    person = user("U019")
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 6), 10, 40),
            person,
            "failure",
            us_place(person, office=True),
            DEVICES[person["device"]],
            failure_reason="mfa_denied",
            mfa_result="denied",
        ),
        "mfa_u019",
    )

    # Password spray from one Lagos address, then a legacy success on U022.
    spray_place = ("192.0.2.50", "Lagos", "Lagos", "64510")
    for index, user_id in enumerate(SPRAY_USERS):
        person = user(user_id)
        usual = DEVICES[person["device"]]
        add(
            bucket,
            fill_event(
                at(date(2026, 11, 11), 8, 0),
                person,
                "success",
                us_place(person, office=True),
                usual,
            ),
            f"spray_context_{user_id}",
        )
        minute = 40 + index
        label = None
        if index == 0:
            label = "spray_u001_fail"
        elif index == 4:
            label = "spray_u010_fail"
        elif user_id == "U022":
            label = "spray_u022_fail"
        row = fill_event(
            at(date(2026, 11, 11), 13, minute),
            person,
            "failure",
            spray_place,
            BLANK_DEVICE,
            failure_reason="invalid_password",
            mfa_required="false",
            mfa_result="",
            auth_requirement="single_factor",
        )
        row["country_code"] = "NG"
        add(bucket, row, label)

    person = user("U022")
    sprayed = fill_event(
        at(date(2026, 11, 11), 14, 0),
        person,
        "success",
        spray_place,
        DEVICES["linux_firefox"],
        mfa_required="false",
        mfa_result="not_required",
        auth_requirement="single_factor",
        client_app="legacy_protocol",
    )
    sprayed["country_code"] = "NG"
    add(bucket, sprayed, "spray_u022_success")

    # Known device, known country, 1:40am Chicago.
    person = user("U031")
    add(
        bucket,
        fill_event(
            at(date(2026, 11, 12), 1, 40),
            person,
            "success",
            us_place(person, office=False),
            DEVICES[person["device"]],
        ),
        "latenight_u031",
    )


def write_outputs(csv_path: Path = DEFAULT_CSV, manifest_path: Path = DEFAULT_MANIFEST) -> dict:
    rows, manifest = build_rows()
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return {
        "rows": len(rows),
        "csv": str(csv_path),
        "manifest": str(manifest_path),
        "labels": sorted(manifest),
    }


def main() -> None:
    summary = write_outputs()
    print(
        f"Wrote {summary['rows']} events to {summary['csv']} "
        f"and {len(summary['labels'])} planted labels to {summary['manifest']}"
    )


if __name__ == "__main__":
    main()
