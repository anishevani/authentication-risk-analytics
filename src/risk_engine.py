"""Explainable sign-in risk score.

Each fired rule adds a fixed number of points and a sentence. The score is
the sum of those points, capped at 100. It is a queue priority, not a
probability that the account was taken over.

The rules use only fields that exist on an event dict from the sign-in
extract: result, failure reason, time, user, IP, country, OS, browser,
device type, client app, and MFA result. There is no threat-intel column
and no hardware device id. `password_spray_source` is the threat signal
this file can actually support: one address failing passwords across
several accounts.

`history` is earlier events, for this user and for other users. Rows at
or after `event["event_time"]` are ignored, and a row with the same
`event_id` is ignored. Pass events that happened before this one.

Thresholds are named constants so a reviewer can match them to
docs/risk-model.md.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

POINTS = {
    "failed_login": 5,
    "repeated_failed_logins": 30,
    "failures_followed_by_success": 35,
    "new_device": 15,
    "unusual_location": 20,
    "impossible_travel": 25,
    "unusual_time": 10,
    "mfa_denied": 30,
    "legacy_protocol": 15,
    "password_spray_source": 30,
}

SIGNAL_ORDER = list(POINTS)

REPEATED_FAILURE_MIN = 5
REPEATED_FAILURE_WINDOW = timedelta(minutes=60)
FAILURE_SUCCESS_MIN = 3
FAILURE_SUCCESS_WINDOW = timedelta(minutes=30)
SPRAY_MIN_USERS = 5
SPRAY_WINDOW = timedelta(minutes=60)
TRAVEL_WINDOW = timedelta(hours=2)
UNUSUAL_TIME_MIN_HISTORY = 3
UNUSUAL_TIME_MAX_SHARE = 0.10
OFF_HOURS = frozenset(range(0, 6))
COMPANY_ZONE = ZoneInfo("America/Chicago")
PASSWORD_FAILURES = frozenset({"invalid_password", "account_locked"})
SCORE_CAP = 100


def risk_level_for(score: int) -> str:
    if score < 0 or score > SCORE_CAP:
        raise ValueError(f"risk_score must be between 0 and {SCORE_CAP}")
    if score <= 29:
        return "low"
    if score <= 59:
        return "medium"
    if score <= 79:
        return "high"
    return "critical"


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        if value is None or str(value).strip() == "":
            raise ValueError("event_time is required")
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _text(event: dict, key: str) -> str:
    value = event.get(key)
    if value is None:
        return ""
    return str(value).strip()


def _fmt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def device_key(event: dict) -> tuple[str, str, str] | None:
    """OS + browser + device type. A blank fingerprint is not a new device."""
    os_name = _text(event, "os_name").lower()
    browser = _text(event, "browser_name").lower()
    device_type = _text(event, "device_type").lower()
    if device_type == "unknown":
        device_type = ""
    if not os_name and not browser and not device_type:
        return None
    return (os_name, browser, device_type)


def device_label(key: tuple[str, str, str]) -> str:
    return " | ".join(part or "(blank)" for part in key)


def country_code(event: dict) -> str | None:
    value = _text(event, "country_code").upper()
    return value or None


def is_password_failure(event: dict) -> bool:
    return (
        _text(event, "auth_result").lower() == "failure"
        and _text(event, "failure_reason").lower() in PASSWORD_FAILURES
    )


def is_success(event: dict) -> bool:
    return _text(event, "auth_result").lower() == "success"


def _prior_events(event: dict, history: list[dict]) -> list[tuple[datetime, dict]]:
    current_time = parse_time(event.get("event_time"))
    event_id = _text(event, "event_id")
    prior = []
    for row in history:
        if not isinstance(row, dict):
            raise TypeError("history entries must be dicts")
        if event_id and _text(row, "event_id") == event_id:
            continue
        row_time = parse_time(row.get("event_time"))
        if row_time < current_time:
            prior.append((row_time, row))
    return prior


def calculate_risk(event: dict, history: list[dict] | None = None) -> dict:
    if not isinstance(event, dict):
        raise TypeError("event must be a dict")
    if history is None:
        history = []
    if not isinstance(history, list):
        raise TypeError("history must be a list of event dicts")

    user_id = _text(event, "user_id")
    if not user_id:
        raise ValueError("event is missing user_id")

    current_time = parse_time(event.get("event_time"))
    prior = _prior_events(event, history)
    user_prior = [(moment, row) for moment, row in prior if _text(row, "user_id") == user_id]
    user_successes = [(moment, row) for moment, row in user_prior if is_success(row)]

    fired: dict[str, str] = {}

    password_failures = [
        (moment, row)
        for moment, row in user_prior
        if is_password_failure(row)
        and current_time - REPEATED_FAILURE_WINDOW < moment < current_time
    ]
    if is_password_failure(event):
        password_failures.append((current_time, event))
    if len(password_failures) >= REPEATED_FAILURE_MIN:
        fired["repeated_failed_logins"] = (
            f"{len(password_failures)} password failures for this user "
            f"in the 60 minutes ending at this event. The threshold is "
            f"{REPEATED_FAILURE_MIN}."
        )
    elif is_password_failure(event):
        reason = _text(event, "failure_reason").lower()
        fired["failed_login"] = (
            f"This attempt is a password failure ({reason}), and fewer than "
            f"{REPEATED_FAILURE_MIN} password failures fell in the prior 60 minutes."
        )

    recent_failures = [
        row
        for moment, row in user_prior
        if is_password_failure(row)
        and current_time - FAILURE_SUCCESS_WINDOW < moment < current_time
    ]
    if is_success(event) and len(recent_failures) >= FAILURE_SUCCESS_MIN:
        fired["failures_followed_by_success"] = (
            f"This success follows {len(recent_failures)} password failures "
            f"in the prior 30 minutes. The threshold is {FAILURE_SUCCESS_MIN}."
        )

    current_device = device_key(event)
    seen_devices = []
    for _, row in user_successes:
        key = device_key(row)
        if key is not None and key not in seen_devices:
            seen_devices.append(key)
    if current_device is not None and seen_devices and current_device not in seen_devices:
        seen = ", ".join(device_label(key) for key in seen_devices)
        fired["new_device"] = (
            f"Device '{device_label(current_device)}' has no prior successful "
            f"login for this user. Prior successful devices: {seen}."
        )

    current_country = country_code(event)
    seen_countries = []
    for _, row in user_successes:
        code = country_code(row)
        if code and code not in seen_countries:
            seen_countries.append(code)
    if current_country and seen_countries and current_country not in seen_countries:
        fired["unusual_location"] = (
            f"Country {current_country} has no prior successful login for this "
            f"user. Prior successful countries: {', '.join(seen_countries)}."
        )

    located = [(moment, row) for moment, row in user_successes if country_code(row)]
    if current_country and located:
        last_moment, last_row = max(located, key=lambda item: item[0])
        gap = current_time - last_moment
        last_country = country_code(last_row)
        if last_country != current_country and timedelta(0) < gap <= TRAVEL_WINDOW:
            fired["impossible_travel"] = (
                f"Previous successful login was in {last_country} at {_fmt(last_moment)}, "
                f"{int(gap.total_seconds() // 60)} minutes before this event in "
                f"{current_country}. The window is 2 hours."
            )

    if len(user_successes) >= UNUSUAL_TIME_MIN_HISTORY:
        current_hour = current_time.astimezone(COMPANY_ZONE).hour
        off_count = sum(
            1
            for moment, _ in user_successes
            if moment.astimezone(COMPANY_ZONE).hour in OFF_HOURS
        )
        share = off_count / len(user_successes)
        if current_hour in OFF_HOURS and share < UNUSUAL_TIME_MAX_SHARE:
            fired["unusual_time"] = (
                f"Local hour is {current_hour} in America/Chicago, inside 00:00-05:59. "
                f"{off_count} of {len(user_successes)} prior successful logins for this "
                f"user were in that band (share {share:.2f}, threshold "
                f"{UNUSUAL_TIME_MAX_SHARE:.2f})."
            )

    if _text(event, "mfa_result").lower() == "denied":
        fired["mfa_denied"] = "MFA result is denied."

    if _text(event, "client_app").lower() == "legacy_protocol":
        fired["legacy_protocol"] = "Client app is legacy_protocol."

    current_ip = _text(event, "ip_address")
    if current_ip:
        spray_users = {
            _text(row, "user_id")
            for moment, row in prior
            if _text(row, "ip_address") == current_ip
            and is_password_failure(row)
            and current_time - SPRAY_WINDOW < moment < current_time
        }
        if is_password_failure(event):
            spray_users.add(user_id)
        if len(spray_users) >= SPRAY_MIN_USERS:
            fired["password_spray_source"] = (
                f"IP {current_ip} has password failures for {len(spray_users)} distinct "
                f"users in the 60 minutes ending at this event. The threshold is "
                f"{SPRAY_MIN_USERS}."
            )

    signals = [name for name in SIGNAL_ORDER if name in fired]
    contributions = [
        {"signal": name, "points": POINTS[name], "reason": fired[name]} for name in signals
    ]
    raw = sum(item["points"] for item in contributions)
    score = min(SCORE_CAP, raw)
    return {
        "risk_score": score,
        "risk_level": risk_level_for(score),
        "signals": signals,
        "contributions": contributions,
    }


def score_events(events: list[dict]) -> list[dict]:
    """Score each event with only the events that sort before it."""
    ordered = sorted(
        events,
        key=lambda row: (parse_time(row.get("event_time")), _text(row, "event_id")),
    )
    scored = []
    for index, event in enumerate(ordered):
        result = calculate_risk(event, ordered[:index])
        scored.append({"event_id": _text(event, "event_id"), **result})
    return scored
