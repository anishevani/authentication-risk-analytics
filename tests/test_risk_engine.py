"""Scenarios for the sign-in risk score.

Each case states the history the rule is allowed to see, the points, and the
level. The planted-extract test at the bottom checks that the same rules fire
on the labeled rows in data/raw/authentication_events.csv.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from risk_engine import POINTS, calculate_risk, risk_level_for

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "data" / "raw" / "authentication_events.csv"
MANIFEST_PATH = ROOT / "data" / "raw" / "planted_events.json"


def ev(**overrides) -> dict:
    row = {
        "event_id": "T",
        "event_time": "2026-11-10T15:00:00Z",
        "user_id": "U100",
        "username": "analyst@northwind.example",
        "auth_result": "success",
        "failure_reason": "",
        "ip_address": "198.51.100.10",
        "country_code": "US",
        "region": "Illinois",
        "city": "Chicago",
        "asn": "64500",
        "user_agent": "Mozilla/5.0",
        "os_name": "Windows 10",
        "browser_name": "Chrome",
        "device_type": "desktop",
        "client_app": "browser",
        "mfa_required": "true",
        "mfa_result": "satisfied",
        "session_id": "S-T",
        "auth_requirement": "multi_factor",
        "sign_in_type": "interactive",
    }
    row.update(overrides)
    return row


def baseline(user: str = "U100") -> list[dict]:
    """Four weekday-morning successes on the usual Chicago desktop."""
    return [
        ev(
            event_id=f"B{index}",
            event_time=f"2026-11-{day}T15:00:00Z",
            user_id=user,
            session_id=f"S-B{index}",
        )
        for index, day in enumerate(("03", "04", "05", "06"), start=1)
    ]


def password_failure(event_id: str, when: str, user: str = "U100", **overrides) -> dict:
    return ev(
        event_id=event_id,
        event_time=when,
        user_id=user,
        auth_result="failure",
        failure_reason="invalid_password",
        mfa_result="",
        session_id="",
        **overrides,
    )


def scenario_normal():
    return {
        "name": "normal_login",
        "event": ev(),
        "history": baseline(),
        "score": 0,
        "level": "low",
        "signals": [],
    }


def scenario_wrong_password_once():
    return {
        "name": "wrong_password_once",
        "event": password_failure("T", "2026-11-10T15:00:00Z"),
        "history": baseline(),
        "score": 5,
        "level": "low",
        "signals": ["failed_login"],
    }


def scenario_repeated_failures():
    history = baseline() + [
        password_failure("F1", "2026-11-10T14:20:00Z"),
        password_failure("F2", "2026-11-10T14:30:00Z"),
        password_failure("F3", "2026-11-10T14:40:00Z"),
        password_failure("F4", "2026-11-10T14:50:00Z"),
    ]
    return {
        "name": "repeated_failures",
        "event": password_failure("T", "2026-11-10T15:00:00Z"),
        "history": history,
        "score": 30,
        "level": "medium",
        "signals": ["repeated_failed_logins"],
    }


def scenario_new_device():
    return {
        "name": "new_device",
        "event": ev(os_name="iOS 17", browser_name="Safari", device_type="mobile", client_app="mobile_app"),
        "history": baseline(),
        "score": 15,
        "level": "low",
        "signals": ["new_device"],
    }


def scenario_foreign_location():
    return {
        "name": "foreign_location",
        "event": ev(country_code="DE", region="Berlin", city="Berlin", ip_address="203.0.113.180"),
        "history": baseline(),
        "score": 20,
        "level": "low",
        "signals": ["unusual_location"],
    }


def scenario_late_night():
    return {
        "name": "late_night_login",
        "event": ev(event_time="2026-11-10T07:30:00Z"),
        "history": baseline(),
        "score": 10,
        "level": "low",
        "signals": ["unusual_time"],
    }


def scenario_failures_then_success():
    history = baseline() + [
        password_failure("F1", "2026-11-10T14:40:00Z"),
        password_failure("F2", "2026-11-10T14:45:00Z"),
        password_failure("F3", "2026-11-10T14:50:00Z"),
    ]
    return {
        "name": "failures_followed_by_success",
        "event": ev(),
        "history": history,
        "score": 35,
        "level": "medium",
        "signals": ["failures_followed_by_success"],
    }


def scenario_password_spray():
    history = baseline()
    for index, user in enumerate(("U201", "U202", "U203", "U204"), start=1):
        history.append(
            password_failure(
                f"S{index}",
                f"2026-11-10T14:{40 + index}:00Z",
                user=user,
                ip_address="192.0.2.50",
                country_code="US",
            )
        )
    return {
        "name": "password_spray",
        "event": password_failure("T", "2026-11-10T14:50:00Z", ip_address="192.0.2.50"),
        "history": history,
        "score": 35,
        "level": "medium",
        "signals": ["failed_login", "password_spray_source"],
    }


def scenario_mfa_denied():
    return {
        "name": "mfa_denied",
        "event": ev(
            auth_result="failure",
            failure_reason="mfa_denied",
            mfa_result="denied",
            session_id="",
        ),
        "history": baseline(),
        "score": 30,
        "level": "medium",
        "signals": ["mfa_denied"],
    }


def scenario_impossible_travel():
    history = baseline() + [
        ev(event_id="HOME", event_time="2026-11-10T15:00:00Z", session_id="S-HOME")
    ]
    return {
        "name": "impossible_travel",
        "event": ev(
            event_time="2026-11-10T16:00:00Z",
            country_code="NG",
            region="Lagos",
            city="Lagos",
            ip_address="192.0.2.40",
        ),
        "history": history,
        "score": 45,
        "level": "medium",
        "signals": ["unusual_location", "impossible_travel"],
    }


def scenario_legacy_protocol():
    return {
        "name": "legacy_protocol",
        "event": ev(client_app="legacy_protocol"),
        "history": baseline(),
        "score": 15,
        "level": "low",
        "signals": ["legacy_protocol"],
    }


def scenario_combined_high():
    history = baseline() + [
        password_failure("F1", "2026-11-10T14:40:00Z"),
        password_failure("F2", "2026-11-10T14:45:00Z"),
        password_failure("F3", "2026-11-10T14:50:00Z"),
    ]
    return {
        "name": "combined_high",
        "event": ev(
            os_name="Linux",
            browser_name="Firefox",
            country_code="DE",
            region="Berlin",
            city="Berlin",
            ip_address="203.0.113.180",
        ),
        "history": history,
        "score": 70,
        "level": "high",
        "signals": ["failures_followed_by_success", "new_device", "unusual_location"],
    }


def scenario_combined_critical():
    history = baseline() + [
        password_failure("F1", "2026-11-10T07:10:00Z"),
        password_failure("F2", "2026-11-10T07:14:00Z"),
        password_failure("F3", "2026-11-10T07:18:00Z"),
        password_failure("F4", "2026-11-10T07:22:00Z"),
        password_failure("F5", "2026-11-10T07:26:00Z"),
    ]
    return {
        "name": "combined_critical",
        "event": ev(
            event_time="2026-11-10T07:30:00Z",
            os_name="Linux",
            browser_name="Firefox",
            country_code="BR",
            region="Sao Paulo",
            city="Sao Paulo",
            ip_address="192.0.2.77",
            client_app="legacy_protocol",
            mfa_required="false",
            mfa_result="not_required",
            auth_requirement="single_factor",
        ),
        "history": history,
        "score": 100,
        "level": "critical",
        "signals": [
            "repeated_failed_logins",
            "failures_followed_by_success",
            "new_device",
            "unusual_location",
            "unusual_time",
            "legacy_protocol",
        ],
    }


SCENARIOS = [
    scenario_normal(),
    scenario_wrong_password_once(),
    scenario_repeated_failures(),
    scenario_new_device(),
    scenario_foreign_location(),
    scenario_late_night(),
    scenario_failures_then_success(),
    scenario_password_spray(),
    scenario_mfa_denied(),
    scenario_impossible_travel(),
    scenario_legacy_protocol(),
    scenario_combined_high(),
    scenario_combined_critical(),
]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda scenario: scenario["name"])
def test_scenario_score(scenario):
    result = calculate_risk(scenario["event"], scenario["history"])
    assert result["signals"] == scenario["signals"]
    assert result["risk_level"] == scenario["level"]
    assert result["risk_score"] == scenario["score"]
    raw = sum(item["points"] for item in result["contributions"])
    assert result["risk_score"] == min(100, raw)
    assert [item["signal"] for item in result["contributions"]] == result["signals"]
    for item in result["contributions"]:
        assert item["points"] == POINTS[item["signal"]]
        assert item["reason"]


def test_four_failures_stay_a_single_failure():
    history = baseline() + [
        password_failure("F1", "2026-11-10T14:40:00Z"),
        password_failure("F2", "2026-11-10T14:46:00Z"),
        password_failure("F3", "2026-11-10T14:52:00Z"),
    ]
    result = calculate_risk(password_failure("T", "2026-11-10T15:00:00Z"), history)
    assert result["signals"] == ["failed_login"]
    assert result["risk_score"] == 5


def test_failure_exactly_60_minutes_earlier_is_outside_the_window():
    history = baseline() + [
        password_failure("EDGE", "2026-11-10T14:00:00Z"),
        password_failure("F1", "2026-11-10T14:40:00Z"),
        password_failure("F2", "2026-11-10T14:46:00Z"),
        password_failure("F3", "2026-11-10T14:52:00Z"),
    ]
    result = calculate_risk(password_failure("T", "2026-11-10T15:00:00Z"), history)
    assert result["signals"] == ["failed_login"]
    assert result["risk_score"] == 5


def test_first_login_has_no_personal_baseline():
    result = calculate_risk(ev(country_code="NG", os_name="Linux", browser_name="Firefox"), [])
    assert result["risk_score"] == 0
    assert result["signals"] == []


def test_blank_device_is_not_a_new_device():
    result = calculate_risk(
        ev(os_name="", browser_name="", device_type="", user_agent=""),
        baseline(),
    )
    assert "new_device" not in result["signals"]


def test_night_shift_history_does_not_flag_another_night_login():
    history = [
        ev(event_id=f"N{index}", event_time=f"2026-11-0{index}T07:15:00Z", session_id=f"S-N{index}")
        for index in range(3, 7)
    ]
    result = calculate_risk(ev(event_time="2026-11-10T07:30:00Z"), history)
    assert "unusual_time" not in result["signals"]
    assert result["risk_score"] == 0


def test_same_user_failures_on_one_ip_are_not_a_spray():
    history = [
        password_failure("F1", "2026-11-10T14:40:00Z", ip_address="192.0.2.50"),
        password_failure("F2", "2026-11-10T14:42:00Z", ip_address="192.0.2.50"),
        password_failure("F3", "2026-11-10T14:44:00Z", ip_address="192.0.2.50"),
        password_failure("F4", "2026-11-10T14:46:00Z", ip_address="192.0.2.50"),
    ]
    result = calculate_risk(
        password_failure("T", "2026-11-10T14:48:00Z", ip_address="192.0.2.50"),
        baseline() + history,
    )
    assert "password_spray_source" not in result["signals"]
    assert "repeated_failed_logins" in result["signals"]


def test_future_events_in_history_are_ignored():
    history = baseline() + [
        password_failure("LATER", "2026-11-10T18:00:00Z"),
        ev(event_id="T", event_time="2026-11-10T15:00:00Z"),
    ]
    result = calculate_risk(ev(), history)
    assert result["risk_score"] == 0
    assert result["signals"] == []


def test_mfa_denial_is_not_also_counted_as_a_password_failure():
    result = calculate_risk(
        ev(auth_result="failure", failure_reason="mfa_denied", mfa_result="denied", session_id=""),
        baseline(),
    )
    assert result["signals"] == ["mfa_denied"]
    assert result["risk_score"] == POINTS["mfa_denied"]


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, "low"),
        (29, "low"),
        (30, "medium"),
        (59, "medium"),
        (60, "high"),
        (79, "high"),
        (80, "critical"),
        (100, "critical"),
    ],
)
def test_level_bands(score, level):
    assert risk_level_for(score) == level


def test_level_rejects_scores_outside_the_cap():
    with pytest.raises(ValueError):
        risk_level_for(101)


PLANTED = {
    "normal_u001": (0, []),
    "typo_u002": (5, ["failed_login"]),
    "typo_u002_success": (0, []),
    "new_device_u006": (15, ["new_device"]),
    "traveler_u008_day1": (20, ["unusual_location"]),
    "traveler_u008_day2": (0, []),
    "traveler_u008_day3": (0, []),
    "burst_u014_fail1": (5, ["failed_login"]),
    "burst_u014_fail5": (30, ["repeated_failed_logins"]),
    "mfa_u019": (30, ["mfa_denied"]),
    "latenight_u031": (10, ["unusual_time"]),
    "travel_u012_home": (0, []),
    "travel_u012_lagos": (45, ["unusual_location", "impossible_travel"]),
    "travel_u012_return": (0, []),
    "brute_u009_recovery": (0, []),
    "spray_u001_fail": (40, ["failed_login", "unusual_location", "legacy_protocol"]),
    "spray_u010_fail": (
        70,
        ["failed_login", "unusual_location", "legacy_protocol", "password_spray_source"],
    ),
    "spray_u022_success": (
        80,
        ["new_device", "unusual_location", "legacy_protocol", "password_spray_source"],
    ),
    "brute_u009_fail5": (
        75,
        ["repeated_failed_logins", "unusual_location", "unusual_time", "legacy_protocol"],
    ),
    "brute_u009_success": (
        100,
        [
            "repeated_failed_logins",
            "failures_followed_by_success",
            "new_device",
            "unusual_location",
            "unusual_time",
            "legacy_protocol",
        ],
    ),
}


def test_extract_queue_matches_the_profiled_file():
    with CSV_PATH.open(newline="") as handle:
        events = list(csv.DictReader(handle))
    from collections import Counter

    from risk_engine import score_events

    levels = Counter(item["risk_level"] for item in score_events(events))
    assert len(events) == 1124
    assert levels["low"] == 1100
    assert levels["medium"] == 12
    assert levels["high"] == 10
    assert levels["critical"] == 2


def test_planted_rows_in_the_extract_score_as_documented():
    with CSV_PATH.open(newline="") as handle:
        events = list(csv.DictReader(handle))
    manifest = json.loads(MANIFEST_PATH.read_text())
    ordered = sorted(events, key=lambda row: (row["event_time"], row["event_id"]))
    position = {row["event_id"]: index for index, row in enumerate(ordered)}
    for label, (score, signals) in PLANTED.items():
        event_id = manifest[label]["event_id"]
        index = position[event_id]
        result = calculate_risk(ordered[index], ordered[:index])
        assert result["signals"] == signals, label
        assert result["risk_score"] == score, label
        assert result["risk_level"] == risk_level_for(score)
