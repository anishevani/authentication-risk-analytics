"""The incident note may quote the score and the signal sentences, and nothing past them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from build_dashboard import DEFAULT_CSV, build_records, load_events
from build_evaluation import CASES, scenario_document
from incident_summarizer import facts_from_event, summarize_incident

ROOT = Path(__file__).resolve().parents[1]
EVAL_PATH = ROOT / "evaluation" / "security_scenarios.json"


def test_queued_note_uses_the_investigation_wording_and_quotes_every_reason():
    events = load_events(DEFAULT_CSV)
    records = {row["event_id"]: row for row in build_records(events)}
    critical = records["E000905"]
    note = critical["explanation"]
    assert "warrants investigation because" in note["summary"]
    assert "warrants investigation because" in note["why_flagged"]
    assert "hacked" not in json.dumps(note).lower()
    for item in critical["contributions"]:
        assert item["reason"] in note["why_flagged"]
        assert item["reason"] in " ".join(note["relevant_indicators"])
    assert critical["risk_score"] == 100
    assert critical["risk_level"] == "critical"


def test_a_low_score_does_not_ask_for_containment():
    events = load_events(DEFAULT_CSV)
    records = {row["event_id"]: row for row in build_records(events)}
    normal = records["E000014"]
    assert normal["risk_score"] == 0
    blob = json.dumps(normal["explanation"]).lower()
    assert "warrants investigation" not in blob
    assert "no containment" in blob
    assert "disable" not in blob


def test_extra_keys_on_the_event_are_not_copied_into_the_note():
    events = load_events(DEFAULT_CSV)
    event = next(row for row in events if row["event_id"] == "E000014")
    event["analyst_note"] = "This user was hacked."
    from risk_engine import score_events

    result = next(item for item in score_events(events) if item["event_id"] == "E000014")
    facts = facts_from_event(event, result)
    assert "analyst_note" not in facts
    note = summarize_incident(facts)
    assert "hacked" not in json.dumps(note).lower()


def test_missing_fact_is_rejected():
    with pytest.raises(ValueError):
        summarize_incident({"event_id": "E1"})


def test_evaluation_file_matches_a_fresh_review():
    events = load_events(DEFAULT_CSV)
    fresh = scenario_document(events)
    saved = json.loads(EVAL_PATH.read_text())
    assert [item["id"] for item in saved["scenarios"]] == [name for name, _ in CASES] + [
        "rejected_loose_wording"
    ]
    by_id = {item["id"]: item for item in saved["scenarios"]}
    for scenario in fresh["scenarios"]:
        saved_scenario = by_id[scenario["id"]]
        assert saved_scenario["review"]["invented_facts"] == scenario["review"]["invented_facts"]
        assert saved_scenario["review"]["exaggerated_certainty"] == scenario["review"]["exaggerated_certainty"]
        assert saved_scenario["review"]["bad_recommendation"] == scenario["review"]["bad_recommendation"]
        assert saved_scenario["review"]["missing_evidence"] == scenario["review"]["missing_evidence"]
        assert saved_scenario["explanation"] == scenario["explanation"]
    rejected = by_id["rejected_loose_wording"]["review"]
    assert rejected["invented_facts"]
    assert rejected["exaggerated_certainty"]
    assert rejected["bad_recommendation"]
    assert rejected["missing_evidence"]
    for scenario in saved["scenarios"]:
        if scenario["kind"] == "summarizer":
            review = scenario["review"]
            assert not review["invented_facts"]
            assert not review["exaggerated_certainty"]
            assert not review["bad_recommendation"]
            assert not review["missing_evidence"]
