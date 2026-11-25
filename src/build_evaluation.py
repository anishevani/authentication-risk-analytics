"""Write evaluation/security_scenarios.json from the scored extract.

Summarizer rows are real attempts. The rejected row is a loose note that
the checker is expected to fail. It is not produced by summarize_incident.
"""

from __future__ import annotations

import json
from pathlib import Path

from build_dashboard import build_records, load_events
from incident_summarizer import facts_from_event, rejected_example, review_explanation, summarize_incident
from risk_engine import score_events

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON = ROOT / "evaluation" / "security_scenarios.json"

CASES = (
    ("normal_login", "E000014"),
    ("wrong_password_once", "E000120"),
    ("mfa_denied", "E000510"),
    ("impossible_travel", "E000732"),
    ("spray_success", "E000880"),
    ("critical_sao_paulo_success", "E000905"),
)


def scenario_document(events: list[dict]) -> dict:
    scored = {item["event_id"]: item for item in score_events(events)}
    by_id = {row["event_id"]: row for row in events}
    scenarios = []
    for name, event_id in CASES:
        facts = facts_from_event(by_id[event_id], scored[event_id])
        explanation = summarize_incident(facts)
        scenarios.append(
            {
                "id": name,
                "kind": "summarizer",
                "event_id": event_id,
                "facts": facts,
                "explanation": explanation,
                "review": review_explanation(explanation, facts),
            }
        )
    normal = next(item["facts"] for item in scenarios if item["id"] == "normal_login")
    bad = rejected_example(normal)
    scenarios.append(
        {
            "id": "rejected_loose_wording",
            "kind": "rejected_example",
            "event_id": normal["event_id"],
            "facts": normal,
            "explanation": bad,
            "review": review_explanation(bad, normal),
            "what_is_wrong": [
                "Says the user was hacked and that account takeover is confirmed.",
                "Names a Russian address that is not on the row.",
                "Cites a threat-intel match the extract does not have.",
                "Tells the analyst to disable every employee and reset all passwords.",
                "Does not quote the signal sentence, because no signal fired.",
            ],
        }
    )
    return {"scenarios": scenarios}


def write_evaluation(events: list[dict], path: Path = DEFAULT_JSON) -> dict:
    document = scenario_document(events)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n")
    return document


def main() -> None:
    document = write_evaluation(load_events(ROOT / "data" / "raw" / "authentication_events.csv"))
    for scenario in document["scenarios"]:
        review = scenario["review"]
        print(
            scenario["id"],
            "invented" if review["invented_facts"] else "grounded",
            "certain" if review["exaggerated_certainty"] else "hedged",
            "bad-step" if review["bad_recommendation"] else "step-ok",
            "missing" if review["missing_evidence"] else "evidence-ok",
        )


if __name__ == "__main__":
    main()
