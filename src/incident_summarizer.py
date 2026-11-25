"""Incident note built only from verified event facts.

The note may quote the score, the level, and the signal sentences already
produced by the risk engine. It may not add a place, an address, a count,
or a conclusion that is not in those facts.

The wording for a queued attempt is "this activity warrants investigation
because...". The note does not say the user was hacked, and it does not
treat the score as proof of account takeover.
"""

from __future__ import annotations

import json
import re

from risk_engine import SIGNAL_ORDER, device_key, device_label

HIGH_RISK_MIN_SCORE = 60
QUEUE_MIN_SCORE = 30

FACT_KEYS = (
    "event_id",
    "event_time",
    "user_id",
    "username",
    "auth_result",
    "failure_reason",
    "ip_address",
    "country_code",
    "city",
    "device",
    "client_app",
    "mfa_result",
    "risk_score",
    "risk_level",
    "signals",
    "contributions",
)

# Phrases the note is not allowed to produce. "confirmed" alone is avoided
# so that a step may still say "confirm whether" a person saw a prompt.
HACKED_CLAIMS = (
    "hacked",
    "compromised",
    "account takeover",
    "confirmed attack",
    "confirmed breach",
    "was breached",
    "malicious user",
    "this user was",
)
CERTAINTY_CLAIMS = (
    "definitely",
    "certainly",
    "undoubtedly",
    "no doubt",
    "guaranteed",
    "is confirmed",
    "was confirmed",
)
INVENTED_MARKERS = (
    "threat intel",
    "threat-intel",
    "is_attack_ip",
    "russia",
    "russian",
    "china",
    "vietnam",
    "north korea",
)
CONTAINMENT_PHRASES = (
    "disable every",
    "lock every",
    "reset all",
    "reset every",
    "every employee",
    "all passwords",
)
DISMISS_PHRASES = (
    "no action",
    "ignore this",
    "false alarm",
    "nothing to investigate",
)

STEP_LIBRARY = {
    "repeated_failed_logins": (
        "Line the failure timestamps up against this user's other attempts "
        "the same day, and ask whether they were retrying a password."
    ),
    "failures_followed_by_success": (
        "Use the session id as the pointer into access logs. This extract has "
        "no authorization events, so that read is outside this file."
    ),
    "new_device": (
        "Ask whether the person enrolled a new phone or browser. The device "
        "value is the operating system, browser, and device type, not a hardware id."
    ),
    "unusual_location": (
        "Ask whether travel or a VPN explains the country named in the signal."
    ),
    "impossible_travel": (
        "Put the two timestamps in the signal side by side. A VPN can produce this gap."
    ),
    "unusual_time": (
        "Compare the local hour in the signal with this user's earlier successful "
        "hours before treating the clock as suspicious."
    ),
    "mfa_denied": "Ask whether the person saw the MFA prompt and rejected it.",
    "legacy_protocol": (
        "Check whether this account is allowed to sign in with a legacy client. "
        "In this extract those clients do not require MFA."
    ),
    "password_spray_source": (
        "List the other accounts that failed from this IP in the same hour "
        "before changing any password."
    ),
    "failed_login": (
        "One password failure is below the queue. Check that it did not continue into a burst."
    ),
}


def facts_from_event(event: dict, result: dict) -> dict:
    """Copy the fields the note is allowed to see. Extra keys on either dict are dropped."""
    key = device_key(event)
    device = device_label(key) if key else ""
    failure_reason = event.get("failure_reason") or ""
    mfa_result = event.get("mfa_result") or ""
    contributions = []
    for item in result.get("contributions") or []:
        contributions.append(
            {
                "signal": item["signal"],
                "points": int(item["points"]),
                "reason": item["reason"],
            }
        )
    return {
        "event_id": str(event["event_id"]),
        "event_time": str(event["event_time"]),
        "user_id": str(event["user_id"]),
        "username": str(event["username"]),
        "auth_result": str(event["auth_result"]),
        "failure_reason": str(failure_reason),
        "ip_address": str(event["ip_address"]),
        "country_code": str(event["country_code"]),
        "city": str(event.get("city") or ""),
        "device": device,
        "client_app": str(event["client_app"]),
        "mfa_result": str(mfa_result),
        "risk_score": int(result["risk_score"]),
        "risk_level": str(result["risk_level"]),
        "signals": list(result.get("signals") or []),
        "contributions": contributions,
    }


def _require_facts(facts: dict) -> dict:
    if not isinstance(facts, dict):
        raise TypeError("facts must be a dict")
    missing = [key for key in FACT_KEYS if key not in facts]
    if missing:
        raise ValueError(f"facts are missing keys: {missing}")
    cleaned = {key: facts[key] for key in FACT_KEYS}
    if not isinstance(cleaned["contributions"], list):
        raise TypeError("contributions must be a list")
    if not isinstance(cleaned["signals"], list):
        raise TypeError("signals must be a list")
    return cleaned


def _steps_for(facts: dict) -> list[str]:
    steps = [
        STEP_LIBRARY[name]
        for name in SIGNAL_ORDER
        if name in facts["signals"] and name in STEP_LIBRARY
    ]
    if facts["risk_score"] < QUEUE_MIN_SCORE:
        steps.append("No containment. Leave the attempt in the log.")
    else:
        steps.append(
            "Write down which sentence was checked against the log before any account change."
        )
    return steps


def _join_text(explanation: dict) -> str:
    parts = [
        explanation["summary"],
        explanation["why_flagged"],
        *explanation["relevant_indicators"],
        *explanation["recommended_steps"],
    ]
    return "\n".join(parts)


def summarize_incident(facts: dict) -> dict:
    facts = _require_facts(facts)
    score = facts["risk_score"]
    level = facts["risk_level"]
    summary = (
        f"Attempt {facts['event_id']} for {facts['username']} at {facts['event_time']} "
        f"from {facts['ip_address']} in {facts['country_code']}"
        + (f" ({facts['city']})" if facts["city"] else "")
        + f". Result: {facts['auth_result']}. Client: {facts['client_app']}. "
        f"Score: {score} ({level})."
    )
    if score >= QUEUE_MIN_SCORE:
        summary += " This activity warrants investigation because the fired signals are listed below."
        why = "This activity warrants investigation because " + " ".join(
            item["reason"] for item in facts["contributions"]
        )
    elif facts["contributions"]:
        why = "The score stays in the low band. Signals that fired: " + " ".join(
            item["reason"] for item in facts["contributions"]
        )
    else:
        why = "No risk signal fired. The attempt stays in the log."
    indicators = [
        f"{item['signal']} (+{item['points']}): {item['reason']}"
        for item in facts["contributions"]
    ]
    if not indicators:
        indicators = ["No signal fired."]
    explanation = {
        "summary": summary,
        "why_flagged": why,
        "relevant_indicators": indicators,
        "recommended_steps": _steps_for(facts),
    }
    problems = review_explanation(explanation, facts)
    if any(problems[name] for name in ("invented_facts", "exaggerated_certainty", "bad_recommendation", "missing_evidence")):
        raise RuntimeError(f"summarizer produced a note that fails review: {problems}")
    return explanation


def review_explanation(explanation: dict, facts: dict) -> dict:
    """Four checks from the Wednesday evaluation: invented, certain, bad step, missing evidence."""
    facts = _require_facts(facts)
    blob = _join_text(explanation)
    lowered = blob.lower()
    corpus = json.dumps(facts, ensure_ascii=False)
    corpus_lower = corpus.lower()

    invented = []
    for number in re.findall(r"\d+", blob):
        if number not in corpus:
            invented.append(number)
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob):
        if ip not in corpus:
            invented.append(ip)
    for marker in INVENTED_MARKERS:
        if marker in lowered and marker not in corpus_lower:
            invented.append(marker)

    exaggerated = [phrase for phrase in HACKED_CLAIMS + CERTAINTY_CLAIMS if phrase in lowered]
    bad = [phrase for phrase in CONTAINMENT_PHRASES if phrase in lowered]
    if facts["risk_score"] < QUEUE_MIN_SCORE:
        for phrase in ("disable the account", "lock the account", "reset the password"):
            if phrase in lowered:
                bad.append(phrase)
    if facts["risk_score"] >= HIGH_RISK_MIN_SCORE:
        bad.extend(phrase for phrase in DISMISS_PHRASES if phrase in lowered)

    missing = []
    if facts["contributions"]:
        for item in facts["contributions"]:
            if item["reason"] not in blob:
                missing.append(item["signal"])
    elif "no risk signal fired" not in lowered and "no signal fired" not in lowered:
        missing.append("no_signal")

    return {
        "invented_facts": bool(invented),
        "exaggerated_certainty": bool(exaggerated),
        "bad_recommendation": bool(bad),
        "missing_evidence": bool(missing),
        "invented_details": invented,
        "certainty_details": exaggerated,
        "recommendation_details": bad,
        "missing_details": missing,
    }


def rejected_example(facts: dict) -> dict:
    """A loose note used only as the failure case in the evaluation. Not a real output."""
    _require_facts(facts)
    return {
        "summary": (
            "This user was hacked from a Russian IP 203.0.113.99. "
            "The account takeover is confirmed."
        ),
        "why_flagged": "The model is certain this is definitely a breach.",
        "relevant_indicators": ["Threat intel matched the address."],
        "recommended_steps": [
            "Disable every employee account and reset all passwords immediately."
        ],
    }
