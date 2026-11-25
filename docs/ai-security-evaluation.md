# AI security evaluation

Wednesday, November 25. The question is whether the incident note stays inside the facts.

`src/incident_summarizer.py` writes four parts: summary, why flagged, relevant indicators, recommended steps. The only inputs are the row and the signal sentences from `calculate_risk`. `review_explanation` then checks four failure modes.

| Check | What fails it |
| --- | --- |
| Invented facts | A number, IP address, place name, or "threat intel" that is not in the fact payload |
| Exaggerated certainty | "hacked", "compromised", "account takeover", "definitely", "certainly", "this user was" |
| Bad recommendation | A company-wide disable or password reset, a lockout for a low score, or "no action" on a score of 60 or above |
| Missing evidence | A fired signal whose sentence is absent from the note, or a quiet row that never says no signal fired |

The cases are in `evaluation/security_scenarios.json`. Six are real rows. One is a loose note kept as the failure case. It is not produced by the summarizer. `tests/test_incident_summarizer.py` rebuilds the file's reviews and expects the same flags.

## Real rows

All six summarizer notes passed all four checks.

| Case | Event | Score | Wording |
| --- | --- | --- | --- |
| Normal login | `E000014` | 0 low | Stays in the log. No containment. |
| Wrong password once | `E000120` | 5 low | Quotes the single failure. No containment. |
| MFA denied | `E000510` | 30 medium | Warrants investigation. Asks whether the person saw the prompt. |
| Impossible travel | `E000732` | 45 medium | Quotes the 40-minute US-to-NG gap. Asks about a VPN. |
| Spray success | `E000880` | 80 critical | Quotes 12 users on `192.0.2.50`. Says to list those accounts before changing a password. |
| Sao Paulo success | `E000905` | 100 critical | Quotes all six signal sentences. Says the activity warrants investigation. |

The Sao Paulo summary, copied from the note:

> Attempt E000905 for indigo.walsh@northwind.example at 2026-11-12T07:20:00Z from 192.0.2.77 in BR (Sao Paulo). Result: success. Client: legacy_protocol. Score: 100 (critical). This activity warrants investigation because the fired signals are listed below.

The rule points on that row add to 125. The score the note reports is 100, which is the cap. The six sentences are still in "why flagged" and in the indicators. The note does not say the user was hacked.

## The loose note that fails

`rejected_loose_wording` uses the facts of the normal login (`E000014`, score 0, no signals) and a different paragraph:

> This user was hacked from a Russian IP 203.0.113.99. The account takeover is confirmed.

The checker marks all four:

| Check | Why |
| --- | --- |
| Invented facts | `203.0.113.99` is not the address on the row. "Russian" is not in the facts. "Threat intel" is not a column. |
| Exaggerated certainty | "hacked", "this user was", "account takeover", "definitely", "confirmed". |
| Bad recommendation | "Disable every employee account and reset all passwords immediately" on a score of 0. |
| Missing evidence | No signal fired, and the note never says so. |

That paragraph is the pattern the summarizer is built to avoid. A queued row says "this activity warrants investigation because" and then the signal sentence. A quiet row says to leave it in the log.
