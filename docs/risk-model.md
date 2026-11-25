# Risk model

Thursday, November 19. The score is a queue priority for one authentication attempt. It is the sum of the rules that fired, capped at 100. Each fired rule adds a fixed number of points and one sentence. `calculate_risk` returns both.

A probability of account takeover would need confirmed takeover labels. This extract has none. The weights below are judgments about what security operations should read first. They are written down so they can be changed on purpose.

The worked examples are in `docs/risk-scenarios.md`. The constants live in `src/risk_engine.py` under the same names used here.

## What the function sees

```python
calculate_risk(event, history) -> {
    "risk_score": 80,
    "risk_level": "critical",
    "signals": ["new_device", "unusual_location", "legacy_protocol", "password_spray_source"],
    "contributions": [
        {"signal": "new_device", "points": 15, "reason": "..."},
    ],
}
```

`event` is one attempt, with the columns in `docs/data-profile.md`. `history` is earlier attempts, for this user and for other users. Rows at or after `event_time` are ignored, and a row with the same `event_id` is ignored. Two events that share a timestamp do not see each other.

Personal rules (new device, new country, off-hours, impossible travel) need a baseline of earlier successes for that user. A person's first login scores 0 from those rules. Absolute rules (a password failure, a repeated burst, an MFA denial, a legacy client, a spray address) can fire with an empty history.

## Bands

| Score | Level | How the queue uses it |
| --- | --- | --- |
| 0–29 | low | Stays in the log |
| 30–59 | medium | Read after high and critical |
| 60–79 | high | Read the same day |
| 80–100 | critical | Read first. A session may already exist |

On this file that split is 1,100 low, 12 medium, 10 high, 2 critical.

## Rules

Points are not probabilities and they are not scaled against each other after the fact. If the sentences add past 100, the score is 100 and every sentence is still listed. The overnight Sao Paulo success adds to 125 and is reported as 100, with all six sentences intact.

| Signal | Points | Fires when |
| --- | --- | --- |
| `failed_login` | 5 | This attempt is `invalid_password` or `account_locked`, and the repeated-failure rule did not fire |
| `repeated_failed_logins` | 30 | This user has at least 5 password failures in the 60 minutes ending at this attempt, including this attempt if it is one |
| `failures_followed_by_success` | 35 | This attempt succeeded, and the user had at least 3 password failures in the prior 30 minutes |
| `new_device` | 15 | The device proxy has no earlier success for this user, and the user already has at least one success on a known device |
| `unusual_location` | 20 | The country has no earlier success for this user, and the user already has at least one success with a country |
| `impossible_travel` | 25 | The previous successful country is different, and that success was at most 2 hours ago |
| `unusual_time` | 10 | The Chicago hour is 0–5, the user has at least 3 earlier successes, and under 10% of those successes were in hours 0–5 |
| `mfa_denied` | 30 | `mfa_result` is `denied` |
| `legacy_protocol` | 15 | `client_app` is `legacy_protocol` |
| `password_spray_source` | 30 | This IP has password failures for at least 5 distinct users in the 60 minutes ending at this attempt |

Password failures are `invalid_password` and `account_locked`. An MFA denial is its own rule and is not also counted as a bad password.

The device proxy is lowercase `os_name`, `browser_name`, and `device_type`. A blank proxy does not fire `new_device`. Browser version is not part of the key, so Chrome 120 and Chrome 121 are the same device. Windows 10 and Windows 11 would be different devices. A shared office NAT does not fire `password_spray_source` unless five accounts actually fail from it inside the same hour. On this file the office addresses never do.

`impossible_travel` and `unusual_location` can both fire. They answer different questions: "this country is new for the account" and "the previous success was too recent for this country to be physical travel". A VPN can trip the second one. The sentence names the previous country and the gap in minutes, which is the check an analyst uses to throw the row out.

`unusual_time` uses America/Chicago for every employee. The reason is in the profile: the file has no per-user zone, and the workforce in the extract is in Chicago, New York, and Austin. Someone whose successful history is already overnight is not flagged for another overnight login. The share threshold is there for that case.

## Why these weights, including where they leave the example

The brief's example card was: repeated failures +25, new device +15, unusual location +20, unusual time +10, threat indicator +30. New device, unusual location, and unusual time are unchanged. The other choices are:

- Repeated failures are +30, not +25. Five failures in an hour should enter the medium queue on their own. At +25 the burst sits in low, next to a typo, and the queue misses the pattern the business problem asked for.
- The threat indicator is `password_spray_source` at +30. The file has no threat-intel column and no `is_attack_ip` flag. The observable version of "this source is hostile" is one address failing passwords across accounts in an hour. Calling that column a threat feed would invent a field the profile says is absent.
- `failed_login` is +5 so one typo stays low (score 5) and is still visible in the sentence list.
- `failures_followed_by_success` is +35 so a success after a short burst is medium even when the device and the country are familiar. A success is when the session starts.
- `mfa_denied` is +30. The password was accepted and the second factor was not. That is a different event from a typo, and it is medium on its own.
- `legacy_protocol` is +15. Alone it stays low. On a new country, or on a spray address, it is the MFA bypass stacked on top of the other facts.
- `impossible_travel` is +25. A new country the next morning of a trip is `unusual_location` only (+20, low). The same new country 40 minutes after a domestic success is medium.

## What the model will get wrong

A first login has no personal baseline, so a brand-new account's first session from anywhere scores 0 unless an absolute rule fires (legacy client, spray address, MFA denial, password failure).

A trip to a country the account has used before scores 0 on location. Berlin day 2 in this file is that case. The SQL "first time in this country" query and the score agree: only the first Berlin success is listed.

City changes inside the United States add nothing. Chicago to Austin is the same country.

The office NAT collects typos. A whole-file failure count ranks it. The 60-minute distinct-user rule does not. Both views are in the project on purpose. Using only the count would page the headquarters address.

The cap hides the difference between 100 and anything above it. The Sao Paulo success is 125 points of rules and a score of 100. Read `contributions` when two critical rows need to be ordered against each other.

## Interview drill

Why choose explainable rules instead of a complex model here?

I would keep the rules, and I would say so before talking about accuracy.

Security operations has to explain a queue placement to the person who was locked out, to an auditor, and to the analyst who will tune the threshold next month. Each point in this score maps to a sentence with a count, a window, and a threshold. Someone else can recompute `E000905` from the log line and the card and land on the same six reasons. That is the property I would not give up.

Analysts ignore a score they cannot check. A rule they can argue with is a rule they will use. Trust is part of the control. If the Lagos row is a VPN, the analyst can see "40 minutes after a US success" and clear it. A model score of 0.91 does not tell them which fact to clear.

This file cannot train a supervised model of account takeover. There is no confirmed-takeover label. There are 1,124 attempts and 36 users. Fitting a complex model to that would produce a ranking we could not audit and could not defend when it was wrong. The public risk-based-authentication research sets are large and labeled. This operating file is not one of them. Rules do not need that label to put the overnight success at the top of today's queue.

The cost of a false high score is concrete: a lockout, or an analyst reading a benign row ahead of a real one. The cost is asymmetric, and it shows up one login at a time. If five failures in an hour is too sensitive, the change is `REPEATED_FAILURE_MIN` and a sentence in this note. The other rules stay put. A refit would move every weight at once, and we would still have no labeled set to judge the new fit.

What the rules give up is real. They miss combinations nobody wrote down, and the weights are judgments. I would treat the score as the queue, keep the sentences, and only compare a model against this card once confirmed takeovers exist to score both on. Until then the explainable card is the system I can hand to another analyst.
