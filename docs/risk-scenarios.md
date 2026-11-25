# Risk scenarios

Saturday, November 21. Each scenario is one call to `calculate_risk`. The history is earlier attempts only. Points come from `docs/risk-model.md`. The same arithmetic is locked in `tests/test_risk_engine.py`.

Where the teaching extract contains the same pattern, the event id is from `data/raw/planted_events.json`. Times below are UTC. Chicago is six hours behind in this date range.

Raw points can add past 100. The reported score stops at 100. The sentences do not.

## How to read a row

1. Start at 0.
2. Add a rule only if its condition is true for this attempt and this history.
3. Cap the sum at 100.
4. Band it: 0–29 low, 30–59 medium, 60–79 high, 80–100 critical.

A personal rule (device, country, hour, travel) stays quiet when the user has no earlier successes to compare against. An absolute rule (password failure, burst, MFA denial, legacy client, spray) does not need that baseline.

## 1. Normal login

**Score 0. Low. No signals.**

`U100` has four earlier successes: Windows 10, Chrome, desktop, United States, 09:00 Chicago. The new attempt is the same device, the same country, 09:00 Chicago, MFA satisfied, a browser, and it succeeds.

Nothing is different from the baseline, so every rule stays quiet. A quiet rule is a rule whose condition is false, not a rule that was skipped. There is no recent password failure, the device has succeeded before, the country has succeeded before, the hour is outside 0–5, MFA is satisfied, and the client is a browser.

In the extract this is `E000014`, `avery.chen@northwind.example`, `U001`, 2026-11-02T14:26:44Z (08:26 Chicago). Score 0.

Analyst: leave it in the log.

## 2. Wrong password once

**Score 5. Low. `failed_login`.**

Same baseline, same device, same country, same hour. This attempt is `invalid_password`. There are no other password failures in the prior 60 minutes.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `failed_login` | 5 | One password failure, under the burst threshold of 5 |

`repeated_failed_logins` stays quiet because the count is 1, not 5. A fourth failure inside the hour is still this rule and still score 5. The test `test_four_failures_stay_a_single_failure` locks that. A failure exactly 60 minutes earlier is outside the window and does not count.

In the extract: `E000120`, `blake.ortiz@northwind.example`, `U002`, 2026-11-03T14:12:00Z, score 5. The success two minutes later, `E000121`, is score 0. One preceding failure is under the "3 failures then a success" threshold.

Analyst: no page. The account got the password right on the next try, from the same device and country.

## 3. Repeated failures

**Score 30. Medium. `repeated_failed_logins`.**

Same device and country, 09:00 Chicago. Four password failures in the prior 40 minutes, and this attempt is the fifth.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `repeated_failed_logins` | 30 | 5 password failures inside 60 minutes |

`failed_login` does not also fire. The burst replaces the single-typo rule so the points are not added twice. Location, device, and hour match the baseline.

In the extract: `U014`, `noah.hassan@northwind.example`, home address `203.0.113.14`, Chicago. `E000716` at 15:10 UTC is failure number 1 and scores 5. `E000720` at 15:14 UTC is failure number 5 and scores 30. `E000721` at 15:15 UTC is `account_locked`, failure number 6, and also scores 30. `account_locked` counts as a password failure.

Analyst: medium. One account, one familiar device, many passwords. This is a guessing attempt or a stuck client, and it is worth a look because it crossed five in an hour. It is not yet a new country or a new device.

## 4. New device

**Score 15. Low. `new_device`.**

The attempt succeeds from iOS 17, Safari, mobile. Every earlier success was Windows 10, Chrome, desktop. Country is still US. Hour is 09:00 Chicago. MFA is satisfied. Client is `mobile_app`.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `new_device` | 15 | `ios 17 \| safari \| mobile` has no earlier success. The earlier device is `windows 10 \| chrome \| desktop` |

A blank OS, browser, and device type does not fire this rule. The legacy spray failures are blank on purpose, so they are not all scored as new devices.

In the extract: `E000410`, `finley.garcia@northwind.example`, `U006`, 2026-11-05T18:10:00Z (12:10 Chicago), an iPhone, score 15.

Analyst: low. People replace phones. Read it only if another rule is also present.

## 5. Foreign location

**Score 20. Low. `unusual_location`.**

Same laptop as the baseline, 09:00 Chicago, MFA satisfied, success, country DE. The earlier successes are all US. The previous US success is days ago, so the 2-hour travel rule stays quiet.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `unusual_location` | 20 | DE has no earlier success. Earlier country: US |

In the extract this is the first Berlin morning: `E000607`, `harper.singh@northwind.example`, `U008`, 2026-11-09T15:30:00Z, score 20. The next morning, `E000724` on 10 November, is the same laptop in Berlin and scores 0. Germany is now in the history. The third morning, `E000834`, also scores 0. The SQL geography query lists only the first Berlin success, for the same reason.

Analyst: low on the first day, nothing on the later days. A trip the account has already started should not keep paging.

## 6. Late-night login

**Score 10. Low. `unusual_time`.**

Same device, same country, success, MFA satisfied. The timestamp is 2026-11-10T07:30:00Z, which is 01:30 Chicago. The four earlier successes are all at 09:00 Chicago. Zero of four is under the 10% share, and four is at least the three successes the rule requires.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `unusual_time` | 10 | Chicago hour 1, and 0 of 4 earlier successes were in hours 0–5 |

A user whose earlier successes are already in that band is not flagged. The test builds four 01:15 Chicago successes and a fifth at 01:30, and the score stays 0. With fewer than three earlier successes the rule stays quiet too. There is no baseline yet.

In the extract: `E000906`, `zen.hoff@northwind.example`, `U031`, 2026-11-12T07:40:00Z (01:40 Chicago), usual laptop, US, score 10.

Analyst: low. One odd hour on a known device is a person who could not sleep, until it lines up with a new device or a new country.

## 7. Failures followed by success

**Score 35. Medium. `failures_followed_by_success`.**

Three password failures at 14:40, 14:45, and 14:50 UTC. This attempt succeeds at 15:00 UTC from the usual device and the usual country.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `failures_followed_by_success` | 35 | A success with 3 password failures in the prior 30 minutes |

The burst rule stays quiet because three is under five, and this attempt is a success so it is not itself a password failure. Device and country match.

The extract's single-typo-then-success (`E000120` then `E000121`) does not fire this rule. The threshold is 3, and that pair has 1. The extract's version of a real burst-then-success is the Sao Paulo row in scenario 13, where this rule is one of six.

Analyst: medium. The session now exists, and the password was wrong three times just before it. Read the device and the country on that success before clearing it. In this isolated case both are familiar, which is why it is medium and not high.

## 8. Password spray

**Score 35. Medium. `failed_login`, `password_spray_source`.**

Four other users have an `invalid_password` from `192.0.2.50` in the prior ten minutes. This attempt is `U100`'s first password failure from that same address. The fixture keeps the country and the device familiar so the spray rule is visible on its own.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `failed_login` | 5 | This attempt is a password failure, and this user is not yet at 5 |
| `password_spray_source` | 30 | `192.0.2.50` has password failures for 5 distinct users inside 60 minutes |

Five failures by one user on one address are a burst, not a spray. The test for that case fires `repeated_failed_logins` and leaves `password_spray_source` quiet. The spray rule counts users, not attempts.

In the extract the spray is `192.0.2.50` in Lagos, and the country is new, so the scores are higher than this isolated fixture. `E000867` (`U001`, 19:40 UTC) is the first of the twelve and scores 40: failed login +20 location +15 legacy client. The address is not a spray yet, because only one user has failed from it. `E000871` (`U010`, 19:44 UTC) is the fifth user and scores 70. From there through `U022`'s failure the score stays 70.

Analyst: the fifth distinct account is the moment this address becomes the story. The first four are medium because of the new country and the legacy client. The office NAT in Chicago has more lifetime failures than this and does not fire the rule, because those typos are spread across days.

## 9. MFA denied

**Score 30. Medium. `mfa_denied`.**

Usual device, usual country, business hour. `auth_result` is `failure`, `failure_reason` is `mfa_denied`, `mfa_result` is `denied`.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `mfa_denied` | 30 | The MFA result is `denied` |

`failed_login` stays quiet. A rejected second factor is not a wrong password, and it does not count toward the burst of five.

In the extract: `E000510`, `sam.nowak@northwind.example`, `U019`, 2026-11-06T16:40:00Z (10:40 Chicago), Windows 10, Chrome, New York office address `198.51.100.20`. Score 30. It is the only `denied` value in the file.

Analyst: medium. The password was accepted. Either the person could not complete the prompt, or someone who has the password could not complete it. The device and the country being familiar is why this is not high.

## 10. Impossible travel

**Score 45. Medium. `unusual_location`, `impossible_travel`.**

A success in the US at 15:00 UTC, from the usual laptop. This success is at 16:00 UTC in Nigeria, same laptop.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `unusual_location` | 20 | NG has no earlier success |
| `impossible_travel` | 25 | Previous success was US at 15:00 UTC, 60 minutes earlier |

Both rules fire because both facts are true. A later trip to a country the account has used, inside two hours, would fire travel only.

In the extract the gap is 40 minutes: `E000712` is `U012` in Chicago at 15:00 UTC, and `E000732` is the same user and the same laptop in Lagos at 15:40 UTC. Score 45. The sentence the engine writes is: previous successful login was in US at 2026-11-10T15:00:00Z, 40 minutes before this event in NG. The return to Chicago at 22:00 UTC the same day scores 0 on travel, because the gap from 15:40 is longer than two hours, and US is already in the history.

Analyst: medium. Ask whether a VPN could put the laptop in Lagos for one session. The sentence has the two timestamps, which is the whole investigation.

## 11. Legacy protocol on an otherwise normal success

**Score 15. Low. `legacy_protocol`.**

Usual device, usual country, business hour, success, and `client_app` is `legacy_protocol`.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `legacy_protocol` | 15 | The client app is `legacy_protocol` |

Alone, a legacy client stays low. The weight is there so it stacks. Scenarios 12 and 13 are that stack. The extract has no legacy success that is otherwise normal. Both legacy successes are the critical rows.

Analyst: low if it is truly the only signal. Confirm the application is one the company still allows to use basic auth.

## 12. Combined signals, high

**Score 70. High. `failures_followed_by_success`, `new_device`, `unusual_location`.**

Three password failures in the prior 20 minutes. This attempt succeeds at 09:00 Chicago from Linux, Firefox, desktop, in Germany. The baseline is Windows, Chrome, United States, and the previous US success is days ago.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `failures_followed_by_success` | 35 | 3 password failures, then this success, inside 30 minutes |
| `new_device` | 15 | Linux / Firefox has no earlier success |
| `unusual_location` | 20 | DE has no earlier success |
| **Sum** | **70** | High |

The burst rule stays quiet because there are three failures, not five. Travel stays quiet because the previous success is days back. The hour is 9. The client in this fixture is still a browser, so legacy does not fire.

Analyst: high. A session was opened on a new device in a new country immediately after the password was wrong. This is the row to read before any score-15 new phone.

## 13. Combined signals, critical, capped

**Score 100. Critical. Six signals. Raw points 125.**

Five password failures between 07:10 and 07:26 UTC (01:10–01:26 Chicago). This attempt succeeds at 07:30 UTC from Linux, Firefox, Brazil, `legacy_protocol`, MFA not required. The earlier successes are daytime, United States, Windows, Chrome.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `repeated_failed_logins` | 30 | 5 password failures in the prior 60 minutes |
| `failures_followed_by_success` | 35 | Those failures are also inside the prior 30 minutes |
| `new_device` | 15 | Linux / Firefox is new for the account |
| `unusual_location` | 20 | BR is new for the account |
| `unusual_time` | 10 | Chicago hour 1, and the earlier successes are daytime |
| `legacy_protocol` | 15 | MFA was not required because the client is legacy |
| **Raw sum** | **125** | |
| **Reported score** | **100** | The cap |

The sentences still list 125 points. The cap is only the number used for the band. Two critical rows are ordered by reading the sentences, not by the tied score of 100.

In the extract this pattern is `E000905`, `indigo.walsh@northwind.example`, `U009`, 2026-11-12T07:20:00Z (01:20 Chicago), address `192.0.2.77`, Sao Paulo. Six failures precede it, so the counts in the sentences are 6 rather than 5. Raw points are the same 125, reported score 100. The engine's reasons on that row:

- 6 password failures for this user in the 60 minutes ending at this event. The threshold is 5.
- This success follows 6 password failures in the prior 30 minutes. The threshold is 3.
- Device `linux | firefox | desktop` has no prior successful login. Prior device: `windows 10 | edge | desktop`.
- Country BR has no prior successful login. Prior country: US.
- Local hour is 1 in America/Chicago. 0 of 25 prior successes were in that band.
- Client app is `legacy_protocol`.

`E000903` and `E000904`, the fifth and sixth failures, score 75 (high) before the success exists: burst + country + hour + legacy client. The success is the critical row because the session opened.

The other critical row in the file is the spray success, which is a different combination and a useful comparison.

## 14. Spray success

**Score 80. Critical. `new_device`, `unusual_location`, `legacy_protocol`, `password_spray_source`.**

This is the second "several signals at once" case, and it is the one that does not use the failure-then-success rule. `U022` failed once from `192.0.2.50`. That is under both the burst threshold and the three-failures-then-success threshold. The address, not the account's own failure count, is the threat signal. Twelve users failed from it in the prior hour. The success is Linux / Firefox, Lagos, legacy protocol, 14:00 Chicago, six hours after a normal US morning, so travel does not fire.

| Rule | Points | Why it fired |
| --- | --- | --- |
| `new_device` | 15 | Linux / Firefox; the account's laptop is macOS / Safari |
| `unusual_location` | 20 | NG is new |
| `legacy_protocol` | 15 | The success did not require MFA |
| `password_spray_source` | 30 | 12 distinct users failed from `192.0.2.50` inside the hour |
| **Sum** | **80** | Critical |

In the extract: `E000880`, `val.rossi@northwind.example`, `U022`, 2026-11-11T20:00:00Z.

Analyst: critical, and a different story from Sao Paulo. Sao Paulo is one account being guessed, then opened. Lagos is one address walking through the company, then opening one of those accounts. The SQL IP table shows the same split: `192.0.2.77` has one user with a password failure, `192.0.2.50` has twelve.

## Checks that keep rules from over-firing

These are in the test file so the card above cannot drift.

| Check | Result |
| --- | --- |
| 4 password failures in an hour | Score 5, `failed_login` only |
| A failure timestamped exactly 60 minutes earlier | Outside the window |
| First login of an account, new country, new device | Score 0. No baseline |
| Blank device fingerprint | `new_device` stays quiet |
| Earlier successes already overnight | Another overnight login scores 0 |
| Five failures, one user, one IP | Burst, not spray |
| An MFA denial | Not also counted as a bad password |
| Events later than this one, passed in `history` by mistake | Ignored |
| Scores 29, 30, 59, 60, 79, 80, 100 | low, medium, medium, high, high, critical, critical |

The extract-level lock is the queue itself: 1,100 low, 12 medium, 10 high, 2 critical.
