# Data profile

Monday, November 16. The question for the day is which fields the sign-in file actually has. The risk rules in `docs/risk-model.md` use this list and no other.

## Source

No production authentication export was in the workspace. The file under analysis is `data/raw/authentication_events.csv`, written by `src/generate_auth_events.py` with seed 21. It is a teaching extract shaped like an interactive sign-in log for a 36-person company. Usernames are on the `.example` domain. Every IP address is in an RFC 5737 documentation range, so none of them are routable production addresses.

`src/profile_auth_data.py` reads that CSV and writes `data/processed/profile_report.json`. The counts in this note come from that run, and the load check in `src/load_events.py` reproduced the row, user, success, failure, and session totals in PostgreSQL.

Re-running the generator rewrites the same bytes. The planted patterns an analyst is meant to be able to find are labeled in `data/raw/planted_events.json`.

## Shape

| Fact | Value |
| --- | --- |
| Rows | 1,124 authentication attempts |
| Columns | 21 |
| Users | 36 (`U001`–`U036`), 36 usernames |
| IP addresses | 43 |
| First attempt | 2026-11-02T13:59:39Z (07:59 Chicago) |
| Last attempt | 2026-11-13T22:40:37Z (16:40 Chicago) |
| Successes | 1,069 (95.1%) |
| Failures | 55 (4.9%) |
| Distinct timestamps | 1,111 |

The window is Monday 2 November through Friday 13 November 2026, plus a thin weekend. Three timestamps are shared. Twelve sprayed accounts sign in together at 2026-11-11T14:00:00Z, the planted morning before the afternoon spray. Two other seconds each contain two different users (`U004` with `U035` on 2 November, `U004` with `U028` on 10 November). The scorer does not let events that share a timestamp see each other. All of those rows are ordinary US successes and score 0, so the ties do not move the queue.

## Columns

Blank means the CSV cell is empty. The loader stores that as NULL. `session_id` is empty on every failure and filled on every success (1,069 session ids, 0 successes missing one, 0 failures carrying one).

| Column | Missing | Distinct | What it is |
| --- | --- | --- | --- |
| `event_id` | 0 | 1,124 | Attempt id, `E000001` upward, assigned in time order |
| `event_time` | 0 | 1,111 | UTC timestamp |
| `user_id` | 0 | 36 | Stable account id |
| `username` | 0 | 36 | `first.last@northwind.example` |
| `auth_result` | 0 | 2 | `success` or `failure` |
| `failure_reason` | 1,069 | 4 | Empty on success. Otherwise `invalid_password`, `account_locked`, or `mfa_denied` |
| `ip_address` | 0 | 43 | Source address |
| `country_code` | 0 | 4 | Country for that address |
| `region` | 0 | 6 | Region or state |
| `city` | 0 | 6 | City |
| `asn` | 0 | 5 | Autonomous system number on the address |
| `user_agent` | 18 | 6 | Raw user agent. Blank on 18 legacy attempts |
| `os_name` | 18 | 5 | OS parsed from the user agent |
| `browser_name` | 18 | 5 | Browser parsed from the user agent |
| `device_type` | 18 | 3 | `desktop`, `mobile`, or blank |
| `client_app` | 0 | 3 | `browser`, `mobile_app`, or `legacy_protocol` |
| `mfa_required` | 0 | 2 | `true` or `false` |
| `mfa_result` | 54 | 4 | `satisfied`, `not_required`, `denied`, or blank |
| `session_id` | 55 | 1,070 | Set on successes only. The extra distinct value is the blank |
| `auth_requirement` | 0 | 2 | `multi_factor` or `single_factor` |
| `sign_in_type` | 0 | 2 | `interactive` or `non_interactive` |

`mfa_required` is `true` on 763 attempts and `false` on 361. `auth_requirement` has the same split. The 361 single-factor rows are 341 non-interactive refreshes plus 20 legacy-protocol attempts.

## Results, MFA, and client

| `auth_result` | Attempts | Share |
| --- | --- | --- |
| success | 1,069 | 95.1% |
| failure | 55 | 4.9% |

| `failure_reason` | Attempts |
| --- | --- |
| blank (the successes) | 1,069 |
| `invalid_password` | 52 |
| `account_locked` | 2 |
| `mfa_denied` | 1 |

| `mfa_result` | Attempts | Share |
| --- | --- | --- |
| satisfied | 726 | 64.6% |
| not_required | 343 | 30.5% |
| blank | 54 | 4.8% |
| denied | 1 | 0.1% |

The 54 blank MFA results are password failures that never reached the second factor. The one denial is `E000510` (`mfa_denied`). The 55th failure is that denial, which is why blank MFA results are 54 rather than 55.

| `client_app` | Attempts | `sign_in_type` | Attempts |
| --- | --- | --- | --- |
| browser | 1,103 | interactive | 783 |
| legacy_protocol | 20 | non_interactive | 341 |
| mobile_app | 1 | | |

| OS | Attempts | Browser | Attempts | Device type | Attempts |
| --- | --- | --- | --- | --- | --- |
| Windows 10 | 926 | Chrome | 774 | desktop | 1,105 |
| macOS | 177 | Safari | 178 | mobile | 1 |
| blank | 18 | Edge | 152 | blank | 18 |
| Linux | 2 | blank | 18 | | |
| iOS 17 | 1 | Firefox | 2 | | |

The device the risk rule uses is `os_name` + `browser_name` + `device_type`. There is no hardware device id. The 18 blank fingerprints are a subset of the 20 legacy-protocol rows. The other two legacy rows are the Linux/Firefox successes, which do have a device proxy.

## Geography

| City | Country | Attempts | Distinct users on attempts in that city |
| --- | --- | --- | --- |
| Chicago | US | 535 | 18 |
| New York | US | 316 | 10 |
| Austin | US | 249 | 8 |
| Lagos | NG | 14 | 13 |
| Sao Paulo | BR | 7 | 1 |
| Berlin | DE | 3 | 1 |

US attempts are 1,100 of 1,124 (97.9%). The roster behind the US rows is 18 Chicago employees, 10 New York, 8 Austin. Lagos is 12 spray attempts against 12 users plus one success, and one further success by `U012` from a different Lagos address. Sao Paulo is one user's overnight burst. Berlin is one user's three weekday mornings.

ASN values are `64500` (office), `64501` (home), `64502` (Berlin), `64510` (both Lagos addresses), and `64511` (Sao Paulo).

## Hour of day, America/Chicago

The company has people in Chicago, New York, and Austin, and the file has no per-user time zone. The hour cut and the risk rule both use America/Chicago. In this date range that zone is CST (UTC−6). A New York login at 12:30am Eastern is 11:30pm Chicago the previous evening, so it falls outside the 00:00–05:59 band. The band is a company convention, not each person's local midnight.

| Chicago hour | Attempts | Successes | Failures |
| --- | --- | --- | --- |
| 1 | 8 | 2 | 6 |
| 7 | 1 | 0 | 1 |
| 8 | 223 | 203 | 20 |
| 9 | 273 | 258 | 15 |
| 10 | 175 | 174 | 1 |
| 11 | 83 | 83 | 0 |
| 12 | 6 | 6 | 0 |
| 13 | 89 | 77 | 12 |
| 14 | 88 | 88 | 0 |
| 15 | 89 | 89 | 0 |
| 16 | 89 | 89 | 0 |

Hours 0, 2–6, and 17–23 have no rows. Hour 1 is the overnight Sao Paulo sequence plus one known-device login at 01:40. Hour 7 is a single password typo at 07:59, three minutes before an 08:00 login. The off-hours rule uses hours 0 through 5, so that 07:59 typo is not an off-hours attempt.

A `psql` session on this machine prints `timestamptz` in Pacific time. The hour query in `sql/security_analysis.sql` converts to America/Chicago on purpose. Use that column, not the session's displayed offset.

## IP failure counts, read with the successes

Five addresses have 5 or more failures across the whole file. The failure rate is what separates them. `sql/security_analysis.sql` returns this table:

| IP | Country | Failures | Successes | Failure rate | Users with a password failure |
| --- | --- | --- | --- | --- | --- |
| 192.0.2.50 | NG | 12 | 1 | 0.923 | 12 |
| 192.0.2.77 | BR | 6 | 1 | 0.857 | 1 |
| 203.0.113.14 | US | 6 | 19 | 0.240 | 1 |
| 198.51.100.20 | US | 8 | 184 | 0.042 | 7 |
| 198.51.100.10 | US | 10 | 310 | 0.031 | 8 |

`198.51.100.10` and `198.51.100.20` are the Chicago and New York office addresses. Typos from several employees land on the same NAT over two weeks, and the success count is large. `192.0.2.50` fails twelve different users in eleven minutes and succeeds once. The Python spray rule requires five distinct users inside 60 minutes, so the office addresses stay out of that rule. The whole-file SQL list is still worth reading, with the rate beside the count.

## Fields the file does not have

These were on the concept list for the week. They are not columns, and the rules do not invent them:

| Concept | What the file has instead |
| --- | --- |
| Authorization | Nothing. No resource, role, or permission. |
| Hardware device id | `os_name`, `browser_name`, `device_type` |
| Threat-intel or `is_attack_ip` flag | Behavior of the address in this file: failures across users in an hour |
| Confirmed account-takeover label | Nothing. The score cannot be checked against a label. |
| Password or password hash | `failure_reason` only |
| Latitude and longitude | `country_code`, `region`, `city` |
| Per-user time zone | America/Chicago applied to `event_time` |

`src/profile_auth_data.py` raises if the CSV gains or drops a column relative to `src/auth_fields.py`. That list is the contract the loader and the generator share.
