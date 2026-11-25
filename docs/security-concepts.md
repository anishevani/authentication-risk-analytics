# Security concepts

Week of November 15. These are the words the rest of the project uses. Each section says what the word means in a security operations queue, then where it shows up in the sign-in extract.

The extract is `data/raw/authentication_events.csv`: 1,124 authentication attempts for 36 employees, 2–13 November 2026. Field-level counts are in `docs/data-profile.md`. The score that ranks an attempt is in `docs/risk-model.md`.

## Authentication

Authentication answers "who is this?". A person or a program presents a credential, and the identity service accepts or rejects it. In this file that decision is one row: `auth_result` is `success` or `failure`. A success means the service issued a session. A failure means it did not.

The file records the attempt, not the credential. There is no password and no password hash.

## Authorization

Authorization answers "what may this identity do?". It happens after a successful authentication, and it is a different decision: which mailbox, which file, which admin action.

This extract has no authorization field. There is no resource decision, no role, and no permission. A successful sign-in is not evidence that the session then read something sensitive. The queue this project builds is a queue of sign-in attempts. It does not approve or deny access to a resource.

## MFA

Multi-factor authentication asks for a second proof after the password. The usual proofs are an authenticator app, a hardware key, or a push to a phone the account already trusts.

Two columns carry it:

| Column | Values in this file |
| --- | --- |
| `mfa_required` | `true` on 763 attempts, `false` on 361 |
| `mfa_result` | `satisfied` 726, `not_required` 343, blank 54, `denied` 1 |

`satisfied` means the second factor was accepted. `not_required` covers non-interactive session refreshes and the legacy-protocol attempts, which never asked for a second factor. A blank `mfa_result` means the attempt ended before MFA. In this file all 54 blanks are password failures (`invalid_password` or `account_locked`). `denied` means the password step was passed and the second factor was rejected. That happens once, on `E000510`.

`auth_requirement` matches the same split: `multi_factor` on the 763 attempts where MFA was required, `single_factor` on the other 361.

## Failed login

A failed login is an attempt that did not open a session. There are 55 failures (4.9% of the file). The reason is recorded:

| `failure_reason` | Attempts |
| --- | --- |
| `invalid_password` | 52 |
| `account_locked` | 2 |
| `mfa_denied` | 1 |

One wrong password is ordinary. The same account failing several times in an hour is the pattern security operations actually wants to see, and so is one address failing the password on many accounts. Those two patterns are different attacks and the rules treat them differently. See `docs/risk-model.md`.

## Device

A device is the client the person used. This file has no hardware device id. The proxy is three columns parsed from the user agent: `os_name`, `browser_name`, and `device_type`. The risk rule calls that triple the device.

The proxy is present on 1,106 attempts. It is blank on 18, and every one of those 18 is a `legacy_protocol` attempt. A blank fingerprint is not treated as a new device, because "we could not parse a device" is a different fact from "this account has never succeeded from this device".

What the file actually contains:

| OS | Attempts | Browser | Attempts | Device type | Attempts |
| --- | --- | --- | --- | --- | --- |
| Windows 10 | 926 | Chrome | 774 | desktop | 1,105 |
| macOS | 177 | Safari | 178 | mobile | 1 |
| Linux | 2 | Edge | 152 | blank | 18 |
| iOS 17 | 1 | Firefox | 2 | | |
| blank | 18 | blank | 18 | | |

`client_app` is separate from the device proxy. It says how the client talked to the identity service: `browser` (1,103), `legacy_protocol` (20), or `mobile_app` (1). Legacy protocol is the basic-auth style client that often skips MFA. Both Linux successes in this file used it.

## IP

An IP address is the network source of the attempt. The file has 43 distinct addresses in `ip_address`, plus `country_code`, `region`, `city`, and `asn` derived from that address.

Every address in the file is in an RFC 5737 documentation range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). They are labels in a teaching extract, not routable addresses from a production network.

An IP is a useful signal and a noisy one. The Chicago office address `198.51.100.10` appears on 320 attempts because many employees share it. Twelve password failures from `192.0.2.50` in eleven minutes, each for a different user, is a different fact. The profile and the SQL both keep the success count next to the failure count so those two do not get collapsed into "an IP with many failures".

## Session

A session is the authenticated period that starts when a sign-in succeeds. `session_id` is set on all 1,069 successes and on none of the 55 failures. The loader checks that split.

The id itself is not a risk fact. It names the session. Risk comes from how the session was opened: which device, which country, whether a burst of failures came first, whether MFA was skipped.

`sign_in_type` separates the two ways a session shows up here. `interactive` (783) is a person signing in. `non_interactive` (341) is a later refresh of a session that was already opened, with `mfa_result` `not_required`. A refresh from the usual device and country adds no points. A refresh does not erase signals that are actually present on that row.

## Risk score

A risk score is a priority for the queue. In this project it is an integer from 0 to 100, produced by adding the points of the rules that fired, then capping the sum at 100. The bands are low (0–29), medium (30–59), high (60–79), and critical (80–100).

The number is the order in which an analyst should read attempts. A probability would require confirmed account-takeover labels, and this file has none. The same attempt always produces the same score, and `contributions` lists the sentence for each rule that fired. Two people with the event and the earlier history can recompute it by hand.

## Account takeover

Account takeover is an attacker using a real person's account. The usual path in a sign-in log is a burst of password failures, sometimes from a new address or a new device, sometimes followed by a success that then skips MFA because the client is a legacy protocol.

This file does not label any row as a confirmed takeover. Nothing in the score, the SQL, or the tests measures "how many takeovers we caught". What they measure is whether the patterns above are pushed up the queue, and whether an ordinary morning login stays at the bottom. That is the decision security operations can make with this extract.
