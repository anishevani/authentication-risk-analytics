# Limitations

The score is a place in a queue. It is not a probability, and it is not a finding that an account was taken over.

The extract is synthetic. Seed 21 of `src/generate_auth_events.py` wrote it because no production sign-in export was in the workspace. Usernames are on `.example`. Every IP address is in an RFC 5737 documentation range. Counts describe this file only.

There is no confirmed-takeover label, so nothing here measures how many takeovers the queue caught. There is no threat-intel column. `password_spray_source` is the behavior of an address inside this file: password failures for five or more users in 60 minutes.

There is no hardware device id. The device is the operating system, browser, and device type. A blank fingerprint is not treated as a new device.

There is no authorization data. A success means a session id was issued. The note tells the analyst to take that id to the access logs, which are not in this extract.

Off-hours use America/Chicago for every employee. New York is an hour ahead. A 12:30am Eastern login can fall outside the 00:00–05:59 Chicago band.

A person's first successful login has no personal baseline, so a new country or a new device on that first row does not score. Absolute rules still can: a password failure, a burst, an MFA denial, a legacy client, a spray address.

A shared office address collects typos across two weeks. The whole-file SQL list shows Chicago `198.51.100.10` with 10 failures and 310 successes. The 60-minute spray rule does not flag it. Reading the failure count alone would.

The reported score stops at 100. `E000905` is 125 points of rules and a score of 100. The investigation page shows both numbers. The sentences are still the way to tell two critical rows apart.

The incident note is a template over verified facts, reviewed by a checker. It will not say "this user was hacked." It also will not notice a pattern that the rules did not already name.
