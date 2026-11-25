# Five-minute demo

What to show, and what to say. Open the dashboard with `python3 -m http.server 8877 --directory dashboard`, then `http://127.0.0.1:8877/index.html`. Have `docs/ai-security-evaluation.md` ready for the last minute.

## 0:00 Problem

Security operations cannot read 1,124 sign-ins. The question is which attempts to open first. This file is a teaching extract: 36 employees, 2–13 November 2026, documentation IP addresses, no production log. The score is a queue position. It is not a claim that someone was hacked.

## 0:45 What was built

Point at the architecture in the README. The CSV is scored in Python from earlier attempts. The same file is loaded to PostgreSQL for the SQL cuts. The dashboard reads the scored file. The incident note is allowed to quote the score and the signal sentences, and a checker rejects anything past that.

## 1:30 Overview

On 01 Security Overview, read the four numbers: 1,124 attempts, 55 failed logins, 12 high-risk events (score 60 or above), 9 affected users. The distribution is 1,100 low, 12 medium, 10 high, 2 critical. The table under it is the queue, score 30 and above: 24 rows. The first row is a success, which is the point. A success is when a session exists.

## 2:30 Investigation

Open `E000905`. Say the filters: user, event, time, IP, device, risk. This row is indigo.walsh, 01:20 Chicago, Sao Paulo, `192.0.2.77`, legacy client, result success, score 100.

Read two sentences out loud. Six password failures in 60 minutes. The device `linux | firefox | desktop` has no prior success; the prior device is Windows and Edge. Then the cap: the rules add to 125, the reported score is 100, and every signal is still listed.

The steps underneath are questions. Did they retry a password? Is a legacy client allowed? The session id is the handoff to access logs, which this extract does not have.

## 3:40 The note, and the bad version

Read the incident note's first sentence: "This activity warrants investigation because the fired signals are listed below." Stop on that wording.

Then the failure case in `docs/ai-security-evaluation.md`. Same kind of row, loose paragraph: "This user was hacked from a Russian IP." The checker flags invented facts, exaggerated certainty, a company-wide password reset, and missing evidence. The real note on a normal login (`E000014`, score 0) says to leave it in the log.

## 4:30 Limitations

No takeover labels, so this is not a detection rate. No threat-intel feed. The device is not a hardware id. The Chicago office address has 10 failures and 310 successes, and it is not in the spray rule, because those failures are not five users in one hour. Rules were chosen because an analyst has to be able to recompute the sentence.

Stop at five minutes. The tag on the repo is `v1.0`.
