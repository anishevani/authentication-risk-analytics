-- Detection queries for the sign-in extract.
-- Thresholds match docs/risk-model.md and src/risk_engine.py.
-- Times in the hour query are America/Chicago, the company zone used by the scorer.
-- These queries prioritize attempts. They do not label an account takeover.
-- The file has no threat-intel column; a "bad" IP here is one whose failure
-- counts stand out in this extract.

-- ---------------------------------------------------------------------------
-- Users with many failed logins
-- A row appears once the user reaches 5 password failures inside 60 minutes.
-- invalid_password and account_locked both count. mfa_denied does not.
-- ---------------------------------------------------------------------------

WITH password_failures AS (
    SELECT event_id, event_time, user_id, username, ip_address, failure_reason
    FROM auth_events
    WHERE auth_result = 'failure'
      AND failure_reason IN ('invalid_password', 'account_locked')
)
SELECT
    a.user_id,
    a.username,
    a.event_time,
    a.ip_address,
    a.failure_reason,
    COUNT(*) AS failures_in_60_minutes
FROM password_failures AS a
JOIN password_failures AS b
    ON b.user_id = a.user_id
   AND b.event_time <= a.event_time
   AND b.event_time > a.event_time - INTERVAL '60 minutes'
GROUP BY a.event_id, a.user_id, a.username, a.event_time, a.ip_address, a.failure_reason
HAVING COUNT(*) >= 5
ORDER BY a.event_time, a.user_id;

-- ---------------------------------------------------------------------------
-- IPs producing unusual failure counts
-- "Unusual" in this extract means 5 or more failures from one address
-- across the whole file. Read failure_rate and successes beside the count.
-- A shared office address collects typos from many employees over two weeks
-- and still has a low failure rate. A spray address fails across many users
-- and almost never succeeds. The risk rule is tighter than this list: it
-- fires only when one address fails passwords for 5 distinct users inside
-- 60 minutes, so the office NAT does not enter the Python queue.
-- ---------------------------------------------------------------------------

SELECT
    host(ip_address) AS ip_address,
    MIN(country_code) AS country_code,
    COUNT(*) FILTER (WHERE auth_result = 'failure') AS failures,
    COUNT(*) FILTER (WHERE auth_result = 'success') AS successes,
    ROUND(
        COUNT(*) FILTER (WHERE auth_result = 'failure')::numeric / COUNT(*),
        3
    ) AS failure_rate,
    COUNT(DISTINCT user_id) FILTER (
        WHERE auth_result = 'failure'
          AND failure_reason IN ('invalid_password', 'account_locked')
    ) AS users_with_password_failure
FROM auth_events
GROUP BY ip_address
HAVING COUNT(*) FILTER (WHERE auth_result = 'failure') >= 5
ORDER BY failure_rate DESC, failures DESC, ip_address;

-- ---------------------------------------------------------------------------
-- Login activity by hour, company local time
-- Off-hours in the risk model are local hours 0 through 5.
-- ---------------------------------------------------------------------------

SELECT
    EXTRACT(HOUR FROM event_time AT TIME ZONE 'America/Chicago')::int AS chicago_hour,
    COUNT(*) AS events,
    COUNT(*) FILTER (WHERE auth_result = 'success') AS successes,
    COUNT(*) FILTER (WHERE auth_result = 'failure') AS failures
FROM auth_events
GROUP BY chicago_hour
ORDER BY chicago_hour;

-- ---------------------------------------------------------------------------
-- New or unknown devices
-- The device key is os + browser + device type, the same proxy the scorer uses.
-- A row is the first success on that key for a user who already had a success
-- on a different key. The file has no hardware device id. Attempts with a
-- blank OS, browser, and device type are excluded, because a blank fingerprint
-- is not evidence of a new device.
-- ---------------------------------------------------------------------------

WITH successes AS (
    SELECT
        event_id,
        event_time,
        user_id,
        username,
        lower(os_name) || ' | ' || lower(browser_name) || ' | ' || lower(device_type) AS device_key,
        country_code,
        city
    FROM auth_events
    WHERE auth_result = 'success'
      AND COALESCE(os_name, '') <> ''
),
ordered AS (
    SELECT
        successes.*,
        ROW_NUMBER() OVER (
            PARTITION BY user_id
            ORDER BY event_time, event_id
        ) AS user_success_number,
        ROW_NUMBER() OVER (
            PARTITION BY user_id, device_key
            ORDER BY event_time, event_id
        ) AS device_success_number
    FROM successes
)
SELECT
    event_id,
    event_time,
    user_id,
    username,
    device_key,
    country_code,
    city
FROM ordered
WHERE device_success_number = 1
  AND user_success_number > 1
ORDER BY event_time, user_id;

-- ---------------------------------------------------------------------------
-- Unusual geography
-- First successful country for a user is the baseline, so it is not listed.
-- Later successes from a country that user has not succeeded from before are
-- listed. A failed attempt from a new country is a separate question; the
-- scorer flags those too, and this query is the success view an analyst
-- can read next to the traveler story.
-- ---------------------------------------------------------------------------

WITH successes AS (
    SELECT
        event_id,
        event_time,
        user_id,
        username,
        country_code,
        city,
        host(ip_address) AS ip_address
    FROM auth_events
    WHERE auth_result = 'success'
      AND COALESCE(country_code, '') <> ''
),
marked AS (
    SELECT
        successes.*,
        MIN(event_time) OVER (PARTITION BY user_id) AS first_success,
        MIN(event_time) OVER (PARTITION BY user_id, country_code) AS first_in_country
    FROM successes
)
SELECT
    event_id,
    event_time,
    user_id,
    username,
    country_code,
    city,
    ip_address
FROM marked
WHERE event_time = first_in_country
  AND event_time > first_success
ORDER BY event_time, user_id;

-- ---------------------------------------------------------------------------
-- Failure followed by success
-- A success with at least 3 password failures for the same user in the
-- prior 30 minutes. This is the scorer's failures_followed_by_success rule.
-- ---------------------------------------------------------------------------

SELECT
    s.event_id,
    s.event_time,
    s.user_id,
    s.username,
    host(s.ip_address) AS ip_address,
    s.country_code,
    s.client_app,
    COUNT(f.event_id) AS password_failures_in_prior_30_minutes
FROM auth_events AS s
JOIN auth_events AS f
    ON f.user_id = s.user_id
   AND f.auth_result = 'failure'
   AND f.failure_reason IN ('invalid_password', 'account_locked')
   AND f.event_time < s.event_time
   AND f.event_time > s.event_time - INTERVAL '30 minutes'
WHERE s.auth_result = 'success'
GROUP BY
    s.event_id,
    s.event_time,
    s.user_id,
    s.username,
    s.ip_address,
    s.country_code,
    s.client_app
HAVING COUNT(f.event_id) >= 3
ORDER BY password_failures_in_prior_30_minutes DESC, s.event_time;

-- ---------------------------------------------------------------------------
-- MFA denied
-- The extract records this directly. One denial is a medium score on its own
-- in the risk model (30 points) when no other rule fires.
-- ---------------------------------------------------------------------------

SELECT
    event_id,
    event_time,
    user_id,
    username,
    host(ip_address) AS ip_address,
    country_code,
    os_name,
    browser_name,
    failure_reason
FROM auth_events
WHERE mfa_result = 'denied'
ORDER BY event_time, user_id;

-- ---------------------------------------------------------------------------
-- Legacy protocol
-- basic-auth style clients. In this extract they are the spray and the
-- overnight Sao Paulo success. A legacy success is the row to read first.
-- ---------------------------------------------------------------------------

SELECT
    event_id,
    event_time,
    user_id,
    username,
    auth_result,
    failure_reason,
    host(ip_address) AS ip_address,
    country_code,
    os_name,
    browser_name
FROM auth_events
WHERE client_app = 'legacy_protocol'
ORDER BY event_time, user_id;

-- ---------------------------------------------------------------------------
-- Session check
-- Successes carry a session id. Failures do not. A non-zero count here means
-- the load or the extract drifted from that rule.
-- ---------------------------------------------------------------------------

SELECT
    COUNT(*) FILTER (WHERE auth_result = 'success' AND session_id IS NULL) AS successes_missing_session,
    COUNT(*) FILTER (WHERE auth_result = 'failure' AND session_id IS NOT NULL) AS failures_with_session
FROM auth_events;
