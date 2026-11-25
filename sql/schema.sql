-- Sign-in grain for the authentication extract.
-- One row per authentication attempt. A blank in the CSV is loaded as NULL.
-- There is no threat-intel column, no hardware device id, and no
-- account-takeover label, because the source file does not have them.
-- IP addresses in this extract are RFC 5737 documentation addresses.

DROP TABLE IF EXISTS auth_events;

CREATE TABLE auth_events (
    event_id TEXT PRIMARY KEY,
    event_time TIMESTAMPTZ NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT,
    auth_result TEXT NOT NULL CHECK (auth_result IN ('success', 'failure')),
    failure_reason TEXT CHECK (
        failure_reason IS NULL
        OR failure_reason IN ('invalid_password', 'mfa_denied', 'account_locked')
    ),
    ip_address INET NOT NULL,
    country_code TEXT NOT NULL CHECK (char_length(country_code) = 2),
    region TEXT,
    city TEXT,
    asn INTEGER,
    user_agent TEXT,
    os_name TEXT,
    browser_name TEXT,
    device_type TEXT CHECK (
        device_type IS NULL
        OR device_type IN ('desktop', 'mobile', 'tablet')
    ),
    client_app TEXT NOT NULL CHECK (
        client_app IN ('browser', 'mobile_app', 'legacy_protocol')
    ),
    mfa_required BOOLEAN NOT NULL,
    mfa_result TEXT CHECK (
        mfa_result IS NULL
        OR mfa_result IN ('not_required', 'satisfied', 'denied')
    ),
    session_id TEXT,
    auth_requirement TEXT NOT NULL CHECK (
        auth_requirement IN ('single_factor', 'multi_factor')
    ),
    sign_in_type TEXT NOT NULL CHECK (
        sign_in_type IN ('interactive', 'non_interactive')
    ),
    CONSTRAINT auth_events_session_matches_result CHECK (
        (auth_result = 'success' AND session_id IS NOT NULL)
        OR (auth_result = 'failure' AND session_id IS NULL)
    )
);

CREATE INDEX auth_events_user_time_idx ON auth_events (user_id, event_time);
CREATE INDEX auth_events_ip_time_idx ON auth_events (ip_address, event_time);
CREATE INDEX auth_events_result_time_idx ON auth_events (auth_result, event_time);

COMMENT ON TABLE auth_events IS
    'One authentication attempt. Risk rules read this table; they do not label a row as a confirmed takeover.';
COMMENT ON COLUMN auth_events.os_name IS
    'Operating system parsed from the user agent. Together with browser_name and device_type this is the device proxy. There is no hardware device id.';
COMMENT ON COLUMN auth_events.session_id IS
    'Present on successes only. An identifier for the session that was opened, not a risk fact by itself.';
COMMENT ON COLUMN auth_events.country_code IS
    'Country derived for the IP. The file has no latitude or longitude.';
COMMENT ON COLUMN auth_events.mfa_result IS
    'not_required, satisfied, or denied. Blank when the attempt failed before MFA.';
