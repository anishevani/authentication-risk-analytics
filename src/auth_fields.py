"""Column contract for the sign-in extract.

The profiler, the loader, and the generator all use this list. A column that
is not here is not in the file, and the risk rules do not get to assume it.
"""

COLUMNS = [
    "event_id",
    "event_time",
    "user_id",
    "username",
    "auth_result",
    "failure_reason",
    "ip_address",
    "country_code",
    "region",
    "city",
    "asn",
    "user_agent",
    "os_name",
    "browser_name",
    "device_type",
    "client_app",
    "mfa_required",
    "mfa_result",
    "session_id",
    "auth_requirement",
    "sign_in_type",
]

# Concepts from the week that this extract does not store as columns.
ABSENT_CONCEPTS = [
    "authorization decision (no resource-access or permission field)",
    "hardware device id (os, browser, and device type are the device proxy)",
    "threat-intel feed or is_attack_ip flag",
    "confirmed account-takeover label",
    "password or password hash",
    "gps latitude and longitude (country, region, and city only)",
    "per-user time zone (one company zone is applied later, America/Chicago)",
]
