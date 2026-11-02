from datetime import datetime, timedelta, timezone

from database import get_connection, add_event


FAILED_LOGIN_THRESHOLD = 5
WINDOW_MINUTES = 5

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def detect_event(source_ip, event_type, username="unknown", description=""):
    event_type = event_type.upper().strip()
    source_ip = source_ip.strip()
    username = username.strip() or "unknown"

    if not source_ip:
        raise ValueError("Source IP is required.")

    if event_type == "FAILED_LOGIN":
        return detect_failed_login(
            source_ip,
            username,
            description or "Failed login attempt"
        )

    if event_type == "SUCCESSFUL_LOGIN":
        return add_event(
            source_ip,
            event_type,
            username,
            "LOW",
            description or "Successful login"
        )

    if event_type == "SUSPICIOUS_ACTIVITY":
        return add_event(
            source_ip,
            event_type,
            username,
            "HIGH",
            description or "Suspicious activity detected"
        )

    if event_type == "PORT_SCAN":
        return add_event(
            source_ip,
            event_type,
            username,
            "MEDIUM",
            description or "Possible port scan detected"
        )

    if event_type == "MALWARE_ALERT":
        return add_event(
            source_ip,
            event_type,
            username,
            "CRITICAL",
            description or "Potential malware activity detected"
        )

    return add_event(
        source_ip,
        event_type,
        username,
        "LOW",
        description or "Security event recorded"
    )


def detect_failed_login(source_ip, username, description):
    event_id = add_event(
        source_ip,
        "FAILED_LOGIN",
        username,
        "MEDIUM",
        description
    )

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(minutes=WINDOW_MINUTES)
    ).isoformat(timespec="seconds")

    with get_connection() as conn:
        count = conn.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE source_ip = ?
              AND event_type = 'FAILED_LOGIN'
              AND timestamp >= ?
        """, (source_ip, cutoff)).fetchone()[0]

        if count >= FAILED_LOGIN_THRESHOLD:
            conn.execute("""
                UPDATE security_events
                SET severity = 'HIGH',
                    description =
                        'Repeated failed logins: possible brute-force activity'
                WHERE id = ?
            """, (event_id,))

            # Avoid creating a new alert for every subsequent failed login.
            existing = conn.execute("""
                SELECT id
                FROM security_events
                WHERE source_ip = ?
                  AND event_type = 'BRUTE_FORCE_ALERT'
                  AND timestamp >= ?
                LIMIT 1
            """, (source_ip, cutoff)).fetchone()

            if not existing:
                conn.execute("""
                    INSERT INTO security_events (
                        timestamp, source_ip, event_type,
                        username, severity, description
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                    source_ip,
                    "BRUTE_FORCE_ALERT",
                    username,
                    "CRITICAL",
                    f"Possible brute-force attack: {count} failed logins "
                    f"within {WINDOW_MINUTES} minutes"
                ))

    return event_id


def classify_severity(event_type):
    event_type = event_type.upper()

    mapping = {
        "SUCCESSFUL_LOGIN": "LOW",
        "FAILED_LOGIN": "MEDIUM",
        "PORT_SCAN": "MEDIUM",
        "SUSPICIOUS_ACTIVITY": "HIGH",
        "BRUTE_FORCE_ALERT": "CRITICAL",
        "MALWARE_ALERT": "CRITICAL"
    }

    return mapping.get(event_type, "LOW")