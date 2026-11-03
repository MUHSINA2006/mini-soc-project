import json
import ipaddress
import subprocess
import time
import urllib.error
import urllib.request

API_URL = "https://mini-soc-dashboard-6fw5.onrender.com/api/events"
POLL_SECONDS = 15
MAX_EVENTS_PER_POLL = 100

# Remember processed event records during this run.
seen_records = set()


POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'

try {
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4624, 4625
        } -MaxEvents 100 -ErrorAction SilentlyContinue
    )

    $result = foreach ($event in $events) {
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.Name] = [string]$item.'#text'
        }

        [PSCustomObject]@{
            RecordId = $event.RecordId
            TimeCreated = $event.TimeCreated.ToUniversalTime().ToString('o')
            EventId = $event.Id
            TargetUserName = $data['TargetUserName']
            IpAddress = $data['IpAddress']
            LogonType = $data['LogonType']
        }
    }

    ConvertTo-Json -InputObject @($result) -Compress -Depth 4
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""


def read_windows_events():
    """Read recent successful and failed Windows logon events."""

    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                POWERSHELL_SCRIPT,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            encoding="utf-8",
            errors="replace",
        )

    except subprocess.TimeoutExpired:
        print("Windows event query timed out.")
        return []

    except OSError as exc:
        print(f"Could not start PowerShell: {exc}")
        return []

    if result.returncode != 0:
        print("Could not read Windows Security events.")
        if result.stderr.strip():
            print(result.stderr.strip())
        return []

    output = result.stdout.strip()

    if not output:
        print("No supported Windows login events found.")
        return []

    try:
        events = json.loads(output)
    except json.JSONDecodeError as exc:
        print(f"Could not parse PowerShell JSON: {exc}")
        print("PowerShell output:", output[:500])
        return []

    if isinstance(events, dict):
        events = [events]

    if not isinstance(events, list):
        print("Unexpected Windows event data format.")
        return []

    return events


def send_event(event):
    """Send one supported Windows login event to the hosted dashboard."""

    try:
        event_id = int(event["EventId"])
        record_id = str(event["RecordId"])
    except (KeyError, TypeError, ValueError):
        print("Skipping event with missing or invalid identifiers.")
        return False

    logon_type = str(event.get("LogonType") or "").strip()
    username = str(event.get("TargetUserName") or "unknown").strip()

    source_ip = str(event.get("IpAddress") or "").strip()

    # Ignore routine service logons.
    if logon_type == "5":
        return False

    # Ignore events without an actual source IP.
    if not source_ip or source_ip == "-":
        print(
            f"Skipped Windows event {record_id}: "
            "no source IP was recorded."
        )
        return False

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        print(f"Skipped event {record_id}: invalid IP address.")
        return False

    if event_id == 4625:
        event_type = "FAILED_LOGIN"
        description = (
            f"Windows failed logon; record {record_id}; "
            f"logon type {logon_type or 'unknown'}"
        )

    elif event_id == 4624:
        event_type = "SUCCESSFUL_LOGIN"
        description = (
            f"Windows successful logon; record {record_id}; "
            f"logon type {logon_type or 'unknown'}"
        )

    else:
        return False

    payload = {
        "source_ip": source_ip,
        "event_type": event_type,
        "username": username or "unknown",
        "description": description,
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_body = response.read().decode(
                "utf-8", errors="replace"
            )

            if response.status in (200, 201):
                print(
                    f"Imported Windows event {record_id}: "
                    f"{event_type}, user={username}, "
                    f"HTTP {response.status}"
                )
                return True

            print(
                f"Unexpected API response for event {record_id}: "
                f"HTTP {response.status} - {response_body}"
            )

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(
            f"API rejected event {record_id}: "
            f"HTTP {exc.code} - {body}"
        )

    except urllib.error.URLError as exc:
        print(f"Cannot connect to hosted dashboard: {exc.reason}")

    except TimeoutError:
        print(f"Request timed out for Windows event {record_id}.")

    return False


def main():
    print("Windows Security Log Collector")
    print(f"Destination: {API_URL}")
    print(f"Polling interval: {POLL_SECONDS} seconds")
    print("Monitoring Windows logon events 4624 and 4625.")
    print("Press Ctrl+C to stop.\n")

    while True:
        try:
            events = read_windows_events()

            # Process oldest records first.
            events.sort(
                key=lambda item: int(item.get("RecordId", 0))
            )

            imported = 0

            for event in events:
                record_id = str(event.get("RecordId", "")).strip()

                if not record_id or record_id in seen_records:
                    continue

                # Ignore routine events without marking them as imported.
                # The filters in send_event determine whether an event
                # is suitable for the dashboard.
                if send_event(event):
                    seen_records.add(record_id)
                    imported += 1

            print(
                f"Poll complete: {len(events)} Windows events checked; "
                f"{imported} imported. "
                f"Waiting {POLL_SECONDS} seconds..."
            )

            time.sleep(POLL_SECONDS)

        except KeyboardInterrupt:
            print("\nCollector stopped.")
            break

        except Exception as exc:
            print(f"Unexpected collector error: {exc}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()