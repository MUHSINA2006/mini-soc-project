import json
import subprocess
import time
import urllib.error
import urllib.request

API_URL = "http://127.0.0.1:5000/api/events"
POLL_SECONDS = 15

POWERSHELL_SCRIPT = r"""
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624, 4625
} -MaxEvents 20 -ErrorAction SilentlyContinue

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

ConvertTo-Json -InputObject @($result) -Compress
"""


def read_windows_events():
    script = r"""
    $ErrorActionPreference = 'SilentlyContinue'
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624, 4625
    } -MaxEvents 10 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $event = $_
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
    } | ConvertTo-Json -Compress
    """

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )

    if result.returncode != 0:
        print("PowerShell error:", result.stderr.strip() or "<no stderr>")
        print("PowerShell output:", result.stdout.strip() or "<no stdout>")
        return []

    output = result.stdout.strip()
    if not output:
        return []

    events = json.loads(output)

    if isinstance(events, dict):
        return [events]

    return events

def send_event(event):
    event_id = int(event["EventId"])
    logon_type = str(event.get("LogonType") or "")
    username = event.get("TargetUserName") or "unknown"
    source_ip = (event.get("IpAddress") or "").strip()

    # Ignore routine service logons.
    if logon_type == "5":
        return False

    # Ignore events without a real source IP.
    if not source_ip or source_ip == "-":
        return False

    import ipaddress

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return False

    if event_id == 4625:
        event_type = "FAILED_LOGIN"
        description = (
            f"Windows failed logon; record {event['RecordId']}; "
            f"logon type {logon_type or 'unknown'}"
        )
    elif event_id == 4624:
        event_type = "SUCCESSFUL_LOGIN"
        description = (
            f"Windows successful logon; record {event['RecordId']}; "
            f"logon type {logon_type or 'unknown'}"
        )
    else:
        return False

    payload = {
        "source_ip": source_ip,
        "event_type": event_type,
        "username": username,
        "description": description,
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            print(
                f"Imported Windows event {event['RecordId']}: "
                f"HTTP {response.status}"
            )
            return True
    except urllib.error.HTTPError as exc:
        print(
            f"API rejected event {event['RecordId']}: "
            f"HTTP {exc.code}: "
            f"{exc.read().decode('utf-8', errors='replace')}"
        )
    except urllib.error.URLError as exc:
        print(f"Cannot connect to Flask API: {exc.reason}")

    return False

def main():
    # The collector needs permission to read the Security log.
    # Run this script from an elevated PowerShell if access is denied.
    seen_records = set()

    print("Windows Security Log Collector")
    print(f"Sending supported events to {API_URL}")
    print("Press Ctrl+C to stop.")

    while True:
        try:
            events = read_windows_events()

            # Oldest first so repeated polls preserve event order.
            events.sort(key=lambda item: int(item.get("RecordId", 0)))

            for event in events:
                record_id = str(event.get("RecordId", ""))

                if not record_id or record_id in seen_records:
                    continue

                # Mark only after processing; retry if the API is unavailable.
                if send_event(event):
                    seen_records.add(record_id)

            time.sleep(POLL_SECONDS)

        except subprocess.CalledProcessError as exc:
            print("Could not read Windows Security events.")
            print(exc.stderr.strip() or str(exc))
            time.sleep(POLL_SECONDS)

        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            print(f"Could not parse Windows event data: {exc}")
            time.sleep(POLL_SECONDS)

        except KeyboardInterrupt:
            print("\nCollector stopped.")
            break


if __name__ == "__main__":
    main()