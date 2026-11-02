import csv
import io
import ipaddress

from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    Response
)

from database import (
    init_db,
    get_events,
    get_statistics,
    get_event_by_id,
    update_event_status,
    export_events
)

from detector import detect_event


app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(get_statistics())


@app.route("/api/events")
def api_events():
    search = request.args.get("search", "").strip().lower()
    severity = request.args.get("severity", "").strip().upper()

    events = get_events(limit=500)

    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        events = [
            event for event in events
            if event["severity"] == severity
        ]

    if search:
        events = [
            event for event in events
            if search in str(event).lower()
        ]

    return jsonify(events)


@app.route("/api/events", methods=["POST"])
def create_event():
    data = request.get_json(silent=True) or {}

    source_ip = str(data.get("source_ip", "")).strip()
    event_type = str(data.get("event_type", "")).strip().upper()
    username = str(data.get("username", "demo_user")).strip()
    description = str(data.get("description", "")).strip()

    if not source_ip or not event_type:
        return jsonify({
            "error": "source_ip and event_type are required"
        }), 400

    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return jsonify({
            "error": "Enter a valid IPv4 or IPv6 address"
        }), 400

    allowed_types = {
        "FAILED_LOGIN",
        "SUCCESSFUL_LOGIN",
        "SUSPICIOUS_ACTIVITY",
        "PORT_SCAN",
        "MALWARE_ALERT"
    }

    if event_type not in allowed_types:
        return jsonify({
            "error": "Unsupported event type"
        }), 400

    if len(username) > 100 or len(description) > 500:
        return jsonify({
            "error": "Username or description is too long"
        }), 400

    event_id = detect_event(
        source_ip,
        event_type,
        username,
        description
    )

    event = get_event_by_id(event_id)

    return jsonify({
        "message": "Security event recorded",
        "event": event
    }), 201


@app.route("/api/events/<int:event_id>/status", methods=["PATCH"])
def change_status(event_id):
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).strip().title()

    if status not in {"Open", "Investigating", "Resolved"}:
        return jsonify({
            "error": "Status must be Open, Investigating, or Resolved"
        }), 400

    if not update_event_status(event_id, status):
        return jsonify({"error": "Event not found"}), 404

    return jsonify({
        "message": "Event status updated",
        "id": event_id,
        "status": status
    })


@app.route("/api/simulate", methods=["POST"])
def simulate_events():
    # Uses documentation-only IP addresses for safe demonstration.
    demo_ip = "192.0.2.25"

    for _ in range(5):
        detect_event(
            demo_ip,
            "FAILED_LOGIN",
            "demo_user",
            "Simulated failed login for dashboard demonstration"
        )

    detect_event(
        "198.51.100.20",
        "PORT_SCAN",
        "demo_user",
        "Simulated port scan event"
    )

    detect_event(
        "203.0.113.50",
        "MALWARE_ALERT",
        "demo_user",
        "Simulated malware alert; no malware was executed"
    )

    return jsonify({
        "message": "Demo events created successfully"
    }), 201


@app.route("/api/export")
def export_csv():
    output = io.StringIO()
    fieldnames = [
        "id", "timestamp", "source_ip", "event_type",
        "username", "severity", "description", "status"
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(export_events())

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=soc_security_report.csv"
        }
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)