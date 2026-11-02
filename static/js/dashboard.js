let severityChart = null;
let timelineChart = null;

const $ = (id) => document.getElementById(id);

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}

function showMessage(text) {
    $("message").textContent = text;
}

async function fetchJSON(url, options = {}) {
    const response = await fetch(url, options);

    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || `Request failed: ${response.status}`);
    }

    return response.json();
}

async function loadStats() {
    const stats = await fetchJSON("/api/stats");

    $("totalEvents").textContent = stats.total_events;
    $("failedLogins").textContent = stats.failed_logins;
    $("criticalAlerts").textContent = stats.critical_alerts;
    $("suspiciousIPs").textContent = stats.suspicious_ips;

    renderSeverityChart(stats.severity_counts);
    renderTimelineChart(stats.timeline);
}

function renderSeverityChart(counts) {
    const labels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const values = labels.map(label => counts[label] || 0);

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart($("severityChart"), {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    "#22c55e",
                    "#eab308",
                    "#f97316",
                    "#ef4444"
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#e7edf7" }
                }
            }
        }
    });
}

function renderTimelineChart(timeline) {
    if (timelineChart) {
        timelineChart.destroy();
    }

    timelineChart = new Chart($("timelineChart"), {
        type: "bar",
        data: {
            labels: timeline.map(item => item.day),
            datasets: [{
                label: "Events",
                data: timeline.map(item => item.count),
                backgroundColor: "#38bdf8",
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: { color: "#9caec5" },
                    grid: { color: "#293952" }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#9caec5",
                        precision: 0
                    },
                    grid: { color: "#293952" }
                }
            },
            plugins: {
                legend: {
                    labels: { color: "#e7edf7" }
                }
            }
        }
    });
}

async function loadEvents() {
    const params = new URLSearchParams();
    params.set("search", $("searchInput").value.trim());
    params.set("severity", $("severityFilter").value);

    const events = await fetchJSON(`/api/events?${params.toString()}`);
    const table = $("eventsTable");

    if (events.length === 0) {
        table.innerHTML = `
            <tr><td colspan="8">No security events found.</td></tr>
        `;
        return;
    }

    table.innerHTML = events.map(event => `
        <tr>
            <td>${escapeHTML(new Date(event.timestamp).toLocaleString())}</td>
            <td>${escapeHTML(event.source_ip)}</td>
            <td>${escapeHTML(event.event_type)}</td>
            <td>${escapeHTML(event.username)}</td>
            <td>
                <span class="severity severity-${escapeHTML(event.severity)}">
                    ${escapeHTML(event.severity)}
                </span>
            </td>
            <td>${escapeHTML(event.description)}</td>
            <td>${escapeHTML(event.status)}</td>
            <td>
                <select
                    aria-label="Update event status"
                    onchange="updateStatus(${Number(event.id)}, this.value)">
                    <option value="Open" ${event.status === "Open" ? "selected" : ""}>Open</option>
                    <option value="Investigating" ${event.status === "Investigating" ? "selected" : ""}>Investigating</option>
                    <option value="Resolved" ${event.status === "Resolved" ? "selected" : ""}>Resolved</option>
                </select>
            </td>
        </tr>
    `).join("");
}

async function updateStatus(id, status) {
    try {
        await fetchJSON(`/api/events/${id}/status`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status })
        });

        showMessage(`Event #${id} updated to ${status}.`);
        await refreshDashboard();
    } catch (error) {
        showMessage(error.message);
    }
}

async function refreshDashboard() {
    try {
        await Promise.all([loadStats(), loadEvents()]);
    } catch (error) {
        showMessage(`Dashboard error: ${error.message}`);
    }
}

async function simulateEvents() {
    $("simulateBtn").disabled = true;

    try {
        const result = await fetchJSON("/api/simulate", {
            method: "POST"
        });

        showMessage(result.message);
        await refreshDashboard();
    } catch (error) {
        showMessage(`Simulation failed: ${error.message}`);
    } finally {
        $("simulateBtn").disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    $("simulateBtn").addEventListener("click", simulateEvents);
    $("searchInput").addEventListener("input", loadEvents);
    $("severityFilter").addEventListener("change", loadEvents);

    refreshDashboard();

    // Refresh dashboard statistics and events every 10 seconds.
    setInterval(refreshDashboard, 10000);
});