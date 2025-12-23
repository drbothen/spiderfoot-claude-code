#!/usr/bin/env python3
"""
Mock SIEM API for OSINT Lab Demos

Simulates a SIEM alert feed for incident response demos.
Provides realistic alert data that analysts would triage.

Endpoints:
    GET /health              - Health check
    GET /alerts              - List all alerts
    GET /alerts/<alert_id>   - Get specific alert by ID
    GET /alerts/pending      - Get alerts pending enrichment
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


# =============================================================================
# MOCK SIEM ALERTS
# =============================================================================

ALERTS = {
    "SEC-2024-00147": {
        "alert_id": "SEC-2024-00147",
        "timestamp": "2024-01-15T14:32:18Z",
        "severity": "HIGH",
        "source": "Firewall",
        "rule": "Outbound C2 Beaconing Detected",
        "description": "Regular interval connections to external IP detected",
        "src_ip": "10.1.50.23",
        "src_host": "WS-JSMITH-PC",
        "dst_ip": "185.220.101.1",
        "dst_port": 443,
        "protocol": "TCP",
        "connection_count": 47,
        "interval_seconds": 60,
        "first_seen": "2024-01-15T13:45:00Z",
        "last_seen": "2024-01-15T14:32:00Z",
        "action_taken": "Alert generated, connection allowed",
        "enrichment_status": "pending",
        "analyst_notes": None
    },
    "SEC-2024-00148": {
        "alert_id": "SEC-2024-00148",
        "timestamp": "2024-01-15T09:17:32Z",
        "severity": "MEDIUM",
        "source": "Email Gateway",
        "rule": "Suspicious Domain in Email Link",
        "description": "Email contains link to recently registered lookalike domain",
        "recipient": "jsmith@acme-corp.lab",
        "sender": "hr-updates@acme-corp-benefits.com",
        "subject": "Important: Update Your Benefits Information",
        "suspicious_domain": "acme-corp-benefits.com",
        "domain_age_days": 5,
        "action_taken": "Email quarantined",
        "enrichment_status": "pending",
        "analyst_notes": None
    },
    "SEC-2024-00149": {
        "alert_id": "SEC-2024-00149",
        "timestamp": "2024-01-15T02:15:44Z",
        "severity": "HIGH",
        "source": "Web Application Firewall",
        "rule": "Credential Stuffing Attack Detected",
        "description": "High volume of failed authentication attempts from single IP",
        "target_application": "VPN Portal",
        "target_url": "https://vpn.acme-corp.lab/login",
        "src_ip": "91.121.155.13",
        "failed_attempts": 1247,
        "successful_attempts": 3,
        "unique_usernames_tried": 892,
        "time_window_minutes": 15,
        "rate_per_minute": 83,
        "compromised_accounts": [
            "sysadmin@acme-corp.lab",
            "it.admin@acme-corp.lab",
            "legacy.support@acme-corp.lab"
        ],
        "action_taken": "IP blocked after 1000 attempts",
        "enrichment_status": "pending",
        "analyst_notes": "Attack used credential list consistent with known breach data. 3 accounts may be compromised."
    }
}


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "siem-api"})


@app.route('/alerts')
def list_alerts():
    """List all SIEM alerts."""
    alerts = list(ALERTS.values())
    return jsonify({
        "count": len(alerts),
        "alerts": alerts
    })


@app.route('/alerts/pending')
def pending_alerts():
    """List alerts pending enrichment."""
    pending = [a for a in ALERTS.values() if a.get("enrichment_status") == "pending"]
    return jsonify({
        "count": len(pending),
        "alerts": pending
    })


@app.route('/alerts/<alert_id>')
def get_alert(alert_id):
    """Get a specific alert by ID."""
    if alert_id in ALERTS:
        return jsonify(ALERTS[alert_id])
    return jsonify({"error": "Alert not found", "alert_id": alert_id}), 404


@app.route('/alerts/<alert_id>/ioc')
def get_alert_ioc(alert_id):
    """Extract the primary IOC from an alert for enrichment."""
    if alert_id not in ALERTS:
        return jsonify({"error": "Alert not found", "alert_id": alert_id}), 404

    alert = ALERTS[alert_id]
    ioc = None
    ioc_type = None

    # Extract IOC based on alert type
    if "dst_ip" in alert:
        ioc = alert["dst_ip"]
        ioc_type = "ip"
    elif "src_ip" in alert and alert.get("source") == "Web Application Firewall":
        ioc = alert["src_ip"]
        ioc_type = "ip"
    elif "suspicious_domain" in alert:
        ioc = alert["suspicious_domain"]
        ioc_type = "domain"

    if ioc:
        return jsonify({
            "alert_id": alert_id,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "context": {
                "severity": alert.get("severity"),
                "rule": alert.get("rule"),
                "description": alert.get("description")
            }
        })

    return jsonify({"error": "No IOC found in alert", "alert_id": alert_id}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
