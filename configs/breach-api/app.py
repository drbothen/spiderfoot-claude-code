#!/usr/bin/env python3
"""
Mock Breach API for OSINT Lab Demos

Simulates a breach database API (similar to HIBP) for local testing.
Returns fake breach data for @acme-corp.lab email addresses.

Usage:
    GET /breaches?email=user@acme-corp.lab
    GET /breaches/domain/acme-corp.lab
"""

from flask import Flask, jsonify, request
from datetime import datetime
import hashlib

app = Flask(__name__)

# Fake breach database
BREACHES = {
    "AcmeDataLeak2023": {
        "name": "Acme Corporation Data Leak 2023",
        "date": "2023-08-15",
        "records": 45000,
        "data_types": ["email", "password_hash", "name", "phone"],
        "description": "Customer database exposed via misconfigured S3 bucket"
    },
    "VendorPortalBreach": {
        "name": "Vendor Portal Security Incident",
        "date": "2022-03-22",
        "records": 12500,
        "data_types": ["email", "password", "company"],
        "description": "Third-party vendor portal compromised"
    },
    "LegacySystemLeak": {
        "name": "Legacy System Data Exposure",
        "date": "2021-11-10",
        "records": 8200,
        "data_types": ["email", "password_hash", "ip_address"],
        "description": "Unpatched legacy system exploited"
    },
    "PhishingCampaign2024": {
        "name": "Phishing Campaign Credential Harvest",
        "date": "2024-01-20",
        "records": 350,
        "data_types": ["email", "password"],
        "description": "Credentials harvested via targeted phishing"
    }
}

# Fake exposed emails (maps to breaches)
EXPOSED_EMAILS = {
    "jsmith@acme-corp.lab": ["AcmeDataLeak2023", "LegacySystemLeak"],
    "sjohnson@acme-corp.lab": ["AcmeDataLeak2023"],
    "mchen@acme-corp.lab": ["VendorPortalBreach"],
    "info@acme-corp.lab": ["AcmeDataLeak2023", "PhishingCampaign2024"],
    "sales@acme-corp.lab": ["AcmeDataLeak2023"],
    "support@acme-corp.lab": ["AcmeDataLeak2023", "VendorPortalBreach"],
    "it.admin@acme-corp.lab": ["LegacySystemLeak", "PhishingCampaign2024"],
    "dev.lead@acme-corp.lab": ["VendorPortalBreach"],
    "sysadmin@acme-corp.lab": ["LegacySystemLeak"],
    "legacy.support@acme-corp.lab": ["LegacySystemLeak"],
    "bob.retired@acme-corp.lab": ["AcmeDataLeak2023", "LegacySystemLeak"],
    "api.team@acme-corp.lab": ["VendorPortalBreach"],
    "helpdesk@acme-corp.lab": ["PhishingCampaign2024"],
}


@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "breach-api"})


@app.route('/breaches')
def check_email():
    """Check if an email appears in any breaches."""
    email = request.args.get('email', '').lower()

    if not email:
        return jsonify({"error": "email parameter required"}), 400

    if email in EXPOSED_EMAILS:
        breach_ids = EXPOSED_EMAILS[email]
        breaches = [BREACHES[bid] for bid in breach_ids if bid in BREACHES]
        return jsonify({
            "email": email,
            "found": True,
            "breach_count": len(breaches),
            "breaches": breaches
        })

    return jsonify({
        "email": email,
        "found": False,
        "breach_count": 0,
        "breaches": []
    })


@app.route('/breaches/domain/<domain>')
def check_domain(domain):
    """Get all breached emails for a domain."""
    domain = domain.lower()

    exposed = {
        email: [BREACHES[bid] for bid in breach_ids]
        for email, breach_ids in EXPOSED_EMAILS.items()
        if email.endswith(f"@{domain}")
    }

    if exposed:
        return jsonify({
            "domain": domain,
            "found": True,
            "exposed_accounts": len(exposed),
            "accounts": [
                {
                    "email": email,
                    "breach_count": len(breaches),
                    "breaches": [b["name"] for b in breaches],
                    "most_recent": max(b["date"] for b in breaches)
                }
                for email, breaches in exposed.items()
            ]
        })

    return jsonify({
        "domain": domain,
        "found": False,
        "exposed_accounts": 0,
        "accounts": []
    })


@app.route('/breaches/list')
def list_breaches():
    """List all known breaches."""
    return jsonify({
        "total_breaches": len(BREACHES),
        "breaches": list(BREACHES.values())
    })


@app.route('/paste/<email>')
def check_pastes(email):
    """Simulate paste site exposure check."""
    email = email.lower()

    # Fake paste data for some emails
    if email in ["it.admin@acme-corp.lab", "sysadmin@acme-corp.lab"]:
        return jsonify({
            "email": email,
            "found": True,
            "pastes": [
                {
                    "source": "Pastebin",
                    "id": "abc123xyz",
                    "date": "2023-05-15",
                    "title": "Acme Credentials Dump"
                }
            ]
        })

    return jsonify({
        "email": email,
        "found": False,
        "pastes": []
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
