#!/usr/bin/env python3
"""
Mock Threat Intelligence API for OSINT Lab Demos

Simulates multiple threat intelligence sources for incident response demos.
Key feature: sources intentionally disagree to demonstrate synthesis challenges.

Endpoints:
    GET /virustotal/ip/<ip>     - VirusTotal-style IP reputation
    GET /greynoise/ip/<ip>      - GreyNoise-style noise classification
    GET /abuseipdb/ip/<ip>      - AbuseIPDB-style abuse reports
    GET /shodan/ip/<ip>         - Shodan-style service discovery
    GET /whois/domain/<domain>  - WHOIS-style domain info

Demo Scenario:
    185.220.101.1 returns divergent intelligence:
    - GreyNoise: "benign" (Tor exit, opportunistic noise)
    - AbuseIPDB: 87% confidence malicious (1247 reports)
    - VirusTotal: 15/90 vendors flag malicious

    This creates the synthesis challenge for Claude Code.
"""

from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import random

app = Flask(__name__)


# =============================================================================
# MOCK THREAT INTEL DATA
# =============================================================================

# IP reputation data - designed for divergent intelligence demo
IP_DATA = {
    # Tor exit node - sources disagree!
    "185.220.101.1": {
        "virustotal": {
            "ip": "185.220.101.1",
            "malicious": 15,
            "suspicious": 8,
            "harmless": 67,
            "undetected": 0,
            "tags": ["tor", "proxy", "anonymizer"],
            "last_analysis_date": "2024-01-14",
            "as_owner": "Tor Exit Node Operator",
            "country": "DE"
        },
        "greynoise": {
            "ip": "185.220.101.1",
            "seen": True,
            "classification": "benign",
            "noise": True,
            "riot": False,
            "name": "Tor Exit Node",
            "link": "https://viz.greynoise.io/ip/185.220.101.1",
            "last_seen": "2024-01-15",
            "message": "This IP is a known Tor exit node. Traffic is opportunistic scanning, not targeted attacks."
        },
        "abuseipdb": {
            "ipAddress": "185.220.101.1",
            "isPublic": True,
            "abuseConfidenceScore": 87,
            "countryCode": "DE",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Tor Exit Node",
            "domain": "torproject.org",
            "totalReports": 1247,
            "numDistinctUsers": 523,
            "lastReportedAt": "2024-01-14T23:45:00Z",
            "reports": [
                {"categories": [14, 18], "comment": "SSH brute force", "reportedAt": "2024-01-14"},
                {"categories": [14], "comment": "Port scan detected", "reportedAt": "2024-01-13"},
                {"categories": [18, 21], "comment": "Web attack attempts", "reportedAt": "2024-01-12"}
            ]
        },
        "shodan": {
            "ip": "185.220.101.1",
            "ports": [22, 80, 443, 9001],
            "hostnames": ["tor-exit.example.de"],
            "country_code": "DE",
            "org": "Tor Exit Node Operator",
            "data": [
                {"port": 9001, "transport": "tcp", "product": "Tor"},
                {"port": 443, "transport": "tcp", "product": "nginx"},
                {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9"}
            ],
            "vulns": [],
            "tags": ["tor", "proxy"]
        }
    },

    # Known malicious C2 server
    "91.121.155.13": {
        "virustotal": {
            "ip": "91.121.155.13",
            "malicious": 45,
            "suspicious": 12,
            "harmless": 33,
            "undetected": 0,
            "tags": ["malware", "c2", "cobalt-strike"],
            "last_analysis_date": "2024-01-10",
            "as_owner": "OVH SAS",
            "country": "FR"
        },
        "greynoise": {
            "ip": "91.121.155.13",
            "seen": True,
            "classification": "malicious",
            "noise": False,
            "riot": False,
            "name": "Unknown",
            "last_seen": "2024-01-10",
            "message": "This IP has been observed in targeted attacks, not internet background noise."
        },
        "abuseipdb": {
            "ipAddress": "91.121.155.13",
            "isPublic": True,
            "abuseConfidenceScore": 100,
            "countryCode": "FR",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "OVH SAS",
            "domain": "ovh.net",
            "totalReports": 892,
            "numDistinctUsers": 345,
            "lastReportedAt": "2024-01-10T18:30:00Z",
            "reports": [
                {"categories": [14, 21], "comment": "Cobalt Strike beacon", "reportedAt": "2024-01-10"},
                {"categories": [20], "comment": "Malware distribution", "reportedAt": "2024-01-09"}
            ]
        },
        "shodan": {
            "ip": "91.121.155.13",
            "ports": [80, 443, 8080],
            "hostnames": [],
            "country_code": "FR",
            "org": "OVH SAS",
            "data": [
                {"port": 443, "transport": "tcp", "product": "nginx", "ssl": {"cert": {"expires": "2024-06-01"}}},
                {"port": 8080, "transport": "tcp", "product": "Unknown"}
            ],
            "vulns": ["CVE-2021-44228"],
            "tags": ["c2"]
        }
    },

    # Benign scanner (ScanMe)
    "45.33.32.156": {
        "virustotal": {
            "ip": "45.33.32.156",
            "malicious": 0,
            "suspicious": 2,
            "harmless": 88,
            "undetected": 0,
            "tags": ["scanner", "nmap"],
            "last_analysis_date": "2024-01-12",
            "as_owner": "Linode",
            "country": "US"
        },
        "greynoise": {
            "ip": "45.33.32.156",
            "seen": True,
            "classification": "benign",
            "noise": True,
            "riot": True,
            "name": "Nmap ScanMe",
            "last_seen": "2024-01-15",
            "message": "This is scanme.nmap.org - an intentional scan target for testing."
        },
        "abuseipdb": {
            "ipAddress": "45.33.32.156",
            "isPublic": True,
            "abuseConfidenceScore": 5,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Linode",
            "domain": "nmap.org",
            "totalReports": 12,
            "numDistinctUsers": 8,
            "lastReportedAt": "2024-01-05T10:00:00Z",
            "reports": []
        },
        "shodan": {
            "ip": "45.33.32.156",
            "ports": [22, 80, 443, 9929, 31337],
            "hostnames": ["scanme.nmap.org"],
            "country_code": "US",
            "org": "Linode",
            "data": [
                {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "6.6.1"},
                {"port": 80, "transport": "tcp", "product": "Apache", "version": "2.4.7"}
            ],
            "vulns": [],
            "tags": ["self-signed"]
        }
    }
}

# Domain data for phishing/typosquat demos
DOMAIN_DATA = {
    "acme-corp-benefits.com": {
        "whois": {
            "domain": "acme-corp-benefits.com",
            "registrar": "NameCheap, Inc.",
            "creation_date": "2024-01-10",
            "expiration_date": "2025-01-10",
            "name_servers": ["ns1.suspiciousdns.com", "ns2.suspiciousdns.com"],
            "registrant_country": "RU",
            "registrant_org": "Privacy Protected",
            "dnssec": False,
            "status": ["clientTransferProhibited"],
            "age_days": 5
        },
        "virustotal": {
            "domain": "acme-corp-benefits.com",
            "malicious": 8,
            "suspicious": 5,
            "harmless": 2,
            "undetected": 75,
            "categories": {"phishing": 6, "malware": 2},
            "last_analysis_date": "2024-01-14"
        }
    },
    "update-service.net": {
        "whois": {
            "domain": "update-service.net",
            "registrar": "Tucows Domains Inc.",
            "creation_date": "2023-12-15",
            "expiration_date": "2024-12-15",
            "name_servers": ["ns1.update-service.net", "ns2.update-service.net"],
            "registrant_country": "PA",
            "registrant_org": "WhoisGuard Protected",
            "dnssec": False,
            "status": ["clientTransferProhibited"],
            "age_days": 30
        },
        "virustotal": {
            "domain": "update-service.net",
            "malicious": 12,
            "suspicious": 8,
            "harmless": 5,
            "undetected": 65,
            "categories": {"c2": 10, "malware": 2},
            "last_analysis_date": "2024-01-13"
        }
    }
}


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "threatintel-api"})


@app.route('/virustotal/ip/<ip>')
def virustotal_ip(ip):
    """VirusTotal-style IP reputation lookup."""
    if ip in IP_DATA and "virustotal" in IP_DATA[ip]:
        return jsonify({
            "data": IP_DATA[ip]["virustotal"],
            "source": "mock-virustotal"
        })
    return jsonify({
        "data": {
            "ip": ip,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 90,
            "tags": [],
            "message": "No data available"
        },
        "source": "mock-virustotal"
    })


@app.route('/greynoise/ip/<ip>')
def greynoise_ip(ip):
    """GreyNoise-style IP classification."""
    if ip in IP_DATA and "greynoise" in IP_DATA[ip]:
        return jsonify({
            "data": IP_DATA[ip]["greynoise"],
            "source": "mock-greynoise"
        })
    return jsonify({
        "data": {
            "ip": ip,
            "seen": False,
            "classification": "unknown",
            "noise": False,
            "riot": False,
            "message": "IP not observed in GreyNoise dataset"
        },
        "source": "mock-greynoise"
    })


@app.route('/abuseipdb/ip/<ip>')
def abuseipdb_ip(ip):
    """AbuseIPDB-style IP abuse report."""
    if ip in IP_DATA and "abuseipdb" in IP_DATA[ip]:
        return jsonify({
            "data": IP_DATA[ip]["abuseipdb"],
            "source": "mock-abuseipdb"
        })
    return jsonify({
        "data": {
            "ipAddress": ip,
            "isPublic": True,
            "abuseConfidenceScore": 0,
            "totalReports": 0,
            "message": "No reports found"
        },
        "source": "mock-abuseipdb"
    })


@app.route('/shodan/ip/<ip>')
def shodan_ip(ip):
    """Shodan-style service discovery."""
    if ip in IP_DATA and "shodan" in IP_DATA[ip]:
        return jsonify({
            "data": IP_DATA[ip]["shodan"],
            "source": "mock-shodan"
        })
    return jsonify({
        "data": {
            "ip": ip,
            "ports": [],
            "hostnames": [],
            "message": "No data available"
        },
        "source": "mock-shodan"
    })


@app.route('/whois/domain/<domain>')
def whois_domain(domain):
    """WHOIS-style domain information."""
    if domain in DOMAIN_DATA and "whois" in DOMAIN_DATA[domain]:
        return jsonify({
            "data": DOMAIN_DATA[domain]["whois"],
            "source": "mock-whois"
        })
    return jsonify({
        "data": {
            "domain": domain,
            "message": "No WHOIS data available"
        },
        "source": "mock-whois"
    })


@app.route('/virustotal/domain/<domain>')
def virustotal_domain(domain):
    """VirusTotal-style domain reputation."""
    if domain in DOMAIN_DATA and "virustotal" in DOMAIN_DATA[domain]:
        return jsonify({
            "data": DOMAIN_DATA[domain]["virustotal"],
            "source": "mock-virustotal"
        })
    return jsonify({
        "data": {
            "domain": domain,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 90,
            "message": "No data available"
        },
        "source": "mock-virustotal"
    })


@app.route('/enrich/ip/<ip>')
def enrich_ip(ip):
    """Aggregate all sources for an IP (convenience endpoint)."""
    result = {
        "ip": ip,
        "sources": {}
    }

    if ip in IP_DATA:
        for source, data in IP_DATA[ip].items():
            result["sources"][source] = data
    else:
        result["message"] = "No threat intelligence data available for this IP"

    return jsonify(result)


@app.route('/enrich/domain/<domain>')
def enrich_domain(domain):
    """Aggregate all sources for a domain (convenience endpoint)."""
    result = {
        "domain": domain,
        "sources": {}
    }

    if domain in DOMAIN_DATA:
        for source, data in DOMAIN_DATA[domain].items():
            result["sources"][source] = data
    else:
        result["message"] = "No threat intelligence data available for this domain"

    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
