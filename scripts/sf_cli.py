#!/usr/bin/env python3
"""
SpiderFoot CLI Helper for AI Coding Assistant Integration

This script provides programmatic access to SpiderFoot's REST API,
enabling AI coding assistants like Claude Code to orchestrate OSINT
scans and retrieve results for analysis.

Usage:
    sf-cli scan --target example.com --profile footprint
    sf-cli status --scan-id <id>
    sf-cli results --scan-id <id> --format json
    sf-cli list

With uv (recommended):
    uv run sf-cli scan --target example.com --profile footprint

Pipe results to Claude Code for interpretation:
    uv run sf-cli results --scan-id <id> --format json | \\
        claude -p "Analyze these OSINT findings and provide a risk assessment"
"""

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)


# Default module sets for scan profiles
# These provide consistent behavior across SpiderFoot versions
PROFILE_MODULES = {
    "passive": [
        "sfp_spider", "sfp_dnsresolve", "sfp_whois", "sfp_dns",
        "sfp_dnsdumpster", "sfp_archiveorg"
    ],
    "footprint": [
        "sfp_spider", "sfp_dnsresolve", "sfp_whois", "sfp_dns",
        "sfp_dnsdumpster", "sfp_archiveorg", "sfp_portscan_tcp",
        "sfp_webanalytics", "sfp_webserver", "sfp_emailformat"
    ],
    "investigate": [
        "sfp_spider", "sfp_dnsresolve", "sfp_whois", "sfp_dns",
        "sfp_dnsdumpster", "sfp_archiveorg", "sfp_portscan_tcp",
        "sfp_webanalytics", "sfp_webserver", "sfp_emailformat",
        "sfp_sslcert", "sfp_shodan", "sfp_threatminer"
    ],
}


class SpiderFootClient:
    """Client for SpiderFoot REST API."""

    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "sf-cli/1.0"
        })

    def _request(self, method: str, endpoint: str, **kwargs) -> dict | list:
        """Make API request."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            if response.text:
                return response.json()
            return {}
        except requests.exceptions.RequestException as e:
            print(f"API Error: {e}", file=sys.stderr)
            sys.exit(1)

    def list_scans(self) -> list:
        """List all scans."""
        return self._request("GET", "/scanlist")

    def start_scan(self, target: str, scan_name: str = None,
                   profile: str = "footprint", modules: list = None) -> dict:
        """Start a new scan.

        Args:
            target: Domain, IP, email, or other target
            scan_name: Optional name for the scan
            profile: Scan profile (footprint, investigate, passive, all)
            modules: Optional list of specific modules to use

        Returns:
            dict with scan_id on success or error message
        """
        if scan_name is None:
            scan_name = target

        # Use provided modules, or get modules from profile
        if modules:
            module_list = modules
        elif profile == "all":
            module_list = []  # Empty means all modules
        else:
            module_list = PROFILE_MODULES.get(profile, PROFILE_MODULES["footprint"])

        data = {
            "scanname": scan_name,
            "scantarget": target,
            "modulelist": ",".join(module_list) if module_list else "",
            "typelist": "",
            "usecase": "all" if profile == "all" and not module_list else "",
        }

        result = self._request("POST", "/startscan", data=data)

        # Parse SpiderFoot response format: ["SUCCESS", scan_id] or ["ERROR", message]
        if isinstance(result, list) and len(result) >= 2:
            if result[0] == "SUCCESS":
                return {"status": "success", "scan_id": result[1]}
            else:
                return {"status": "error", "message": result[1]}
        return {"status": "unknown", "raw": result}

    def scan_status(self, scan_id: str) -> dict:
        """Get scan status."""
        scans = self.list_scans()
        for scan in scans:
            if scan[0] == scan_id:
                return {
                    "id": scan[0],
                    "name": scan[1],
                    "target": scan[2],
                    "started": scan[3],
                    "ended": scan[4],
                    "status": scan[6] if len(scan) > 6 else scan[5],
                    "elements": scan[7] if len(scan) > 7 else None,
                    "risk_summary": scan[8] if len(scan) > 8 else None
                }
        return {"error": "Scan not found"}

    def scan_results(self, scan_id: str, event_type: str = None) -> list:
        """Get scan results."""
        endpoint = f"/scaneventresults?id={scan_id}"
        if event_type:
            endpoint += f"&eventType={event_type}"
        return self._request("GET", endpoint)

    def scan_summary(self, scan_id: str) -> dict:
        """Get scan summary with event counts by type."""
        return self._request("GET", f"/scansummary?id={scan_id}&by=type")

    def stop_scan(self, scan_id: str) -> dict:
        """Stop a running scan."""
        return self._request("GET", f"/stopscan?id={scan_id}")

    def delete_scan(self, scan_id: str) -> dict:
        """Delete a scan and its data."""
        return self._request("GET", f"/scandelete?id={scan_id}")

    def get_modules(self) -> list:
        """List available modules."""
        return self._request("GET", "/modules")


def main():
    parser = argparse.ArgumentParser(
        description="SpiderFoot CLI for AI Coding Assistant Integration",
        epilog="Example: uv run sf-cli scan --target example.com --profile footprint"
    )
    parser.add_argument("--url", default="http://localhost:5001",
                        help="SpiderFoot base URL (default: http://localhost:5001)")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Start a new scan")
    scan_parser.add_argument("--target", "-t", required=True,
                             help="Target to scan (domain, IP, email)")
    scan_parser.add_argument("--name", "-n", help="Scan name")
    scan_parser.add_argument("--profile", "-p", default="footprint",
                             choices=["all", "footprint", "investigate", "passive"],
                             help="Scan profile (default: footprint)")
    scan_parser.add_argument("--modules", "-m", help="Comma-separated module list")
    scan_parser.add_argument("--wait", "-w", action="store_true",
                             help="Wait for scan to complete")

    # Status command
    status_parser = subparsers.add_parser("status", help="Get scan status")
    status_parser.add_argument("--scan-id", "-i", required=True, help="Scan ID")

    # Results command
    results_parser = subparsers.add_parser("results", help="Get scan results")
    results_parser.add_argument("--scan-id", "-i", required=True, help="Scan ID")
    results_parser.add_argument("--type", "-t", help="Filter by event type")
    results_parser.add_argument("--format", "-f", default="json",
                                choices=["json", "csv", "table"],
                                help="Output format (default: json)")

    # Summary command
    summary_parser = subparsers.add_parser("summary", help="Get scan summary")
    summary_parser.add_argument("--scan-id", "-i", required=True, help="Scan ID")

    # List command
    subparsers.add_parser("list", help="List all scans")

    # Modules command
    subparsers.add_parser("modules", help="List available modules")

    # Stop command
    stop_parser = subparsers.add_parser("stop", help="Stop a running scan")
    stop_parser.add_argument("--scan-id", "-i", required=True, help="Scan ID")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a scan")
    delete_parser.add_argument("--scan-id", "-i", required=True, help="Scan ID")

    # Import API keys command
    import_parser = subparsers.add_parser("import-keys", help="Import API keys from .env file")
    import_parser.add_argument("--env-file", "-e", default=".env",
                               help="Path to .env file (default: .env)")
    import_parser.add_argument("--config-file", "-c",
                               help="Path to existing spiderfoot.cfg file to import")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    client = SpiderFootClient(args.url)

    if args.command == "scan":
        modules = args.modules.split(",") if args.modules else None
        result = client.start_scan(
            target=args.target,
            scan_name=args.name,
            profile=args.profile,
            modules=modules
        )
        print(json.dumps(result, indent=2))

        if result.get("status") == "success" and args.wait:
            scan_id = result.get("scan_id")
            if scan_id:
                print(f"\nWaiting for scan {scan_id} to complete...", file=sys.stderr)
                while True:
                    status = client.scan_status(scan_id)
                    current_status = status.get("status", "UNKNOWN")
                    if current_status in ["FINISHED", "ABORTED", "ERROR-FAILED"]:
                        print(f"\nScan {current_status}", file=sys.stderr)
                        break
                    time.sleep(5)
                summary = client.scan_summary(scan_id)
                print(json.dumps(summary, indent=2))

    elif args.command == "status":
        result = client.scan_status(args.scan_id)
        print(json.dumps(result, indent=2))

    elif args.command == "results":
        result = client.scan_results(args.scan_id, args.type)
        if args.format == "json":
            print(json.dumps(result, indent=2))
        elif args.format == "csv":
            if result:
                print(",".join(result[0].keys()) if isinstance(result[0], dict) else "")
                for row in result:
                    if isinstance(row, dict):
                        print(",".join(str(v) for v in row.values()))
                    else:
                        print(",".join(str(v) for v in row))
        elif args.format == "table":
            for row in result[:20]:  # Limit to 20 rows
                print(row)

    elif args.command == "summary":
        result = client.scan_summary(args.scan_id)
        print(json.dumps(result, indent=2))

    elif args.command == "list":
        result = client.list_scans()
        for scan in result:
            # scan format: [id, name, target, started, ended, last_updated, status, elements, risk]
            status = scan[6] if len(scan) > 6 else "UNKNOWN"
            print(f"ID: {scan[0]}, Name: {scan[1]}, Target: {scan[2]}, Status: {status}")

    elif args.command == "modules":
        result = client.get_modules()
        for module in result:
            print(f"{module['name']}: {module.get('descr', 'No description')}")

    elif args.command == "stop":
        result = client.stop_scan(args.scan_id)
        print(json.dumps(result, indent=2))

    elif args.command == "delete":
        result = client.delete_scan(args.scan_id)
        print(json.dumps(result, indent=2))

    elif args.command == "import-keys":
        import subprocess
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_script = os.path.join(script_dir, "configure_api_keys.py")

        cmd = [sys.executable, config_script, "--url", args.url]

        if args.config_file:
            # Import existing config file directly
            cmd.extend(["--generate-cfg", args.config_file, "--import"])
        else:
            # Generate from .env and import
            cmd.extend(["--env-file", args.env_file, "--generate-cfg", "spiderfoot.cfg", "--import"])

        result = subprocess.run(cmd)
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
