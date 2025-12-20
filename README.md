# SpiderFoot + Claude Code: OSINT Automation with AI

A Docker-based lab environment for automating OSINT reconnaissance with [SpiderFoot](https://github.com/smicallef/spiderfoot) and interpreting results with AI coding assistants like [Claude Code](https://claude.ai/claude-code).

## What This Does

SpiderFoot automates open-source intelligence gathering across 200+ modules. This lab provides:

- **Docker Compose environment** with SpiderFoot and test targets
- **CLI tool (`sf-cli`)** for programmatic scan control
- **AI integration pattern** for piping results to Claude Code for interpretation

Instead of manually correlating findings across dozens of browser tabs, you run a scan and ask Claude to analyze the results:

```bash
uv run sf-cli results --scan-id $SCAN_ID --format json | \
  claude -p "Analyze these OSINT findings. Identify the top 3 risks and recommend actions."
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ with [uv](https://github.com/astral-sh/uv) (recommended) or pip
- Claude Code CLI (optional, for AI interpretation)

### Setup

```bash
# Clone the repository
git clone https://github.com/joshmagady/spiderfoot-claude-code.git
cd spiderfoot-claude-code

# Start the lab (first run builds SpiderFoot image, takes 2-3 min)
./lab.sh up

# Install the CLI tool
uv sync
```

### Run Your First Scan

```bash
# Scan the local test target
uv run sf-cli scan --target web-target --profile footprint --name "test-scan" --wait

# Get scan results
uv run sf-cli list
uv run sf-cli results --scan-id <SCAN_ID> --format json
```

### Interpret with Claude Code

```bash
# Pipe results to Claude for analysis
uv run sf-cli results --scan-id <SCAN_ID> --format json | \
  claude -p "Analyze these SpiderFoot OSINT results. Provide:
    1) Executive summary
    2) Top 3 risks
    3) Recommended actions"
```

## Lab Services

| Service | URL | Description |
|---------|-----|-------------|
| SpiderFoot | http://localhost:5001 | OSINT automation web UI |
| Web Target | http://localhost:8080 | Fake company site with exposed info |
| Juice Shop | http://localhost:3000 | OWASP vulnerable web app |
| DVWA | http://localhost:8081 | Damn Vulnerable Web App |

## CLI Reference

### Scan Commands

```bash
# Start a scan with different profiles
uv run sf-cli scan --target example.com --profile footprint
uv run sf-cli scan --target example.com --profile passive   # Stealth mode
uv run sf-cli scan --target example.com --profile investigate  # Include threat intel

# Wait for completion
uv run sf-cli scan --target example.com --profile footprint --wait
```

### Results Commands

```bash
# List all scans
uv run sf-cli list

# Get scan status
uv run sf-cli status --scan-id <ID>

# Get results (JSON for AI processing)
uv run sf-cli results --scan-id <ID> --format json

# Get summary
uv run sf-cli summary --scan-id <ID>
```

### Management Commands

```bash
# Stop a running scan
uv run sf-cli stop --scan-id <ID>

# Delete a scan
uv run sf-cli delete --scan-id <ID>

# List available modules
uv run sf-cli modules
```

## Scan Profiles

| Profile | Use Case | Modules |
|---------|----------|---------|
| `passive` | Stealth reconnaissance | DNS, WHOIS, archive.org (no direct contact) |
| `footprint` | Attack surface mapping | Above + port scan, web analysis, email discovery |
| `investigate` | Threat intelligence | Above + SSL certs, Shodan, threat feeds |
| `all` | Maximum coverage | All 200+ modules (slow) |

## Lab Management

```bash
./lab.sh up       # Start all services
./lab.sh down     # Stop (preserves data)
./lab.sh reset    # Full reset (deletes scan data)
./lab.sh status   # Show container status
./lab.sh logs     # Follow logs
./lab.sh shell    # Shell into SpiderFoot container
./lab.sh urls     # Show service URLs
```

## Example Workflows

### Attack Surface Discovery

```bash
uv run sf-cli scan --target yourcompany.com --profile footprint --wait

uv run sf-cli results --scan-id $SCAN_ID --format json | \
  claude -p "Identify all discovered subdomains, IPs, and web apps.
    Flag any that appear to be:
    - Development or staging environments
    - Unmaintained or outdated
    - Running vulnerable software"
```

### IOC Enrichment (Incident Response)

```bash
uv run sf-cli scan --target 203.0.113.42 --profile investigate --wait

uv run sf-cli results --scan-id $SCAN_ID --format json | \
  claude -p "This IP appeared in our security logs. Tell me:
    - Is it associated with known threat actors?
    - What infrastructure is connected?
    - Should we block it?"
```

### Third-Party Risk Assessment

```bash
uv run sf-cli scan --target vendor.com --profile passive --wait

uv run sf-cli results --scan-id $SCAN_ID --format json | \
  claude -p "Assess this vendor's external security posture.
    Evaluate SSL config, credential exposures, tech stack.
    Produce a risk score (Low/Medium/High) with justification."
```

## API Keys for Enhanced Scanning

Configure API keys in SpiderFoot's web UI (http://localhost:5001 > Settings) to enable enhanced modules:

- **Have I Been Pwned** - Credential breach checking
- **VirusTotal** - Malware/threat analysis
- **Shodan** - Internet-wide device discovery
- **SecurityTrails** - Passive DNS
- **Hunter.io** - Corporate email discovery
- **AlienVault OTX** - Threat intelligence

## Legal Notice

**Always obtain authorization before scanning external targets.**

This lab includes local test targets for learning SpiderFoot mechanics. For external reconnaissance:

- Only scan domains you own or have written permission to assess
- Respect rate limits and terms of service
- Be aware of privacy regulations (GDPR, CCPA)
- Passive-only scans review public information but still require authorization context

## License

MIT License - See [LICENSE](LICENSE) for details.

## Related

- [SpiderFoot](https://github.com/smicallef/spiderfoot) - The OSINT automation tool
- [Claude Code](https://claude.ai/claude-code) - AI coding assistant
- [Article: Automating OSINT with Claude Code and SpiderFoot](https://blog.magady.me) - Full walkthrough
