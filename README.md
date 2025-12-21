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
git clone https://github.com/drbothen/spiderfoot-claude-code.git
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

Many SpiderFoot modules require API keys from third-party services. You can configure these in two ways:

### Option 1: Environment File (Recommended)

Pre-configure API keys before starting the lab:

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API keys
# Only add keys for services you have accounts with
```

The `.env` file is gitignored, so your keys stay private. **API keys are automatically imported on container startup** - no manual configuration required.

**Example `.env` entries:**
```bash
SFP_SHODAN_API_KEY=your_shodan_key_here
SFP_VIRUSTOTAL_API_KEY=your_virustotal_key_here
SFP_HUNTER_API_KEY=your_hunter_key_here
```

**Manual import (if needed):**
```bash
# Re-import API keys without restarting
uv run sf-cli import-keys --env-file .env
```

### Option 2: Web UI

Configure API keys through SpiderFoot's web interface:

1. Open http://localhost:5001
2. Navigate to Settings
3. Find modules with a padlock icon (requires API key)
4. Enter your API key and click Save

### Key Services for Enhanced Scanning

| Service | Module | Use Case | Free Tier |
|---------|--------|----------|-----------|
| [Shodan](https://www.shodan.io/) | sfp_shodan | Device discovery, exposed services | Yes |
| [VirusTotal](https://www.virustotal.com/) | sfp_virustotal | Malware/threat analysis | Yes |
| [Have I Been Pwned](https://haveibeenpwned.com/) | sfp_haveibeenpwned | Credential breach checking | Paid |
| [Hunter.io](https://hunter.io/) | sfp_hunter | Corporate email discovery | Yes |
| [AlienVault OTX](https://otx.alienvault.com/) | sfp_alienvault | Threat intelligence | Yes |
| [SecurityTrails](https://securitytrails.com/) | sfp_securitytrails | Passive DNS, historical data | Yes |
| [Censys](https://censys.io/) | sfp_censys | Certificate/host search | Yes |
| [BuiltWith](https://builtwith.com/) | sfp_builtwith | Technology profiling | Yes |

See `.env.example` for the complete list of supported API keys.

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
