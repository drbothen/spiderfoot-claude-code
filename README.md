# SpiderFoot + Claude Code: OSINT Automation with AI

A Docker-based lab environment for automating OSINT reconnaissance with [SpiderFoot](https://github.com/smicallef/spiderfoot) and interpreting results with AI coding assistants like [Claude Code](https://claude.ai/claude-code).

## What This Does

SpiderFoot automates open-source intelligence gathering across 200+ modules. This lab provides:

- **Docker Compose environment** with SpiderFoot and realistic test targets
- **Shadow IT simulation** with 15+ subdomains mimicking common attack surface patterns
- **Mock breach API** for credential exposure testing without external dependencies
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

### Core Infrastructure

| Service | URL | Description |
|---------|-----|-------------|
| SpiderFoot | http://localhost:5001 | OSINT automation web UI |
| DNS Server | localhost:5353 | dnsmasq for *.acme-corp.lab resolution |
| Breach API | http://localhost:5050 | Mock HIBP-style breach database |

### Acme Corp Attack Surface (acme-corp.lab)

The lab simulates a realistic company attack surface with shadow IT patterns commonly found during real engagements:

| Subdomain | Host Port | IP Address | What It Simulates |
|-----------|-----------|------------|-------------------|
| www.acme-corp.lab | 8080 | 172.28.0.10 | Production website |
| intranet.acme-corp.lab | 8080 | 172.28.0.10 | Internal portal (exposed) |
| dev.acme-corp.lab | 8082 | 172.28.0.11 | Dev server with debug enabled |
| test.acme-corp.lab | 8082 | 172.28.0.11 | Test environment (debug mode) |
| jenkins.acme-corp.lab | 8082 | 172.28.0.11 | CI/CD server (unauthenticated) |
| staging.acme-corp.lab | 8083 | 172.28.0.12 | Forgotten WordPress 4.9.8 |
| admin.acme-corp.lab | 8083 | 172.28.0.12 | Admin panel (default creds) |
| api.acme-corp.lab | 8084 | 172.28.0.13 | Exposed Swagger documentation |
| grafana.acme-corp.lab | 8084 | 172.28.0.13 | Monitoring dashboard |
| old.acme-corp.lab | 8085 | 172.28.0.14 | Legacy server (PHP 5.4) |
| ftp.acme-corp.lab | 8085 | 172.28.0.14 | FTP server nobody remembers |
| files.acme-corp.lab | 8086 | 172.28.0.15 | File server with exposed .git |
| backup.acme-corp.lab | 8086 | 172.28.0.15 | Backup server (directory listing) |
| vpn.acme-corp.lab | 8087 | 172.28.0.16 | VPN portal with version disclosure |
| shop.acme-corp.lab | 3000 | 172.28.0.30 | E-commerce (Juice Shop) |
| dvwa.acme-corp.lab | 8081 | 172.28.0.31 | Training app (DVWA) |

### Vulnerable Web Apps

| Service | URL | Description |
|---------|-----|-------------|
| Juice Shop | http://localhost:3000 | OWASP vulnerable web app |
| DVWA | http://localhost:8081 | Damn Vulnerable Web App |

## DNS Configuration

The lab includes a dnsmasq server for resolving `*.acme-corp.lab` subdomains. To use subdomain resolution:

### Option 1: Query the Lab DNS Directly

```bash
# Resolve subdomains via lab DNS
dig @localhost -p 5353 dev.acme-corp.lab
dig @localhost -p 5353 api.acme-corp.lab
```

### Option 2: Configure Host DNS (macOS/Linux)

Add the lab DNS as a resolver for the `.lab` TLD:

```bash
# macOS
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1\nport 5353" | sudo tee /etc/resolver/lab

# Linux (systemd-resolved)
# Add to /etc/systemd/resolved.conf.d/lab.conf
[Resolve]
DNS=127.0.0.1#5353
Domains=~lab
```

### Option 3: Configure SpiderFoot to Use Lab DNS

SpiderFoot is already configured to use the lab's DNS server (172.28.0.2) for internal resolution.

## Mock Breach API

The lab includes a local breach database API that simulates Have I Been Pwned functionality. This allows credential exposure demos without external API keys.

### Endpoints

```bash
# Check a specific email
curl http://localhost:5050/breaches/email/jsmith@acme-corp.lab

# Check all emails for a domain
curl http://localhost:5050/breaches/domain/acme-corp.lab

# Health check
curl http://localhost:5050/health
```

### Exposed Emails in the Mock Database

| Email | Breaches |
|-------|----------|
| jsmith@acme-corp.lab | AcmeDataLeak2023, LegacySystemLeak |
| it.admin@acme-corp.lab | LegacySystemLeak, PhishingCampaign2024 |
| sarah.ops@acme-corp.lab | AcmeDataLeak2023 |
| bob.developer@acme-corp.lab | GitHubTokenLeak2024, AcmeDataLeak2023 |
| hr@acme-corp.lab | PhishingCampaign2024 |

### Using with SpiderFoot

The lab includes custom SpiderFoot modules that integrate with the breach API automatically:

| Module | Purpose |
|--------|---------|
| `sfp_breach_api` | Checks discovered emails against the local breach database |
| `sfp_email_lab` | Email extractor that accepts `.lab` TLD (standard module rejects non-internet TLDs) |

These modules are included in the `footprint` and `investigate` scan profiles. When you scan `acme-corp.lab`, SpiderFoot will:

1. Crawl web pages and extract email addresses (`sfp_email_lab`)
2. Check each email against the breach database (`sfp_breach_api`)
3. Produce `EMAILADDR_COMPROMISED` events for matches

```bash
# Scan and check for breached credentials
uv run sf-cli scan --target acme-corp.lab --profile footprint --wait

# View compromised emails
uv run sf-cli results --scan-id $SCAN_ID --type EMAILADDR_COMPROMISED
```

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

# Get detailed status (active modules, discovered IPs/domains)
uv run sf-cli status --scan-id <ID> --detailed

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

### Shadow IT Discovery (Lab)

Use the lab to practice finding forgotten infrastructure:

```bash
# Scan the lab domain
uv run sf-cli scan --target acme-corp.lab --profile footprint --wait

# Analyze discovered subdomains
uv run sf-cli results --scan-id $SCAN_ID --format json | \
  claude -p "Analyze this attack surface scan. Identify:
    1) Shadow IT patterns (dev, staging, test servers)
    2) Exposed internal tools (Jenkins, GitLab, Grafana)
    3) Legacy/forgotten systems
    4) Information disclosure risks
    Prioritize findings by exploitability."
```

### Credential Exposure Check (Lab)

Test credential exposure workflows with the mock breach API:

```bash
# Check breach database for the domain
curl http://localhost:5050/breaches/domain/acme-corp.lab | \
  claude -p "Analyze these breach exposures. For each affected user:
    1) Assess risk based on breach types
    2) Recommend immediate actions
    3) Identify patterns (are admins or devs more exposed?)"
```

## External Legal Targets

These external services explicitly permit security scanning for educational purposes:

| Target | URL | What You Can Practice |
|--------|-----|----------------------|
| ScanMe Nmap | scanme.nmap.org | Port scanning, service detection |
| TestPHP Vulnweb | testphp.vulnweb.com | Web app vuln scanning (Acunetix) |
| TestHTML5 Vulnweb | testhtml5.vulnweb.com | Modern web app scanning |
| TestASPNET Vulnweb | testasp.vulnweb.com | ASP.NET vulnerability scanning |
| HackTheBox | *.hackthebox.com | CTF-style scanning (requires account) |
| TryHackMe | *.tryhackme.com | CTF-style scanning (requires account) |

### Usage Notes

- **Always verify current terms**: Check each site's scanning policy before use
- **Rate limiting**: Be respectful of resources, don't flood with requests
- **Passive preferred**: Start with passive scans before active enumeration
- **Educational only**: These are for learning, not offensive operations

### Example: External Passive Scan

```bash
# Passive scan of a legal target (no direct probing)
uv run sf-cli scan --target testphp.vulnweb.com --profile passive --wait

# Analyze external reconnaissance
uv run sf-cli results --scan-id $SCAN_ID --format json | \
  claude -p "Analyze this passive reconnaissance of a legal test target.
    Summarize what can be learned without touching the target directly."
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
# API Keys
SFP_SHODAN_API_KEY=your_shodan_key_here
SFP_VIRUSTOTAL_API_KEY=your_virustotal_key_here
SFP_HUNTER_API_KEY=your_hunter_key_here

# Module Options (SFOPT_<MODULE>_<OPTION>=value)
SFOPT__STOR_DB_MAXSTORAGE=0    # Store full web content (required for email extraction)
SFOPT_SPIDER_MAXPAGES=100      # Limit pages crawled per domain
```

### Module Options

Beyond API keys, you can configure SpiderFoot module options via environment variables:

```
SFOPT_<MODULE>_<OPTION>=value
```

**Format rules:**
- Module names are uppercased without the `sfp_` prefix
- Modules with double underscores (like `sfp__stor_db`) use a leading underscore

**Examples:**
| Environment Variable | SpiderFoot Setting |
|---------------------|-------------------|
| `SFOPT_SPIDER_MAXPAGES=100` | `sfp_spider:maxpages=100` |
| `SFOPT__STOR_DB_MAXSTORAGE=0` | `sfp__stor_db:maxstorage=0` |
| `SFOPT_PORTSCAN_TCP_PORTS=22,80,443` | `sfp_portscan_tcp:ports=22,80,443` |

**Important:** The `SFOPT__STOR_DB_MAXSTORAGE=0` setting is required for email extraction to work. The default (1024 bytes) truncates web content before emails can be found.

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
