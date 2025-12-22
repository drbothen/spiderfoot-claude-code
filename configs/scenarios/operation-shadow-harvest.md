# Operation Shadow Harvest - Simulated Incident Scenario

A multi-day attack scenario for demonstrating incident response workflows with SpiderFoot and Claude Code. This scenario provides realistic context for IOC enrichment demos.

## Attack Overview

**Threat Actor Profile:**
- Financially motivated cybercrime group
- Uses commodity malware and living-off-the-land techniques
- Leverages Tor for anonymization
- Targets mid-size enterprises for credential theft and data exfiltration

**Target Organization:**
- Acme Corporation (acme-corp.lab)
- ~500 employees, Finance and Manufacturing sectors
- Remote workforce with VPN access

---

## Timeline

### Day 1 (Monday) - Initial Access via Phishing

**09:15 AM** - Phishing email delivered
- Recipient: jsmith@acme-corp.lab (Finance Department)
- Subject: "Important: Update Your Benefits Information"
- Sender: hr-updates@acme-corp-benefits.com (typosquat domain)
- Domain registered 5 days prior with Russian registrar

**09:17 AM** - User clicks link
- Redirected to credential harvesting page
- Page mimics internal HR portal
- User enters corporate credentials

**IOC:** `acme-corp-benefits.com`
- Alert: `siem-alert-002.json`

---

### Day 2 (Tuesday) - Credential Use

**10:32 AM** - Attacker logs into VPN
- Source IP: 185.220.101.1 (Tor exit node)
- Valid credentials for jsmith@acme-corp.lab
- Session duration: 4 hours

**10:35 AM** - Internal reconnaissance begins
- Attacker maps network shares
- Identifies sensitive data locations
- Downloads employee directory

**IOC:** `185.220.101.1`
- Note: This IP triggers divergent intelligence (GreyNoise: benign, AbuseIPDB: 87% malicious)

---

### Day 3 (Wednesday) - Persistence Established

**02:15 AM** - Scheduled task created
- Host: WS-JSMITH-PC
- Task: Windows Update Service (masquerading)
- Executable: Hidden in %APPDATA%

**02:16 AM** - First beacon to C2
- Destination: update-service.net:443
- Protocol: HTTPS (encrypted)
- Interval: 60 seconds

**IOC:** `update-service.net`

---

### Day 4 (Thursday) - Lateral Movement

**14:22 PM** - RDP to file server
- Source: WS-JSMITH-PC (10.1.50.23)
- Destination: FILESERVER01 (10.1.10.5)
- Credentials: jsmith (compromised)

**14:25 PM** - Sensitive data accessed
- /finance/q4-projections.xlsx
- /hr/salary-data-2024.xlsx
- /executive/board-presentation.pptx

**No external IOC** - Internal lateral movement

---

### Day 5 (Friday) - Detection

**14:32 PM** - Firewall detects beaconing
- 47 connections over 47 minutes
- Consistent 60-second interval
- Packet sizes suggest encrypted C2

**14:33 PM** - SIEM alert generated
- Alert ID: SEC-2024-00147
- Severity: HIGH
- Rule: Outbound C2 Beaconing Detected

**14:35 PM** - SOC analyst begins investigation
- **THIS IS WHERE THE ARTICLE STARTS**

**IOC:** `185.220.101.1`
- Alert: `siem-alert-001.json`

---

## IOCs for Enrichment Demo

| IOC | Type | Expected Finding | Alert |
|-----|------|------------------|-------|
| 185.220.101.1 | IP | Tor exit - divergent intel (GreyNoise benign, AbuseIPDB 87%) | siem-alert-001.json |
| acme-corp-benefits.com | Domain | Typosquat, phishing, 5 days old | siem-alert-002.json |
| update-service.net | Domain | C2, 30 days old, Panama registrant | N/A |
| 91.121.155.13 | IP | Known malicious C2 (all sources agree) | siem-alert-003.json |

---

## Demo Workflow

### 1. Alert Triage (siem-alert-001.json)

```bash
# View the alert
cat configs/alerts/siem-alert-001.json | jq .

# Key details: 60-second beaconing to 185.220.101.1
```

### 2. IOC Enrichment with Mock Mode

```bash
# Enrich the suspicious IP using mock threat intel
uv run sf-cli scan --target 185.220.101.1 --profile ir --mock --wait

# Get results for Claude analysis
uv run sf-cli results --scan-id $SCAN_ID --format json > enrichment.json
```

### 3. Synthesis with Claude Code

```bash
# Pipe results to Claude with alert context
cat enrichment.json | claude -p "Given this SIEM alert context:
$(cat configs/alerts/siem-alert-001.json)

Analyze the enrichment results and provide:
1. Verdict: Is this real C2 or internet noise?
2. Confidence level and reasoning
3. Why sources disagree and how behavioral context resolves it
4. Recommended immediate actions"
```

### 4. Expected Claude Output

Claude should recognize:
- GreyNoise labels it "benign" because it's a known Tor exit (opportunistic scanning)
- AbuseIPDB shows 87% abuse confidence from 1,247 reports (many Tor exits get reported)
- VirusTotal shows mixed results (15/90 malicious)

**Key insight:** The 60-second beaconing interval from a specific internal host changes the assessment. Random Tor traffic doesn't beacon at precise intervals. This is intentional C2 communication.

**Verdict:** Likely C2 over Tor
**Confidence:** High
**Action:** Isolate WS-JSMITH-PC immediately, preserve memory for forensics

---

## Scenario Extensions

### Credential Stuffing Attack (siem-alert-003.json)

A parallel attack using 91.121.155.13:
- 1,247 failed login attempts in 15 minutes
- 3 successful logins (compromised accounts)
- Uses credential list from known breaches
- All threat intel sources agree: malicious

```bash
# Enrich the attacker IP
uv run sf-cli scan --target 91.121.155.13 --profile ir --mock --wait
```

### Phishing Domain Investigation (siem-alert-002.json)

Follow-up investigation of the initial phishing:
- Domain age: 5 days (high risk)
- Russian registrar, privacy protected
- Visual similarity to legitimate domain

```bash
# Investigate the phishing domain
uv run sf-cli scan --target acme-corp-benefits.com --profile ir --mock --wait
```

---

## Learning Objectives

1. **Divergent Intelligence:** How to reconcile conflicting threat intel sources
2. **Behavioral Context:** Why alert context changes IOC interpretation
3. **Time Compression:** 30-60 minutes of manual research compressed to 5-10 minutes
4. **Synthesis Value:** Claude adds judgment, not just aggregation
5. **Mock Mode:** Repeatable demos without burning API quotas
