#!/bin/bash
# Filter SpiderFoot results to show key threat intel findings
# Usage: sf-cli results --scan-id XXX --format json | filter-findings.sh

# Show threat intel findings: malicious IPs, software, ports, DNS, WHOIS, SSL, and GreyNoise
# Decode HTML entities in the output
jq '.[] | {type: .[10], source: .[3], data: .[1]} | select(
  .type == "MALICIOUS_IPADDR" or
  .type == "SOFTWARE_USED" or
  .type == "TCP_PORT_OPEN" or
  .type == "INTERNET_NAME_UNRESOLVED" or
  .type == "BGP_AS_OWNER" or
  .type == "NETBLOCK_OWNER" or
  .type == "SSL_CERTIFICATE_ISSUED" or
  .type == "SSL_CERTIFICATE_ISSUER" or
  (.type == "RAW_RIR_DATA" and .source == "sfp_greynoise_mock")
)' | sed 's/&quot;/"/g; s/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g'
