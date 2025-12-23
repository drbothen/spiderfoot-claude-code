#!/bin/bash
# Filter SpiderFoot results for Claude synthesis
# Includes all RAW_RIR_DATA for full threat intel context
# Usage: sf-cli results --scan-id XXX --format json | filter-synthesis.sh

jq '.[] | {type: .[10], source: .[3], data: .[1]} | select(
  .type == "MALICIOUS_IPADDR" or
  .type == "SOFTWARE_USED" or
  .type == "TCP_PORT_OPEN" or
  .type == "INTERNET_NAME_UNRESOLVED" or
  .type == "BGP_AS_OWNER" or
  .type == "NETBLOCK_OWNER" or
  .type == "SSL_CERTIFICATE_ISSUED" or
  .type == "SSL_CERTIFICATE_ISSUER" or
  .type == "RAW_RIR_DATA"
)' | sed 's/&quot;/"/g; s/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g'
