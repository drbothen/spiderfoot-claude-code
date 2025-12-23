#!/bin/bash
# Filter SpiderFoot results to show key threat intel findings
# Usage: sf-cli results --scan-id XXX --format json | filter-findings.sh

jq '.[] | {type: .[10], data: .[1]} | select(.type == "MALICIOUS_IPADDR" or .type == "SOFTWARE_USED")'
