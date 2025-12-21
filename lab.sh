#!/usr/bin/env bash
# SpiderFoot OSINT Lab Management Script
# Usage: ./lab.sh [up|down|reset|status|logs|shell]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "SpiderFoot OSINT Lab Management"
    echo ""
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  up            Start the lab environment"
    echo "  down          Stop and remove containers (preserves data)"
    echo "  reset         Full reset - removes containers AND data volumes"
    echo "  status        Show container status"
    echo "  logs          Follow container logs"
    echo "  shell         Open bash shell in SpiderFoot container"
    echo "  urls          Show URLs for all services"
    echo ""
    echo "Host DNS (for using real domain names from host):"
    echo "  hosts-enable  Add lab domains to /etc/hosts"
    echo "  hosts-disable Remove lab domains from /etc/hosts"
    echo "  hosts-status  Show current /etc/hosts state"
    echo ""
}

# Hosts file management
MARKER_START="# spiderfoot-lab-start"
MARKER_END="# spiderfoot-lab-end"

HOSTS_BLOCK="$MARKER_START
127.0.0.1 acme-corp.lab
127.0.0.1 www.acme-corp.lab
127.0.0.1 dev.acme-corp.lab
127.0.0.1 test.acme-corp.lab
127.0.0.1 staging.acme-corp.lab
127.0.0.1 admin.acme-corp.lab
127.0.0.1 portal.acme-corp.lab
127.0.0.1 api.acme-corp.lab
127.0.0.1 old.acme-corp.lab
127.0.0.1 legacy.acme-corp.lab
127.0.0.1 files.acme-corp.lab
127.0.0.1 backup.acme-corp.lab
127.0.0.1 vpn.acme-corp.lab
127.0.0.1 mail.acme-corp.lab
127.0.0.1 ftp.acme-corp.lab
127.0.0.1 intranet.acme-corp.lab
127.0.0.1 jenkins.acme-corp.lab
127.0.0.1 gitlab.acme-corp.lab
127.0.0.1 grafana.acme-corp.lab
$MARKER_END"

hosts_enable() {
    if grep -q "$MARKER_START" /etc/hosts; then
        echo -e "${YELLOW}Lab hosts already enabled${NC}"
        return 0
    fi

    echo -e "${GREEN}Adding lab hosts to /etc/hosts (requires sudo)...${NC}"
    echo "$HOSTS_BLOCK" | sudo tee -a /etc/hosts > /dev/null
    echo -e "${GREEN}Lab hosts enabled. You can now use domain names like:${NC}"
    echo "  curl http://dev.acme-corp.lab:8082"
    echo "  curl http://files.acme-corp.lab:8086"
}

hosts_disable() {
    if ! grep -q "$MARKER_START" /etc/hosts; then
        echo -e "${YELLOW}Lab hosts not found in /etc/hosts${NC}"
        return 0
    fi

    echo -e "${YELLOW}Removing lab hosts from /etc/hosts (requires sudo)...${NC}"
    sudo sed -i '' "/$MARKER_START/,/$MARKER_END/d" /etc/hosts
    echo -e "${GREEN}Lab hosts disabled${NC}"
}

hosts_status() {
    if grep -q "$MARKER_START" /etc/hosts; then
        echo -e "${GREEN}Lab hosts: ENABLED${NC}"
        echo ""
        grep -A 20 "$MARKER_START" /etc/hosts | head -22
    else
        echo -e "${YELLOW}Lab hosts: DISABLED${NC}"
        echo ""
        echo "Run './lab.sh hosts-enable' to use real domain names"
    fi
}

lab_up() {
    echo -e "${GREEN}Starting SpiderFoot OSINT Lab...${NC}"
    docker compose up -d

    echo ""
    echo -e "${GREEN}Waiting for services to be healthy...${NC}"
    sleep 5

    lab_urls
}

lab_down() {
    echo -e "${YELLOW}Stopping SpiderFoot OSINT Lab...${NC}"
    docker compose down
    echo -e "${GREEN}Lab stopped. Data volumes preserved.${NC}"
}

lab_reset() {
    echo -e "${RED}Resetting SpiderFoot OSINT Lab...${NC}"
    echo "This will delete all scan data and configurations!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker compose down -v
        echo -e "${GREEN}Lab reset complete.${NC}"
    else
        echo "Reset cancelled."
    fi
}

lab_status() {
    echo -e "${GREEN}SpiderFoot OSINT Lab Status:${NC}"
    echo ""
    docker compose ps
}

lab_logs() {
    docker compose logs -f
}

lab_shell() {
    echo -e "${GREEN}Opening shell in SpiderFoot container...${NC}"
    docker exec -it spiderfoot /bin/sh
}

lab_urls() {
    echo ""
    echo -e "${GREEN}=== Lab Services ===${NC}"
    echo ""
    echo "SpiderFoot UI:    http://localhost:5001"
    echo "Web Target:       http://localhost:8080"
    echo "OWASP Juice Shop: http://localhost:3000"
    echo "DVWA:             http://localhost:8081"
    echo ""
    echo -e "${YELLOW}Note: First DVWA access requires database setup.${NC}"
    echo -e "${YELLOW}      Click 'Create / Reset Database' on first visit.${NC}"
    echo ""
}

# Main
case "${1:-}" in
    up)
        lab_up
        ;;
    down)
        lab_down
        ;;
    reset)
        lab_reset
        ;;
    status)
        lab_status
        ;;
    logs)
        lab_logs
        ;;
    shell)
        lab_shell
        ;;
    urls)
        lab_urls
        ;;
    hosts-enable)
        hosts_enable
        ;;
    hosts-disable)
        hosts_disable
        ;;
    hosts-status)
        hosts_status
        ;;
    *)
        usage
        exit 1
        ;;
esac
