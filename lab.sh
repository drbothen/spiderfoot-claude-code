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
    echo "  up       Start the lab environment"
    echo "  down     Stop and remove containers (preserves data)"
    echo "  reset    Full reset - removes containers AND data volumes"
    echo "  status   Show container status"
    echo "  logs     Follow container logs"
    echo "  shell    Open bash shell in SpiderFoot container"
    echo "  urls     Show URLs for all services"
    echo ""
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
    *)
        usage
        exit 1
        ;;
esac
